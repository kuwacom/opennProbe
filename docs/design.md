# 設計メモ

## 処理の流れ

```
PcapReader(mmap) -> parsePacket -> FlowBuilder -> RowFormatter -> RowStore -> CSV
                                       |
                                  NdpiEngine(L7)
```

| ファイル | 役割 |
|---|---|
| `src/PcapReader.*` | libpcap 形式の読み取り。caplen > 262144 で停止・snaplen 超過の切り詰め・末尾の切れたレコードの扱いを libpcap に合わせる。読み終えたページは madvise で手放す |
| `src/Packet.*` | Ethernet/VLAN/IPv4/IPv6(拡張ヘッダ)/TCP/UDP/ICMP の解析。ペイロードはコピーしない |
| `src/FlowKey.hpp` `src/OpenTable.hpp` | 双方向 5-tuple キー(40 バイト固定)と open addressing の表(線形探査・後方シフト削除) |
| `src/Flow.hpp` `src/TcpRetxVariants.hpp` | フローの集計状態。再送候補の状態は TCP だけが持つ |
| `src/FlowBuilder.*` | フローの区切り(期限・向き別 idle・DNS の分割/touch)と各パケットの集計、nDPI への受け渡し |
| `src/RowFormatter.*` | 終わったフローの列の計算と整形 |
| `src/RowStore.*` | 行の保持・外部安定ソート・列順の決定と CSV 書き出し |
| `src/NdpiEngine.*` | nDPI の初期化・パケット投入・giveup |
| `src/Rules.hpp` | 互換モードごとの規則の値 |

## 出力順と列順

参照実装(調査用プロトタイプ)は、フローを出した順に行を並べてから開始時刻で安定ソートする。
同じ開始時刻の行の並びはフローを出した順で決まるので、次の順序を参照実装と同じにしている。

- 期限切れの走査は、パケット時刻の秒が進んだ最初のパケットの処理前に行う。
  参照実装は全フローを表への挿入順に見るが、ここでは「切れる秒」で並べたヒープから取り出し、同じ秒に切れたフローを挿入順に並べ替えて出す
  (切れる条件 `sec - ls > lim` または `sec - fs > life` は `sec >= min(ls + lim + 1, fs + life + 1)` と同値)
- 向き別 idle・DNS の分割/touch で作り直したフローは、表の同じ位置(挿入順)を引き継ぐ
- 最後に残ったフローは挿入順に出す

列順は pandas の `DataFrame(list of dict)` と同じく「最初の行の列 + 後から現れた列を末尾に追加」。
ICMP 行だけにある `ALT_ICMP_LAST` と TCP 行だけにある `ALT_RX_*` の位置が、最初に出た行の種類で変わる。
`ALT_ICMP_LAST` は欠けた行があれば float 列(`2816.0`)になる。

## L7(nDPI)

- フローごとに nDPI のフロー状態を持ち、そのフローのパケットを IP ヘッダから全部渡す(長さは unsigned short)
- 判定が完了したら(app != 0 かつ追加解析なし)以後は渡さない。このとき giveup は判定済みのスタックをそのまま返すので、
  その場で結果を確定してフロー状態を解放する
- nDPI が packets_limit(32)に達して以後のパケットを無視する状態(fail_with_unknown)になったら、呼び出しを省いて数だけ数える。
  判定済みならそこで確定・解放する。未判定のフローは giveup が他フローの状態(キャッシュ)を見るので、出力時まで状態を残す
- giveup はフローを出力するときに、参照実装と同じ順序で呼ぶ

## 浮動小数点の列

参照実装(Python 3.11)と同じ演算順にしてビット単位で合わせる。

- 平均は整数和 / 要素数(double)。分散は `(x - mean) ** 2` を libm の `pow` で計算して素朴に逐次加算
  (コンパイラが `x * x` に畳まないよう関数ポインタ経由で呼ぶ)
- IAT_STDDEV は ms 整数の Σx・Σx² から float32 で `Σx²/n - (Σx/n)²` を計算し、float32 の sqrt を切り捨て
- FMA への融合を無効にしてビルドする(`-ffp-contract=off`)

## 規則を差し替えるときの入口

| 規則 | 場所 |
|---|---|
| 期限(lifetime・idle・RST 後)・向き別 idle・DNS の分割/touch | `Rules.hpp` の値と `FlowBuilder::add` / `computeDeadline` / `expire` |
| RST で終了済みにするか・RST 後の再送で最終時刻を進めないか | `FlowBuilder::count` |
| RETRANSMITTED_* の判定 | `TcpRetxVariants`(現在は候補 A5)と `RowFormatter::emit` |
| IAT・標準偏差 | `RowFormatter::putDir` |
| SECOND_BYTES・THROUGHPUT・DURATION | `RowFormatter::emit` |

互換モードは `makeRules` で値を切り替える。値だけで表せない差は `Rules` に真偽値を足して分岐させる。
