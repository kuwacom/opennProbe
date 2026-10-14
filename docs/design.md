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
| `src/Flow.hpp` | フローの集計状態。到着間隔は個数・和・二乗和・最小・最大だけを逐次に持つ |
| `src/TcpRetx.hpp` | RETRANSMITTED_* の再送判定(bin と A5) |
| `src/FlowBuilder.*` | フローの区切り(期限・向き別 idle・RST 後の期限・DNS の分割/touch)と各パケットの集計、nDPI への受け渡し |
| `src/RowFormatter.*` | 終わったフローの 53 列の計算と整形 |
| `src/RowStore.*` | 行の保持・外部安定ソート・CSV 書き出し |
| `src/NdpiEngine.*` | nDPI の初期化・パケット投入・giveup |
| `src/Rules.hpp` | 互換モード(official / nprobe)ごとの規則の値 |

## 出力順

参照実装(調査用プロトタイプ)は、フローを出した順に行を並べてから開始時刻で安定ソートする。
同じ開始時刻の行の並びはフローを出した順で決まるので、次の順序を参照実装と同じにしている。

- 期限切れの走査は、パケット時刻の秒が進んだ最初のパケットの処理前に行う。
  参照実装は全フローを表への挿入順に見るが、ここでは「切れる秒」で並べたヒープから取り出し、同じ秒に切れたフローを挿入順に並べ替えて出す
  (切れる条件 `sec - ls > lim` または `sec - fs > life` は `sec >= min(ls + lim + 1, fs + life + 1)` と同値)
- 向き別 idle・DNS の分割/touch で作り直したフローは、表の同じ位置(挿入順)を引き継ぐ
- nprobe モードの RST 後の期限で切ったフローは表から外し、新フローは表の末尾(新しい挿入順)に入る
- 最後に残ったフローは挿入順に出す

列は NF-v3 の 53 列で固定(L7 なしのときは L7_PROTO を除く 52 列)。行が 0 のときは空ファイルにする(参照実装は列も無い)。
CSV の引用符は値にカンマを含むときだけ付ける(nprobe モードの SECOND_BYTES)。

## 互換モード

| 規則 | official | nprobe | 場所 |
|---|---|---|---|
| 再送 IN | bin(古い seq はペイロードがあれば再送) | bin(古い seq は期待 seq − 1 で 1 バイト以下のときだけ) | `TcpRetx::binHit` |
| 再送 OUT | A5 | bin | `TcpRetx::counts` |
| RST を見たフロー | 無通信の上限 22 秒(最後の非再送パケットから) | 無通信の上限なし + 後続パケットでの期限(15 秒) | `Rules`・`FlowBuilder::computeDeadline` / `rstExpired` |
| 継続 0 ms | 1 にする | 0 のまま | `RowFormatter::emit` |
| SECOND_BYTES | 逆向きバイト / 継続 ms | 絶対秒スロットのバイト列(`Flow::secBytes`) | `RowFormatter::putSecondBytes` |
| L7_PROTO | master か app の 1 つ | `master.app` | `RowFormatter::emit` |

bin の判定(向き別に直前パケットの seq・期待 seq・payload 長・window・flags を持つ):

1. D2S の payload 0 は数えない(状態は更新する)
2. seq が期待 seq と同じ: 再送でない
3. seq が直前の seq と同じ: payload 長・flags・window が直前と同じで、payload > 0 か flags が SYN/FIN/RST 単独なら再送
4. seq が直前の seq か期待 seq 以上: 直前の seq より前で payload > 0 なら再送
5. それ以外(どちらより前)で payload 0・flags が SYN/FIN/RST 単独: キープアライブとして状態も変えない
6. それ以外: official はペイロードがあれば再送、nprobe は seq が期待 seq − 1 で payload 1 バイト以下のときだけ再送

nprobe モードの RST 後の期限は、同じキーのパケットが届いたときに見る。
直前に届いたパケット(どのフローのでも。全長 0 で捨てるパケットも含む)が最終パケットから 15 秒以上後か、
届いたパケットが 15 秒以上後で bin 判定で再送にならなければ、旧フローを出して新フローにする。

## L7(nDPI)

- フローごとに nDPI のフロー状態を持ち、そのフローのパケットを IP ヘッダから全部渡す(長さは unsigned short)
- 判定が完了したら(app != 0 かつ追加解析なし)以後は渡さない。このとき giveup は判定済みのスタックをそのまま返すので、
  その場で結果を確定してフロー状態を解放する
- nDPI が packets_limit(32)に達して以後のパケットを無視する状態(fail_with_unknown)になったら呼び出しを省く。
  判定済みならそこで確定・解放する。未判定のフローは giveup が他フローの状態(キャッシュ)を見るので、出力時まで状態を残す
- giveup はフローを出力するときに、参照実装と同じ順序で呼ぶ
- 合成 12 本では nDPI 4.8.0(nProbe 10.4 同梱版)と 93f02ee5 の判定が同じ。公式 CSV に合うのは 93f02ee5(4.9 開発版)

## 整数・浮動小数点の列

参照実装(Python 3.11)と同じ演算順にしてビット単位で合わせる。

- 到着間隔は us 差を ms に床除算した整数。最小値は先頭から続く 0 ms を飛ばして初期化する
- IAT_AVG は整数和 / 個数(double)を 0 方向に切り捨て(和は 2^53 未満なので double の除算と一致する)
- IAT_STDDEV は ms 整数の Σx・Σx² から、nDPI の `ndpi_data_variance` と同じ `(f32(Σx²) - f32(Σx)² / n) / n` を
  各段 float32 で計算し、float32 の sqrt を切り捨てる。Σx・Σx² は __int128 で厳密に持つ
- FMA への融合を無効にしてビルドする(`-ffp-contract=off`)

## 規則を差し替えるときの入口

| 規則 | 場所 |
|---|---|
| 期限(lifetime・idle・RST 後)・向き別 idle・DNS の分割/touch | `Rules.hpp` の値と `FlowBuilder::add` / `computeDeadline` / `rstExpired` / `expire` |
| RST で終了済みにするか・RST 後の再送で最終時刻を進めないか | `FlowBuilder::count` |
| RETRANSMITTED_* の判定 | `TcpRetx` と `RowFormatter::emit` |
| IAT・標準偏差 | `FlowBuilder::accUpdate`(集計)と `RowFormatter::putDir`(出力) |
| SECOND_BYTES・THROUGHPUT・DURATION・L7_PROTO の書式 | `RowFormatter::emit` / `putSecondBytes` |

互換モードは `makeRules` で値を切り替える。値だけで表せない差は `Rules` に列挙や真偽値を足して分岐させる。
規則調査用の比較変種(再送判定の候補グリッド・ALT_* 列)は製品版から外した(調査は調査用プロトタイプで行う)。
