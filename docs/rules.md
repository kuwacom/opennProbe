# 計算規則

opennProbe がフローをどう区切り、53 列をどう計算するかの説明。規則は、公開されている公式 NF-CSE-CIC-IDS2018-v3 CSV
(以下「公式」)と CSE-CIC-IDS2018 の pcap の突き合わせ、合成 pcap に対する nProbe 10.4 の出力の観測、公開情報から定めた。

- 「一致率」は公式 12 本(`tests/official/`。公式と対応が取れた 415,185 組)での official モードの完全一致率
- 確度: 「確定」= 公式の全行の集計と突き合わせで例外がない、「推定」= 一致率は高いが規則の由来や細部が未確定
- 実装の場所は `docs/design.md`「規則を差し替えるときの入口」

## 公式 CSV の作られ方(公開情報と観測)

UQ の論文(Luay ら 2025)によると、公式は nProbe で pcap を 1 ファイルずつ変換し(`-V 9 --dont-reforge-time`)、出力を結合して
ラベルを付けたもの。nProbe・nDPI の版と idle timeout は公開されていない。観測から分かったこと:

| 項目 | 内容 |
|---|---|
| 変換の単位 | pcap ファイル(= 1 台のマシン)ごとに独立。ファイル間でフローはつながらない |
| 時刻 | UTC エポック ms。pcap のパケット時刻の us を ms に切り捨てたもの |
| 後処理 | ① 継続 0 ms を 1 にする ② L7_PROTO を上位番号だけにする ③ SECOND_BYTES を「逆向きバイト / 継続 ms」の整数にする。nProbe の生出力にはない |
| 期限 | lifetime 120 秒・idle 60 秒(向き別)。比較は秒単位 |
| 対象 | IPv4 と IPv6(IPv6 は IP 列が `0.0.0.0`)。それ以外は捨てる |
| 行の範囲 | 公式は nProbe 出力の**部分集合**。行のない pcap が多く、行のある pcap でも時間的に一部だけのことが多い(原因は不明) |

## フロー区切り

### フロー表

- キー: (PROTOCOL, {(IP, port), (IP, port)}) の双方向キー。ICMP はポート 0(ICMP type はキーに入れない)
- パケット長 L: IPv4 は IP ヘッダの全長、IPv6 はペイロード長 + 40
- IPv4 の全長が 0 のパケット(TSO のまま取得されたもの)は丸ごと捨てる(バイト・パケット数・時刻・フラグのどれにも入れない)
- pcap の読み取りは libpcap と同じ: caplen > 262144 のレコードで読み取りを止める。末尾の途中で切れたレコードは捨てる
  (`--keep-truncated-tail` で読めた部分を使う)
- pcap の終わりで全フローを出す(ファイル境界 = フロー境界)

### パケット到着時の判定(この順に評価)

パケット p(時刻 t [us]、`sec = floor(t / 1e6)`)が既存フロー F に来たとき:

| # | 条件 | 動作 | 確度 |
|---|---|---|---|
| 1 | `sec − floor(F の最初の時刻) > 120` | F を出し、p から新フロー | 確定 |
| 2 | `sec − floor(F の p と同じ向きの最終時刻) > 60`(その向きのパケットがまだなければ F の最終時刻) | 同上 | 推定(強) |
| 3 | (official)F で RST を見ており、`sec − floor(F.last_alive) > 22`。`last_alive` は RST 後の再送パケットでは進めない | 同上 | 推定 |
| 3' | (nprobe)F で RST を見ており、p の直前に届いたパケット(どのフローのでも)の時刻 − F の最終時刻 ≥ 15 秒、または p の時刻 − F の最終時刻 ≥ 15 秒で p が F の再送でない | 同上 | 推定(強) |
| 4 | F が UDP ポート 53/5355 の DNS で応答(QR=1)を受け済み、かつ p が src→dst の問い合わせ(QR=0) | ID が F と異なる → F を出し p から新フロー。同じ(再送)→ 下記 touch | 確定 |
| — | 上のどれでもない | p を F に加える | |

- FIN では区切らない(FIN の 64 秒後まで同じフローの例が公式にある)
- 期限切れの走査は「パケット時刻の秒が進んだ最初のパケット」の処理前に行う。判定は秒単位なので、出力のタイミングは値に影響しない

### touch(DNS の同 ID 再問い合わせ)

応答済みの DNS フロー F に同じ ID の問い合わせ p が来たとき:

1. p を F の累積統計にだけ反映する: FLOW_END・向き別の最終時刻(DURATION_IN/OUT)・IAT・ヒストグラム・TTL
2. F を出す(F のバイト数・パケット数には p を入れない)
3. 新フロー G を作り、F の累積統計(ヒストグラム・IAT・TTL・向き別の直前パケット時刻)を引き継ぐ。
   G の FLOW_START・バイト・パケット数・フラグ等は p から数え直す

公式には、ヒストグラムの合計がパケット数を超える行や、IAT があるのに IN_PKTS=1 の行があり、この規則で再現できる。

### 向き

- src = フローの最初のパケットの送信側(SYN の有無・ポート番号の大小は見ない)。期限で切れた続きのフローも同じで、
  続きがサーバ側のパケットから始まれば src はサーバになる
- IN = src→dst、OUT = dst→src

## 列ごとの計算規則

記号: t は us 整数。`raw = floor((last_t − first_t) / 1000)`(フロー全体の継続 ms)。S2D / D2S は src→dst / dst→src。

| 列 | 規則 | 一致率 | 確度 |
|---|---|---:|---|
| FLOW_START_MILLISECONDS | `floor(first_t / 1000)` | (キー) | 確定 |
| FLOW_END_MILLISECONDS | `floor(last_t / 1000)`(touch の p を含む) | 99.990% | 確定 |
| IPV4_SRC/DST_ADDR・L4_SRC/DST_PORT・PROTOCOL | 向きの規則どおり。IPv6 は IP を `0.0.0.0`。ICMP はポート 0 | (キー) | 確定 |
| L7_PROTO | nDPI の判定(下記「L7_PROTO」)。official は上位番号 1 つ、nprobe は `master.app` | 99.984% | 推定 |
| IN_BYTES / OUT_BYTES | 向き別の L の合計 | 99.991% / 99.998% | 確定 |
| IN_PKTS / OUT_PKTS | 向き別のパケット数 | 同上 | 確定 |
| TCP_FLAGS | CLIENT_TCP_FLAGS OR SERVER_TCP_FLAGS | 100% | 確定 |
| CLIENT_TCP_FLAGS / SERVER_TCP_FLAGS | S2D / D2S の TCP フラグの OR | 99.997% / 100% | 確定 |
| FLOW_DURATION_MILLISECONDS | official: `max(raw, 1)` / nprobe: `raw` | 99.990% | 確定 |
| DURATION_IN / DURATION_OUT | 向き別に `floor((その向きの最終 t − 最初の t) / 1000)`。パケット 0〜1 個なら 0 | 99.985% / 99.989% | 確定 |
| MIN_TTL / MAX_TTL | S2D のパケットのうち**フローの最初のパケットを除いたもの**の TTL(IPv6 は hop limit)の最小・最大。該当なしは 0。D2S は使わない | 99.999% | 確定 |
| LONGEST_FLOW_PKT / SHORTEST_FLOW_PKT | 両向きの L の最大・最小 | 100% | 確定 |
| MIN_IP_PKT_LEN | OUT_PKTS > 0 なら SHORTEST_FLOW_PKT、0 なら 0 | 100% | 確定 |
| MAX_IP_PKT_LEN | LONGEST_FLOW_PKT と同じ | 100% | 確定 |
| SRC_TO_DST_SECOND_BYTES | official: `raw ≥ 1` なら `floor(OUT_BYTES / raw)`、`raw = 0` なら `floor(OUT_BYTES / 100)`(名前と逆向きのバイト)。nprobe: 下記「互換モード」 | 100% | 確定(式の由来は不明) |
| DST_TO_SRC_SECOND_BYTES | 同上で IN_BYTES を使う | 99.999% | 確定 |
| RETRANSMITTED_IN/OUT_BYTES・_PKTS | 向き別の再送判定(下記)。バイトは L の合計 | IN 99.970% / OUT 99.960% | 推定 |
| SRC_TO_DST_AVG_THROUGHPUT | `floor(IN_BYTES × 8000 / (raw + 1))` | 99.990% | 確定 |
| DST_TO_SRC_AVG_THROUGHPUT | `floor(OUT_BYTES × 8000 / (raw + 1))` | 99.991% | 確定 |
| NUM_PKTS_UP_TO_128_BYTES 〜 1024_TO_1514_BYTES | L で 5 区間: `≤128` / `129–256` / `257–512` / `513–1024` / `1025–1514`。1514 超は数えない。touch の p を含む | 99.991〜100% | 確定 |
| TCP_WIN_MAX_IN / TCP_WIN_MAX_OUT | 向き別の TCP ヘッダのウィンドウ値(16 bit・スケールを掛けない)の最大。TCP 以外は 0 | 100% | 確定 |
| ICMP_TYPE | ICMP/ICMPv6: 最初のパケットの `type × 256 + code`。TCP: `R = RETRANSMITTED_IN_BYTES` として `(R & 0xFF) × 256 + ((R >> 16) & 0xFF)`。その他 0 | 99.970% | 確定(再送列に連動) |
| ICMP_IPV4_TYPE | ICMP/ICMPv6: type。TCP: `R & 0xFF`。その他 0 | 99.970% | 確定(同上) |
| DNS_QUERY_ID / DNS_QUERY_TYPE | UDP でポート 53 か 5355 を含むフローの、最初の DNS メッセージの ID と最初の質問の type | 100% | 確定 |
| DNS_TTL_ANSWER | 最初の応答(QR=1)で質問部の直後にある最初の RR(回答・権威・追加のどれでも)の TTL。応答なし・RR なしは 0 | 99.994% | 確定 |
| FTP_COMMAND_RET_CODE | 常に 0(公式の全行が 0) | 100% | 確定 |
| SRC_TO_DST_IAT_* / DST_TO_SRC_IAT_* | 向き別の連続パケット間隔 `x = floor(Δt / 1000)`(ms 整数・touch で引き継いだ分を含む)。n = 間隔の数 | 下の 4 行 | |
| ・IAT_MIN | 先頭から続く 0 は飛ばし、最初の非 0 で初期化。以降は通常の最小(以降の 0 は入る)。全部 0 なら 0 | 100% | 確定 |
| ・IAT_MAX | 最大 | 99.989% / 99.998% | 確定 |
| ・IAT_AVG | `floor(Σx / n)` | 99.991% / 99.999% | 確定 |
| ・IAT_STDDEV | Σx・Σx² を整数で求め、以降は float32 で `s = f32(Σx)`、`v = (f32(Σx²) − f32(s·s) / n) / n`、`trunc(sqrtf(v))`(v ≤ 0 なら 0)。母分散。nDPI の `ndpi_data_variance` と同じ演算順 | 99.991% / 99.999% | 確定 |

時刻はすべて us の整数で持ち、浮動小数で持たない。浮動小数の列は `-ffp-contract=off` でビルドして FMA への融合を避ける。

## 再送判定

### 状態機械による判定(コード上の名前は `bin`)

合成 pcap に対する nProbe 10.4 の出力の観測に合わせた判定。向き別に状態
[ref, nxt, 直前の payload 長, 直前の window, 直前の flags] を持つ。ref = 自分の直前パケットの seq(最初は最初のパケットの seq)、
nxt = 直前の `seq + payload + SYN`(FIN は消費しない)。比較はすべて 32 bit 符号なし。

1. その向きの最初のパケット: 状態を作るだけ
2. `seq == nxt`: 通常(数えない)
3. `seq == ref`: payload 長・flags・window が直前と同じで、かつ payload > 0 か flags が SYN/FIN/RST 単独なら再送
4. `seq ≥ ref` か `seq ≥ nxt`(上記以外): `seq < ref` かつ payload > 0 なら再送。他は順序違い(数えない)
5. それ以外(ref・nxt より前): payload 0 で flags が SYN/FIN/RST 単独ならキープアライブ(数えず、状態も変えない)。
   それ以外は、official: payload > 0 なら再送 / nprobe: `seq == nxt − 1` かつ payload ≤ 1 のときだけ再送
6. D2S の payload 0 のパケットは数えない(状態は更新する)

### シーケンス終端の最大値による判定(コード上の名前は `A5`)

向き別に「シーケンス終端(`seq + payload + SYN`)の最大値」を持ち、終端がそれ以下のパケットを再送とする。
相手側から 1 パケットでも来ていたら SYN の重複は数えない。official モードの OUT 向きに使う(公式では状態機械より一致が高い)。

## 互換モード

公式は nProbe の出力に後処理を加えたもので、さらに公式の作成に使われた nProbe(版は非公開)と、観測に使えた nProbe 10.4 では
一部の規則が食い違う。どちらに合わせるかで出力が変わるため、2 つのモードを持つ。

- `official`(既定): 公式 CSV と同じ値を出す。食い違う規則は公式 12 本で一致率の高い方を採った
- `nprobe`: nProbe 10.4 の生出力と同じ値を出す(後処理なし)。合成 12 本(60 フロー)で L7 以外の 52 列が全一致

| 規則 | official | nprobe |
|---|---|---|
| RETRANSMITTED_IN_* | 状態機械(5 で payload > 0 なら再送) | 状態機械(5 で `nxt − 1` かつ payload ≤ 1 だけ再送) |
| RETRANSMITTED_OUT_* | シーケンス終端の最大値 | IN と同じ状態機械 |
| ICMP_TYPE / ICMP_IPV4_TYPE(TCP) | 再送 IN バイトから(式は共通) | 同左 |
| RST を見たフローの期限 | `last_alive` から 22 秒(判定 #3) | 15 秒空いた後のパケット到着で切る(判定 #3') |
| FLOW_DURATION_MILLISECONDS | 0 を 1 にする | 0 のまま |
| SRC/DST_TO_SRC_SECOND_BYTES | `floor(逆向きバイト / raw)`(raw = 0 は / 100) | 秒ごとの IP バイトのカンマ結合(下記) |
| L7_PROTO | master が 0 でなければ master、0 なら app | `master.app`(master が 0 か app と同じなら 1 つ) |
| IAT_STDDEV・その他の列 | 共通 | 共通 |

nprobe モードの SECOND_BYTES: 向き別に、パケット時刻の**エポック秒**(切り捨て)ごとの IP バイト合計を、そのフローの最初のパケットの秒から
最終パケットの秒まで並べ、空の秒は空文字列として `,` で結合する(要素数 = 秒の差 + 1)。その向きのパケットが最初の秒に無いときは
先頭が空要素になる。スロットの境界はフロー開始からの 1 秒ではなく絶対秒。値にカンマを含むので CSV では引用符で囲む。

## L7_PROTO

- フローごとに nDPI のフロー状態を持ち、そのフローの全パケット(IP ヘッダから)を `ndpi_detection_process_packet` に渡す。
  打ち切りは nDPI の既定(フローあたり 32 パケット)に任せ、出力時に `ndpi_detection_giveup`(ポート・IP による推測あり)を呼ぶ
- 期限で切れた続きのフローは状態を引き継がず新しく判定する
- nDPI の版は固定コミット `93f02ee5`(4.9 開発版)。公式に出る番号の範囲から、公式は 4.9 開発版相当(BFD = 401 の追加後・LDP = 409 の追加前)と
  推定した。nDPI は版をまたいで番号を別プロトコルに再利用することがあるので版を固定する

| nDPI | 公式 12 本の L7_PROTO 一致率 |
|---|---:|
| 4.9 開発版 93f02ee5(採用) | 0.99984 |
| 4.10 | 0.99982 |
| 4.8.0 | 0.99974 |
| 4.12 / 4.14 / 5.0 | 0.989(RDP 88 を TLS 91 と出す) |

## 公式 CSV との突き合わせ

`tools/compare_official.py` の方法:

1. pcap を 1 本ずつ丸ごと変換する(区間に切らない)
2. 公式から、その pcap のマシン IP(CSE-CIC-IDS2018 の pcap 名の末尾)を src か dst に持つ行を抜き、全列一致の重複を一意化する
   (公式には全列一致の重複行が多い。重複の再現は変換器の責務にしない)
3. 「向き付き 5-tuple + FLOW_START_MILLISECONDS」で対応づける。公式は部分集合なので**公式側の被覆**だけを見て、変換側の余分な行は数えない
4. 対応した組で列ごとの完全一致率を出す(L7_PROTO は別集計)
5. 公式の IPv6 行(IP 列が `0.0.0.0`)はマシン IP で割り当てられないので、公式側に無い限り変換側からも外す

公式の行は、どの行も「pcap を持つマシンの IP」を端点にちょうど 1 つ持つ(端末どうしの通信行はない)ので、IPv4 行の出所の pcap は一意に決まる。
