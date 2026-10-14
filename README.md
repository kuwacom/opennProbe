# opennProbe

> **English summary.** opennProbe is an independent, open-source flow exporter that converts pcap files into the
> 53-feature NetFlow-based "NF-v3" format used by the University of Queensland NIDS datasets (e.g. NF-CSE-CIC-IDS2018-v3).
> Its flow-splitting and per-column rules were derived from the published CSVs, the public CSE-CIC-IDS2018 pcaps and
> black-box observation, so that converting the original pcaps reproduces the published rows (99.896% of matched flows
> agree on all 52 non-L7 columns). It is written in C++17, uses nDPI for `L7_PROTO`, and is licensed under GPL-3.0-or-later.
> This project is not affiliated with ntop; nProbe is a trademark of ntop. Documentation is in Japanese.

pcap から **NF-v3**(UQ の NetFlow データセット第 3 版 NF-CSE-CIC-IDS2018-v3 などで使われている 53 特徴量)の CSV を作る
フローエクスポータ。公式 CSV と同じ値になるように、フローの区切りと各列の計算規則を公式データとの突き合わせと観測から定めた独立実装。

## できること・できないこと

用途:

- 公式 NF-v3 データセットと**同じ定義の特徴量**を、自分で取った pcap や別のデータセットの pcap から作る
  (NF-v3 で学習したモデルを別環境のトラフィックで評価する、など)
- 公式 CSV の各列がどう計算されているかを知る(`docs/rules.md`)
- nProbe 10.4 の生出力と同じ書式で出す(`--compat nprobe`)

できないこと・しないこと:

- ライブキャプチャ・NetFlow/IPFIX の送出はしない(pcap ファイル -> CSV のオフライン変換だけ)
- `Label` / `Attack` 列は付けない(ラベル付けは元データセットの ground truth と別途照合する)
- 公式 CSV の行の取捨は再現しない。公式は nProbe 出力の部分集合で、行のない pcap・時間帯が多い(「既知の残差」)
- nProbe の代わりではない。NF-v3 の 53 列以外の情報要素は出さない
- 入力は libpcap 形式(Ethernet・VLAN)。pcapng には対応しない(`editcap -F pcap` などで変換する)

## 必要なもの

| もの | 用途 |
|---|---|
| Linux・gcc/g++(C++17)・CMake 3.16 以上・git・make | ビルド。root は不要 |
| nDPI(コミット `93f02ee5`) | L7_PROTO の判定。`scripts/build-ndpi.sh` がソースを取得して静的ライブラリにする(autotools・root 不要) |
| Python 3.9 以上 + scapy 2.8.0(任意) | 合成テストの pcap 生成 |
| Python 3.10 以上 + pandas(任意) | `tools/` の公式 CSV との突き合わせ |

## ビルド

```bash
git clone https://github.com/kuwacom/opennProbe.git
cd opennProbe
scripts/build-ndpi.sh          # nDPI 93f02ee5 を third_party/ndpi に取得してビルド(数分)
cmake -S . -B build
cmake --build build -j
build/opennprobe --version     # opennprobe 1.0.0 (nDPI 4.9.0-93f02ee5)
```

- nDPI の取得元は環境変数 `NDPI_REPO`(既定 `https://github.com/ntop/nDPI.git`。手元の clone のパスでもよい)、
  並列数は `JOBS` で変えられる。出力先は第 1 引数(既定 `third_party/ndpi`)。別の場所に置いたら `cmake -DNDPI_PREFIX=<出力先>`
- L7_PROTO が要らなければ nDPI なしでビルドできる(出力は L7_PROTO を除く 52 列):

  ```bash
  cmake -S . -B build -DOPENNPROBE_WITH_NDPI=OFF
  cmake --build build -j
  ```

- `cmake --install build --prefix ~/.local` で `~/.local/bin/opennprobe` に入る

## 使い方

```bash
build/opennprobe -o out.csv input.pcap                    # 1 本(official モード・L7 あり)
build/opennprobe --compat nprobe -o out.csv input.pcap    # nProbe 10.4 の生出力互換
build/opennprobe --no-l7 -o out.csv input.pcap            # L7_PROTO を判定しない(速い)
build/opennprobe -j 8 -o outdir/ a.pcap b.pcap c.pcap     # 複数本をファイル単位で 8 並列 -> outdir/<pcap 名>.csv
```

| オプション | 意味 |
|---|---|
| `-o PATH` | 出力 CSV(入力 1 本。省略時は標準出力)/ 出力ディレクトリ(入力が複数。`<pcap のファイル名>.csv` を作る) |
| `-j N` | 複数入力の並列数(ファイルごとに別プロセス。既定 1) |
| `--compat MODE` | 互換モード: `official`(既定)/ `nprobe` |
| `--no-l7` | nDPI を使わない(L7_PROTO 列を出さない 52 列) |
| `--keep-truncated-tail` | 末尾の途中で切れたレコードも読めた部分で使う(既定は libpcap と同じく捨てる) |
| `--spill-mb N` | 出力行をメモリにためる上限(MB)。超えた分は整列して一時ファイルに出し、最後にマージする(既定 64。0 は無制限) |
| `--tmpdir DIR` | 一時ファイルの置き場(既定 `$TMPDIR` か `/tmp`) |
| `-v` | 件数・ピークのフロー数・処理時間を標準エラーに出す |
| `--version` | 版と nDPI の版を出す |

- pcap は 1 本ずつ独立に変換する(公式と同じ。ファイルをまたいでフローはつながらない)。大きな pcap を分割すると
  分割点でフローが切れるので、公式と比べるときは元の pcap のまま変換する
- 出力は FLOW_START_MILLISECONDS の昇順(同じ時刻はフローを出した順)。メモリは入力の大きさによらずほぼ一定(「性能」)

### Python から

`python/opennprobe` は実行ファイルを subprocess で呼ぶ薄いラッパー(依存なし)。

```bash
pip install ./python
export OPENNPROBE_BIN=$PWD/build/opennprobe    # または cmake --install で PATH の通った場所に入れる
```

```python
import opennprobe

opennprobe.convert("input.pcap", "out.csv")                       # official・L7 あり
opennprobe.convert_many(["a.pcap", "b.pcap"], "outdir", jobs=8, l7=False, compat="nprobe")
```

実行ファイルは引数 `binary`・環境変数 `OPENNPROBE_BIN`・PATH の順に探す。pip で入れずに `PYTHONPATH=python` で
リポジトリから直接使うときは、最後に `build/opennprobe` も探す。

## 出力列

1 行 1 フロー。列名と並びは公式 NF-CSE-CIC-IDS2018-v3 の 53 特徴量と同じ(`Label`・`Attack` は無い)。
IN = src→dst、OUT = dst→src(src はフローの最初のパケットの送信側)。バイトは IP パケット長(IPv4 は全長、IPv6 はペイロード長 + 40)。

| 列 | 単位・内容 |
|---|---|
| FLOW_START_MILLISECONDS / FLOW_END_MILLISECONDS | UTC エポック ms(最初・最後のパケット) |
| IPV4_SRC_ADDR / L4_SRC_PORT / IPV4_DST_ADDR / L4_DST_PORT / PROTOCOL | 5-tuple。IPv6 は IP が `0.0.0.0`、ICMP はポート 0 |
| L7_PROTO | nDPI のプロトコル番号(official は整数、nprobe は `master.app`) |
| IN_BYTES / IN_PKTS / OUT_BYTES / OUT_PKTS | バイト / パケット数 |
| TCP_FLAGS / CLIENT_TCP_FLAGS / SERVER_TCP_FLAGS | TCP フラグの OR(全体 / IN / OUT) |
| FLOW_DURATION_MILLISECONDS / DURATION_IN / DURATION_OUT | ms(全体 / 向き別) |
| MIN_TTL / MAX_TTL | IN 向き(最初のパケットを除く)の TTL・hop limit |
| LONGEST_FLOW_PKT / SHORTEST_FLOW_PKT / MIN_IP_PKT_LEN / MAX_IP_PKT_LEN | バイト |
| SRC_TO_DST_SECOND_BYTES / DST_TO_SRC_SECOND_BYTES | official: 名前と**逆向き**のバイト / 継続 ms の整数。nprobe: 秒ごとのバイトのカンマ結合(文字列) |
| RETRANSMITTED_IN_BYTES / _IN_PKTS / _OUT_BYTES / _OUT_PKTS | 再送と判定したバイト / パケット数 |
| SRC_TO_DST_AVG_THROUGHPUT / DST_TO_SRC_AVG_THROUGHPUT | bit/s(`bytes × 8000 / (継続 ms + 1)`) |
| NUM_PKTS_UP_TO_128_BYTES 〜 NUM_PKTS_1024_TO_1514_BYTES | 長さ別のパケット数(5 区間。1514 超は数えない) |
| TCP_WIN_MAX_IN / TCP_WIN_MAX_OUT | TCP ヘッダのウィンドウ値の最大(スケールを掛けない) |
| ICMP_TYPE / ICMP_IPV4_TYPE | ICMP の `type × 256 + code` / type。TCP では再送 IN バイトから作られる値(公式と同じ) |
| DNS_QUERY_ID / DNS_QUERY_TYPE / DNS_TTL_ANSWER | 最初の DNS メッセージの ID・質問 type / 最初の応答の最初の RR の TTL(秒) |
| FTP_COMMAND_RET_CODE | 常に 0(公式と同じ) |
| SRC_TO_DST_IAT_MIN / _MAX / _AVG / _STDDEV、DST_TO_SRC_IAT_* | 向き別の到着間隔(ms 整数) |

各列の正確な規則は **`docs/rules.md`**。

## 互換モード

| 規則 | `official`(既定) | `nprobe` |
|---|---|---|
| 合わせる相手 | 公式 NF-CSE-CIC-IDS2018-v3 CSV | nProbe 10.4 の生出力 |
| RETRANSMITTED_IN_* | 状態機械。ACK 済み範囲より前の payload 付きパケットは再送 | 状態機械。ACK 済み範囲より前は「期待 seq − 1 で 1 バイト以下」だけ再送 |
| RETRANSMITTED_OUT_* | シーケンス終端の最大値以下なら再送 | IN と同じ状態機械 |
| RST を見たフローの期限 | 最後の非再送パケットから 22 秒 | 15 秒空いた後のパケット到着で切る |
| FLOW_DURATION_MILLISECONDS | 0 ms は 1 にする | 0 のまま |
| SRC/DST_TO_SRC_SECOND_BYTES | 逆向きバイト / 継続 ms(継続 0 ms は / 100) | 絶対秒ごとの IP バイトのカンマ結合 |
| L7_PROTO | 上位番号 1 つ(master が 0 なら app) | `master.app` |

2 つある理由: 公式 CSV は nProbe の出力に後処理(継続 0→1・SECOND_BYTES・L7 の書式)を加えたもので、nProbe の生出力とは書式が違う。
さらに公式の作成に使われた nProbe の版は公開されておらず、観測に使えた nProbe 10.4 とは再送と RST 後の期限の規則が食い違う。
公式データを再現したいときは `official`、nProbe で取った他のデータと揃えたいときは `nprobe` を使う。

## 検証

### 合成テスト(リポジトリ内で完結)

規則の境界(ヒストグラムの境目・再送・RST 後の期限・DNS の分割など)を突く 12 本の小さな pcap を scapy で生成し、
両モード × L7 あり/なしの出力を期待 CSV(`tests/synth/expected/`)とバイト単位で比べる。
nprobe モード(L7 なし)の期待 CSV は、同じ pcap を nProbe 10.4 で変換した出力と 60 フロー × 52 列すべて一致することを確認したもの
(nProbe の出力そのものは同梱しない。詳細は `tests/synth/README.md`)。

```bash
python3 -m venv .venv
.venv/bin/pip install scapy==2.8.0
PYTHON=.venv/bin/python scripts/synth-test.sh     # 「合成 12 本: 一致 48 / 48」なら成功
# ctest からも呼べる: (cd build && PYTHON=$PWD/../.venv/bin/python ctest)
```

nDPI なしのビルドでは L7 ありの比較を飛ばす(24 / 24)。scapy の版が違って生成した pcap のバイト列が変わると、
`tests/synth/pcaps.sha256` の確認で止まる。

### 公式データでの再現

データセットはリポジトリに含めない。各配布元から取得し、それぞれの利用条件に従うこと。

1. **CSE-CIC-IDS2018 の pcap**(UNB CIC・AWS Open Data。AWS アカウント不要)

   ```bash
   aws s3 ls --no-sign-request --region ca-central-1 "s3://cse-cic-ids2018/Original Network Traffic and Log data/"
   aws s3 cp --no-sign-request --region ca-central-1 \
       "s3://cse-cic-ids2018/Original Network Traffic and Log data/Wednesday-14-02-2018/pcap.zip" 0214/   # 39.9 GB
   aws s3 cp --no-sign-request --region ca-central-1 \
       "s3://cse-cic-ids2018/Original Network Traffic and Log data/Wednesday-21-02-2018/pcap.zip" 0221/   # 53.5 GB
   (cd 0214 && unzip -q pcap.zip)    # 0214/pcap/ に端末別の pcap(拡張子なし。名前の末尾がその端末の IP)
   (cd 0221 && unzip -q pcap.zip)
   ```

   AWS CLI が無ければ HTTPS でも取れる(`https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com/` + キーを URL エンコードしたもの)。
   データセットの説明: <https://www.unb.ca/cic/datasets/ids-2018.html>・<https://registry.opendata.aws/cse-cic-ids2018/>

2. **NF-CSE-CIC-IDS2018-v3 の CSV**(UQ。配布ページの NetFlow V3 Datasets -> NF-CSE-CIC-IDS2018-v3 からダウンロード)

   - 配布ページ: <https://staff.itee.uq.edu.au/marius/NIDS_datasets/>
   - 展開すると `NF-CSE-CIC-IDS2018-v3.csv`(20,115,529 行・53 特徴量 + `Label` + `Attack`)

3. **回帰テスト(公式 12 本)**: 2/14 の 9 本と 2/21 の 3 本を変換し、出力の SHA-256 を `tests/official/expected.sha256` と比べる。
   pcap はファイル名ではなく中身の SHA-256(`tests/official/pcaps.tsv`)で探す。

   ```bash
   JOBS=8 scripts/regress.sh 0214/pcap 0221/pcap     # 「公式: 一致 48 / 48(pcap 12 / 12 本)」なら成功
   ```

   期待値は「規則を公式との突き合わせで詰めた調査用プロトタイプ」の出力とバイト単位で一致したもの。
   `regress.sh` は `--keep-truncated-tail` を付けて変換する(プロトタイプと同じ読み方。opennProbe の既定とは末尾 1 レコードの扱いだけ違う)

4. **公式 CSV との突き合わせ**(`tools/`。pandas が要る)

   ```bash
   # 公式フル CSV から 1 日分(現地日 = UTC 04:00 区切り)をストリームで抜く(メモリはほぼ一定)
   python3 tools/official_extract.py NF-CSE-CIC-IDS2018-v3.csv official_0214.csv --start-day 2018-02-14
   # pcap を 1 本ずつ丸ごと変換(出力名 <pcap 名>.csv の末尾 IP で公式行を割り当てる)
   build/opennprobe -j 16 -o out0214/ 0214/pcap/*
   # 公式側の被覆と列ごとの一致率を出す
   python3 tools/compare_official.py --official official_0214.csv --converted out0214 --out result --prefix d0214
   ```

   出力は `result/d0214_summary.txt`(pcap 別・合算・列別)・`_per_pcap.tsv`・`_per_column.tsv`。
   突き合わせの方法は `docs/rules.md`「公式 CSV との突き合わせ」。official モードの出力と比べること
   (nprobe モードは書式が違うので後処理 3 列が一致しない)。2/14 の全量突き合わせでは公式約 213 万行を保持するため RAM が 2〜3 GB 要る

## 検証結果

### 公式 12 本(2/14 の 9 本・2/21 の 3 本)

official モード・L7 あり(nDPI 93f02ee5)。公式一意行 415,211 行。

| 指標 | 値 |
|---|---:|
| 公式側の被覆(対応が取れた割合) | 0.99994(415,185 組) |
| L7 以外の 52 列がすべて一致した組 | 0.99896 |
| L7_PROTO の一致 | 0.99984 |
| RETRANSMITTED_IN_* / RETRANSMITTED_OUT_* | 99.970% / 99.960% |
| ICMP_TYPE・ICMP_IPV4_TYPE | 99.970% |
| SRC_TO_DST / DST_TO_SRC_IAT_STDDEV | 99.991% / 99.999% |
| FLOW_END_MILLISECONDS | 99.990% |
| 被害サーバの pcap(FTP/SSH ブルートフォースを受けた端末。公式 287,597 行) | 被覆・52 列とも 1.0000 |

pcap 別(端末の種別とサブネット):

| pcap | 公式一意行 | 被覆 | 52 列全一致 |
|---|---:|---:|---:|
| 2/14 EC2(172.31.64.0/24) | 17,591 | 0.9998 | 0.9951 |
| 2/14 PC(172.31.64.0/24・公式は一部の時間だけ) | 1,062 | 1.0000 | 0.9981 |
| 2/14 WIN(172.31.65.0/24) | 16,469 | 0.9998 | 0.9974 |
| 2/14 PC(172.31.65.0/24) | 10,569 | 0.9999 | 0.9959 |
| 2/14 PC(172.31.66.0/24)A | 13,221 | 0.9999 | 0.9975 |
| 2/14 PC(172.31.66.0/24)B | 13,056 | 0.9998 | 0.9972 |
| 2/14 UCAP(172.31.69.0/24) | 2,482 | 1.0000 | 0.9980 |
| 2/14 被害サーバ UCAP(172.31.69.0/24) | 287,597 | 1.0000 | 1.0000 |
| 2/14 EC2(172.31.69.0/24・公式は一部の時間だけ) | 2,504 | 1.0000 | 0.9992 |
| 2/21 DESKTOP(172.31.64.0/24)A | 15,478 | 0.9998 | 0.9963 |
| 2/21 DESKTOP(172.31.64.0/24)B | 20,083 | 0.9995 | 0.9967 |
| 2/21 DESKTOP(172.31.65.0/24) | 15,099 | 0.9999 | 0.9961 |
| 計 | 415,211 | 0.99994 | 0.99896 |

### 2/14 全量の結果

2018-02-14 の pcap 全 449 本(うち公式に行がある 213 本)を変換し、公式の 2/14 分と突き合わせた結果。

| 指標 | 値 |
|---|---:|
| 入力(pcap 本数・合計サイズ・レコード数) | 449 本・48.6 GB・87,783,076 |
| 変換時間(`-j 24`・L7 あり) | 120 秒 |
| 処理速度(合計 pps) | 約 0.73 M |
| 1 プロセスの最大 RSS | 106 MB |
| 公式一意行 | 1,822,065 |
| 公式側の被覆 | 0.99977 |
| L7 以外の 52 列がすべて一致した組 | 0.99656 |
| L7_PROTO の一致 | 0.99957 |

- 計測は 32 vCPU・RAM 31 GB の Linux 機。経過時間はディスク読み取り(約 340 MB/s)で決まり、CPU 使用率は平均 2.4 コア分だった。pcap 全体が RAM より大きいので 2 回目もほぼ全量を読み直す(2 回目 133 秒)
- 異常終了 0 本。caplen > 262144 のレコードで読み取りを止めた pcap が 55 本、末尾が途中で切れた pcap が 8 本ある
- 99.99% を下回る主な列: RETRANSMITTED_OUT_* 0.99836・RETRANSMITTED_IN_* と ICMP 2 列 0.99926・DURATION_IN 0.99950・FLOW_END/FLOW_DURATION/スループット 0.99963〜0.99965。公式 12 本より低いのは、検証セット外の pcap で再送とフロー区切りの残差が多いため

## 性能

詳細は `docs/benchmark.md`。2/14 の最大の pcap 1 本(850 MB・4,718,327 レコード・288,914 フロー)、official モード:

| 実装 | L7 | 秒 | pps | 最大 RSS |
|---|---|---:|---:|---:|
| 調査用プロトタイプ(Python) | あり | 156.3 | 30 k | 2,219 MB |
| opennProbe | あり | 2.68 | 1.76 M | 107 MB |
| opennProbe | なし | 1.59 | 2.97 M | 98 MB |

- プロトタイプの 58 倍(L7 あり)/ 89 倍(L7 なし)、RSS は約 1/20
- 出力行は `--spill-mb`(既定 64 MB)を超えると一時ファイルに逃がして外部ソートするので、RSS は入力の大きさによらずほぼ一定
- `-j` はファイル単位の並列。公式 12 本(2.55 GB)を `-j 12` で 2.7 秒(L7 あり)/ 1.5 秒(L7 なし)。経過時間は最大の 1 本でほぼ決まる
- L7 ありの時間の約 4 割は nDPI 内部

## 既知の残差

公式 12 本(official モード)で一致しない組と、規則が確定していない点。

| 項目 | 内容 |
|---|---|
| 再送 IN / OUT | IN 124 組・OUT 168 組が不一致。公式に最も合う判定と nProbe 10.4 に合う判定が違い(`docs/rules.md`「再送判定」)、どちらでも説明しきれない例がある。TCP の ICMP 2 列も同じ行で連動して外れる |
| RST 後の期限 | 公式は 22 秒型、nProbe 10.4 は 15 秒型が合う。公式で 22 秒型でも外れる例があり、公式の作成に使われた nProbe の規則は未確定 |
| フロー区切り | 被覆の残り 0.006%(pcap 1 本あたり 0〜10 フロー)。主に RST・異常な TCP 終了の周辺 |
| IAT_STDDEV | 45 組(S2D 39・D2S 6)。演算順は nDPI と同じにしたので、us 端数の丸めなど別の要因 |
| SECOND_BYTES(nprobe モード) | nProbe 10.4 の観測で、フロー末尾の秒が出ない例が 1 件。終了時の最後のスロットの扱いが未確定 |
| L7_PROTO | 不一致 68 組。66 組は期限で切れた続きのフローで、公式が 0・こちらがポート推測値(nProbe 10.4 でも位置が公式と揃わず、入力全体のタイミングに依存するとみられる)。2 組は NetBIOS / SMB の取り違え |
| 公式が部分集合 | 公式は nProbe 出力の一部しか含まない(2/14 は 449 本中 213 本に行があり、それも時間的に一部のことが多い)。行の取捨は再現しないので、被覆は公式側だけで測る |
| 公式の重複行 | 全列一致の重複行が多い(2/14 の 28.8%。攻撃行と一部の端末の行が 2 回ずつ)。突き合わせは一意化してから行う |
| 時刻が壊れたレコード | 一部の pcap に時刻が壊れたレコードがある。公式に該当行がないため nProbe の扱いは確かめられない |

## 法務

- **本プロジェクトは ntop とは無関係で、ntop の承認・支援を受けていない。nProbe は ntop の商標。** 名前の "nProbe" は
  nProbe と互換の出力を作ることを示すためだけに使っている
- nProbe のバイナリ・逆アセンブル結果・逆コンパイルしたコードを含まない。規則は、公開データ(公式 CSV と pcap)の突き合わせ、
  nProbe の出力の観測(合成 pcap などを変換した結果を比べるブラックボックスの観測)、公開情報(UQ の論文・nProbe の公開ドキュメント、
  かつて GPL-3.0 で公開されていた旧 nProbe 6.x のソースを挙動の参考として)から定め、コードはすべて独自に書いた
- ライセンスは **GPL-3.0-or-later**(`LICENSE`)。各ソースの先頭に `SPDX-License-Identifier: GPL-3.0-or-later`
- nDPI(LGPL-3.0)はリポジトリに含めない。`scripts/build-ndpi.sh` がビルド時に nDPI の公開リポジトリから取得し、静的にリンクする。
  ビルドした実行ファイルを配布する場合は nDPI の LGPL-3.0 の条件にも従うこと
- データセット(CSE-CIC-IDS2018・NF-CSE-CIC-IDS2018-v3)は同梱しない。利用は各配布元のライセンス・利用条件と引用の求めに従うこと。
  `tests/` には pcap の SHA-256・大きさと、変換出力の SHA-256 だけを置いている

## 引用

opennProbe で作ったデータを使う場合は、元のデータセットを引用すること。

- NF-v3(NetFlow V3 データセット):
  M. Luay, S. Layeghy, S. Hosseininoorbin, M. Sarhan, N. Moustafa, M. Portmann,
  "Temporal Analysis of NetFlow Datasets for Network Intrusion Detection Systems", arXiv:2503.04404, 2025.
  <https://arxiv.org/abs/2503.04404>
- NetFlow データセットの先行版(NF-v1 / NF-v2): M. Sarhan ら, arXiv:2011.09144 / arXiv:2101.11315
- CSE-CIC-IDS2018: I. Sharafaldin, A. H. Lashkari, A. A. Ghorbani,
  "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization",
  Proc. 4th International Conference on Information Systems Security and Privacy (ICISSP), 2018.
- nDPI: ntop, <https://github.com/ntop/nDPI>

## リポジトリの構成

| パス | 内容 |
|---|---|
| `src/` | 本体(C++17) |
| `scripts/` | nDPI のビルド・合成テスト・公式 12 本の回帰テスト・ベンチ |
| `tools/` | 公式 CSV の日単位抽出と、変換出力との全量突き合わせ(Python・pandas) |
| `python/` | Python ラッパー |
| `tests/synth/` | 合成 pcap の生成スクリプトと期待 CSV |
| `tests/official/` | 公式 12 本の pcap と期待出力の SHA-256 |
| `docs/rules.md` | フロー区切りと列ごとの計算規則・互換モード |
| `docs/design.md` | 実装の構成・出力順・規則の差し替え方 |
| `docs/benchmark.md` | 性能の測定結果 |
