# opennProbe

pcap から NF-v3 特徴量(NF-CSE-CIC-IDS2018-v3 などで使われている NetFlow 系の 53 列)の CSV を作るフローエクスポータ。
公開データセットの公式 CSV と同じ値になるように、フローの区切りと各列の計算規則を観測から合わせた独立実装。

- 入力: libpcap 形式の pcap(Ethernet)。IPv4 / IPv6
- 出力: CSV(1 行 1 フロー。開始時刻順。NF-v3 の 53 列)
- L7_PROTO: nDPI(固定コミットをソースからビルドして静的リンク)
- 互換モード: `official`(公式 CSV に合わせる。既定)/ `nprobe`(nProbe 10.4 の生出力に合わせる)

nProbe のバイナリ・逆アセンブル結果・コードは含まない。公式 CSV や CSE-CIC-IDS2018 の pcap も同梱しない。

## ビルド

必要なもの: gcc/g++(C++17)・CMake 3.16 以上・git。root は不要。

```bash
scripts/build-ndpi.sh          # nDPI 93f02ee5 を third_party/ndpi に静的ライブラリとしてビルド
cmake -S . -B build
cmake --build build -j
```

- nDPI の取得元は `NDPI_REPO`(既定 GitHub)で変えられる(手元の clone のパスでもよい)
- L7 なしでよければ `cmake -S . -B build -DOPENNPROBE_WITH_NDPI=OFF`(nDPI 不要。`--no-l7` 専用)

## 使い方

```bash
build/opennprobe -o out.csv input.pcap                   # 1 本(official モード)
build/opennprobe --compat nprobe -o out.csv input.pcap   # nProbe 10.4 の生出力互換
build/opennprobe --no-l7 -o out.csv input.pcap           # L7_PROTO を判定しない(速い)
build/opennprobe -j 8 -o outdir/ a.pcap b.pcap ...        # 複数本をファイル単位で並列(outdir/<pcap 名>.csv)
```

| オプション | 意味 |
|---|---|
| `-o PATH` | 出力 CSV(入力 1 本。省略時は標準出力)/ 出力ディレクトリ(入力が複数) |
| `-j N` | 複数入力の並列数(ファイルごとに別プロセス) |
| `--compat MODE` | 規則の互換モード: `official`(既定)/ `nprobe` |
| `--no-l7` | nDPI を使わない(L7_PROTO 列を出さない 52 列) |
| `--keep-truncated-tail` | 末尾の途中で切れたレコードも読めた部分で使う(既定は libpcap と同じく捨てる) |
| `--spill-mb N` | 出力行をメモリにためる上限(MB)。超えた分は整列して一時ファイルに出し最後にマージする(既定 64。0 は無制限) |
| `--tmpdir DIR` | 一時ファイルの置き場(既定 `$TMPDIR` か `/tmp`) |
| `-v` | 件数・ピークのフロー数・処理時間を標準エラーに出す |
| `--version` | 版と nDPI の版を出す |

Python からは `python/opennprobe`(subprocess で呼ぶ薄いラッパー)を使う。

```python
import opennprobe
opennprobe.convert("input.pcap", "out.csv")
opennprobe.convert_many(["a.pcap", "b.pcap"], "outdir", jobs=8, l7=False, compat="nprobe")
```

実行ファイルは `OPENNPROBE_BIN`・PATH・`build/opennprobe` の順に探す。

## 規則の要点

両モード共通:

- フロー表: (PROTOCOL, 2 端点) の双方向キー。src/dst は最初のパケットの送信側
- 期限: 開始から 120 秒・向き別の無通信 60 秒。判定は「パケット時刻の秒が進んだ最初のパケット」の処理前に行い、比較は秒単位
- DNS: 応答済みのフローに別 ID の問い合わせが来たら新フロー、同じ ID の再送は統計を引き継ぐ(touch)
- IPv4 全長 0 のパケット(TSO)は捨てる。caplen > 262144 のレコードで読み取りを止める(libpcap と同じ)
- L7: フローの全パケットを nDPI に渡し、出力時に giveup(ポート・IP 推測あり)
- IAT の標準偏差は ms 整数の Σx・Σx² から `(Σx² - (Σx)²/n) / n` を float32 で計算し、sqrt を切り捨てる(公式・nProbe の丸めを再現)

モードで変わるもの:

| 規則 | official | nprobe |
|---|---|---|
| RETRANSMITTED_IN_* | bin 判定(古い seq はペイロードがあれば再送) | bin 判定(古い seq は期待 seq − 1 で 1 バイト以下のときだけ再送) |
| RETRANSMITTED_OUT_* | A5 判定(シーケンス終端の最大値以下) | IN と同じ bin 判定 |
| RST を見たフローの期限 | 無通信 60 秒の代わりに、最後の非再送パケットから 22 秒 | 無通信の期限なし。次に自身のパケットが届いたとき、直前のパケット(どのフローのでも)が最終パケットから 15 秒以上後か、届いたパケットが 15 秒以上後で再送でなければ切って新フローにする |
| FLOW_DURATION_MILLISECONDS | 0 は 1 にする | 0 のまま |
| SRC/DST_TO_SRC_SECOND_BYTES | 逆向きバイト / 継続 ms(継続 0 ms は / 100) | 絶対秒のスロットごとの IP バイトをカンマで結合した文字列 |
| L7_PROTO | master が 0 でなければ master、0 なら app | `master.app`(master が 0 か app と同じなら 1 つ) |

## 回帰テスト

```bash
# 合成 12 本(リポジトリ内で完結。scapy 入りの Python が要る)
PYTHON=python3 scripts/synth-test.sh        # または cmake --build build && (cd build && ctest)

# 公式 12 本(CSE-CIC-IDS2018 の pcap の置き場所を引数で与える。ファイル名ではなく SHA-256 で識別)
scripts/regress.sh <2/14 の pcap ディレクトリ> <2/21 の pcap ディレクトリ>
```

- 合成 12 本(`tests/synth/`): `gen_*.py` で pcap を生成(決定的。`pcaps.sha256` で確認)-> 両モード × L7 あり/なしで変換 ->
  `tests/synth/expected/` の CSV とバイト単位で比べる。期待 CSV は opennProbe の出力。nprobe モード(L7 なし)の期待 CSV は
  nProbe 10.4 の出力と 60 フロー × 52 列すべて一致することを確認済み(L7_PROTO は 60 中 57 一致)。詳細は `tests/synth/README.md`
- 公式 12 本(`tests/official/`): `pcaps.tsv` の SHA-256 に合う pcap を探して両モード × L7 あり/なしで変換し、
  出力の SHA-256 を `expected.sha256` と比べる。期待値は調査用プロトタイプの出力とバイト単位で一致したもの

ベンチ: `BENCH_LIST=list.tsv BENCH_OUT=bench.tsv scripts/bench.sh <ラベル>`(list.tsv: `<名前>\t<pcap>`)

設計の詳細は `docs/design.md`、測定結果は `docs/benchmark.md`。

## ライセンス

GPL-3.0-or-later(`LICENSE`)。静的リンクする nDPI は LGPL-3.0。
