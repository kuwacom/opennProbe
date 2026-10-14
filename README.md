# opennProbe

pcap から NF-v3 特徴量(NF-CSE-CIC-IDS2018-v3 などで使われている NetFlow 系の 53 列)の CSV を作るフローエクスポータ。
公開データセットの公式 CSV と同じ値になるように、フローの区切りと各列の計算規則を観測から合わせた独立実装。

- 入力: libpcap 形式の pcap(Ethernet)。IPv4 / IPv6
- 出力: CSV(1 行 1 フロー。開始時刻順)
- L7_PROTO: nDPI(固定コミットをソースからビルドして静的リンク)

nProbe のバイナリ・逆アセンブル結果・コードは含まない。公式 CSV や pcap も同梱しない。

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
build/opennprobe -o out.csv input.pcap             # 1 本
build/opennprobe --no-l7 -o out.csv input.pcap     # L7_PROTO を判定しない(速い)
build/opennprobe -j 8 -o outdir/ a.pcap b.pcap ...  # 複数本をファイル単位で並列(outdir/<pcap 名>.csv)
```

| オプション | 意味 |
|---|---|
| `-o PATH` | 出力 CSV(入力 1 本。省略時は標準出力)/ 出力ディレクトリ(入力が複数) |
| `-j N` | 複数入力の並列数(ファイルごとに別プロセス) |
| `--no-l7` | nDPI を使わない(L7 系の列は 0) |
| `--compat MODE` | 規則の互換モード。現在は `official`(公式 CSV に合わせた規則)のみ |
| `--keep-truncated-tail` | 末尾の途中で切れたレコードも読めた部分で使う(既定は libpcap と同じく捨てる) |
| `--spill-mb N` | 出力行をメモリにためる上限(MB)。超えた分は整列して一時ファイルに出し最後にマージする(既定 64。0 は無制限) |
| `--tmpdir DIR` | 一時ファイルの置き場(既定 `$TMPDIR` か `/tmp`) |
| `-v` | 件数・ピークのフロー数・処理時間を標準エラーに出す |

Python からは `python/opennprobe`(subprocess で呼ぶ薄いラッパー)を使う。

```python
import opennprobe
opennprobe.convert("input.pcap", "out.csv")
opennprobe.convert_many(["a.pcap", "b.pcap"], "outdir", jobs=8, l7=False)
```

実行ファイルは `OPENNPROBE_BIN`・PATH・`build/opennprobe` の順に探す。

## 規則の要点(official)

- フロー表: (PROTOCOL, 2 端点) の双方向キー。src/dst は最初のパケットの送信側
- 期限: 開始から 120 秒・向き別の無通信 60 秒・RST 後は 22 秒(RST 後の再送では最終時刻を進めない)。
  判定は「パケット時刻の秒が進んだ最初のパケット」の処理前に行い、比較は秒単位
- DNS: 応答済みのフローに別 ID の問い合わせが来たら新フロー、同じ ID の再送は統計を引き継ぐ(touch)
- IPv4 全長 0 のパケット(TSO)は捨てる。caplen > 262144 のレコードで読み取りを止める(libpcap と同じ)
- L7: フローの全パケットを nDPI に渡し、出力時に giveup(ポート・IP 推測あり)。master が 0 でなければ master、0 なら app
- IAT の標準偏差は ms 整数の Σx・Σx² から float32 で計算する(公式の丸めを再現)

`ALT_` で始まる列は規則調査用の補助列(再送判定の候補・別定義の標準偏差など)。

## 回帰テスト・ベンチ

参照出力(調査用プロトタイプの CSV)とのバイト単位の比較と、速度・メモリの測定を行うスクリプト。
pcap と参照出力はリポジトリに含めないので、パスは環境変数で与える。

```bash
REGRESS_LIST=list.tsv REGRESS_REF=ref/ scripts/regress.sh      # list.tsv: <名前>\t<pcap>、ref/{l7,nol7}/<名前>.csv
BENCH_LIST=list.tsv BENCH_OUT=bench.tsv scripts/bench.sh <ラベル>
```

設計の詳細は `docs/design.md`、測定結果は `docs/benchmark.md`。

## ライセンス

GPL-3.0-or-later(`LICENSE`)。静的リンクする nDPI は LGPL-3.0。
