# 合成 12 本の回帰テスト

規則の境界(ヒストグラムの境目・再送・RST 後の期限・DNS の分割など)を 1 本ずつ突く小さな pcap を scapy で生成し、
opennProbe の出力を期待 CSV とバイト単位で比べる。実行は `scripts/synth-test.sh`(`ctest` からも呼ばれる)。

| ファイル | 内容 |
|---|---|
| `helper.py` | 生成の共通部(時刻は固定のエポック秒 + オフセットを EDecimal で正確に入れる) |
| `gen_NN_*.py` | 1 本ずつの生成スクリプト(出力先は環境変数 `SYNTH_OUT`) |
| `verify_pcaps.py` | 生成した pcap の中身を 1 パケット 1 行で表示する(目視用) |
| `pcaps.sha256` | 生成した pcap の SHA-256(scapy 2.8.0 で生成。生成は決定的で、2 回生成しても同じバイト列になる) |
| `expected/<モード>/NN_*.csv` | 期待 CSV(opennProbe の出力)。`official`・`official_l7`・`nprobe`・`nprobe_l7` |

## 期待 CSV の根拠

- `nprobe`(L7 なし): この 12 本を nProbe 10.4 で変換した出力と、60 フロー × 52 列(L7_PROTO 以外)がすべて一致することを確認済み
  (nProbe の出力ファイルそのものは同梱しない)。nProbe で観測したときの pcap はアドレスが 10.0.0.0/16 で、
  ここでは第 1・2 オクテットを 198.18 に置き換えている。置き換え前後で opennProbe の出力はアドレス以外同じ
- `nprobe_l7`: L7_PROTO は nProbe 10.4 と 60 フロー中 57 一致。nDPI 4.8.0(nProbe 10.4 同梱版)と
  opennProbe の nDPI 93f02ee5 はこの 12 本で同じ判定になる
- `official`・`official_l7`: 公式 CSV の後処理を含む規則。調査用プロトタイプの出力とバイト単位で一致することを確認済み

scapy の版が変わって pcap のバイト列が変わると、`pcaps.sha256` の確認で止まる(その場合は期待 CSV も見直す)。
規則を変えたときは `scripts/synth-test.sh --update` で期待 CSV を作り直し、差分を確かめてからコミットする。
