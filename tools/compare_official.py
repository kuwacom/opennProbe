# SPDX-License-Identifier: GPL-3.0-or-later
"""変換器出力(pcap 1 本 = CSV 1 本)と公式の日単位抽出 CSV を全量で突き合わせる

検証方法は docs/rules.md「公式 CSV との突き合わせ」どおり:
1. 変換器は pcap を 1 本ずつ丸ごと変換してある(区間に切らない)
2. 公式から、その pcap のマシン IP(変換 CSV ファイル名末尾の IPv4)を src/dst に持つ行を抜き、
   全列一致の重複を一意化する
3. 「向き付き 5-tuple + FLOW_START_MILLISECONDS」で対応づける。公式は部分集合なので
   公式側の被覆だけを見て、変換器側の余分行は数えない
4. 対応した組で 53 列それぞれの完全一致率を出す(L7_PROTO は別集計)
5. IPv6 行(IP 列が 0.0.0.0)は、公式側に 0.0.0.0 が含まれない限り変換器側から外す
   (マシン IP で公式を割り当てると IPv6 行はどの pcap にも属さない)

pcap 単位で処理するので、公式が数十万行あってもメモリは数 GB 以内に収まる
- 公式は 1 度だけチャンク読みし、マシン IP を端点に持つ行だけを IP ごとに保持する
- 公式 1 行はちょうど 1 つのマシン IP に割り当てられる(端末どうしの通信行がなく、
  IPv6 行は 0.0.0.0 のまま割り当てられない)ため、合算は各 pcap の和でよい

使い方: compare_official.py --official <公式日単位CSV> --converted <変換出力ディレクトリ>
        [--pattern "*.csv"] [--ip-map <name.tsv>] [--out <出力先>] [--prefix <名前>]
出力: <prefix>_per_pcap.tsv(pcap 別の表) / <prefix>_per_column.tsv(列別の合算) / <prefix>_summary.txt(要約)
"""

import argparse
import os
import re
import sys

import pandas as pd

KEY = ["IPV4_SRC_ADDR", "L4_SRC_PORT", "IPV4_DST_ADDR", "L4_DST_PORT", "PROTOCOL"]
START = "FLOW_START_MILLISECONDS"
# NF-v3 の 53 列(公式 CSV の 53 特徴量に一致)
NF = [START, "FLOW_END_MILLISECONDS", "IPV4_SRC_ADDR", "L4_SRC_PORT",
      "IPV4_DST_ADDR", "L4_DST_PORT", "PROTOCOL", "L7_PROTO",
      "IN_BYTES", "IN_PKTS", "OUT_BYTES", "OUT_PKTS",
      "TCP_FLAGS", "CLIENT_TCP_FLAGS", "SERVER_TCP_FLAGS",
      "FLOW_DURATION_MILLISECONDS", "DURATION_IN", "DURATION_OUT",
      "MIN_TTL", "MAX_TTL", "LONGEST_FLOW_PKT", "SHORTEST_FLOW_PKT",
      "MIN_IP_PKT_LEN", "MAX_IP_PKT_LEN",
      "SRC_TO_DST_SECOND_BYTES", "DST_TO_SRC_SECOND_BYTES",
      "RETRANSMITTED_IN_BYTES", "RETRANSMITTED_IN_PKTS", "RETRANSMITTED_OUT_BYTES",
      "RETRANSMITTED_OUT_PKTS",
      "SRC_TO_DST_AVG_THROUGHPUT", "DST_TO_SRC_AVG_THROUGHPUT",
      "NUM_PKTS_UP_TO_128_BYTES", "NUM_PKTS_128_TO_256_BYTES", "NUM_PKTS_256_TO_512_BYTES",
      "NUM_PKTS_512_TO_1024_BYTES", "NUM_PKTS_1024_TO_1514_BYTES",
      "TCP_WIN_MAX_IN", "TCP_WIN_MAX_OUT", "ICMP_TYPE", "ICMP_IPV4_TYPE",
      "DNS_QUERY_ID", "DNS_QUERY_TYPE", "DNS_TTL_ANSWER", "FTP_COMMAND_RET_CODE",
      "SRC_TO_DST_IAT_MIN", "SRC_TO_DST_IAT_MAX", "SRC_TO_DST_IAT_AVG", "SRC_TO_DST_IAT_STDDEV",
      "DST_TO_SRC_IAT_MIN", "DST_TO_SRC_IAT_MAX", "DST_TO_SRC_IAT_AVG", "DST_TO_SRC_IAT_STDDEV"]
IPV6 = "0.0.0.0"
# ファイル名末尾の IPv4(capPC1-<IPv4> / UCAP<IPv4> など、ホスト名部分に数字が混ざる)
IP_TAIL = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$")


def extract_ip(name: str) -> str | None:
    m = IP_TAIL.search(name[: -len(".csv")] if name.endswith(".csv") else name)
    return m.group(1) if m else None


def key_of(df: pd.DataFrame) -> pd.Series:
    """対応づけキー: 向き付き 5-tuple + FLOW_START_MILLISECONDS"""
    s = [df[c].astype(str) for c in KEY] + [df[START].astype(str)]
    return s[0] + "|" + s[1] + "|" + s[2] + "|" + s[3] + "|" + s[4] + "|" + s[5]


def load_official(path: str, ips: set[str], chunksize: int) -> dict[str, pd.DataFrame]:
    """公式日単位 CSV をチャンク読みし、マシン IP を端点に持つ行だけを IP ごとに返す

    公式 CSV の全列(ROW を除く)を保持する。重複の一意化は各 pcap の比較時に行うため、
    ここでは行を絞るだけにする(Label / Attack も一意化に含める)
    """
    groups: dict[str, list[pd.DataFrame]] = {}
    reader = pd.read_csv(path, chunksize=chunksize, keep_default_na=False,
                         dtype={"IPV4_SRC_ADDR": "category", "IPV4_DST_ADDR": "category"})
    for ch in reader:
        if "ROW" in ch.columns:
            ch = ch.drop(columns=["ROW"])
        src = ch[KEY[0]].astype(str)
        dst = ch[KEY[2]].astype(str)
        mask = src.isin(ips) | dst.isin(ips)
        if not mask.any():
            continue
        sub = ch[mask].copy()
        # 端末どうしの通信行はなく、src/dst のどちらか一方だけがマシン IP に一致する
        sub["ip"] = src[mask].where(src[mask].isin(ips), dst[mask])
        for ip, gdf in sub.groupby("ip", sort=False, observed=True):
            groups.setdefault(ip, []).append(gdf.drop(columns=["ip"]))
    return {ip: pd.concat(parts, ignore_index=True) for ip, parts in groups.items()}


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--official", required=True, help="公式の日単位抽出 CSV(official_extract.py の出力)")
    ap.add_argument("--converted", required=True, help="変換器出力ディレクトリ(pcap 1 本 = CSV 1 本)")
    ap.add_argument("--pattern", default="*.csv", help="変換 CSV のファイル名パターン")
    ap.add_argument("--ip-map", help="ファイル名<TAB>IP の一覧 TSV(ファイル名末尾から IP を取れない場合)")
    ap.add_argument("--chunksize", type=int, default=500_000)
    ap.add_argument("--out", default=".", help="出力先ディレクトリ")
    ap.add_argument("--prefix", default="compare", help="出力ファイル名の接頭辞")
    a = ap.parse_args()

    paths = sorted(p for p in os.listdir(a.converted) if p.endswith(".csv") and
                   (a.pattern == "*.csv" or re.fullmatch(a.pattern.replace("*", ".*"), p)))
    if not paths:
        sys.exit(f"変換 CSV が見つからない: {a.converted}/{a.pattern}")
    ip_map = {}
    if a.ip_map:
        for line in open(a.ip_map):
            if line.strip():
                name, ip = line.rstrip("\n").split("\t")
                ip_map[name] = ip

    pairs = {}
    for p in paths:
        ip = ip_map.get(p) or extract_ip(p)
        if not ip:
            print(f"警告: IP を特定できないため除外: {p}")
            continue
        pairs[p] = ip

    print(f"公式 {a.official} を読み込み中({len(pairs)} 本の変換 CSV)")
    groups = load_official(a.official, set(pairs.values()), a.chunksize)
    print(f"マシン IP に割り当てた公式行: {sum(len(v) for v in groups.values()):,} 行({len(groups)} IP)")

    col = {c: [0, 0] for c in NF}  # 列別の [一致, 対応] の合算
    tot52 = [0, 0]  # L7 以外 52 列の全一致の合算
    totl7 = [0, 0]  # L7_PROTO の合算(変換側に L7 がある場合だけ)
    rows = []
    for p in paths:
        ip = pairs[p]
        of = groups.get(ip)
        if of is None:
            print(f"{p}: 公式行なし(被覆の対象外)")
            rows.append({"basename": p, "ip": ip, "official_raw": 0, "official_unique": 0,
                         "matched": 0, "coverage": None, "col52_rate": None, "l7_rate": None})
            continue
        n_raw = len(of)
        of_u = of.drop_duplicates().reset_index(drop=True)
        pr = pd.read_csv(os.path.join(a.converted, p), keep_default_na=False)
        if not (of_u[KEY[0]] == IPV6).any():
            # 公式側に IPv6 表記の行がなければ、変換側の IPv6 行は対応づけ対象外
            pr = pr[pr[KEY[0]] != IPV6].reset_index(drop=True)
        of_u["_k"] = key_of(of_u)
        pr["_k"] = key_of(pr)
        m = of_u.merge(pr, on="_k", suffixes=("", "_p"))
        # キー 6 列(5-tuple + 開始時刻)は対応づけ条件そのものなので比較列から外し、
        # L7_PROTO も別集計にする -> col52_rate は「L7 以外 52 列」の全一致率(キー 6 列は必ず一致するので
        # 実質は残り 46 列の AND。52 列という数え方に含めても結果は同じ)
        cmp_cols = [c for c in NF
                    if c not in KEY and c != START and c != "L7_PROTO" and c + "_p" in m]
        eq_all = pd.Series(True, index=m.index)
        for c in cmp_cols:
            eq = m[c].astype(str) == m[c + "_p"].astype(str)
            col[c][0] += int(eq.sum())
            col[c][1] += len(m)
            eq_all &= eq
        r = {"basename": p, "ip": ip, "official_raw": n_raw, "official_unique": len(of_u),
             "matched": len(m), "coverage": len(m) / len(of_u) if len(of_u) else None,
             "col52_rate": eq_all.mean() if len(m) else None}
        if "L7_PROTO_p" in m:
            # 変換側にも L7 がある場合だけ比較する(--no-l7 の出力には L7 がない)
            e7 = m["L7_PROTO"].astype(str) == m["L7_PROTO_p"].astype(str)
            r["l7_rate"] = e7.mean()
            totl7[0] += int(e7.sum())
            totl7[1] += len(m)
        else:
            r["l7_rate"] = None
        tot52[0] += int(eq_all.sum())
        tot52[1] += len(m)
        rows.append(r)
        print(f"{p} (ip {ip}): 公式 {n_raw:,} -> 一意 {len(of_u):,} / 対応 {len(m):,}"
              f" / 被覆 {r['coverage']:.4f} / 52列全一致 {r['col52_rate']:.4f}"
              + (f" / L7 {r['l7_rate']:.4f}" if r["l7_rate"] is not None else ""))

    os.makedirs(a.out, exist_ok=True)
    per = pd.DataFrame(rows)
    per.to_csv(os.path.join(a.out, f"{a.prefix}_per_pcap.tsv"), sep="\t", index=False)

    pc = pd.DataFrame([(c, v[0], v[1], v[0] / v[1] if v[1] else None) for c, v in col.items()],
                      columns=["column", "eq", "matched", "rate"])
    pc.to_csv(os.path.join(a.out, f"{a.prefix}_per_column.tsv"), sep="\t", index=False)

    # 53 列のうちキー 5 列と開始時刻は対応づけ条件なので、列別の合算表には比較対象外であることを付記する
    with open(os.path.join(a.out, f"{a.prefix}_summary.txt"), "w", encoding="utf-8") as f:
        w = f.write
        w("pcap | 公式行(raw) | 公式一意行 | 対応 | 被覆 | 52列全一致(L7除く) | L7一致率\n")
        for r in rows:
            cov = "-" if r["coverage"] is None else f"{r['coverage']:.4f}"
            c52 = "-" if r["col52_rate"] is None else f"{r['col52_rate']:.4f}"
            l7 = "-" if r["l7_rate"] is None else f"{r['l7_rate']:.4f}"
            nm = f"{r['basename']} | {r['official_raw']:,} | {r['official_unique']:,}"
            w(f"{nm} | {r['matched']:,} | {cov} | {c52} | {l7}\n")
        u, mt = int(per.official_unique.sum()), int(per.matched.sum())
        w(f"\n合算 公式一意行 {u:,} / 対応 {mt:,}")
        if u:
            w(f" / 被覆 {mt / u:.5f}")
        if tot52[1]:
            w(f" / 52列全一致 {tot52[0]:,}({tot52[0] / tot52[1]:.5f})")
        if totl7[1]:
            w(f" / L7 {totl7[0]:,}({totl7[0] / totl7[1]:.5f})")
        w("\n\n列別一致率(合算):\ncolumn | eq | matched | rate\n")
        for c, v in col.items():
            note = " (対応づけキー)" if c in KEY or c == START else ""
            val = f"{v[0] / v[1]:.5f}{note}\n" if v[1] else f"n/a{note}\n"
            w(f"{c} | {v[0]:,} | {v[1]:,} | {val}")
    print(f"出力: {a.out}/{a.prefix}_per_pcap.tsv / {a.prefix}_per_column.tsv"
          f" / {a.prefix}_summary.txt")


if __name__ == "__main__":
    main()
