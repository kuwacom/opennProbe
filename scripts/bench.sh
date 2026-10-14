#!/usr/bin/env bash
# ベンチ: pcap ごとに L7 あり/なしで経過時間・最大 RSS・pps を測る(/usr/bin/time -v)
#
# 使い方: BENCH_LIST=<一覧.tsv> scripts/bench.sh [ラベル]
#   一覧.tsv: <名前><TAB><pcap のパス>
# 環境変数: OPENNPROBE_BIN(既定 <リポジトリ>/build/opennprobe)・BENCH_OUT(結果の追記先 TSV)・REPEAT(既定 1)
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
bin=${OPENNPROBE_BIN:-$root/build/opennprobe}
list=${BENCH_LIST:?BENCH_LIST を指定してください}
label=${1:-run}
res=${BENCH_OUT:-/dev/stdout}
repeat=${REPEAT:-1}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

while IFS=$'\t' read -r name pcap; do
  case "$name" in ''|'#'*) continue ;; esac
  for mode in l7 nol7; do
    args=""
    [ "$mode" = nol7 ] && args="--no-l7"
    for _ in $(seq "$repeat"); do
      # shellcheck disable=SC2086
      /usr/bin/time -v "$bin" $args -v -o "$tmp/out.csv" "$pcap" 2> "$tmp/err" > /dev/null
      el=$(sed -n 's/.*Elapsed (wall clock) time (h:mm:ss or m:ss): //p' "$tmp/err" | awk -F: '{ if (NF==3) print $1*3600+$2*60+$3; else print $1*60+$2 }')
      rss=$(sed -n 's/.*Maximum resident set size (kbytes): //p' "$tmp/err")
      rec=$(sed -n 's/^records \([0-9]*\).*/\1/p' "$tmp/err")
      flows=$(sed -n 's/^flows \([0-9]*\).*/\1/p' "$tmp/err")
      pps=$(awk -v r="$rec" -v e="$el" 'BEGIN { printf "%.0f", (e > 0 ? r / e : 0) }')
      printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$label" "$name" "$mode" "$rec" "$flows" "$el" "$pps" "$rss" >> "$res"
    done
  done
done < "$list"
