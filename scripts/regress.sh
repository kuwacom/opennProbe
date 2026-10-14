#!/usr/bin/env bash
# 回帰テスト: 参照出力(調査用プロトタイプ proto2_l7.py の CSV)とバイト単位で比べる
#
# 使い方: REGRESS_LIST=<一覧.tsv> REGRESS_REF=<参照ディレクトリ> scripts/regress.sh [l7|nol7|both]
#   一覧.tsv:  <名前><TAB><pcap のパス>  の行(# で始まる行は無視)
#   参照ディレクトリ: l7/<名前>.csv(L7 あり)・nol7/<名前>.csv(--no-l7 相当)
# 環境変数:
#   OPENNPROBE_BIN  実行ファイル(既定 <リポジトリ>/build/opennprobe)
#   REGRESS_OUT     出力先(既定 一時ディレクトリ)
#   JOBS            並列数(既定 8)
#   REGRESS_ARGS    opennprobe への追加引数(既定 --keep-truncated-tail: プロトタイプは末尾の切れたレコードも使うため)
set -uo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
bin=${OPENNPROBE_BIN:-$root/build/opennprobe}
list=${REGRESS_LIST:?REGRESS_LIST を指定してください}
ref=${REGRESS_REF:?REGRESS_REF を指定してください}
out=${REGRESS_OUT:-$(mktemp -d)}
jobs=${JOBS:-8}
modes=${1:-both}
[ "$modes" = both ] && modes="l7 nol7"

run_one() {
  local mode=$1 name=$2 pcap=$3
  local args="${REGRESS_ARGS---keep-truncated-tail}"
  [ "$mode" = nol7 ] && args="$args --no-l7"
  mkdir -p "$out/$mode"
  # shellcheck disable=SC2086
  "$bin" $args -o "$out/$mode/$name.csv" "$pcap" 2> "$out/$mode/$name.err"
  local rc=$?
  local r="$ref/$mode/$name.csv"
  if [ $rc -ne 0 ]; then
    echo "FAIL $mode $name (終了コード $rc)"
  elif [ ! -f "$r" ]; then
    echo "NOREF $mode $name"
  elif cmp -s "$out/$mode/$name.csv" "$r"; then
    echo "OK   $mode $name $(($(wc -l < "$r") - 1)) 行"
  else
    local ln
    ln=$(cmp "$out/$mode/$name.csv" "$r" 2>&1 | sed -n 's/.* line \([0-9]*\).*/\1/p')
    echo "DIFF $mode $name 最初の不一致 ${ln:-?} 行目"
  fi
}
mkdir -p "$out/res"
while IFS=$'\t' read -r name pcap; do
  case "$name" in ''|'#'*) continue ;; esac
  for m in $modes; do
    run_one "$m" "$name" "$pcap" > "$out/res/$m-$name.txt" &
    while [ "$(jobs -r | wc -l)" -ge "$jobs" ]; do sleep 0.2; done
  done
done < "$list"
wait
cat "$out"/res/*.txt | sort -k2,2 -k3,3 > "$out/result.txt"
cat "$out/result.txt"
ok=$(grep -c '^OK' "$out/result.txt")
all=$(wc -l < "$out/result.txt")
echo "一致 $ok / $all  (出力: $out)"
[ "$ok" -eq "$all" ]
