#!/usr/bin/env bash
# 公式 12 本(CSE-CIC-IDS2018 の pcap)の回帰テスト
#
# pcap はリポジトリに含めないので、置き場所(ファイルかディレクトリ)を引数で与える。
# pcap はファイル名ではなく中身の SHA-256 で識別する(tests/official/pcaps.tsv。大きさが合うファイルだけハッシュを取る)。
# 両モード × L7 あり/なしで変換し、出力 CSV の SHA-256 を tests/official/expected.sha256 と比べる。
# 末尾の途中で切れたレコードは読めた部分で使う(--keep-truncated-tail。期待値を作った調査用プロトタイプと同じ扱い)
#
# 使い方: scripts/regress.sh [--update] <pcap のファイルかディレクトリ>...
#   --update  比較せずに expected.sha256 を今の出力で置き換える(規則を変えたときだけ使う)
# 環境変数:
#   OPENNPROBE_BIN  実行ファイル(既定 <リポジトリ>/build/opennprobe)
#   JOBS            並列数(既定 8)
#   REGRESS_OUT     出力 CSV の置き場(既定 一時ディレクトリ。終了時に消す)
#   VARIANTS        比べる組(既定 "official official_l7 nprobe nprobe_l7")
set -uo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
bin=${OPENNPROBE_BIN:-$root/build/opennprobe}
tdir=$root/tests/official
jobs=${JOBS:-8}
variants=${VARIANTS:-official official_l7 nprobe nprobe_l7}
update=0
if [ "${1:-}" = "--update" ]; then
  update=1
  shift
fi
if [ $# -eq 0 ]; then
  sed -n '2,/^set /p' "$0" | sed '$d'
  exit 2
fi
if [ -n "${REGRESS_OUT:-}" ]; then
  out=$REGRESS_OUT
  mkdir -p "$out"
else
  out=$(mktemp -d)
  trap 'rm -rf "$out"' EXIT
fi

# 1. 引数のファイルから、pcaps.tsv の大きさと SHA-256 が合うものを探す
declare -A want_size=() want_sha=() path_of=()
while IFS=$'\t' read -r name size sha _; do
  case "$name" in ''|'#'*) continue ;; esac
  want_size[$size]+="$name "
  want_sha[$name]=$sha
done < "$tdir/pcaps.tsv"
for a in "$@"; do
  if [ -d "$a" ]; then
    find "$a" -maxdepth 1 -type f -print0
  elif [ -f "$a" ]; then
    printf '%s\0' "$a"
  else
    echo "見つかりません: $a" >&2
  fi
done | while IFS= read -r -d '' f; do
  size=$(stat -c %s "$f")
  [ -n "${want_size[$size]:-}" ] || continue
  sha=$(sha256sum "$f" | cut -d' ' -f1)
  for name in ${want_size[$size]}; do
    [ "${want_sha[$name]}" = "$sha" ] && printf '%s\t%s\n' "$name" "$f"
  done
done > "$out/found.tsv"
while IFS=$'\t' read -r name f; do path_of[$name]=$f; done < "$out/found.tsv"
for name in "${!want_sha[@]}"; do
  [ -n "${path_of[$name]:-}" ] || echo "MISSING $name(pcaps.tsv の SHA-256 に合うファイルがありません)"
done
if [ ${#path_of[@]} -eq 0 ]; then
  echo "対象の pcap が 1 本も見つかりません"
  exit 1
fi

# 2. 変換して出力の SHA-256 を取る
mkdir -p "$out/res"
for name in $(printf '%s\n' "${!path_of[@]}" | sort); do
  for v in $variants; do
    (
      mode=${v%_l7}
      args="--keep-truncated-tail --compat $mode"
      [ "$v" = "$mode" ] && args="$args --no-l7"
      mkdir -p "$out/$name"
      # shellcheck disable=SC2086
      if "$bin" $args -o "$out/$name/$v.csv" "${path_of[$name]}" 2> "$out/$name/$v.err"; then
        printf '%s  %s/%s.csv\n' "$(sha256sum "$out/$name/$v.csv" | cut -d' ' -f1)" "$name" "$v"
      else
        printf 'FAIL  %s/%s.csv\n' "$name" "$v"
      fi
    ) > "$out/res/$name-$v.txt" &
    while [ "$(jobs -r | wc -l)" -ge "$jobs" ]; do sleep 0.2; done
  done
done
wait
cat "$out"/res/*.txt | sort -k2 > "$out/actual.sha256"

if [ $update -eq 1 ]; then
  # 見つからなかった pcap の行は残す
  { grep -v -F -f <(cut -d' ' -f3 "$out/actual.sha256") "$tdir/expected.sha256" 2> /dev/null; cat "$out/actual.sha256"; } |
    sort -k2 > "$out/expected.new"
  mv "$out/expected.new" "$tdir/expected.sha256"
  echo "expected.sha256 を更新しました($(wc -l < "$out/actual.sha256") 行)"
  exit 0
fi
ok=0
all=0
while read -r sha file; do
  all=$((all + 1))
  exp=$(awk -v f="$file" '$2 == f { print $1 }' "$tdir/expected.sha256")
  if [ "$sha" = "$exp" ]; then
    ok=$((ok + 1))
  else
    echo "DIFF $file"
  fi
done < "$out/actual.sha256"
echo "公式: 一致 $ok / $all(pcap ${#path_of[@]} / ${#want_sha[@]} 本)"
[ "$ok" -eq "$all" ]
