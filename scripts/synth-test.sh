#!/usr/bin/env bash
# 合成 12 本の回帰テスト: pcap を生成 -> 変換 -> 期待 CSV(tests/synth/expected)とバイト単位で比べる
#
# 使い方: scripts/synth-test.sh [--update]
#   --update  比較せずに期待 CSV を今の出力で置き換える(規則を変えたときだけ使う)
# 環境変数:
#   OPENNPROBE_BIN  実行ファイル(既定 <リポジトリ>/build/opennprobe)
#   PYTHON          scapy の入った Python(既定 python3)
#   SYNTH_WORK      作業ディレクトリ(既定 一時ディレクトリ。終了時に消す)
# 終了コード: 0 全一致 / 1 不一致 / 77 scapy が無い(ctest では SKIP 扱い)
set -uo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
bin=${OPENNPROBE_BIN:-$root/build/opennprobe}
py=${PYTHON:-python3}
tdir=$root/tests/synth
update=0
[ "${1:-}" = "--update" ] && update=1

if ! "$py" -c 'import scapy' 2> /dev/null; then
  echo "SKIP: $py に scapy がありません(pip install scapy)"
  exit 77
fi
if [ -n "${SYNTH_WORK:-}" ]; then
  work=$SYNTH_WORK
  mkdir -p "$work"
else
  work=$(mktemp -d)
  trap 'rm -rf "$work"' EXIT
fi

# 1. pcap を生成し、生成物が期待どおりか(scapy の版差などで変わっていないか)を SHA-256 で確かめる
mkdir -p "$work/pcap"
for g in "$tdir"/gen_*.py; do
  if ! SYNTH_OUT="$work/pcap" "$py" "$g" > /dev/null; then
    echo "FAIL pcap の生成に失敗しました: $(basename "$g")"
    exit 1
  fi
done
if ! (cd "$work/pcap" && sha256sum --quiet -c "$tdir/pcaps.sha256"); then
  echo "FAIL 生成した pcap が tests/synth/pcaps.sha256 と違います(scapy の版: $("$py" -c 'import scapy; print(scapy.__version__)'))"
  exit 1
fi

# 2. 両モード × L7 あり/なしで変換して比べる(nDPI なしのビルドなら L7 ありは飛ばす)
variants="official nprobe"
if ! "$bin" --version | grep -q 'nDPI なし'; then
  variants="$variants official_l7 nprobe_l7"
else
  echo "nDPI なしのビルドなので L7 ありの比較は飛ばします"
fi
ok=0
all=0
for v in $variants; do
  mode=${v%_l7}
  args="--compat $mode"
  [ "$v" = "$mode" ] && args="$args --no-l7"
  mkdir -p "$work/out/$v"
  for pcap in "$work"/pcap/*.pcap; do
    name=$(basename "$pcap" .pcap)
    out=$work/out/$v/$name.csv
    exp=$tdir/expected/$v/$name.csv
    all=$((all + 1))
    # shellcheck disable=SC2086
    if ! "$bin" $args -o "$out" "$pcap"; then
      echo "FAIL $v $name(終了コード $?)"
      continue
    fi
    if [ $update -eq 1 ]; then
      mkdir -p "$(dirname "$exp")"
      cp "$out" "$exp"
      ok=$((ok + 1))
    elif cmp -s "$out" "$exp"; then
      ok=$((ok + 1))
    else
      echo "DIFF $v $name"
      diff "$exp" "$out" | head -6
    fi
  done
done
echo "合成 12 本: 一致 $ok / $all"
[ "$ok" -eq "$all" ]
