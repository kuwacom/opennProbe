#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# nDPI を固定コミットのソースから静的ライブラリにビルドする(root・autotools 不要)
# configure の生成物(ndpi_define.h・ndpi_config.h)は最小限を手で作る
#
# 使い方: scripts/build-ndpi.sh [出力先]   (既定: <リポジトリ>/third_party/ndpi)
# 環境変数:
#   NDPI_REPO   取得元(既定 https://github.com/ntop/nDPI.git。手元の clone のパスでもよい)
#   NDPI_COMMIT 固定コミット(既定 93f02ee5 = 公式 NF-v3 の判定に近い 4.9 開発版。LDP 追加の直前)
#   JOBS        並列コンパイル数(既定 nproc)
#   CC          C コンパイラ(既定 gcc)
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
prefix=${1:-$root/third_party/ndpi}
repo=${NDPI_REPO:-https://github.com/ntop/nDPI.git}
commit=${NDPI_COMMIT:-93f02ee507d050eedc88a8b9d66b20c97917e476}
jobs=${JOBS:-$(nproc)}
cc=${CC:-gcc}
maj=4
min=9

src=$prefix/src
mkdir -p "$prefix"
if [ ! -d "$src/.git" ]; then
  git init -q "$src"
fi
if ! git -C "$src" cat-file -e "$commit^{commit}" 2>/dev/null; then
  # コミット指定の浅い取得を試み、だめなら全履歴を取る
  git -C "$src" fetch -q --depth 1 "$repo" "$commit" || git -C "$src" fetch -q "$repo"
fi
git -C "$src" -c advice.detachedHead=false checkout -q -f "$commit"

inc=$src/src/include
sed -e 's/@NDPI_API_VERSION@/0/' -e "s/@NDPI_MAJOR@/$maj/" -e "s/@NDPI_MINOR@/$min/" -e 's/@NDPI_PATCH@/0/' \
  -e 's/@HANDLE_TLS_SIGS@//' "$inc/ndpi_define.h.in" > "$inc/ndpi_define.h"
cat > "$inc/ndpi_config.h" <<EOF
#define NDPI_MAJOR_RELEASE "$maj"
#define NDPI_MINOR_RELEASE "$min"
#define NDPI_PATCH_LEVEL "0"
#define NDPI_GIT_RELEASE "$maj.$min.0-${commit:0:8}"
#define NDPI_GIT_DATE "$maj.$min"
#define NDPI_BASE_DIR ""
#define PACKAGE_VERSION "$maj.$min.0"
EOF

obj=$prefix/obj
rm -rf "$obj"
mkdir -p "$obj" "$prefix/lib" "$prefix/include/ndpi"
cd "$src/src/lib"
ls protocols/*.c third_party/src/*.c third_party/src/hll/*.c ./*.c 2>/dev/null |
  xargs -P "$jobs" -I{} sh -c 'o='"$obj"'/$(echo {} | sed "s#^\./##" | tr / _).o; '"$cc"' -O2 -fPIC -DPIC -I. -I../include -Ithird_party/include -DNDPI_LIB_COMPILATION -w -c {} -o $o'
rm -f "$prefix/lib/libndpi.a"
ar rcs "$prefix/lib/libndpi.a" "$obj"/*.o
cp "$inc"/*.h "$prefix/include/ndpi/"
echo "built $prefix/lib/libndpi.a (nDPI $commit)"
