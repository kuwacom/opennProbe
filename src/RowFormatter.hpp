// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

#include "Flow.hpp"
#include "RowStore.hpp"
#include "Rules.hpp"
#include "TextBuffer.hpp"

namespace opennprobe {

/**
 * # RowFormatter
 * 終わったフローから 1 行ぶんの列を計算して RowStore に渡す
 *
 * ### 特徴
 * - 列は NF-v3 の 53 列(L7 なしのときは L7_PROTO を除く 52 列)。順序は header() と同じ
 * - IAT の標準偏差は ms 整数の Σx・Σx² から float32 で計算する(公式・nProbe の丸めを再現)
 */
class RowFormatter {
 public:
  RowFormatter(const Rules& rules, bool withL7) : rules_(rules), withL7_(withL7) {}

  void emit(const Flow& f, RowStore& store);

  /** ### header
   * @param withL7 - L7_PROTO 列を含めるか
   * @returns CSV の見出し行(改行なし)
   */
  static std::string header(bool withL7);

 private:
  void putDir(const Flow& f, int i);
  void putSecondBytes(const Flow& f, int d);

  const Rules& rules_;
  bool withL7_;
  TextBuffer buf_;
  TextBuffer tmp_;
};

}  // namespace opennprobe
