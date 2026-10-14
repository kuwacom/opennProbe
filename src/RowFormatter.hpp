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
 * - 列の値と書式は参照実装(proto2_l7.py の features)に合わせる
 * - 標準偏差など浮動小数点の列は参照実装と同じ演算順(素朴な逐次和・libm の pow/sqrt・float32)で計算する
 */
class RowFormatter {
 public:
  explicit RowFormatter(const Rules& rules) : rules_(rules) {}

  void emit(const Flow& f, RowStore& store);

 private:
  void putDir(const Flow& f, int i);

  const Rules& rules_;
  TextBuffer buf_;
};

}  // namespace opennprobe
