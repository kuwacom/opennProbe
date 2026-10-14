// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

namespace opennprobe {

/**
 * # TextBuffer
 * CSV の 1 行を組み立てるための追記専用バッファ
 *
 * ### 特徴
 * - 整数は自前で 10 進化する(snprintf より速く、ロケールにも依存しない)
 * - 浮動小数点は小数 3 桁固定の 1 種類だけ使うので snprintf に任せる
 */
class TextBuffer {
 public:
  void clear() { buf_.clear(); }
  size_t size() const { return buf_.size(); }
  const char* data() const { return buf_.data(); }
  std::string& str() { return buf_; }

  void put(char c) { buf_.push_back(c); }
  void put(const char* s) { buf_.append(s); }
  void put(const char* s, size_t n) { buf_.append(s, n); }
  void put(const std::string& s) { buf_.append(s); }

  void putU(uint64_t v) {
    char tmp[24];
    int n = 0;
    do {
      tmp[n++] = static_cast<char>('0' + v % 10);
      v /= 10;
    } while (v != 0);
    while (n > 0) buf_.push_back(tmp[--n]);
  }

  void putI(int64_t v) {
    if (v < 0) {
      buf_.push_back('-');
      // INT64_MIN でも溢れないよう符号なしで反転する
      putU(~static_cast<uint64_t>(v) + 1);
    } else {
      putU(static_cast<uint64_t>(v));
    }
  }

  /** ### putFixed3
   * Python の f"{x:.3f}" と同じ表記(glibc の printf も正しく丸めるので一致する)
   */
  void putFixed3(double v) {
    char tmp[64];
    int n = std::snprintf(tmp, sizeof(tmp), "%.3f", v);
    if (n > 0) buf_.append(tmp, static_cast<size_t>(n));
  }

 private:
  std::string buf_;
};

/** ### floorDiv
 * Python の // と同じ床除算(負の値でも -inf 方向に丸める)
 */
inline int64_t floorDiv(int64_t a, int64_t b) {
  int64_t q = a / b;
  if ((a % b != 0) && ((a < 0) != (b < 0))) --q;
  return q;
}

}  // namespace opennprobe
