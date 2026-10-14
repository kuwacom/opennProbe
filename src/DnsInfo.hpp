// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace opennprobe {

/**
 * # DnsInfo
 * DNS メッセージから列に使う値だけを取り出した結果
 */
struct DnsInfo {
  uint16_t id = 0;
  uint8_t qr = 0;
  uint16_t qtype = 0;
  bool hasFirstRr = false;  // 質問部の直後に RR を 1 つ以上読めたか
  uint32_t firstRrTtl = 0;
};

/** ### parseDns
 * 質問部を読み飛ばし、直後の最初の RR(回答・権威・追加のどれでも)の TTL を取る。
 * 途中で範囲外になったら、そこまでに読めた値を返す
 *
 * @param p - UDP ペイロード
 * @param len - 長さ
 * @param out - 結果
 * @returns 12 バイト以上あれば true
 */
inline bool parseDns(const uint8_t* p, uint32_t len, DnsInfo& out) {
  if (len < 12) return false;
  auto u16 = [p](uint32_t o) { return static_cast<uint16_t>((p[o] << 8) | p[o + 1]); };
  out = DnsInfo();
  out.id = u16(0);
  out.qr = static_cast<uint8_t>(u16(2) >> 15);
  uint32_t qd = u16(4);
  uint32_t rr = static_cast<uint32_t>(u16(6)) + u16(8) + u16(10);
  uint64_t off = 12;
  // 名前を飛ばす。範囲外なら false
  auto skipName = [p, len](uint64_t& o) {
    while (true) {
      if (o >= len) return false;
      uint8_t ln = p[o];
      if (ln == 0) {
        o += 1;
        return true;
      }
      if ((ln & 0xC0) == 0xC0) {
        o += 2;
        return true;
      }
      o += static_cast<uint64_t>(ln) + 1;
    }
  };
  for (uint32_t i = 0; i < qd; ++i) {
    if (!skipName(off)) return true;
    if (i == 0) {
      if (off + 2 > len) return true;
      out.qtype = u16(static_cast<uint32_t>(off));
    }
    off += 4;
  }
  if (rr == 0) return true;
  if (!skipName(off)) return true;
  if (off + 10 > len) return true;
  out.hasFirstRr = true;
  out.firstRrTtl = (static_cast<uint32_t>(p[off + 4]) << 24) | (static_cast<uint32_t>(p[off + 5]) << 16) |
                   (static_cast<uint32_t>(p[off + 6]) << 8) | p[off + 7];
  return true;
}

}  // namespace opennprobe
