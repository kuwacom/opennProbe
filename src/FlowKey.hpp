// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <cstring>

#include "Packet.hpp"

namespace opennprobe {

/**
 * # FlowKey
 * 双方向 5-tuple キー(PROTOCOL と 2 端点の組。端点の並びは正規化する)
 *
 * ### 特徴
 * - 40 バイト固定で memcmp 比較できる(未使用バイトは 0)
 * - IPv4 と IPv6 は別キー(版も含める)
 */
struct FlowKey {
  uint8_t a[16];
  uint8_t b[16];
  uint16_t pa;
  uint16_t pb;
  uint8_t v;
  uint8_t proto;
  uint8_t pad[2];

  bool operator==(const FlowKey& o) const { return std::memcmp(this, &o, sizeof(FlowKey)) == 0; }

  static FlowKey of(const Packet& p) {
    FlowKey k;
    std::memset(&k, 0, sizeof(k));
    k.v = p.v;
    k.proto = p.proto;
    // 端点は (アドレス, ポート) の小さい方を a にする。等価性だけが要るので順序の定義は任意
    int c = std::memcmp(p.src, p.dst, 16);
    bool srcFirst = c < 0 || (c == 0 && p.sport <= p.dport);
    if (srcFirst) {
      std::memcpy(k.a, p.src, 16);
      std::memcpy(k.b, p.dst, 16);
      k.pa = p.sport;
      k.pb = p.dport;
    } else {
      std::memcpy(k.a, p.dst, 16);
      std::memcpy(k.b, p.src, 16);
      k.pa = p.dport;
      k.pb = p.sport;
    }
    return k;
  }

  uint64_t hash() const {
    uint64_t w[5];
    std::memcpy(w, this, sizeof(w));
    uint64_t h = 0x9E3779B97F4A7C15ull;
    for (uint64_t x : w) {
      h ^= x;
      h *= 0xBF58476D1CE4E5B9ull;
      h ^= h >> 31;
    }
    h ^= h >> 29;
    h *= 0x94D049BB133111EBull;
    h ^= h >> 32;
    return h;
  }
};
static_assert(sizeof(FlowKey) == 40, "FlowKey は 40 バイト");

}  // namespace opennprobe
