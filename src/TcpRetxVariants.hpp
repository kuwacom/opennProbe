// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <utility>
#include <vector>

#include "Packet.hpp"

namespace opennprobe {

/**
 * # TcpRetxVariants
 * TCP 再送判定の候補を並行して数える(ALT_RX_* 列。RETRANSMITTED_* は A5 を使う)
 *
 * ### 特徴
 * - A2/A3: SYN と FIN を 1 として数えたシーケンス終端の最大値との比較
 * - A4/A5: FIN はシーケンスを消費しない扱い。A5 はさらに相手側から 1 パケットでも来ていたら SYN 重複を数えない
 * - B/B2: 直前と同じ seq で終端が直前の終端と同じ
 * - C/C5: 既に見た範囲(区間集合)に完全に含まれるときだけ再送
 */
class TcpRetxVariants {
 public:
  enum Variant { kA2 = 0, kA3, kA4, kA5, kB, kB2, kC, kC5, kCount };

  /** ### update
   * @param p - パケット
   * @param d - 向き(0: src->dst)
   * @param L - IP 長
   * @param otherDirPkts - 相手向きのそれまでのパケット数
   */
  void update(const Packet& p, int d, uint64_t L, uint64_t otherDirPkts) {
    bool syn = p.flags & 2;
    bool fin = p.flags & 1;
    int64_t seglen = p.plen + (syn ? 1 : 0) + (fin ? 1 : 0);
    uint32_t end = static_cast<uint32_t>(p.seq + static_cast<uint64_t>(seglen));
    auto hit = [&](int k) {
      cnt_[k][d][0] += 1;
      cnt_[k][d][1] += L;
    };

    if (has_[d] & kHasHi2) {
      uint32_t hi = hi2_[d];
      if (seglen > 0) {
        if (le(end, hi)) hit(kA2);
        if (le(p.seq, hi) && p.seq != hi) hit(kA3);
      }
    }
    if (!(has_[d] & kHasHi2) || !le(end, hi2_[d])) {
      hi2_[d] = end;
      has_[d] |= kHasHi2;
    }

    int64_t seg4 = p.plen + (syn ? 1 : 0);
    uint32_t end4 = static_cast<uint32_t>(p.seq + static_cast<uint64_t>(seg4));
    if ((has_[d] & kHasHi4) && seg4 > 0 && le(end4, hi4_[d])) {
      hit(kA4);
      if (!(syn && otherDirPkts > 0)) hit(kA5);
    }
    if (!(has_[d] & kHasHi4) || !le(end4, hi4_[d])) {
      hi4_[d] = end4;
      has_[d] |= kHasHi4;
    }

    if (seg4 > 0) {
      if (!(has_[d] & kHasBase)) {
        base_[d] = p.seq;
        has_[d] |= kHasBase;
      }
      uint64_t s0 = static_cast<uint32_t>(p.seq - base_[d]);
      uint64_t e0 = s0 + static_cast<uint64_t>(seg4);
      std::vector<std::pair<uint64_t, uint64_t>>& iv = iv_[d];
      bool covered = false;
      for (const auto& r : iv) {
        if (r.first <= s0 && e0 <= r.second) {
          covered = true;
          break;
        }
      }
      if (covered) {
        hit(kC);
        if (!(syn && otherDirPkts > 0)) hit(kC5);
      }
      insertInterval(iv, s0, e0);
    }

    if ((has_[d] & kHasNext) && p.seq != next_[d] && last_[d] == p.seq && end == next_[d]) {
      hit(kB);
      if (!syn) hit(kB2);
    }
    next_[d] = end;
    last_[d] = p.seq;
    has_[d] |= kHasNext;
  }

  // [variant][向き][0: パケット数 / 1: バイト数]
  uint64_t cnt_[kCount][2][2] = {};

 private:
  enum : uint8_t { kHasHi2 = 1, kHasHi4 = 2, kHasBase = 4, kHasNext = 8 };

  // a <= b(32 bit 周回を考慮)
  static bool le(uint32_t a, uint32_t b) { return static_cast<uint32_t>(b - a) < 0x80000000u; }

  // 区間を加えて併合する(隣接する区間もつなぐ)
  static void insertInterval(std::vector<std::pair<uint64_t, uint64_t>>& iv, uint64_t s, uint64_t e) {
    // 多くは末尾への追加か末尾との併合なので先に扱う
    if (iv.empty()) {
      iv.emplace_back(s, e);
      return;
    }
    if (std::make_pair(s, e) >= iv.back()) {
      auto& b = iv.back();
      if (s <= b.second) {
        if (e > b.second) b.second = e;
      } else {
        iv.emplace_back(s, e);
      }
      return;
    }
    size_t pos = 0;
    while (pos < iv.size() && iv[pos] < std::make_pair(s, e)) ++pos;
    iv.insert(iv.begin() + static_cast<std::ptrdiff_t>(pos), std::make_pair(s, e));
    size_t start = pos > 0 ? pos - 1 : 0;
    size_t w = start;
    for (size_t r = start + 1; r < iv.size(); ++r) {
      if (iv[r].first <= iv[w].second) {
        if (iv[r].second > iv[w].second) iv[w].second = iv[r].second;
      } else {
        iv[++w] = iv[r];
      }
    }
    iv.resize(w + 1);
  }

  uint32_t hi2_[2] = {};
  uint32_t hi4_[2] = {};
  uint32_t base_[2] = {};
  uint32_t next_[2] = {};
  uint32_t last_[2] = {};
  uint8_t has_[2] = {};
  std::vector<std::pair<uint64_t, uint64_t>> iv_[2];
};

}  // namespace opennprobe
