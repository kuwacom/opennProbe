// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

#include "Packet.hpp"
#include "Rules.hpp"

namespace opennprobe {

/**
 * # TcpRetx
 * RETRANSMITTED_* の再送判定(向き別の状態と数)
 *
 * ### 特徴
 * - bin: nProbe 10.4 の観測に合わせた判定。向き別に直前パケットの seq・期待 seq(seq + payload + SYN)・
 *   payload 長・window・flags を持ち、同じ seq で中身も同じ・期待 seq より前などを再送とする
 * - A5: 向き別のシーケンス終端(seq + payload + SYN。FIN は消費しない)の最大値以下なら再送。
 *   相手側から 1 パケットでも来ていたら SYN の重複は数えない(official の OUT 向き)
 */
class TcpRetx {
 public:
  /** ### update
   * @param p - パケット
   * @param d - 向き(0: src->dst)
   * @param L - IP 長
   * @param otherDirPkts - 相手向きのそれまでのパケット数
   * @param rules - 規則(A5 を数えるか・bin の変種)
   */
  void update(const Packet& p, int d, uint64_t L, uint64_t otherDirPkts, const Rules& rules) {
    if (rules.retx == Rules::Retx::kHybrid) updateA5(p, d, L, otherDirPkts);
    bool upd = true;
    if (binHit(p, d, rules.binOld, upd)) {
      bin_[d][0] += 1;
      bin_[d][1] += L;
    }
    if (upd) {
      BinDir& s = st_[d];
      s.ref = p.seq;
      s.nxt = static_cast<uint32_t>(p.seq + static_cast<uint64_t>(p.plen) + ((p.flags & 2) ? 1 : 0));
      s.lpay = p.plen;
      s.lwin = p.win;
      s.lflg = p.flags;
      s.has = true;
    }
  }

  /** ### wouldCountBin
   * p を bin で再送と数えるか(状態は変えない。RST 後の期限判定に使う)
   */
  bool wouldCountBin(const Packet& p, int d, Rules::BinOld old) const {
    bool upd = true;
    return binHit(p, d, old, upd);
  }

  /** ### counts
   * @param rules - 規則
   * @param out - [向き][0: パケット数 / 1: バイト数]
   */
  void counts(const Rules& rules, uint64_t out[2][2]) const {
    for (int k = 0; k < 2; ++k) {
      out[0][k] = bin_[0][k];
      out[1][k] = rules.retx == Rules::Retx::kHybrid ? a5_[1][k] : bin_[1][k];
    }
  }

 private:
  struct BinDir {
    uint32_t ref = 0;  // 比較用の seq(直前パケットの seq)
    uint32_t nxt = 0;  // 直前の seq + payload + SYN
    int64_t lpay = 0;
    uint16_t lwin = 0;
    uint8_t lflg = 0;
    bool has = false;
  };

  static bool lone(uint8_t fl) { return fl == 1 || fl == 2 || fl == 4; }

  // a <= b(32 bit 周回を考慮)
  static bool le(uint32_t a, uint32_t b) { return static_cast<uint32_t>(b - a) < 0x80000000u; }

  bool binHit(const Packet& p, int d, Rules::BinOld old, bool& upd) const {
    // D2S の payload 0 は数えない(状態は通常どおり更新する)
    if (d == 1 && p.plen == 0) return false;
    const BinDir& s = st_[d];
    if (!s.has) return false;
    const uint32_t seq = p.seq;
    const int64_t plen = p.plen;
    const uint8_t fl = p.flags;
    if (seq == s.nxt) return false;
    if (seq == s.ref) {
      // 同じ seq: 中身(payload 長・flags・window)が直前と同じなら再送
      return plen == s.lpay && fl == s.lflg && p.win == s.lwin && (plen > 0 || lone(fl));
    }
    // 期待 seq 以降(順序違い・飛び)は直前 seq より前に戻ったペイロードだけ数える。比較は周回を考えない
    if (seq >= s.ref || seq >= s.nxt) return seq < s.ref && plen > 0;
    if (plen == 0 && lone(fl)) {
      // SYN/FIN/RST 単独の古い seq はキープアライブ扱いで状態も変えない
      upd = false;
      return false;
    }
    if (old == Rules::BinOld::kPayload) return plen > 0;
    return seq == static_cast<uint32_t>(s.nxt - 1) && plen <= 1;
  }

  void updateA5(const Packet& p, int d, uint64_t L, uint64_t otherDirPkts) {
    const bool syn = p.flags & 2;
    const int64_t seg4 = p.plen + (syn ? 1 : 0);
    const uint32_t end4 = static_cast<uint32_t>(p.seq + static_cast<uint64_t>(seg4));
    if (hasHi4_[d] && seg4 > 0 && le(end4, hi4_[d]) && !(syn && otherDirPkts > 0)) {
      a5_[d][0] += 1;
      a5_[d][1] += L;
    }
    if (!hasHi4_[d] || !le(end4, hi4_[d])) {
      hi4_[d] = end4;
      hasHi4_[d] = true;
    }
  }

  BinDir st_[2];
  uint64_t bin_[2][2] = {};
  uint32_t hi4_[2] = {};
  bool hasHi4_[2] = {false, false};
  uint64_t a5_[2][2] = {};
};

}  // namespace opennprobe
