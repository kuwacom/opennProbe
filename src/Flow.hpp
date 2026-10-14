// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <vector>

#include "FlowKey.hpp"
#include "TcpRetx.hpp"

struct ndpi_flow_struct;

namespace opennprobe {

/**
 * # IatAcc
 * 1 向きの到着間隔(ms に切り捨てた us 差)の集計
 *
 * ### 特徴
 * - 出力に要る値(個数・和・二乗和・最大・先頭の 0 を飛ばした最小)だけを逐次に持つ。時刻列は持たない
 * - 和・二乗和は整数で厳密に持つ(標準偏差は出力時に float32 で計算する)
 */
struct IatAcc {
  int64_t lastTs = 0;
  bool hasLast = false;
  bool started = false;  // 0 でない間隔を見たか(最小値の初期化)
  uint64_t n = 0;
  int64_t mn = 0;
  int64_t mx = 0;
  __int128 sum = 0;
  __int128 sumSq = 0;
};

/**
 * # FlowAcc
 * DNS の touch で新フローへ引き継がれる統計(ヒストグラム・向き別の到着間隔・S2D の TTL)
 */
struct FlowAcc {
  uint32_t hist[5] = {};
  IatAcc iat[2];
  uint8_t ttlMin = 0;
  uint8_t ttlMax = 0;
  bool hasTtl = false;
};

/**
 * # Flow
 * 1 フローの集計状態
 *
 * ### 特徴
 * - nDPI のフロー状態は判定が確定した時点で結果だけ残して解放する
 * - SECOND_BYTES の秒スロットは nprobe モードのときだけ使う
 */
struct Flow {
  FlowKey key;
  uint8_t src[16];
  uint8_t dst[16];
  uint16_t sport = 0;
  uint16_t dport = 0;
  uint8_t v = 0;
  uint8_t proto = 0;
  bool terminated = false;
  bool hasD[2] = {false, false};
  bool hasHiseq[2] = {false, false};
  uint8_t flags[2] = {0, 0};
  uint16_t win[2] = {0, 0};

  int64_t first = 0;
  int64_t last = 0;
  int64_t lastAlive = 0;
  int64_t dfirst[2] = {0, 0};
  int64_t dlast[2] = {0, 0};
  uint64_t pk[2] = {0, 0};
  uint64_t by[2] = {0, 0};
  uint32_t lmin = 0;
  uint32_t lmax = 0;
  uint32_t hiseq[2] = {0, 0};

  bool hasDns = false;
  bool dnsAnswered = false;
  uint16_t dnsId = 0;
  uint16_t dnsType = 0;
  uint32_t dnsTtl = 0;

  bool hasIcmp = false;
  uint8_t icmpType = 0;
  uint8_t icmpCode = 0;

  FlowAcc acc;
  TcpRetx tcp;
  // 向き別に「最初のパケットの秒からの秒差」ごとの IP バイト + 1(0 はパケットなし)
  std::vector<uint64_t> secBytes[2];

  // L7(nDPI)
  ndpi_flow_struct* l7h = nullptr;
  bool l7Stop = false;  // 以後 nDPI に渡さない
  bool l7Frozen = false;  // nDPI 側が以後のパケットを無視する状態(fail_with_unknown)
  uint16_t l7Master = 0;
  uint16_t l7App = 0;

  // フロー表の挿入順(同じ秒に切れたフローを出す順。置き換えでは変わらない)
  uint64_t order = 0;
  // 期限切れになる最初の秒(これ以上の秒の走査で出力される)
  int64_t deadline = 0;
  uint32_t gen = 0;
  bool live = false;
};

}  // namespace opennprobe
