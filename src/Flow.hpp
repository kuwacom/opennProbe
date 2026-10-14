// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <memory>
#include <vector>

#include "FlowKey.hpp"
#include "TcpRetxVariants.hpp"

struct ndpi_flow_struct;

namespace opennprobe {

/**
 * # FlowAcc
 * DNS の touch で新フローへ引き継がれる統計(ヒストグラム・向き別時刻列・S2D の TTL)
 *
 * ### 特徴
 * - 向き別の到着時刻(us)を全部持つ。IAT とその派生列(2 パス計算の標準偏差など)はここから出力時に計算する
 */
struct FlowAcc {
  uint32_t hist[5] = {};
  std::vector<int64_t> ts[2];
  uint8_t ttlMin = 0;
  uint8_t ttlMax = 0;
  bool hasTtl = false;
};

enum class SplitKind : uint8_t { kNone = 0, kDirIdle, kDnsId, kTouch };
enum class EndKind : uint8_t { kNone = 0, kIdle, kTerm, kLife };

/**
 * # Flow
 * 1 フローの集計状態
 *
 * ### 特徴
 * - TCP の再送候補の状態は TCP フローだけが持つ(UDP/ICMP のメモリを抑える)
 * - nDPI のフロー状態は判定が確定した時点で結果だけ残して解放する
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
  SplitKind split = SplitKind::kNone;
  EndKind cont = EndKind::kNone;
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
  uint8_t icmpLastType = 0;
  uint8_t icmpLastCode = 0;

  uint32_t nTouch = 0;
  // L が 128/256/512/1024/1514 ちょうど・1514 超のパケット数(ALT_BOUND)
  uint32_t bound[6] = {};

  FlowAcc acc;
  std::unique_ptr<TcpRetxVariants> tcp;

  // L7(nDPI)
  ndpi_flow_struct* l7h = nullptr;
  uint32_t l7n = 0;
  bool l7Stop = false;  // 参照実装の l7_stop(これ以降 nDPI に渡さない)
  bool l7Frozen = false;  // nDPI 側が以後のパケットを無視する状態(fail_with_unknown)
  bool l7Done = false;  // 結果確定済み(l7h は解放済み)
  bool seenSyn = false;
  uint16_t l7Master = 0;
  uint16_t l7App = 0;
  uint8_t l7Guess = 0;

  // フロー表の挿入順(Python dict の順序。置き換えでは変わらない)
  uint64_t order = 0;
  // 期限切れになる最初の秒(これ以上の秒の走査で出力される)
  int64_t deadline = 0;
  uint32_t gen = 0;
  bool live = false;
};

}  // namespace opennprobe
