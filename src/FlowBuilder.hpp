// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <deque>
#include <queue>
#include <vector>

#include "Flow.hpp"
#include "NdpiEngine.hpp"
#include "OpenTable.hpp"
#include "Packet.hpp"
#include "RowFormatter.hpp"
#include "RowStore.hpp"
#include "Rules.hpp"

namespace opennprobe {

/**
 * # FlowBuilder
 * パケット列からフローを組み立て、終わったフローを RowStore へ出す
 *
 * ### 特徴
 * - 期限切れの判定は「パケット時刻の秒が進んだ最初のパケット」の処理前に行う(参照実装の全フロー走査と等価)。
 *   全走査の代わりに期限の秒で並べたヒープを使い、同じ秒に切れたフローは表への挿入順で出す
 * - フローの出力順は参照実装と同じ(同じ開始時刻の行の並びと、nDPI の giveup を呼ぶ順序が一致する)
 * - nDPI のフロー状態は判定が確定したら結果だけ残して解放する
 */
class FlowBuilder {
 public:
  FlowBuilder(const Rules& rules, NdpiEngine* l7, RowStore& store);
  ~FlowBuilder();

  void add(const Packet& p);
  // 残っているフローを全部出す
  void finish();

  uint64_t packets() const { return packets_; }
  uint64_t dropped() const { return dropped_; }
  uint64_t l7Live() const { return l7Live_; }
  uint64_t l7LivePeak() const { return l7LivePeak_; }
  uint64_t activePeak() const { return activePeak_; }

 private:
  struct HeapItem {
    int64_t deadline;
    uint32_t idx;
    uint32_t gen;
    bool operator>(const HeapItem& o) const { return deadline > o.deadline; }
  };

  uint32_t allocFlow();
  void releaseFlow(uint32_t idx);
  // idx の位置に p から新しいフローを作る(order は呼び出し側が決める)
  void initFlow(Flow& f, const Packet& p, const FlowKey& k);
  void resetFlow(Flow& f);
  void count(Flow& f, const Packet& p, int d, bool firstPkt, bool accDone);
  void touch(Flow& f, const Packet& p, int d);
  void accUpdate(FlowAcc& a, const Packet& p, int d, bool firstPkt);
  void l7Feed(Flow& f, const Packet& p);
  void l7Finalize(Flow& f);
  void emit(Flow& f);
  void expire(int64_t sec);
  void updateDeadline(uint32_t idx);
  int64_t computeDeadline(const Flow& f) const;

  const Rules& rules_;
  NdpiEngine* l7_;
  RowStore& store_;
  RowFormatter fmt_;

  // deque なので要素の参照は追加で無効にならない
  std::deque<Flow> pool_;
  std::vector<uint32_t> free_;
  OpenTable active_;
  // 期限で切れたキーの理由(同じキーの次のフローの ALT_CONT)
  OpenTable ended_;
  std::priority_queue<HeapItem, std::vector<HeapItem>, std::greater<HeapItem>> heap_;
  std::vector<uint32_t> expiring_;

  bool hasTick_ = false;
  int64_t tick_ = 0;
  uint64_t nextOrder_ = 0;
  uint64_t packets_ = 0;
  uint64_t dropped_ = 0;
  uint64_t l7Live_ = 0;
  uint64_t l7LivePeak_ = 0;
  uint64_t activePeak_ = 0;
};

}  // namespace opennprobe
