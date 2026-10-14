// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <vector>

#include "FlowKey.hpp"

namespace opennprobe {

/**
 * # OpenTable
 * FlowKey -> 32 bit 値の open addressing ハッシュ表(線形探査)
 *
 * ### 特徴
 * - 削除は後方シフトで行い墓標を残さない(フローの出入りが多くても探査長が伸びない)
 * - 値 0xFFFFFFFF は空きを表すので格納できない
 */
class OpenTable {
 public:
  static constexpr uint32_t kEmpty = 0xFFFFFFFFu;

  OpenTable() { rehash(1024); }

  size_t size() const { return count_; }

  uint32_t* find(const FlowKey& k, uint64_t h) {
    size_t i = h & mask_;
    while (true) {
      Entry& e = slots_[i];
      if (e.val == kEmpty) return nullptr;
      if (e.hash == static_cast<uint32_t>(h) && e.key == k) return &e.val;
      i = (i + 1) & mask_;
    }
  }

  // 既にあれば上書きしない(呼び出し側で find 済みの前提)
  void insert(const FlowKey& k, uint64_t h, uint32_t val) {
    if ((count_ + 1) * 10 > slots_.size() * 7) rehash(slots_.size() * 2);
    put(k, static_cast<uint32_t>(h), h, val);
    ++count_;
  }

  bool erase(const FlowKey& k, uint64_t h, uint32_t* out = nullptr) {
    size_t i = h & mask_;
    while (true) {
      Entry& e = slots_[i];
      if (e.val == kEmpty) return false;
      if (e.hash == static_cast<uint32_t>(h) && e.key == k) break;
      i = (i + 1) & mask_;
    }
    if (out != nullptr) *out = slots_[i].val;
    // 後方シフト削除: 後続の要素を本来の位置に近づける
    size_t j = i;
    while (true) {
      j = (j + 1) & mask_;
      Entry& n = slots_[j];
      if (n.val == kEmpty) break;
      size_t home = n.home & mask_;
      // j の要素が i に移動してよいのは、home が (i, j] の外にあるとき
      bool between = (i <= j) ? (home > i && home <= j) : (home > i || home <= j);
      if (!between) {
        slots_[i] = n;
        i = j;
      }
    }
    slots_[i].val = kEmpty;
    --count_;
    return true;
  }

 private:
  struct Entry {
    FlowKey key;
    uint32_t hash;
    uint32_t val;
    uint64_t home;
  };

  void put(const FlowKey& k, uint32_t h32, uint64_t h, uint32_t val) {
    size_t i = h & mask_;
    while (slots_[i].val != kEmpty) i = (i + 1) & mask_;
    slots_[i].key = k;
    slots_[i].hash = h32;
    slots_[i].val = val;
    slots_[i].home = h;
  }

  void rehash(size_t n) {
    std::vector<Entry> old;
    old.swap(slots_);
    slots_.assign(n, Entry{});
    for (Entry& e : slots_) e.val = kEmpty;
    mask_ = n - 1;
    for (const Entry& e : old) {
      if (e.val != kEmpty) put(e.key, e.hash, e.home, e.val);
    }
  }

  std::vector<Entry> slots_;
  size_t mask_ = 0;
  size_t count_ = 0;
};

}  // namespace opennprobe
