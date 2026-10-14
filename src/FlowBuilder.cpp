// SPDX-License-Identifier: GPL-3.0-or-later
#include "FlowBuilder.hpp"

#include <algorithm>
#include <cstring>
#include <limits>

#include "DnsInfo.hpp"
#include "TextBuffer.hpp"

namespace opennprobe {

namespace {

constexpr int64_t kNoDeadline = std::numeric_limits<int64_t>::min();
constexpr int64_t kCollected = std::numeric_limits<int64_t>::max();

inline uint32_t plenOf(const Packet& p) {
  // 全長 0 の IPv4 を捨てない設定のときだけ使う(caplen から推定)
  if (p.ipLen == 0 && p.v == 4) return p.caplen - 14;
  return p.ipLen;
}

inline int histBin(uint32_t L) {
  if (L <= 128) return 0;
  if (L <= 256) return 1;
  if (L <= 512) return 2;
  if (L <= 1024) return 3;
  if (L <= 1514) return 4;
  return -1;
}

inline int boundBin(uint32_t L) {
  switch (L) {
    case 128:
      return 0;
    case 256:
      return 1;
    case 512:
      return 2;
    case 1024:
      return 3;
    case 1514:
      return 4;
    default:
      break;
  }
  return L > 1514 ? 5 : -1;
}

inline int dirOf(const Flow& f, const Packet& p) {
  return (p.sport == f.sport && std::memcmp(p.src, f.src, 16) == 0) ? 0 : 1;
}

}  // namespace

FlowBuilder::FlowBuilder(const Rules& rules, NdpiEngine* l7, RowStore& store)
    : rules_(rules), l7_(l7), store_(store), fmt_(rules) {}

FlowBuilder::~FlowBuilder() {
  // finish() を呼ばずに破棄されたときも nDPI のフロー状態は解放する
  for (Flow& f : pool_) {
    if (f.l7h != nullptr && l7_ != nullptr) {
      uint16_t m, a;
      uint8_t g;
      l7_->finish(f.l7h, m, a, g);
      f.l7h = nullptr;
    }
  }
}

uint32_t FlowBuilder::allocFlow() {
  if (!free_.empty()) {
    uint32_t idx = free_.back();
    free_.pop_back();
    return idx;
  }
  pool_.emplace_back();
  return static_cast<uint32_t>(pool_.size() - 1);
}

void FlowBuilder::releaseFlow(uint32_t idx) {
  resetFlow(pool_[idx]);
  free_.push_back(idx);
}

void FlowBuilder::resetFlow(Flow& f) {
  uint32_t gen = f.gen + 1;
  f = Flow();
  f.gen = gen;
}

void FlowBuilder::initFlow(Flow& f, const Packet& p, const FlowKey& k) {
  f.key = k;
  std::memcpy(f.src, p.src, 16);
  std::memcpy(f.dst, p.dst, 16);
  f.sport = p.sport;
  f.dport = p.dport;
  f.proto = p.proto;
  f.v = p.v;
  f.first = f.last = f.lastAlive = p.tsUs;
  f.seenSyn = p.proto == 6 && (p.flags & 0x12) == 0x02;
  f.deadline = kNoDeadline;
  f.live = true;
  if (p.proto == 6) f.tcp.reset(new TcpRetxVariants());
  if (l7_ != nullptr) {
    f.l7h = l7_->newFlow();
    ++l7Live_;
    if (l7Live_ > l7LivePeak_) l7LivePeak_ = l7Live_;
  }
}

void FlowBuilder::accUpdate(FlowAcc& a, const Packet& p, int d, bool firstPkt) {
  uint32_t L = plenOf(p);
  int b = histBin(L);
  if (b >= 0) a.hist[b] += 1;
  a.ts[d].push_back(p.tsUs);
  if (d == 0 && !firstPkt) {
    if (!a.hasTtl) {
      a.ttlMin = a.ttlMax = p.ttl;
      a.hasTtl = true;
    } else {
      if (p.ttl < a.ttlMin) a.ttlMin = p.ttl;
      if (p.ttl > a.ttlMax) a.ttlMax = p.ttl;
    }
  }
}

void FlowBuilder::l7Finalize(Flow& f) {
  if (f.l7h == nullptr) return;
  l7_->finish(f.l7h, f.l7Master, f.l7App, f.l7Guess);
  f.l7h = nullptr;
  f.l7Done = true;
  --l7Live_;
}

void FlowBuilder::l7Feed(Flow& f, const Packet& p) {
  if (l7_ == nullptr || f.l7Stop) return;
  ++f.l7n;
  // nDPI が以後のパケットを無視する状態なら呼んでも結果は変わらない(参照実装は呼び続けるが数だけ合わせる)
  if (f.l7Frozen) return;
  uint16_t app = 0;
  bool extra = false;
  bool frozen = false;
  // 参照実装は長さを unsigned short で渡す
  l7_->feed(f.l7h, p.ipb, static_cast<uint16_t>(p.ipbLen), static_cast<uint64_t>(floorDiv(p.tsUs, 1000)), app,
            extra, frozen);
  if (app != 0 && !extra) {
    // 判定完了: 以後 nDPI に渡さない。giveup は判定済みならスタックをそのまま返すので今確定してよい
    f.l7Stop = true;
    l7Finalize(f);
    return;
  }
  if (frozen) {
    f.l7Frozen = true;
    // 未判定のまま凍結したフローは giveup がキャッシュ(他フローの状態)を見るので、出力時まで確定しない
    if (app != 0) l7Finalize(f);
  }
}

void FlowBuilder::count(Flow& f, const Packet& p, int d, bool firstPkt, bool accDone) {
  if (!accDone) accUpdate(f.acc, p, d, firstPkt);
  l7Feed(f, p);
  f.last = p.tsUs;
  if (!f.hasD[d]) {
    f.hasD[d] = true;
    f.dfirst[d] = p.tsUs;
  }
  f.dlast[d] = p.tsUs;
  const uint32_t L = plenOf(p);
  bool isRetx = false;
  const bool wasTerm = f.terminated;
  f.pk[d] += 1;
  f.by[d] += L;
  int bb = boundBin(L);
  if (bb >= 0) f.bound[bb] += 1;
  if (f.pk[0] + f.pk[1] == 1) {
    f.lmin = f.lmax = L;
  } else {
    if (L < f.lmin) f.lmin = L;
    if (L > f.lmax) f.lmax = L;
  }
  if (p.proto == 6) {
    f.flags[d] |= p.flags;
    if (p.win > f.win[d]) f.win[d] = p.win;
    f.tcp->update(p, d, L, f.pk[1 - d]);
    int64_t seglen = p.plen;
    if (rules_.retxSynFin) seglen += ((p.flags & 2) ? 1 : 0) + ((p.flags & 1) ? 1 : 0);
    if (seglen > 0) {
      uint32_t end = static_cast<uint32_t>(p.seq + static_cast<uint64_t>(seglen));
      uint32_t hi = f.hiseq[d];
      if (f.hasHiseq[d] && (static_cast<uint32_t>(end - hi) >= 0x80000000u || end == hi)) {
        isRetx = true;
      } else {
        f.hiseq[d] = end;
        f.hasHiseq[d] = true;
      }
    }
    if (rules_.tcpCloseRst && (p.flags & 4)) f.terminated = true;
  }
  // 終了済み TCP フローでは再送パケットは期限判定用の最終時刻を進めない
  if (!(wasTerm && isRetx && rules_.termRetxNoUpdate)) f.lastAlive = p.tsUs;
  if (p.proto == 1 || p.proto == 58) {
    if (!f.hasIcmp) {
      f.hasIcmp = true;
      f.icmpType = p.icmpType;
      f.icmpCode = p.icmpCode;
    }
    f.icmpLastType = p.icmpType;
    f.icmpLastCode = p.icmpCode;
  }
  if (p.proto == 17 && (p.sport == 53 || p.dport == 53 || p.sport == 5355 || p.dport == 5355)) {
    DnsInfo q;
    if (parseDns(p.payload, p.payloadLen, q)) {
      if (!f.hasDns) {
        f.hasDns = true;
        f.dnsId = q.id;
        f.dnsType = q.qtype;
      }
      if (q.qr == 1) {
        // DNS_TTL_ANSWER は応答の質問部の直後にある最初の RR の TTL
        if (f.dnsTtl == 0 && q.hasFirstRr) f.dnsTtl = q.firstRrTtl;
        f.dnsAnswered = true;
      }
    }
  }
}

void FlowBuilder::touch(Flow& f, const Packet& p, int d) {
  f.last = p.tsUs;
  if (!f.hasD[d]) {
    f.hasD[d] = true;
    f.dfirst[d] = p.tsUs;
  }
  f.dlast[d] = p.tsUs;
  accUpdate(f.acc, p, d, false);
  f.nTouch += 1;
}

void FlowBuilder::emit(Flow& f) {
  if (l7_ != nullptr && f.l7h != nullptr) l7Finalize(f);
  fmt_.emit(f, store_);
}

int64_t FlowBuilder::computeDeadline(const Flow& f) const {
  int64_t fs = floorDiv(f.first, 1000000);
  int64_t ls;
  int64_t lim;
  if (f.terminated) {
    ls = floorDiv(f.lastAlive, 1000000);
    lim = rules_.termIdleSec;
  } else {
    ls = floorDiv(f.last, 1000000);
    lim = rules_.idleSec;
  }
  // 走査の秒 sec で (sec - ls > lim) か (sec - fs > life) なら切れる
  return std::min(ls + lim + 1, fs + rules_.lifeSec + 1);
}

void FlowBuilder::updateDeadline(uint32_t idx) {
  Flow& f = pool_[idx];
  int64_t nd = computeDeadline(f);
  if (nd != f.deadline) {
    f.deadline = nd;
    heap_.push(HeapItem{nd, idx, f.gen});
  }
}

void FlowBuilder::expire(int64_t sec) {
  expiring_.clear();
  while (!heap_.empty() && heap_.top().deadline <= sec) {
    HeapItem it = heap_.top();
    heap_.pop();
    Flow& f = pool_[it.idx];
    if (!f.live || f.gen != it.gen || f.deadline != it.deadline) continue;
    f.deadline = kCollected;
    expiring_.push_back(it.idx);
  }
  if (expiring_.empty()) return;
  // 参照実装は dict の挿入順に全フローを見るので、同じ秒に切れたフローはその順で出す
  std::sort(expiring_.begin(), expiring_.end(),
            [this](uint32_t a, uint32_t b) { return pool_[a].order < pool_[b].order; });
  for (uint32_t idx : expiring_) {
    Flow& f = pool_[idx];
    int64_t ls;
    int64_t lim;
    if (f.terminated) {
      ls = floorDiv(f.lastAlive, 1000000);
      lim = rules_.termIdleSec;
    } else {
      ls = floorDiv(f.last, 1000000);
      lim = rules_.idleSec;
    }
    EndKind why;
    if (sec - ls > lim) {
      why = lim == rules_.idleSec ? EndKind::kIdle : EndKind::kTerm;
    } else {
      why = EndKind::kLife;
    }
    emit(f);
    uint64_t h = f.key.hash();
    active_.erase(f.key, h);
    uint32_t* old = ended_.find(f.key, h);
    if (old != nullptr) {
      *old = static_cast<uint32_t>(why);
    } else {
      ended_.insert(f.key, h, static_cast<uint32_t>(why));
    }
    releaseFlow(idx);
  }
}

void FlowBuilder::add(const Packet& p) {
  ++packets_;
  if (rules_.dropLen0 && p.v == 4 && p.ipLen == 0) {
    ++dropped_;
    return;
  }
  const int64_t sec = floorDiv(p.tsUs, 1000000);
  if (!hasTick_ || sec > tick_) {
    hasTick_ = true;
    tick_ = sec;
    expire(sec);
  }
  const FlowKey k = FlowKey::of(p);
  const uint64_t h = k.hash();
  uint32_t* slot = active_.find(k, h);
  if (slot == nullptr) {
    uint32_t idx = allocFlow();
    Flow& f = pool_[idx];
    initFlow(f, p, k);
    uint32_t why = 0;
    // 同じキーの前のフローが期限で切れた続きか(L7 の扱いを切り分けるための列)
    if (ended_.erase(k, h, &why)) f.cont = static_cast<EndKind>(why);
    f.order = nextOrder_++;
    active_.insert(k, h, idx);
    if (active_.size() > activePeak_) activePeak_ = active_.size();
    count(f, p, 0, true, false);
    updateDeadline(idx);
    return;
  }
  const uint32_t idx = *slot;
  Flow& f = pool_[idx];
  const int d = dirOf(f, p);

  // 既存フローを出して、同じ表の位置(挿入順を保つ)に p から新フローを作る
  auto restart = [&](SplitKind kind) {
    emit(f);
    uint64_t order = f.order;
    resetFlow(f);
    initFlow(f, p, k);
    f.order = order;
    f.split = kind;
    count(f, p, 0, true, false);
    updateDeadline(idx);
  };

  if (rules_.dirIdle) {
    // 到着パケットと同じ向きの最終時刻からの経過(秒単位)が idle を超えたら新フロー
    int64_t ref = f.hasD[d] ? f.dlast[d] : f.last;
    if (sec - floorDiv(ref, 1000000) > rules_.idleSec) {
      restart(SplitKind::kDirIdle);
      return;
    }
  }
  if (f.dnsAnswered && d == 0) {
    DnsInfo q;
    if (parseDns(p.payload, p.payloadLen, q) && q.qr == 0) {
      if (rules_.dnsSplit && q.id != f.dnsId) {
        // 応答済み DNS フローに別 ID の問い合わせ: 旧フローをそのまま出して新フロー
        restart(SplitKind::kDnsId);
        return;
      }
      if (rules_.dnsTouch) {
        // 同じ ID の問い合わせ(再送): 旧フローに一部だけ反映して出し、統計を引き継ぐ
        touch(f, p, d);
        emit(f);
        FlowAcc acc = std::move(f.acc);
        uint64_t order = f.order;
        resetFlow(f);
        initFlow(f, p, k);
        f.acc = std::move(acc);
        f.order = order;
        f.split = SplitKind::kTouch;
        count(f, p, 0, false, true);
        updateDeadline(idx);
        return;
      }
    }
  }
  count(f, p, d, false, false);
  updateDeadline(idx);
}

void FlowBuilder::finish() {
  std::vector<uint32_t> rest;
  rest.reserve(active_.size());
  for (uint32_t i = 0; i < pool_.size(); ++i) {
    if (pool_[i].live) rest.push_back(i);
  }
  std::sort(rest.begin(), rest.end(), [this](uint32_t a, uint32_t b) { return pool_[a].order < pool_[b].order; });
  for (uint32_t idx : rest) {
    emit(pool_[idx]);
    releaseFlow(idx);
  }
}

}  // namespace opennprobe
