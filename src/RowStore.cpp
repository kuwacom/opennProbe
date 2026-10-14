// SPDX-License-Identifier: GPL-3.0-or-later
#include "RowStore.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <numeric>
#include <queue>

#include "TextBuffer.hpp"

namespace opennprobe {

namespace {

const char* const kHeadS1 =
    "FLOW_START_MILLISECONDS,FLOW_END_MILLISECONDS,IPV4_SRC_ADDR,L4_SRC_PORT,IPV4_DST_ADDR,L4_DST_PORT,"
    "PROTOCOL,L7_PROTO,ALT_L7_RAW,ALT_L7_GUESS,ALT_L7_N,ALT_CONT,ALT_SYN,IN_BYTES,OUT_BYTES,IN_PKTS,OUT_PKTS,"
    "TCP_FLAGS,CLIENT_TCP_FLAGS,SERVER_TCP_FLAGS,ALT_DUR_US,ALT_DUR_RAW,FLOW_DURATION_MILLISECONDS,DURATION_IN,"
    "DURATION_OUT,ALT_DURIO_MS,MIN_TTL,MAX_TTL,LONGEST_FLOW_PKT,SHORTEST_FLOW_PKT,MIN_IP_PKT_LEN,"
    "MAX_IP_PKT_LEN,SRC_TO_DST_SECOND_BYTES,DST_TO_SRC_SECOND_BYTES,RETRANSMITTED_IN_PKTS,"
    "RETRANSMITTED_IN_BYTES,RETRANSMITTED_OUT_PKTS,RETRANSMITTED_OUT_BYTES,SRC_TO_DST_AVG_THROUGHPUT,"
    "DST_TO_SRC_AVG_THROUGHPUT,NUM_PKTS_UP_TO_128_BYTES,NUM_PKTS_128_TO_256_BYTES,NUM_PKTS_256_TO_512_BYTES,"
    "NUM_PKTS_512_TO_1024_BYTES,NUM_PKTS_1024_TO_1514_BYTES,TCP_WIN_MAX_IN,TCP_WIN_MAX_OUT,ICMP_TYPE,"
    "ICMP_IPV4_TYPE";
const char* const kHeadIcmp = "ALT_ICMP_LAST";
const char* const kHeadS2 =
    "DNS_QUERY_ID,DNS_QUERY_TYPE,DNS_TTL_ANSWER,FTP_COMMAND_RET_CODE,SRC_TO_DST_IAT_MIN,SRC_TO_DST_IAT_MAX,"
    "SRC_TO_DST_IAT_AVG,SRC_TO_DST_IAT_STDDEV,ALT_SRC_TO_DST_SD64,ALT_SRC_TO_DST_IATF,ALT_SRC_TO_DST_IATMS,"
    "ALT_SRC_TO_DST_SDF,ALT_SRC_TO_DST_SDS,DST_TO_SRC_IAT_MIN,DST_TO_SRC_IAT_MAX,DST_TO_SRC_IAT_AVG,"
    "DST_TO_SRC_IAT_STDDEV,ALT_DST_TO_SRC_SD64,ALT_DST_TO_SRC_IATF,ALT_DST_TO_SRC_IATMS,ALT_DST_TO_SRC_SDF,"
    "ALT_DST_TO_SRC_SDS";
const char* const kHeadRx = "ALT_RX_A2,ALT_RX_A3,ALT_RX_A4,ALT_RX_A5,ALT_RX_B,ALT_RX_B2,ALT_RX_C,ALT_RX_C5";
const char* const kHeadS3 = "ALT_BOUND,ALT_SPLIT,ALT_TERM,ALT_TOUCH,ALT_V";
const char* const kEmptyRx = ",,,,,,,";  // 8 列ぶんの空欄

constexpr size_t kOutChunk = size_t(4) << 20;
constexpr size_t kRunBuf = size_t(1) << 20;

bool writeAll(int fd, const char* p, size_t n) {
  while (n > 0) {
    ssize_t w = ::write(fd, p, n);
    if (w < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    p += w;
    n -= static_cast<size_t>(w);
  }
  return true;
}

}  // namespace

RowStore::RowStore(std::string spillDir, size_t spillBytes)
    : spillDir_(std::move(spillDir)), spillBytes_(spillBytes) {}

RowStore::~RowStore() {
  if (spillFd_ >= 0) ::close(spillFd_);
}

void RowStore::add(int64_t startMs, Shape shape, const std::string& text, uint32_t len1, uint32_t len2,
                   uint32_t lenRx, int64_t icmpLast) {
  if (!haveFirst_) {
    haveFirst_ = true;
    firstShape_ = shape;
  } else if (shape != kBase && shape != firstShape_) {
    int g = shape == kIcmp ? 0 : 1;
    if (std::find(tail_.begin(), tail_.end(), g) == tail_.end()) tail_.push_back(g);
  }
  if (shape != kIcmp) sawNonIcmp_ = true;
  Rec r;
  r.startMs = startMs;
  r.seq = seq_++;
  r.icmpLast = icmpLast;
  r.len1 = len1;
  r.len2 = len2;
  r.lenRx = lenRx;
  r.len3 = static_cast<uint32_t>(text.size()) - len1 - len2 - lenRx;
  r.shape = shape;
  // 上限ちょうどで確保しておき、倍々の伸長で上限の 2 倍を抱えないようにする
  if (spillBytes_ > 0 && arena_.capacity() == 0) arena_.reserve(spillBytes_ + 65536);
  arena_.insert(arena_.end(), text.begin(), text.end());
  recs_.push_back(r);
  ++rows_;
  textBytes_ += text.size();
  if (spillBytes_ > 0 && arena_.size() >= spillBytes_) spill();
}

void RowStore::sortPending(std::vector<uint32_t>& idx) const {
  idx.resize(recs_.size());
  std::iota(idx.begin(), idx.end(), 0u);
  // recs_ は出力順に並んでいるので安定ソートで (開始時刻, 出力順) の順になる
  std::stable_sort(idx.begin(), idx.end(),
                   [this](uint32_t a, uint32_t b) { return recs_[a].startMs < recs_[b].startMs; });
}

void RowStore::spill() {
  if (!spillErr_.empty()) return;
  if (spillFd_ < 0) {
    std::string tmpl = spillDir_ + "/opennprobe-rows-XXXXXX";
    std::vector<char> name(tmpl.begin(), tmpl.end());
    name.push_back('\0');
    spillFd_ = mkstemp(name.data());
    if (spillFd_ < 0) {
      // 一時ファイルが作れなければメモリにため続ける
      std::fprintf(stderr, "%s: %s(行はメモリに保持します)\n", name.data(), std::strerror(errno));
      spillBytes_ = 0;
      return;
    }
    ::unlink(name.data());
  }
  std::vector<uint32_t> idx;
  sortPending(idx);
  std::vector<uint64_t> offs(recs_.size());
  {
    uint64_t o = 0;
    for (size_t i = 0; i < recs_.size(); ++i) {
      offs[i] = o;
      o += recs_[i].len1 + recs_[i].len2 + recs_[i].lenRx + recs_[i].len3;
    }
  }
  std::string buf;
  buf.reserve(kOutChunk + 4096);
  Run run{spillSize_, 0};
  for (uint32_t i : idx) {
    const Rec& r = recs_[i];
    size_t n = r.len1 + r.len2 + r.lenRx + r.len3;
    buf.append(reinterpret_cast<const char*>(&r), sizeof(Rec));
    buf.append(arena_.data() + offs[i], n);
    if (buf.size() >= kOutChunk) {
      if (!writeAll(spillFd_, buf.data(), buf.size())) {
        spillErr_ = std::string("一時ファイルへの書き込みに失敗しました: ") + std::strerror(errno);
        return;
      }
      run.len += buf.size();
      buf.clear();
    }
  }
  if (!buf.empty()) {
    if (!writeAll(spillFd_, buf.data(), buf.size())) {
      spillErr_ = std::string("一時ファイルへの書き込みに失敗しました: ") + std::strerror(errno);
      return;
    }
    run.len += buf.size();
  }
  spillSize_ += run.len;
  runs_.push_back(run);
  // 容量は次の run で使い回す
  recs_.clear();
  arena_.clear();
}

namespace {

/**
 * # RunReader
 * 一時ファイル内の 1 run を先頭から順に読む
 */
class RunReader {
 public:
  RunReader(int fd, uint64_t off, uint64_t len) : fd_(fd), pos_(off), end_(off + len) {}

  // 次の行を読む。text は次の呼び出しまで有効
  template <typename RecT>
  bool next(RecT& r, const char*& text, size_t& n) {
    if (!ensure(sizeof(RecT))) return false;
    std::memcpy(&r, buf_.data() + head_, sizeof(RecT));
    n = r.len1 + r.len2 + r.lenRx + r.len3;
    if (!ensure(sizeof(RecT) + n)) return false;
    text = buf_.data() + head_ + sizeof(RecT);
    head_ += sizeof(RecT) + n;
    return true;
  }

 private:
  bool ensure(size_t need) {
    if (tail_ - head_ >= need) return true;
    std::memmove(buf_.data(), buf_.data() + head_, tail_ - head_);
    tail_ -= head_;
    head_ = 0;
    size_t want = std::max(need, kRunBuf);
    if (buf_.size() < want) buf_.resize(want);
    while (tail_ < need && pos_ < end_) {
      size_t room = buf_.size() - tail_;
      size_t ask = static_cast<size_t>(std::min<uint64_t>(room, end_ - pos_));
      ssize_t got = ::pread(fd_, buf_.data() + tail_, ask, static_cast<off_t>(pos_));
      if (got <= 0) {
        if (got < 0 && errno == EINTR) continue;
        return false;
      }
      tail_ += static_cast<size_t>(got);
      pos_ += static_cast<uint64_t>(got);
    }
    return tail_ >= need;
  }

  int fd_;
  uint64_t pos_;
  uint64_t end_;
  std::vector<char> buf_;
  size_t head_ = 0;
  size_t tail_ = 0;
};

}  // namespace

bool RowStore::write(const std::string& path, std::string& err) {
  if (!spillErr_.empty()) {
    err = spillErr_;
    return false;
  }
  // 一時ファイルを使っていれば、残りも run にして全部をマージする
  if (!runs_.empty() && !recs_.empty()) spill();
  if (!spillErr_.empty()) {
    err = spillErr_;
    return false;
  }
  FILE* fp = path == "-" ? stdout : std::fopen(path.c_str(), "wb");
  if (fp == nullptr) {
    err = path + ": " + std::strerror(errno);
    return false;
  }
  bool ok = true;
  // 参照実装は行が 0 のとき列も無い(pandas の空 DataFrame)。空ファイルにする
  if (rows_ > 0) {
    const bool inlineIcmp = firstShape_ == kIcmp;
    const bool inlineRx = firstShape_ == kTcp;
    const bool icmpFloat = sawNonIcmp_;
    TextBuffer out;
    out.str().reserve(kOutChunk + 4096);
    out.put(kHeadS1);
    if (inlineIcmp) {
      out.put(',');
      out.put(kHeadIcmp);
    }
    out.put(',');
    out.put(kHeadS2);
    if (inlineRx) {
      out.put(',');
      out.put(kHeadRx);
    }
    out.put(',');
    out.put(kHeadS3);
    for (int g : tail_) {
      out.put(',');
      out.put(g == 0 ? kHeadIcmp : kHeadRx);
    }
    out.put('\n');

    auto putIcmp = [&](const Rec& r) {
      if (r.shape != kIcmp) return;
      out.putI(r.icmpLast);
      if (icmpFloat) out.put(".0", 2);
    };
    auto putRx = [&](const Rec& r, const char* p) {
      if (r.shape == kTcp) {
        out.put(p, r.lenRx);
      } else {
        out.put(kEmptyRx);
      }
    };
    auto putRow = [&](const Rec& r, const char* p) {
      out.put(p, r.len1);
      if (inlineIcmp) {
        out.put(',');
        putIcmp(r);
      }
      out.put(',');
      out.put(p + r.len1, r.len2);
      if (inlineRx) {
        out.put(',');
        putRx(r, p + r.len1 + r.len2);
      }
      out.put(',');
      out.put(p + r.len1 + r.len2 + r.lenRx, r.len3);
      for (int g : tail_) {
        out.put(',');
        if (g == 0) {
          putIcmp(r);
        } else {
          putRx(r, p + r.len1 + r.len2);
        }
      }
      out.put('\n');
      if (out.size() >= kOutChunk) {
        if (std::fwrite(out.data(), 1, out.size(), fp) != out.size()) ok = false;
        out.clear();
      }
    };

    if (runs_.empty()) {
      std::vector<uint32_t> idx;
      sortPending(idx);
      std::vector<uint64_t> offs(recs_.size());
      uint64_t o = 0;
      for (size_t i = 0; i < recs_.size(); ++i) {
        offs[i] = o;
        o += recs_[i].len1 + recs_[i].len2 + recs_[i].lenRx + recs_[i].len3;
      }
      for (uint32_t i : idx) putRow(recs_[i], arena_.data() + offs[i]);
    } else {
      // run どうしを (開始時刻, 出力順) でマージする
      std::vector<RunReader> readers;
      readers.reserve(runs_.size());
      for (const Run& r : runs_) readers.emplace_back(spillFd_, r.off, r.len);
      struct Head {
        Rec rec;
        const char* text;
        size_t n;
      };
      std::vector<Head> heads(readers.size());
      auto later = [&heads](size_t a, size_t b) {
        const Rec& x = heads[a].rec;
        const Rec& y = heads[b].rec;
        return x.startMs != y.startMs ? x.startMs > y.startMs : x.seq > y.seq;
      };
      std::priority_queue<size_t, std::vector<size_t>, decltype(later)> pq(later);
      for (size_t i = 0; i < readers.size(); ++i) {
        if (readers[i].next(heads[i].rec, heads[i].text, heads[i].n)) pq.push(i);
      }
      size_t written = 0;
      while (!pq.empty()) {
        size_t i = pq.top();
        pq.pop();
        putRow(heads[i].rec, heads[i].text);
        ++written;
        if (readers[i].next(heads[i].rec, heads[i].text, heads[i].n)) pq.push(i);
      }
      if (written != rows_) {
        err = "一時ファイルの読み戻しに失敗しました";
        ok = false;
      }
    }
    if (out.size() > 0 && std::fwrite(out.data(), 1, out.size(), fp) != out.size()) ok = false;
    if (!ok && err.empty()) err = path + ": 書き込みに失敗しました";
  }
  if (fp != stdout) {
    if (std::fclose(fp) != 0 && ok) {
      err = path + ": " + std::strerror(errno);
      ok = false;
    }
  } else {
    std::fflush(fp);
  }
  return ok;
}

}  // namespace opennprobe
