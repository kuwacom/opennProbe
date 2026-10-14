// SPDX-License-Identifier: GPL-3.0-or-later
#include "RowStore.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <numeric>
#include <queue>

namespace opennprobe {

namespace {

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

// 一時ファイル内の 1 行の見出し(続いて len バイトのテキスト)
struct SpillHead {
  int64_t startMs;
  uint64_t seq;
  uint32_t len;
};

}  // namespace

RowStore::RowStore(std::string header, std::string spillDir, size_t spillBytes)
    : header_(std::move(header)), spillDir_(std::move(spillDir)), spillBytes_(spillBytes) {}

RowStore::~RowStore() {
  if (spillFd_ >= 0) ::close(spillFd_);
}

void RowStore::add(int64_t startMs, const char* text, size_t n) {
  // 上限ちょうどで確保しておき、倍々の伸長で上限の 2 倍を抱えないようにする
  if (spillBytes_ > 0 && arena_.capacity() == 0) arena_.reserve(spillBytes_ + 65536);
  Rec r;
  r.startMs = startMs;
  r.seq = seq_++;
  r.off = arena_.size();
  r.len = static_cast<uint32_t>(n);
  arena_.insert(arena_.end(), text, text + n);
  recs_.push_back(r);
  ++rows_;
  textBytes_ += n;
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
  std::string buf;
  buf.reserve(kOutChunk + 4096);
  Run run{spillSize_, 0};
  for (uint32_t i : idx) {
    const Rec& r = recs_[i];
    SpillHead h{r.startMs, r.seq, r.len};
    buf.append(reinterpret_cast<const char*>(&h), sizeof(h));
    buf.append(arena_.data() + r.off, r.len);
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
  bool next(SpillHead& h, const char*& text) {
    if (!ensure(sizeof(SpillHead))) return false;
    std::memcpy(&h, buf_.data() + head_, sizeof(SpillHead));
    if (!ensure(sizeof(SpillHead) + h.len)) return false;
    text = buf_.data() + head_ + sizeof(SpillHead);
    head_ += sizeof(SpillHead) + h.len;
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
    std::string out;
    out.reserve(kOutChunk + 65536);
    out += header_;
    out += '\n';
    auto putRow = [&](const char* p, size_t n) {
      out.append(p, n);
      if (out.size() >= kOutChunk) {
        if (std::fwrite(out.data(), 1, out.size(), fp) != out.size()) ok = false;
        out.clear();
      }
    };

    if (runs_.empty()) {
      std::vector<uint32_t> idx;
      sortPending(idx);
      for (uint32_t i : idx) putRow(arena_.data() + recs_[i].off, recs_[i].len);
    } else {
      // run どうしを (開始時刻, 出力順) でマージする
      std::vector<RunReader> readers;
      readers.reserve(runs_.size());
      for (const Run& r : runs_) readers.emplace_back(spillFd_, r.off, r.len);
      struct Head {
        SpillHead h;
        const char* text;
      };
      std::vector<Head> heads(readers.size());
      auto later = [&heads](size_t a, size_t b) {
        const SpillHead& x = heads[a].h;
        const SpillHead& y = heads[b].h;
        return x.startMs != y.startMs ? x.startMs > y.startMs : x.seq > y.seq;
      };
      std::priority_queue<size_t, std::vector<size_t>, decltype(later)> pq(later);
      for (size_t i = 0; i < readers.size(); ++i) {
        if (readers[i].next(heads[i].h, heads[i].text)) pq.push(i);
      }
      size_t written = 0;
      while (!pq.empty()) {
        size_t i = pq.top();
        pq.pop();
        putRow(heads[i].text, heads[i].h.len);
        ++written;
        if (readers[i].next(heads[i].h, heads[i].text)) pq.push(i);
      }
      if (written != rows_) {
        err = "一時ファイルの読み戻しに失敗しました";
        ok = false;
      }
    }
    if (!out.empty() && std::fwrite(out.data(), 1, out.size(), fp) != out.size()) ok = false;
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
