// SPDX-License-Identifier: GPL-3.0-or-later
#include "PcapReader.hpp"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

namespace opennprobe {

namespace {
// libpcap の max_snaplen_for_dlt(DLT_EN10MB 等の既定値)
constexpr uint32_t kMaxSnaplen = 262144;
}  // namespace

PcapReader::~PcapReader() {
  if (base_ != nullptr && size_ > 0) munmap(const_cast<uint8_t*>(base_), size_);
}

uint32_t PcapReader::rd32(const uint8_t* p) const {
  uint32_t v;
  std::memcpy(&v, p, 4);
  return swap_ ? __builtin_bswap32(v) : v;
}

bool PcapReader::open(const std::string& path, std::string& err) {
  int fd = ::open(path.c_str(), O_RDONLY);
  if (fd < 0) {
    err = path + ": " + std::strerror(errno);
    return false;
  }
  struct stat st;
  if (fstat(fd, &st) != 0) {
    err = path + ": " + std::strerror(errno);
    ::close(fd);
    return false;
  }
  size_ = static_cast<size_t>(st.st_size);
  if (size_ < 24) {
    ::close(fd);
    err = path + ": pcap ヘッダがありません";
    return false;
  }
  void* m = mmap(nullptr, size_, PROT_READ, MAP_PRIVATE, fd, 0);
  ::close(fd);
  if (m == MAP_FAILED) {
    err = path + ": mmap: " + std::strerror(errno);
    size_ = 0;
    return false;
  }
  base_ = static_cast<const uint8_t*>(m);
  madvise(m, size_, MADV_SEQUENTIAL);

  uint32_t magic;
  std::memcpy(&magic, base_, 4);
  if (magic == 0xa1b2c3d4u) {
    swap_ = false;
  } else if (magic == 0xd4c3b2a1u) {
    swap_ = true;
  } else if (magic == 0xa1b23c4du) {
    swap_ = false;
    nano_ = true;
  } else if (magic == 0x4d3cb2a1u) {
    swap_ = true;
    nano_ = true;
  } else {
    err = path + ": libpcap 形式ではありません(pcapng は未対応)";
    return false;
  }
  uint32_t snaplen = rd32(base_ + 16);
  linkType_ = rd32(base_ + 20) & 0x0FFFFFFF;
  snapshot_ = (snaplen == 0 || snaplen > kMaxSnaplen) ? kMaxSnaplen : snaplen;
  pos_ = 24;
  return true;
}

bool PcapReader::next(int64_t& tsUs, const uint8_t*& data, uint32_t& caplen) {
  if (pos_ >= size_) return false;
  if (size_ - pos_ < 16) {
    stopReason_ = "末尾のレコードヘッダが途中で切れています";
    pos_ = size_;
    return false;
  }
  const uint8_t* h = base_ + pos_;
  uint32_t sec = rd32(h);
  uint32_t frac = rd32(h + 4);
  uint32_t incl = rd32(h + 8);
  if (incl > kMaxSnaplen) {
    stopReason_ = "caplen " + std::to_string(incl) + " > 262144 のレコードで読み取りを停止しました(libpcap 互換)";
    pos_ = size_;
    return false;
  }
  data = h + 16;
  caplen = incl;
  if (size_ - pos_ - 16 < incl) {
    pos_ = size_;
    if (!keepTruncatedTail_) {
      stopReason_ = "末尾のレコードが途中で切れています(使いません)";
      return false;
    }
    // 調査用プロトタイプ(Python の read)と同じく、読めたところまでを 1 レコードとして使う
    stopReason_ = "末尾のレコードが途中で切れています(読めた部分を使いました)";
    caplen = static_cast<uint32_t>(size_ - (h + 16 - base_));
    if (caplen > snapshot_) caplen = snapshot_;
    tsUs = static_cast<int64_t>(sec) * 1000000 + (nano_ ? frac / 1000 : frac);
    ++records_;
    return true;
  }
  if (caplen > snapshot_) {
    caplen = snapshot_;
    ++truncated_;
  }
  pos_ += 16 + static_cast<size_t>(incl);
  // 読み終えた範囲のページを手放す(mmap したファイルのページが RSS に積もらないように)。
  // 直前のレコードは呼び出し側が使うので、それより前だけを対象にする
  if (h - base_ >= static_cast<std::ptrdiff_t>(released_ + kReleaseChunk)) {
    size_t upto = (static_cast<size_t>(h - base_) / kReleaseChunk) * kReleaseChunk;
    madvise(const_cast<uint8_t*>(base_) + released_, upto - released_, MADV_DONTNEED);
    released_ = upto;
  }
  tsUs = static_cast<int64_t>(sec) * 1000000 + (nano_ ? frac / 1000 : frac);
  ++records_;
  return true;
}

}  // namespace opennprobe
