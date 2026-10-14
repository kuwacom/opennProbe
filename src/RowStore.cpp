// SPDX-License-Identifier: GPL-3.0-or-later
#include "RowStore.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <numeric>

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

}  // namespace

void RowStore::add(int64_t startMs, Shape shape, const std::string& text, uint32_t len1, uint32_t len2,
                   uint32_t lenRx, int64_t icmpLast) {
  if (!haveFirst_) {
    haveFirst_ = true;
    firstShape_ = shape;
  } else if (shape != kBase && shape != firstShape_) {
    int g = shape == kIcmp ? 0 : 1;
    if (std::find(tail_.begin(), tail_.end(), g) == tail_.end()) tail_.push_back(g);
  }
  if (shape == kIcmp) sawIcmp_ = true;
  if (shape == kTcp) sawTcp_ = true;
  if (shape != kIcmp) sawNonIcmp_ = true;
  Rec r;
  r.startMs = startMs;
  r.off = arena_.size();
  r.icmpLast = icmpLast;
  r.len1 = len1;
  r.len2 = len2;
  r.lenRx = lenRx;
  r.len3 = static_cast<uint32_t>(text.size()) - len1 - len2 - lenRx;
  r.shape = shape;
  arena_.insert(arena_.end(), text.begin(), text.end());
  recs_.push_back(r);
}

bool RowStore::write(const std::string& path, std::string& err) {
  FILE* fp = path == "-" ? stdout : std::fopen(path.c_str(), "wb");
  if (fp == nullptr) {
    err = path + ": " + std::strerror(errno);
    return false;
  }
  // 参照実装は行が 0 のとき列も無い(pandas の空 DataFrame)。空ファイルにする
  if (!recs_.empty()) {
    std::vector<uint32_t> idx(recs_.size());
    std::iota(idx.begin(), idx.end(), 0u);
    std::stable_sort(idx.begin(), idx.end(),
                     [this](uint32_t a, uint32_t b) { return recs_[a].startMs < recs_[b].startMs; });

    const bool inlineIcmp = firstShape_ == kIcmp;
    const bool inlineRx = firstShape_ == kTcp;
    const bool icmpFloat = sawNonIcmp_;
    TextBuffer out;
    out.str().reserve(1 << 22);
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
    for (uint32_t i : idx) {
      const Rec& r = recs_[i];
      const char* p = arena_.data() + r.off;
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
      if (out.size() >= (1u << 22)) {
        if (std::fwrite(out.data(), 1, out.size(), fp) != out.size()) {
          err = path + ": 書き込みに失敗しました";
          if (fp != stdout) std::fclose(fp);
          return false;
        }
        out.clear();
      }
    }
    if (out.size() > 0 && std::fwrite(out.data(), 1, out.size(), fp) != out.size()) {
      err = path + ": 書き込みに失敗しました";
      if (fp != stdout) std::fclose(fp);
      return false;
    }
  }
  if (fp != stdout) {
    if (std::fclose(fp) != 0) {
      err = path + ": " + std::strerror(errno);
      return false;
    }
  } else {
    std::fflush(fp);
  }
  return true;
}

}  // namespace opennprobe
