// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace opennprobe {

/**
 * # RowStore
 * 出力行をため、最後に開始時刻で安定ソートして CSV に書く
 *
 * ### 特徴
 * - 参照実装(pandas の DataFrame(list of dict) -> sort_values(stable) -> to_csv)と同じ列順・書式にする
 * - 列順は出力順で最初に現れた行の列 + 後から現れた列の追加(ICMP 行の ALT_ICMP_LAST・TCP 行の ALT_RX_*)
 * - ALT_ICMP_LAST は欠けた行が 1 つでもあれば pandas が float 列にするので "N.0" と書く
 * - 行は整形済みテキストの断片で持つ(数値の構造体より小さい)
 */
class RowStore {
 public:
  enum Shape : uint8_t { kBase = 0, kIcmp = 1, kTcp = 2 };

  /** ### add
   * @param startMs - FLOW_START_MILLISECONDS(ソートキー)
   * @param shape - 行の形(持つ列の組)
   * @param text - s1 + s2 + rx + s3 を連結したもの(各断片の先頭・末尾にカンマは付けない)
   * @param len1 - s1(FLOW_START..ICMP_IPV4_TYPE)の長さ
   * @param len2 - s2(DNS_QUERY_ID..ALT_DST_TO_SRC_SDS)の長さ
   * @param lenRx - rx(ALT_RX_A2..C5)の長さ。TCP 以外は 0
   * @param icmpLast - ALT_ICMP_LAST の値(ICMP 行のみ)
   */
  void add(int64_t startMs, Shape shape, const std::string& text, uint32_t len1, uint32_t len2, uint32_t lenRx,
           int64_t icmpLast);

  size_t rows() const { return recs_.size(); }
  size_t textBytes() const { return arena_.size(); }

  bool write(const std::string& path, std::string& err);

 private:
  struct Rec {
    int64_t startMs;
    uint64_t off;
    int64_t icmpLast;
    uint32_t len1;
    uint32_t len2;
    uint32_t lenRx;
    uint32_t len3;
    uint8_t shape;
  };

  std::vector<Rec> recs_;
  std::vector<char> arena_;
  bool haveFirst_ = false;
  uint8_t firstShape_ = kBase;
  // 先頭行に無い列グループを、最初に現れた順に末尾へ足す(0: ICMP_LAST, 1: RX)
  std::vector<int> tail_;
  bool sawIcmp_ = false;
  bool sawTcp_ = false;
  bool sawNonIcmp_ = false;
};

}  // namespace opennprobe
