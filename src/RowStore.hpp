// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <cstdio>
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
 * - 行は整形済みテキストの断片で持つ。たまった量が上限を超えたら整列済みの run として一時ファイルに出し、
 *   最後に全 run を (開始時刻, 出力順) でマージする(外部安定ソート。メモリは上限 + run 数ぶんのバッファ)
 */
class RowStore {
 public:
  enum Shape : uint8_t { kBase = 0, kIcmp = 1, kTcp = 2 };

  /** ### RowStore
   * @param spillDir - 一時ファイルを置くディレクトリ
   * @param spillBytes - メモリにためる行テキストの上限(0 なら一時ファイルを使わない)
   */
  explicit RowStore(std::string spillDir = "/tmp", size_t spillBytes = size_t(64) << 20);
  ~RowStore();
  RowStore(const RowStore&) = delete;
  RowStore& operator=(const RowStore&) = delete;

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

  size_t rows() const { return rows_; }
  size_t textBytes() const { return textBytes_; }
  size_t runs() const { return runs_.size(); }

  bool write(const std::string& path, std::string& err);

 private:
  struct Rec {
    int64_t startMs;
    uint64_t seq;
    int64_t icmpLast;
    uint32_t len1;
    uint32_t len2;
    uint32_t lenRx;
    uint32_t len3;
    uint8_t shape;
  };
  struct Run {
    uint64_t off;
    uint64_t len;
  };

  void spill();
  void sortPending(std::vector<uint32_t>& idx) const;

  std::string spillDir_;
  size_t spillBytes_;
  int spillFd_ = -1;
  uint64_t spillSize_ = 0;
  std::string spillErr_;
  std::vector<Run> runs_;

  std::vector<Rec> recs_;
  std::vector<char> arena_;
  uint64_t seq_ = 0;
  size_t rows_ = 0;
  size_t textBytes_ = 0;

  bool haveFirst_ = false;
  uint8_t firstShape_ = kBase;
  // 先頭行に無い列グループを、最初に現れた順に末尾へ足す(0: ICMP_LAST, 1: RX)
  std::vector<int> tail_;
  bool sawNonIcmp_ = false;
};

}  // namespace opennprobe
