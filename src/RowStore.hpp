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
 * - 行は整形済みテキスト(改行込み)で持つ。同じ開始時刻の行はフローを出した順に並べる
 * - たまった量が上限を超えたら整列済みの run として一時ファイルに出し、
 *   最後に全 run を (開始時刻, 出力順) でマージする(外部安定ソート。メモリは上限 + run 数ぶんのバッファ)
 */
class RowStore {
 public:
  /** ### RowStore
   * @param header - CSV の見出し行(改行なし)
   * @param spillDir - 一時ファイルを置くディレクトリ
   * @param spillBytes - メモリにためる行テキストの上限(0 なら一時ファイルを使わない)
   */
  RowStore(std::string header, std::string spillDir = "/tmp", size_t spillBytes = size_t(64) << 20);
  ~RowStore();
  RowStore(const RowStore&) = delete;
  RowStore& operator=(const RowStore&) = delete;

  /** ### add
   * @param startMs - FLOW_START_MILLISECONDS(ソートキー)
   * @param text - 1 行のテキスト(末尾の改行込み)
   * @param n - text の長さ
   */
  void add(int64_t startMs, const char* text, size_t n);

  size_t rows() const { return rows_; }
  size_t textBytes() const { return textBytes_; }
  size_t runs() const { return runs_.size(); }

  bool write(const std::string& path, std::string& err);

 private:
  struct Rec {
    int64_t startMs;
    uint64_t seq;
    uint64_t off;  // arena_ 内の位置(一時ファイルでは未使用)
    uint32_t len;
  };
  struct Run {
    uint64_t off;
    uint64_t len;
  };

  void spill();
  void sortPending(std::vector<uint32_t>& idx) const;

  std::string header_;
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
};

}  // namespace opennprobe
