// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace opennprobe {

/**
 * # PcapReader
 * libpcap 形式(pcapng 以外)のファイルを mmap して 1 レコードずつ返す
 *
 * ### 特徴
 * - libpcap と同じ読み取り停止: caplen > 262144 のレコードで止める(nProbe は libpcap 経由なのでそこで変換が終わる)
 * - caplen がファイルの snaplen を超えるレコードは libpcap と同じく先頭 snaplen バイトだけ使う
 * - 末尾の途中で切れたレコードは libpcap と同じく使わない(setKeepTruncatedTail で調査用プロトタイプと同じ扱いにできる)
 * - us / ns 精度と両エンディアンに対応(ns は us に切り捨て)
 */
class PcapReader {
 public:
  PcapReader() = default;
  ~PcapReader();
  PcapReader(const PcapReader&) = delete;
  PcapReader& operator=(const PcapReader&) = delete;

  /** ### open
   * @param path - pcap ファイル
   * @param err - 失敗時の理由
   * @returns 開けたら true
   */
  bool open(const std::string& path, std::string& err);

  /** ### next
   * 次のレコードを返す。終端か読み取り停止なら false
   */
  bool next(int64_t& tsUs, const uint8_t*& data, uint32_t& caplen);

  // 末尾の途中で切れたレコードを、読めた部分だけで使う(既定は libpcap と同じく使わない)
  void setKeepTruncatedTail(bool v) { keepTruncatedTail_ = v; }

  uint32_t linkType() const { return linkType_; }
  uint64_t records() const { return records_; }
  uint64_t truncatedToSnaplen() const { return truncated_; }
  // 読み取りが途中で止まった理由(正常終了なら空)
  const std::string& stopReason() const { return stopReason_; }

 private:
  uint32_t rd32(const uint8_t* p) const;

  const uint8_t* base_ = nullptr;
  size_t size_ = 0;
  size_t pos_ = 0;
  size_t released_ = 0;
  static constexpr size_t kReleaseChunk = size_t(32) << 20;
  bool swap_ = false;
  bool nano_ = false;
  bool keepTruncatedTail_ = false;
  uint32_t snapshot_ = 0;
  uint32_t linkType_ = 0;
  uint64_t records_ = 0;
  uint64_t truncated_ = 0;
  std::string stopReason_;
};

}  // namespace opennprobe
