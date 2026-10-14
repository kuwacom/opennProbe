// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace opennprobe {

/**
 * # Packet
 * フロー化に必要なパケット情報(Ethernet フレームから取り出した値)
 *
 * ### 特徴
 * - ペイロードはコピーせず pcap のバッファを指す(次のパケットを読むまで有効)
 * - アドレスは IPv4 なら先頭 4 バイトだけ使い、残りは 0
 */
struct Packet {
  int64_t tsUs = 0;
  const uint8_t* ipb = nullptr;  // IP ヘッダ以降(nDPI に渡す。IP 全長と caplen の短い方まで)
  const uint8_t* payload = nullptr;  // L4 ペイロード先頭(TCP 64・UDP 512 バイトまで)
  uint32_t ipbLen = 0;
  uint32_t payloadLen = 0;
  uint32_t ipLen = 0;  // IPv4 は全長、IPv6 はペイロード長 + 40
  uint32_t caplen = 0;
  int64_t plen = 0;  // L4 ペイロード長(ヘッダの値から計算)
  uint32_t seq = 0;
  uint16_t sport = 0;
  uint16_t dport = 0;
  uint16_t win = 0;
  uint16_t fragOff = 0;
  uint8_t v = 0;  // 4 / 6
  uint8_t proto = 0;
  uint8_t ttl = 0;
  uint8_t flags = 0;  // TCP フラグ
  uint8_t icmpType = 0;
  uint8_t icmpCode = 0;
  uint8_t src[16] = {};
  uint8_t dst[16] = {};
};

/** ### parsePacket
 * Ethernet フレームを解析する。IPv4/IPv6 以外と短すぎるフレームは false
 *
 * @param tsUs - 時刻(us)
 * @param d - フレーム先頭
 * @param len - caplen
 * @param p - 出力
 * @returns フロー化の対象なら true
 */
bool parsePacket(int64_t tsUs, const uint8_t* d, uint32_t len, Packet& p);

}  // namespace opennprobe
