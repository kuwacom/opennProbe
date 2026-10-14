// SPDX-License-Identifier: GPL-3.0-or-later
#include "Packet.hpp"

#include <cstring>

namespace opennprobe {

namespace {

inline uint16_t be16(const uint8_t* p) { return static_cast<uint16_t>((p[0] << 8) | p[1]); }
inline uint32_t be32(const uint8_t* p) {
  return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
         (static_cast<uint32_t>(p[2]) << 8) | p[3];
}

// Python のスライス d[start:start+n] と同じく、範囲外は空・末尾で打ち切る
inline void slice(const uint8_t* d, int64_t len, int64_t start, int64_t n, const uint8_t*& out,
                  uint32_t& outLen) {
  if (start >= len || n <= 0) {
    out = d + (start < len ? start : len);
    outLen = 0;
    return;
  }
  int64_t end = start + n;
  if (end > len) end = len;
  out = d + start;
  outLen = static_cast<uint32_t>(end - start);
}

}  // namespace

bool parsePacket(int64_t tsUs, const uint8_t* d, uint32_t caplen, Packet& p) {
  const int64_t len = caplen;
  if (len < 14) return false;
  int64_t off = 12;
  uint16_t et = be16(d + off);
  off += 2;
  while (et == 0x8100 || et == 0x88A8) {
    // 参照実装はここで範囲外読みの例外になる。読めないフレームは捨てる
    if (off + 4 > len) return false;
    et = be16(d + off + 2);
    off += 4;
  }

  p = Packet();
  p.tsUs = tsUs;
  p.caplen = caplen;
  int64_t l4off;
  int64_t l4end;
  uint8_t proto;
  if (et == 0x0800) {
    if (len < off + 20) return false;
    const uint8_t* ip = d + off;
    int64_t ihl = (ip[0] & 0xF) * 4;
    uint16_t tot = be16(ip + 2);
    uint16_t fo = be16(ip + 6);
    p.ttl = ip[8];
    proto = ip[9];
    std::memcpy(p.src, ip + 12, 4);
    std::memcpy(p.dst, ip + 16, 4);
    p.fragOff = fo & 0x1FFF;
    l4off = off + ihl;
    p.ipLen = tot;
    p.v = 4;
    l4end = off + tot;
  } else if (et == 0x86DD) {
    if (len < off + 40) return false;
    const uint8_t* ip = d + off;
    uint16_t plen6 = be16(ip + 4);
    proto = ip[6];
    p.ttl = ip[7];
    std::memcpy(p.src, ip + 8, 16);
    std::memcpy(p.dst, ip + 24, 16);
    l4off = off + 40;
    // 拡張ヘッダ(hop-by-hop・routing・destination)を簡易に飛ばす
    while ((proto == 0 || proto == 43 || proto == 60) && len >= l4off + 2) {
      proto = d[l4off];
      l4off += (static_cast<int64_t>(d[l4off + 1]) + 1) * 8;
    }
    p.ipLen = static_cast<uint32_t>(plen6) + 40;
    p.v = 6;
    l4end = off + 40 + plen6;
  } else {
    return false;
  }
  p.proto = proto;

  if (p.fragOff == 0) {
    if (proto == 6 && len >= l4off + 20) {
      const uint8_t* t = d + l4off;
      p.sport = be16(t);
      p.dport = be16(t + 2);
      p.seq = be32(t + 4);
      int64_t thl = (t[12] >> 4) * 4;
      p.flags = t[13];
      p.win = be16(t + 14);
      int64_t pl = l4end - (l4off + thl);
      p.plen = pl > 0 ? pl : 0;
      slice(d, len, l4off + thl, 64, p.payload, p.payloadLen);
    } else if (proto == 17 && len >= l4off + 8) {
      const uint8_t* u = d + l4off;
      p.sport = be16(u);
      p.dport = be16(u + 2);
      int64_t ulen = be16(u + 4);
      p.plen = ulen - 8 > 0 ? ulen - 8 : 0;
      slice(d, len, l4off + 8, 512, p.payload, p.payloadLen);
    } else if ((proto == 1 || proto == 58) && len >= l4off + 2) {
      p.icmpType = d[l4off];
      p.icmpCode = d[l4off + 1];
    }
  }
  if (p.ipLen > 0) {
    slice(d, len, off, p.ipLen, p.ipb, p.ipbLen);
  } else {
    slice(d, len, off, len, p.ipb, p.ipbLen);
  }
  return true;
}

}  // namespace opennprobe
