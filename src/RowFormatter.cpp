// SPDX-License-Identifier: GPL-3.0-or-later
#include "RowFormatter.hpp"

#include <cmath>
#include <cstring>

namespace opennprobe {

namespace {

void putIpv4(TextBuffer& b, const uint8_t* a) {
  for (int i = 0; i < 4; ++i) {
    if (i) b.put('.');
    b.putU(a[i]);
  }
}

}  // namespace

std::string RowFormatter::header(bool withL7) {
  std::string h =
      "FLOW_START_MILLISECONDS,FLOW_END_MILLISECONDS,IPV4_SRC_ADDR,L4_SRC_PORT,IPV4_DST_ADDR,L4_DST_PORT,PROTOCOL,";
  if (withL7) h += "L7_PROTO,";
  h +=
      "IN_BYTES,OUT_BYTES,IN_PKTS,OUT_PKTS,TCP_FLAGS,CLIENT_TCP_FLAGS,SERVER_TCP_FLAGS,FLOW_DURATION_MILLISECONDS,"
      "DURATION_IN,DURATION_OUT,MIN_TTL,MAX_TTL,LONGEST_FLOW_PKT,SHORTEST_FLOW_PKT,MIN_IP_PKT_LEN,MAX_IP_PKT_LEN,"
      "SRC_TO_DST_SECOND_BYTES,DST_TO_SRC_SECOND_BYTES,RETRANSMITTED_IN_PKTS,RETRANSMITTED_IN_BYTES,"
      "RETRANSMITTED_OUT_PKTS,RETRANSMITTED_OUT_BYTES,SRC_TO_DST_AVG_THROUGHPUT,DST_TO_SRC_AVG_THROUGHPUT,"
      "NUM_PKTS_UP_TO_128_BYTES,NUM_PKTS_128_TO_256_BYTES,NUM_PKTS_256_TO_512_BYTES,NUM_PKTS_512_TO_1024_BYTES,"
      "NUM_PKTS_1024_TO_1514_BYTES,TCP_WIN_MAX_IN,TCP_WIN_MAX_OUT,ICMP_TYPE,ICMP_IPV4_TYPE,DNS_QUERY_ID,"
      "DNS_QUERY_TYPE,DNS_TTL_ANSWER,FTP_COMMAND_RET_CODE,SRC_TO_DST_IAT_MIN,SRC_TO_DST_IAT_MAX,SRC_TO_DST_IAT_AVG,"
      "SRC_TO_DST_IAT_STDDEV,DST_TO_SRC_IAT_MIN,DST_TO_SRC_IAT_MAX,DST_TO_SRC_IAT_AVG,DST_TO_SRC_IAT_STDDEV";
  return h;
}

void RowFormatter::putDir(const Flow& f, int i) {
  TextBuffer& b = buf_;
  const IatAcc& t = f.acc.iat[i];
  if (t.n == 0) {
    b.put(",0,0,0,0");
    return;
  }
  // 平均は整数和 / 個数の真の除算(和が 2^53 未満なら double どうしの除算と一致する)を 0 方向に切り捨て
  const double n = static_cast<double>(t.n);
  const int64_t avg = static_cast<int64_t>(static_cast<double>(t.sum) / n);
  // 標準偏差: nDPI の ndpi_data_variance と同じ演算順 (f32(Σx²) - f32(Σx)² / n) / n を各段 float32 で行い、
  // float32 の sqrt を切り捨てる(公式 CSV・nProbe 10.4 の丸め誤差を再現)
  const float n32 = static_cast<float>(n);
  const float s32 = static_cast<float>(static_cast<double>(t.sum));
  const float q32 = static_cast<float>(static_cast<double>(t.sumSq));
  const float sq = s32 * s32;
  const float var32 = (q32 - sq / n32) / n32;
  const int64_t sd = var32 > 0 ? static_cast<int64_t>(std::sqrt(var32)) : 0;
  b.put(',');
  b.putI(t.mn);
  b.put(',');
  b.putI(t.mx);
  b.put(',');
  b.putI(avg);
  b.put(',');
  b.putI(sd);
}

void RowFormatter::putSecondBytes(const Flow& f, int d) {
  if (!rules_.secondBytesRaw) {
    // 公式の後処理(推定): 逆向きバイト / 生の継続 ms。生の継続が 0 ms のときは 100 で割る
    const int64_t raw = floorDiv(f.last - f.first, 1000);
    const int64_t by = static_cast<int64_t>(f.by[1 - d]);
    buf_.putI(raw > 0 ? floorDiv(by, raw) : floorDiv(by, 100));
    return;
  }
  // nProbe の生出力: 絶対秒のスロットごとの IP バイトをカンマで結合(空スロットは空文字列)。
  // スロット数は最終パケットと最初のパケットの秒の差 + 1。その向きのパケットが最初のスロットに無いときは先頭に空要素が 1 つ付く
  const std::vector<uint64_t>& sb = f.secBytes[d];
  const int64_t n = floorDiv(f.last, 1000000) - floorDiv(f.first, 1000000) + 1;
  TextBuffer& t = tmp_;
  t.clear();
  bool firstElem = true;
  if (sb.empty() || sb[0] == 0) firstElem = false;  // 先頭の空要素
  for (int64_t i = 0; i < n; ++i) {
    if (!firstElem) t.put(',');
    firstElem = false;
    if (static_cast<uint64_t>(i) < sb.size() && sb[static_cast<size_t>(i)] != 0) t.putU(sb[static_cast<size_t>(i)] - 1);
  }
  // CSV: カンマを含む値だけ引用符で囲む(pandas の to_csv と同じ)
  const bool quote = std::memchr(t.data(), ',', t.size()) != nullptr;
  if (quote) buf_.put('"');
  buf_.put(t.data(), t.size());
  if (quote) buf_.put('"');
}

void RowFormatter::emit(const Flow& f, RowStore& store) {
  TextBuffer& b = buf_;
  b.clear();
  const int64_t startMs = floorDiv(f.first, 1000);
  b.putI(startMs);
  b.put(',');
  b.putI(floorDiv(f.last, 1000));
  b.put(',');
  if (f.v == 4) {
    putIpv4(b, f.src);
  } else {
    b.put("0.0.0.0");
  }
  b.put(',');
  b.putU(f.sport);
  b.put(',');
  if (f.v == 4) {
    putIpv4(b, f.dst);
  } else {
    b.put("0.0.0.0");
  }
  b.put(',');
  b.putU(f.dport);
  b.put(',');
  b.putU(f.proto);
  b.put(',');
  if (withL7_) {
    if (rules_.l7Raw && f.l7Master != 0 && f.l7App != 0 && f.l7Master != f.l7App) {
      // nProbe の生出力の書式(例: 7.63)
      b.putU(f.l7Master);
      b.put('.');
      b.putU(f.l7App);
    } else {
      // master が 0 でなければ master、0 なら app
      b.putU(f.l7Master != 0 ? f.l7Master : f.l7App);
    }
    b.put(',');
  }
  b.putU(f.by[0]);
  b.put(',');
  b.putU(f.by[1]);
  b.put(',');
  b.putU(f.pk[0]);
  b.put(',');
  b.putU(f.pk[1]);
  b.put(',');
  b.putU(f.flags[0] | f.flags[1]);
  b.put(',');
  b.putU(f.flags[0]);
  b.put(',');
  b.putU(f.flags[1]);
  b.put(',');
  const int64_t raw = floorDiv(f.last - f.first, 1000);
  // 公式の後処理: 継続 0 ms を 1 にする(nProbe 10.4 の生出力は 0 のまま)
  b.putI(rules_.durMin1 && raw < 1 ? 1 : raw);
  b.put(',');
  b.putI(f.hasD[0] ? floorDiv(f.dlast[0] - f.dfirst[0], 1000) : 0);
  b.put(',');
  b.putI(f.hasD[1] ? floorDiv(f.dlast[1] - f.dfirst[1], 1000) : 0);
  b.put(',');
  b.putU(f.acc.hasTtl ? f.acc.ttlMin : 0);
  b.put(',');
  b.putU(f.acc.hasTtl ? f.acc.ttlMax : 0);
  b.put(',');
  b.putU(f.lmax);
  b.put(',');
  b.putU(f.lmin);
  b.put(',');
  b.putU(f.pk[1] > 0 ? f.lmin : 0);
  b.put(',');
  b.putU(f.lmax);
  b.put(',');
  putSecondBytes(f, 0);
  b.put(',');
  putSecondBytes(f, 1);
  b.put(',');
  uint64_t rx[2][2] = {{0, 0}, {0, 0}};
  if (f.proto == 6) f.tcp.counts(rules_, rx);
  b.putU(rx[0][0]);
  b.put(',');
  b.putU(rx[0][1]);
  b.put(',');
  b.putU(rx[1][0]);
  b.put(',');
  b.putU(rx[1][1]);
  b.put(',');
  const int64_t by0 = static_cast<int64_t>(f.by[0]);
  const int64_t by1 = static_cast<int64_t>(f.by[1]);
  // raw + 1 が 0 になるのは時刻が 1 ms 逆行した場合だけ(参照実装は 0 除算で止まる)
  b.putI(raw + 1 != 0 ? floorDiv(by0 * 8000, raw + 1) : 0);
  b.put(',');
  b.putI(raw + 1 != 0 ? floorDiv(by1 * 8000, raw + 1) : 0);
  for (int i = 0; i < 5; ++i) {
    b.put(',');
    b.putU(f.acc.hist[i]);
  }
  b.put(',');
  b.putU(f.win[0]);
  b.put(',');
  b.putU(f.win[1]);
  b.put(',');
  if ((f.proto == 1 || f.proto == 58) && f.hasIcmp) {
    b.putU(static_cast<uint32_t>(f.icmpType) * 256 + f.icmpCode);
    b.put(',');
    b.putU(f.icmpType);
  } else if (f.proto == 6) {
    // nProbe の共用領域: TCP では RETRANSMITTED_IN_BYTES の第 0 バイトと第 2 バイトが ICMP 列に出る
    const uint64_t r = rx[0][1];
    b.putU((r & 0xFF) * 256 + ((r >> 16) & 0xFF));
    b.put(',');
    b.putU(r & 0xFF);
  } else {
    b.put("0,0");
  }
  b.put(',');
  b.putU(f.hasDns ? f.dnsId : 0);
  b.put(',');
  b.putU(f.hasDns ? f.dnsType : 0);
  b.put(',');
  b.putU(f.dnsTtl);
  b.put(",0");
  putDir(f, 0);
  putDir(f, 1);
  b.put('\n');
  store.add(startMs, b.data(), b.size());
}

}  // namespace opennprobe
