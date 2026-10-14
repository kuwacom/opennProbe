// SPDX-License-Identifier: GPL-3.0-or-later
#include "RowFormatter.hpp"

#include <cmath>
#include <type_traits>
#include <vector>

namespace opennprobe {

namespace {

// 参照実装の (x - mean) ** 2 は libm の pow を呼ぶ。コンパイラが x*x に畳まないよう関数ポインタ経由で呼ぶ
double (*volatile gPow)(double, double) = ::pow;

inline double sq(double x) { return gPow(x, 2.0); }

void putIpv4(TextBuffer& b, const uint8_t* a) {
  for (int i = 0; i < 4; ++i) {
    if (i) b.put('.');
    b.putU(a[i]);
  }
}

const char* contName(const Flow& f) {
  switch (f.cont) {
    case EndKind::kIdle:
      return "idle";
    case EndKind::kTerm:
      return "term";
    case EndKind::kLife:
      return "life";
    default:
      break;
  }
  return nullptr;
}

const char* splitName(SplitKind s) {
  switch (s) {
    case SplitKind::kDirIdle:
      return "diridle";
    case SplitKind::kDnsId:
      return "dnsid";
    case SplitKind::kTouch:
      return "touch";
    default:
      break;
  }
  return "";
}

/**
 * # IstatsResult
 * 参照実装の istats(要素数・最小・最大・平均・母標準偏差)
 */
struct Istats {
  double mean = 0;
  double sd = 0;
  double sqSum = 0;  // Σ(x - mean)^2(標本標準偏差でも同じ値を使う)
};

template <typename T>
Istats istats(const std::vector<T>& v) {
  Istats r;
  if (v.empty()) return r;
  const double n = static_cast<double>(v.size());
  if constexpr (std::is_integral<T>::value) {
    // 整数の和は厳密(Python の int)。2^53 未満なら int/int の真の除算は double どうしの除算と一致する
    __int128 s = 0;
    for (T x : v) s += x;
    r.mean = static_cast<double>(s) / n;
  } else {
    double s = 0.0;
    for (T x : v) s += x;
    r.mean = s / n;
  }
  double q = 0.0;
  for (T x : v) q += sq(static_cast<double>(x) - r.mean);
  r.sqSum = q;
  r.sd = std::sqrt(q / n);
  return r;
}

}  // namespace

void RowFormatter::putDir(const Flow& f, int i) {
  TextBuffer& b = buf_;
  const std::vector<int64_t>& ts = f.acc.ts[i];
  const size_t m = ts.size() > 0 ? ts.size() - 1 : 0;
  if (m == 0) {
    b.put(",0,0,0,0,0,0.000/0.000/0,0/0/0/0,0,0");
    return;
  }
  std::vector<int64_t> a(m);
  std::vector<double> af(m);
  std::vector<int64_t> bms(m);
  for (size_t j = 0; j < m; ++j) {
    int64_t us = ts[j + 1] - ts[j];
    a[j] = floorDiv(us, 1000);
    af[j] = static_cast<double>(us) / 1000.0;
    bms[j] = floorDiv(ts[j + 1], 1000) - floorDiv(ts[j], 1000);
  }
  // 先頭から続く 0 ms の IAT は最小値の初期化に使わない
  int64_t m0 = 0;
  bool started = false;
  int64_t mx = a[0];
  __int128 sum = 0;
  __int128 sumSq = 0;
  for (int64_t x : a) {
    if (!started) {
      if (x > 0) {
        m0 = x;
        started = true;
      }
    } else if (x < m0) {
      m0 = x;
    }
    if (x > mx) mx = x;
    sum += x;
    sumSq += static_cast<__int128>(x) * x;
  }
  Istats ia = istats(a);
  // 公式の丸め誤差を再現: 整数の Σx・Σx² から割り算以降を float32 で行う
  float n32 = static_cast<float>(static_cast<double>(m));
  float mean32 = static_cast<float>(static_cast<double>(sum)) / n32;
  float q32 = static_cast<float>(static_cast<double>(sumSq)) / n32;
  float mm32 = mean32 * mean32;
  float var32 = q32 - mm32;
  int64_t sd32 = var32 > 0 ? static_cast<int64_t>(std::sqrt(var32)) : 0;

  Istats ifl = istats(af);
  int64_t bmn = bms[0];
  int64_t bmx = bms[0];
  for (int64_t x : bms) {
    if (x < bmn) bmn = x;
    if (x > bmx) bmx = x;
  }
  Istats ib = istats(bms);

  b.put(',');
  b.putI(m0);
  b.put(',');
  b.putI(mx);
  b.put(',');
  b.putI(static_cast<int64_t>(ia.mean));
  b.put(',');
  b.putI(sd32);
  b.put(',');
  b.putI(static_cast<int64_t>(ia.sd));
  b.put(',');
  b.putFixed3(ifl.mean);
  b.put('/');
  b.putFixed3(ifl.sd);
  b.put('/');
  b.putU(m);
  b.put(',');
  b.putI(bmn);
  b.put('/');
  b.putI(bmx);
  b.put('/');
  b.putI(static_cast<int64_t>(ib.mean));
  b.put('/');
  b.putI(static_cast<int64_t>(ib.sd));
  b.put(',');
  b.putI(static_cast<int64_t>(ifl.sd));
  b.put(',');
  if (m > 1) {
    b.putI(static_cast<int64_t>(std::sqrt(ia.sqSum / static_cast<double>(m - 1))));
  } else {
    b.put('0');
  }
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
  // L7: master が 0 でなければ master、0 なら app
  b.putU(f.l7Master != 0 ? f.l7Master : f.l7App);
  b.put(',');
  b.putU(f.l7Master);
  b.put('.');
  b.putU(f.l7App);
  b.put(',');
  b.putU(f.l7Guess);
  b.put(',');
  b.putU(f.l7n);
  b.put(',');
  const char* cn = contName(f);
  b.put(cn != nullptr ? cn : splitName(f.split));
  b.put(',');
  b.putU(f.seenSyn ? 1 : 0);
  b.put(',');
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
  const int64_t durUs = f.last - f.first;
  const int64_t raw = floorDiv(durUs, 1000);
  b.putI(durUs);
  b.put(',');
  b.putI(raw);
  b.put(',');
  b.putI(raw > 1 ? raw : 1);
  b.put(',');
  b.putI(f.hasD[0] ? floorDiv(f.dlast[0] - f.dfirst[0], 1000) : 0);
  b.put(',');
  b.putI(f.hasD[1] ? floorDiv(f.dlast[1] - f.dfirst[1], 1000) : 0);
  b.put(',');
  for (int i = 0; i < 2; ++i) {
    if (i) b.put('/');
    if (f.hasD[i]) {
      b.putI(floorDiv(f.dlast[i], 1000) - floorDiv(f.dfirst[i], 1000));
    } else {
      b.put('0');
    }
  }
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
  // 公式の後処理(推定): 逆向きバイト / 生の継続 ms。生の継続が 0 ms のときは 100 で割る
  const int64_t by0 = static_cast<int64_t>(f.by[0]);
  const int64_t by1 = static_cast<int64_t>(f.by[1]);
  b.putI(raw > 0 ? floorDiv(by1, raw) : floorDiv(by1, 100));
  b.put(',');
  b.putI(raw > 0 ? floorDiv(by0, raw) : floorDiv(by0, 100));
  b.put(',');
  uint64_t rx[2][2] = {{0, 0}, {0, 0}};
  if (f.tcp) {
    for (int d = 0; d < 2; ++d) {
      rx[d][0] = f.tcp->cnt_[TcpRetxVariants::kA5][d][0];
      rx[d][1] = f.tcp->cnt_[TcpRetxVariants::kA5][d][1];
    }
  }
  b.putU(rx[0][0]);
  b.put(',');
  b.putU(rx[0][1]);
  b.put(',');
  b.putU(rx[1][0]);
  b.put(',');
  b.putU(rx[1][1]);
  b.put(',');
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
  RowStore::Shape shape = RowStore::kBase;
  int64_t icmpLast = 0;
  if ((f.proto == 1 || f.proto == 58) && f.hasIcmp) {
    shape = RowStore::kIcmp;
    b.putU(static_cast<uint32_t>(f.icmpType) * 256 + f.icmpCode);
    b.put(',');
    b.putU(f.icmpType);
    icmpLast = static_cast<int64_t>(f.icmpLastType) * 256 + f.icmpLastCode;
  } else if (f.proto == 6) {
    // nProbe の共用領域: TCP では RETRANSMITTED_IN_BYTES の第 0 バイトと第 2 バイトが ICMP 列に出る
    uint64_t r = rx[0][1];
    b.putU((r & 0xFF) * 256 + ((r >> 16) & 0xFF));
    b.put(',');
    b.putU(r & 0xFF);
  } else {
    b.put("0,0");
  }
  const uint32_t len1 = static_cast<uint32_t>(b.size());

  b.putU(f.hasDns ? f.dnsId : 0);
  b.put(',');
  b.putU(f.hasDns ? f.dnsType : 0);
  b.put(',');
  b.putU(f.dnsTtl);
  b.put(",0");
  putDir(f, 0);
  putDir(f, 1);
  const uint32_t len2 = static_cast<uint32_t>(b.size()) - len1;

  uint32_t lenRx = 0;
  if (f.proto == 6 && f.tcp) {
    shape = RowStore::kTcp;
    for (int k = 0; k < TcpRetxVariants::kCount; ++k) {
      if (k) b.put(',');
      const auto& c = f.tcp->cnt_[k];
      b.putU(c[0][0]);
      b.put('/');
      b.putU(c[0][1]);
      b.put('/');
      b.putU(c[1][0]);
      b.put('/');
      b.putU(c[1][1]);
    }
    lenRx = static_cast<uint32_t>(b.size()) - len1 - len2;
  }

  static const uint32_t kBoundKey[6] = {128, 256, 512, 1024, 1514, 9999};
  bool firstB = true;
  for (int i = 0; i < 6; ++i) {
    if (f.bound[i] == 0) continue;
    if (!firstB) b.put(';');
    firstB = false;
    b.putU(kBoundKey[i]);
    b.put(':');
    b.putU(f.bound[i]);
  }
  b.put(',');
  b.put(splitName(f.split));
  b.put(',');
  if (f.terminated) b.put("tcp");
  b.put(',');
  b.putU(f.nTouch);
  b.put(',');
  b.putU(f.v);
  store.add(startMs, shape, b.str(), len1, len2, lenRx, icmpLast);
}

}  // namespace opennprobe
