// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace opennprobe {

/**
 * # Rules
 * フロー区切りと列計算の規則(互換モードごとに値を変える)
 *
 * ### 特徴
 * - 規則の差し替えはここの値と、値を読む FlowBuilder / RowFormatter の分岐だけで済むようにする
 * - official: 公式 NF-CSE-CIC-IDS2018-v3 の CSV に合わせた規則(公式の後処理込み)
 * - nprobe: nProbe 10.4 の生出力に合わせた規則(後処理なし)
 */
struct Rules {
  // RETRANSMITTED_* の数え方
  enum class Retx : uint8_t {
    kHybrid,  // IN は bin、OUT は A5(公式 12 本で向き別に一致が高い方)
    kBin,  // IN/OUT とも bin
  };
  // bin で「既に送った範囲より前」のパケットを再送とみなす条件
  enum class BinOld : uint8_t {
    kPayload,  // ペイロードがあれば再送
    kKeepAlive,  // seq が期待 seq - 1 でペイロード 1 バイト以下(キープアライブ型)のときだけ再送
  };

  std::string compat = "official";
  int64_t idleSec = 60;  // 無通信の上限(向き別の判定にも使う)
  int64_t lifeSec = 120;  // 開始からの上限
  int64_t termIdleSec = 22;  // RST を見たフローの無通信上限(最終の非再送パケットから)
  // RST を見たフローの後続パケットによる期限(us。0 は使わない)。最終パケットからこれだけ空いた後に
  // 別のパケットが届いた(prev)か、自身が再送でない(self)なら切る
  int64_t rstIdleUs = 0;
  bool dirIdle = true;  // 到着パケットと同じ向きの最終時刻で無通信を判定する
  bool dropLen0 = true;  // IPv4 全長 0(TSO)のパケットを捨てる
  bool dnsSplit = true;  // 応答済み DNS フローに別 ID の問い合わせが来たら新フロー
  bool dnsTouch = true;  // 応答済み DNS フローに同じ ID の問い合わせが来たら統計を引き継ぐ
  bool retxSynFin = true;  // 期限判定用の再送判定で SYN/FIN をシーケンス長に含める
  bool termRetxNoUpdate = true;  // RST 後の再送パケットでは期限判定用の最終時刻を進めない
  bool tcpCloseRst = true;  // RST で終了済みにする
  Retx retx = Retx::kHybrid;
  BinOld binOld = BinOld::kPayload;
  bool durMin1 = true;  // FLOW_DURATION_MILLISECONDS の 0 を 1 にする(公式の後処理)
  bool secondBytesRaw = false;  // SECOND_BYTES を絶対秒スロットのバイト列で出す(nProbe の生出力)
  bool l7Raw = false;  // L7_PROTO を "master.app" で出す(nProbe の生出力)
};

/** ### makeRules
 * @param compat - 互換モード名(official / nprobe)
 * @param out - 規則
 * @returns 既知のモードなら true
 */
inline bool makeRules(const std::string& compat, Rules& out) {
  out = Rules();
  out.compat = compat;
  if (compat == "official") return true;
  if (compat == "nprobe") {
    // RST 後は最終時刻からの期限ではなく、15 秒空いた後のパケット到着で切る(nProbe 10.4 の参照と合成 S10 で確認)
    out.termIdleSec = int64_t(1000000000);
    out.rstIdleUs = int64_t(15) * 1000000;
    out.retx = Rules::Retx::kBin;
    out.binOld = Rules::BinOld::kKeepAlive;
    out.durMin1 = false;
    out.secondBytesRaw = true;
    out.l7Raw = true;
    return true;
  }
  return false;
}

}  // namespace opennprobe
