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
 * - official: 公式 NF-CSE-CIC-IDS2018-v3 に合わせた規則(調査用プロトタイプ v2 の既定値)
 */
struct Rules {
  std::string compat = "official";
  int64_t idleSec = 60;  // 無通信の上限(向き別の判定にも使う)
  int64_t lifeSec = 120;  // 開始からの上限
  int64_t termIdleSec = 22;  // RST を見たフローの無通信上限
  bool dirIdle = true;  // 到着パケットと同じ向きの最終時刻で無通信を判定する
  bool dropLen0 = true;  // IPv4 全長 0(TSO)のパケットを捨てる
  bool dnsSplit = true;  // 応答済み DNS フローに別 ID の問い合わせが来たら新フロー
  bool dnsTouch = true;  // 応答済み DNS フローに同じ ID の問い合わせが来たら統計を引き継ぐ
  bool retxSynFin = true;  // 期限判定用の再送判定で SYN/FIN をシーケンス長に含める
  bool termRetxNoUpdate = true;  // RST 後の再送パケットでは期限判定用の最終時刻を進めない
  bool tcpCloseRst = true;  // RST で終了済みにする
};

/** ### makeRules
 * @param compat - 互換モード名
 * @param out - 規則
 * @returns 既知のモードなら true
 */
inline bool makeRules(const std::string& compat, Rules& out) {
  out = Rules();
  out.compat = compat;
  if (compat == "official") return true;
  // nprobe(nProbe 10.4 の素の挙動)は規則の確定待ち
  return false;
}

}  // namespace opennprobe
