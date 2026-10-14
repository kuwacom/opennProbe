// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

struct ndpi_detection_module_struct;
struct ndpi_flow_struct;

namespace opennprobe {

/**
 * # NdpiEngine
 * nDPI(固定版)の呼び出し層。フローの区切りは呼び出し側が決める
 *
 * ### 特徴
 * - 1 プロセス(1 入力ファイル)につき 1 つの検出モジュールを持つ(キャッシュ類の状態がファイル内で閉じる)
 * - 既定設定のまま使う(packets_limit_per_flow=32・guess_on_giveup=3)
 */
class NdpiEngine {
 public:
  NdpiEngine() = default;
  ~NdpiEngine();
  NdpiEngine(const NdpiEngine&) = delete;
  NdpiEngine& operator=(const NdpiEngine&) = delete;

  static bool available();

  bool init(std::string& err);
  std::string revision() const;

  ndpi_flow_struct* newFlow();

  /** ### feed
   * IP ヘッダからのバイト列を 1 パケット渡す
   *
   * @param app - 判定中のアプリ(0 なら未判定)
   * @param extraPossible - 判定後の追加解析がまだ可能か
   * @param frozen - nDPI がこのフローの以後のパケットを無視する状態になったか
   */
  void feed(ndpi_flow_struct* f, const uint8_t* ip, uint16_t len, uint64_t tsMs, uint16_t& app,
            bool& extraPossible, bool& frozen);

  /** ### finish
   * giveup で結果を確定してフロー状態を解放する
   */
  void finish(ndpi_flow_struct* f, uint16_t& master, uint16_t& app, uint8_t& guessed);

 private:
  ndpi_detection_module_struct* mod_ = nullptr;
};

}  // namespace opennprobe
