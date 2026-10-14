// SPDX-License-Identifier: GPL-3.0-or-later
#include "NdpiEngine.hpp"

#include <cstdlib>

#ifdef OPENNPROBE_WITH_NDPI
extern "C" {
#include "ndpi_api.h"
}
#endif

namespace opennprobe {

#ifdef OPENNPROBE_WITH_NDPI

bool NdpiEngine::available() { return true; }

NdpiEngine::~NdpiEngine() {
  if (mod_ != nullptr) ndpi_exit_detection_module(mod_);
}

bool NdpiEngine::init(std::string& err) {
  mod_ = ndpi_init_detection_module(nullptr);
  if (mod_ == nullptr) {
    err = "nDPI の初期化に失敗しました";
    return false;
  }
  NDPI_PROTOCOL_BITMASK all;
  NDPI_BITMASK_SET_ALL(all);
  ndpi_set_protocol_detection_bitmask2(mod_, &all);
  ndpi_finalize_initialization(mod_);
  return true;
}

std::string NdpiEngine::revision() const { return ndpi_revision(); }

ndpi_flow_struct* NdpiEngine::newFlow() {
  return static_cast<ndpi_flow_struct*>(std::calloc(1, ndpi_detection_get_sizeof_ndpi_flow_struct()));
}

void NdpiEngine::feed(ndpi_flow_struct* f, const uint8_t* ip, uint16_t len, uint64_t tsMs, uint16_t& app,
                      bool& extraPossible, bool& frozen) {
  ndpi_protocol p = ndpi_detection_process_packet(mod_, f, ip, len, tsMs, nullptr);
  app = p.app_protocol;
  extraPossible = ndpi_extra_dissection_possible(mod_, f) != 0;
  frozen = f->fail_with_unknown != 0;
}

void NdpiEngine::finish(ndpi_flow_struct* f, uint16_t& master, uint16_t& app, uint8_t& guessed) {
  u_int8_t g = 0;
  ndpi_protocol p = ndpi_detection_giveup(mod_, f, &g);
  master = p.master_protocol;
  app = p.app_protocol;
  guessed = g;
  ndpi_free_flow_data(f);
  std::free(f);
}

#else

bool NdpiEngine::available() { return false; }
NdpiEngine::~NdpiEngine() = default;
bool NdpiEngine::init(std::string& err) {
  err = "nDPI なしでビルドされています(--no-l7 を指定してください)";
  return false;
}
std::string NdpiEngine::revision() const { return ""; }
ndpi_flow_struct* NdpiEngine::newFlow() { return nullptr; }
void NdpiEngine::feed(ndpi_flow_struct*, const uint8_t*, uint16_t, uint64_t, uint16_t& app, bool& extraPossible,
                      bool& frozen) {
  app = 0;
  extraPossible = false;
  frozen = true;
}
void NdpiEngine::finish(ndpi_flow_struct*, uint16_t& master, uint16_t& app, uint8_t& guessed) {
  master = app = 0;
  guessed = 0;
}

#endif

}  // namespace opennprobe
