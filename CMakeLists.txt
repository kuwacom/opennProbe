# SPDX-License-Identifier: GPL-3.0-or-later
cmake_minimum_required(VERSION 3.16)
project(opennprobe VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

option(OPENNPROBE_WITH_NDPI "nDPI で L7_PROTO を判定する" ON)
set(NDPI_PREFIX "${CMAKE_SOURCE_DIR}/third_party/ndpi" CACHE PATH "scripts/build-ndpi.sh の出力先")

add_executable(opennprobe
  src/main.cpp
  src/Packet.cpp
  src/PcapReader.cpp
  src/FlowBuilder.cpp
  src/RowFormatter.cpp
  src/RowStore.cpp
  src/NdpiEngine.cpp)

# 浮動小数点の列(標準偏差など)を参照実装とビット単位で合わせるため、FMA への融合や -ffast-math 系を使わない
target_compile_options(opennprobe PRIVATE -O2 -Wall -Wextra -ffp-contract=off -fno-fast-math)
target_compile_definitions(opennprobe PRIVATE OPENNPROBE_VERSION="${PROJECT_VERSION}")

if(OPENNPROBE_WITH_NDPI)
  find_library(NDPI_LIB NAMES libndpi.a PATHS "${NDPI_PREFIX}/lib" NO_DEFAULT_PATH)
  if(NOT NDPI_LIB)
    message(FATAL_ERROR "libndpi.a が ${NDPI_PREFIX}/lib にありません。scripts/build-ndpi.sh を先に実行してください")
  endif()
  target_compile_definitions(opennprobe PRIVATE OPENNPROBE_WITH_NDPI)
  target_include_directories(opennprobe SYSTEM PRIVATE "${NDPI_PREFIX}/include/ndpi")
  find_package(Threads REQUIRED)
  target_link_libraries(opennprobe PRIVATE ${NDPI_LIB} m Threads::Threads)
endif()

install(TARGETS opennprobe RUNTIME DESTINATION bin)

# 合成 12 本の回帰テスト(pcap の生成に scapy 入りの Python が要る。無ければ SKIP)
enable_testing()
add_test(NAME synth COMMAND bash "${CMAKE_SOURCE_DIR}/scripts/synth-test.sh")
set_tests_properties(synth PROPERTIES
  ENVIRONMENT "OPENNPROBE_BIN=$<TARGET_FILE:opennprobe>"
  SKIP_RETURN_CODE 77)
