// SPDX-License-Identifier: GPL-3.0-or-later
// opennprobe: pcap -> NF-v3 CSV
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "FlowBuilder.hpp"
#include "NdpiEngine.hpp"
#include "Packet.hpp"
#include "PcapReader.hpp"
#include "RowStore.hpp"
#include "Rules.hpp"

using namespace opennprobe;

namespace {

struct Options {
  std::vector<std::string> inputs;
  std::string output;
  std::string compat = "official";
  bool l7 = true;
  bool verbose = false;
  bool keepTruncatedTail = false;
  int jobs = 1;
  std::string tmpdir;
  long spillMb = 64;
};

void usage(FILE* fp) {
  std::fprintf(fp,
               "使い方: opennprobe [オプション] <pcap>...\n"
               "  -o PATH            出力 CSV(入力 1 本。既定は標準出力)/出力ディレクトリ(入力が複数)\n"
               "  -j N               複数入力をファイル単位で N 並列に処理する(既定 1)\n"
               "  --no-l7            L7_PROTO を判定しない(nDPI を使わない)\n"
               "  --compat MODE      規則の互換モード: official(既定)\n"
               "  --keep-truncated-tail\n"
               "                     末尾の途中で切れたレコードも読めた部分で使う(既定は libpcap と同じく捨てる)\n"
               "  --spill-mb N       出力行をメモリにためる上限(MB。超えたら一時ファイルへ。0 は無制限。既定 64)\n"
               "  --tmpdir DIR       一時ファイルの置き場(既定 $TMPDIR か /tmp)\n"
               "  -v                 統計を標準エラーに出す\n"
               "  -h, --help         この説明\n");
}

bool parseArgs(int argc, char** argv, Options& o) {
  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    auto need = [&](const char* name) -> const char* {
      if (i + 1 >= argc) {
        std::fprintf(stderr, "%s に値がありません\n", name);
        std::exit(2);
      }
      return argv[++i];
    };
    if (a == "-o") {
      o.output = need("-o");
    } else if (a == "-j") {
      o.jobs = std::atoi(need("-j"));
      if (o.jobs < 1) o.jobs = 1;
    } else if (a == "--no-l7") {
      o.l7 = false;
    } else if (a == "--compat") {
      o.compat = need("--compat");
    } else if (a == "--tmpdir") {
      o.tmpdir = need("--tmpdir");
    } else if (a == "--spill-mb") {
      o.spillMb = std::atol(need("--spill-mb"));
      if (o.spillMb < 0) o.spillMb = 0;
    } else if (a == "--keep-truncated-tail") {
      o.keepTruncatedTail = true;
    } else if (a == "-v") {
      o.verbose = true;
    } else if (a == "-h" || a == "--help") {
      usage(stdout);
      std::exit(0);
    } else if (!a.empty() && a[0] == '-' && a != "-") {
      std::fprintf(stderr, "不明なオプション: %s\n", a.c_str());
      usage(stderr);
      return false;
    } else {
      o.inputs.push_back(a);
    }
  }
  if (o.inputs.empty()) {
    usage(stderr);
    return false;
  }
  return true;
}

std::string baseName(const std::string& p) {
  size_t s = p.find_last_of('/');
  return s == std::string::npos ? p : p.substr(s + 1);
}

// 1 ファイルを変換する。戻り値はプロセスの終了コード
int convertOne(const std::string& in, const std::string& out, const Options& o, const Rules& rules) {
  auto t0 = std::chrono::steady_clock::now();
  PcapReader reader;
  std::string err;
  if (!reader.open(in, err)) {
    std::fprintf(stderr, "%s\n", err.c_str());
    return 1;
  }
  reader.setKeepTruncatedTail(o.keepTruncatedTail);
  if (reader.linkType() != 1) {
    std::fprintf(stderr, "%s: リンク種別 %u は未対応です(Ethernet のみ)\n", in.c_str(), reader.linkType());
    return 1;
  }
  NdpiEngine engine;
  NdpiEngine* l7 = nullptr;
  if (o.l7) {
    if (!engine.init(err)) {
      std::fprintf(stderr, "%s\n", err.c_str());
      return 1;
    }
    l7 = &engine;
    if (o.verbose) std::fprintf(stderr, "ndpi %s\n", engine.revision().c_str());
  }
  std::string tmpdir = o.tmpdir;
  if (tmpdir.empty()) {
    const char* env = std::getenv("TMPDIR");
    tmpdir = (env != nullptr && *env != '\0') ? env : "/tmp";
  }
  RowStore store(tmpdir, static_cast<size_t>(o.spillMb) << 20);
  {
    FlowBuilder builder(rules, l7, store);
    Packet p;
    int64_t ts;
    const uint8_t* data;
    uint32_t caplen;
    while (reader.next(ts, data, caplen)) {
      if (parsePacket(ts, data, caplen, p)) builder.add(p);
    }
    builder.finish();
    if (!reader.stopReason().empty()) std::fprintf(stderr, "%s: %s\n", in.c_str(), reader.stopReason().c_str());
    if (reader.truncatedToSnaplen() > 0) {
      std::fprintf(stderr, "%s: snaplen を超える %llu レコードを snaplen で切り詰めました\n", in.c_str(),
                   static_cast<unsigned long long>(reader.truncatedToSnaplen()));
    }
    if (o.verbose) {
      std::fprintf(stderr, "records %llu ip %llu dropped_len0 %llu active_peak %llu l7_live_peak %llu\n",
                   static_cast<unsigned long long>(reader.records()),
                   static_cast<unsigned long long>(builder.packets()),
                   static_cast<unsigned long long>(builder.dropped()),
                   static_cast<unsigned long long>(builder.activePeak()),
                   static_cast<unsigned long long>(builder.l7LivePeak()));
    }
  }
  if (!store.write(out, err)) {
    std::fprintf(stderr, "%s\n", err.c_str());
    return 1;
  }
  if (o.verbose) {
    double sec = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    std::fprintf(stderr, "flows %zu row_text %zu B runs %zu time %.3f s pps %.0f\n", store.rows(), store.textBytes(),
                 store.runs(), sec,
                 sec > 0 ? static_cast<double>(reader.records()) / sec : 0.0);
  }
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  Options o;
  if (!parseArgs(argc, argv, o)) return 2;
  Rules rules;
  if (!makeRules(o.compat, rules)) {
    std::fprintf(stderr, "未対応の互換モード: %s\n", o.compat.c_str());
    return 2;
  }
  if (o.l7 && !NdpiEngine::available()) {
    std::fprintf(stderr, "nDPI なしでビルドされています(--no-l7 を指定してください)\n");
    return 2;
  }
  if (o.inputs.size() == 1) {
    return convertOne(o.inputs[0], o.output.empty() ? "-" : o.output, o, rules);
  }
  if (o.output.empty()) {
    std::fprintf(stderr, "入力が複数のときは -o に出力ディレクトリを指定してください\n");
    return 2;
  }
  mkdir(o.output.c_str(), 0777);
  // ファイル単位の並列は fork で行う(nDPI のモジュール状態をファイルごとに完全に分けるため)
  int failed = 0;
  size_t next = 0;
  int running = 0;
  while (next < o.inputs.size() || running > 0) {
    while (running < o.jobs && next < o.inputs.size()) {
      const std::string in = o.inputs[next++];
      const std::string out = o.output + "/" + baseName(in) + ".csv";
      pid_t pid = fork();
      if (pid == 0) {
        std::_Exit(convertOne(in, out, o, rules));
      } else if (pid < 0) {
        std::perror("fork");
        ++failed;
      } else {
        ++running;
      }
    }
    int status = 0;
    if (running > 0 && wait(&status) > 0) {
      --running;
      if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) ++failed;
    }
  }
  return failed == 0 ? 0 : 1;
}
