#include "unwind_outline_api.h"

#include <algorithm>
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <unwind.h>
#include <vector>

#if defined(__clang__) || defined(__GNUC__)
#define NOINLINE __attribute__((noinline))
#define USED __attribute__((used))
#define EXPORT __attribute__((visibility("default")))
#else
#define NOINLINE
#define USED
#define EXPORT
#endif

namespace {

constexpr int kMaxTraceFrames = 96;
constexpr const char *kLibraryNeedle = "libunwind_outline_plugin";

struct PluginMetrics {
  int captures = 0;
  int min_depth = 1000000;
  int shallow_traces = 0;
  int own_library_traces = 0;
  int exceptions_thrown = 0;
  int exceptions_caught = 0;
  int destructors = 0;
  uint64_t checksum = 0;
};

struct TraceState {
  int depth = 0;
  int own_frames = 0;
};

struct PluginError {
  int code = 0;
};

static PluginMetrics g_metrics;
static volatile uint64_t g_sink = 0x452821e638d01377ULL;

static bool isOwnLibraryIp(uintptr_t ip) noexcept {
  Dl_info info;
  memset(&info, 0, sizeof(info));
  if (dladdr(reinterpret_cast<void *>(ip), &info) == 0 || info.dli_fname == nullptr) {
    return false;
  }
  return strstr(info.dli_fname, kLibraryNeedle) != nullptr;
}

static _Unwind_Reason_Code traceFrame(_Unwind_Context *context,
                                      void *arg) noexcept {
  TraceState *state = static_cast<TraceState *>(arg);
  uintptr_t ip = static_cast<uintptr_t>(_Unwind_GetIP(context));
  if (ip != 0) {
    ++state->depth;
    if (isOwnLibraryIp(ip)) {
      ++state->own_frames;
    }
  }
  return state->depth >= kMaxTraceFrames ? _URC_END_OF_STACK : _URC_NO_REASON;
}

NOINLINE USED static void capturePluginUnwind(int tag) noexcept {
  TraceState state;
  _Unwind_Backtrace(traceFrame, &state);
  ++g_metrics.captures;
  if (state.depth < g_metrics.min_depth) {
    g_metrics.min_depth = state.depth;
  }
  if (state.depth < 5) {
    ++g_metrics.shallow_traces;
  }
  if (state.own_frames > 0) {
    ++g_metrics.own_library_traces;
  }
  g_sink ^= static_cast<uint64_t>(tag * 167 + state.depth * 19 +
                                  state.own_frames * 23);
}

NOINLINE USED static void pluginMix(int tag) noexcept {
  uint64_t value = g_sink + 0xbe5466cf34e90c6cULL;
  value ^= value << 7;
  value += static_cast<uint64_t>(tag * 101 + 3);
  value *= 0xc2b2ae3d27d4eb4fULL;
  g_sink = (g_sink >> 9) ^ value;
}

#define PLUGIN_CAPTURE(TAG)                                                   \
  do {                                                                        \
    pluginMix(TAG);                                                           \
    capturePluginUnwind(TAG);                                                 \
    pluginMix((TAG) + 5);                                                     \
  } while (0)

struct PluginGuard {
  explicit PluginGuard(int t) noexcept : tag(t) {
    pluginMix(tag);
  }
  ~PluginGuard() noexcept {
    ++g_metrics.destructors;
    PLUGIN_CAPTURE(tag + 2000);
  }
  int tag;
};

struct GlobalUnloadProbe {
  ~GlobalUnloadProbe() noexcept {
    capturePluginUnwind(777777);
  }
};

static GlobalUnloadProbe g_unload_probe;

#define DEFINE_PLUGIN_CASE(ID)                                                \
  NOINLINE USED static uint64_t pluginCase_##ID(int n) {                      \
    PluginGuard guard(n + ID * 13);                                           \
    std::vector<std::string> values;                                          \
    values.reserve(6);                                                        \
    for (int i = 0; i < 6; ++i) {                                             \
      values.push_back(std::string("plugin-") + std::to_string(n + ID + i));  \
    }                                                                         \
    std::rotate(values.begin(), values.begin() + (ID % 6), values.end());     \
    PLUGIN_CAPTURE(n + ID);                                                   \
    uint64_t result = 0;                                                      \
    for (const auto &value : values) {                                        \
      result += static_cast<uint64_t>(value.size() * 11 + value[0]);          \
    }                                                                         \
    if (((n + ID) % 13) == 4) {                                               \
      ++g_metrics.exceptions_thrown;                                          \
      throw PluginError{n + ID * 100 + 4};                                    \
    }                                                                         \
    PLUGIN_CAPTURE(n + ID + 100);                                             \
    return result ^ static_cast<uint64_t>(g_sink);                            \
  }

DEFINE_PLUGIN_CASE(0)
DEFINE_PLUGIN_CASE(1)
DEFINE_PLUGIN_CASE(2)
DEFINE_PLUGIN_CASE(3)
DEFINE_PLUGIN_CASE(4)
DEFINE_PLUGIN_CASE(5)
DEFINE_PLUGIN_CASE(6)
DEFINE_PLUGIN_CASE(7)
DEFINE_PLUGIN_CASE(8)
DEFINE_PLUGIN_CASE(9)
DEFINE_PLUGIN_CASE(10)
DEFINE_PLUGIN_CASE(11)
DEFINE_PLUGIN_CASE(12)
DEFINE_PLUGIN_CASE(13)
DEFINE_PLUGIN_CASE(14)
DEFINE_PLUGIN_CASE(15)
DEFINE_PLUGIN_CASE(16)
DEFINE_PLUGIN_CASE(17)
DEFINE_PLUGIN_CASE(18)
DEFINE_PLUGIN_CASE(19)
DEFINE_PLUGIN_CASE(20)
DEFINE_PLUGIN_CASE(21)
DEFINE_PLUGIN_CASE(22)
DEFINE_PLUGIN_CASE(23)
DEFINE_PLUGIN_CASE(24)
DEFINE_PLUGIN_CASE(25)
DEFINE_PLUGIN_CASE(26)
DEFINE_PLUGIN_CASE(27)
DEFINE_PLUGIN_CASE(28)
DEFINE_PLUGIN_CASE(29)
DEFINE_PLUGIN_CASE(30)
DEFINE_PLUGIN_CASE(31)

using PluginFn = uint64_t (*)(int);

static PluginFn kPluginCases[] = {
    pluginCase_0,  pluginCase_1,  pluginCase_2,  pluginCase_3,
    pluginCase_4,  pluginCase_5,  pluginCase_6,  pluginCase_7,
    pluginCase_8,  pluginCase_9,  pluginCase_10, pluginCase_11,
    pluginCase_12, pluginCase_13, pluginCase_14, pluginCase_15,
    pluginCase_16, pluginCase_17, pluginCase_18, pluginCase_19,
    pluginCase_20, pluginCase_21, pluginCase_22, pluginCase_23,
    pluginCase_24, pluginCase_25, pluginCase_26, pluginCase_27,
    pluginCase_28, pluginCase_29, pluginCase_30, pluginCase_31,
};

static int finishResult(int iterations, uint32_t flags, UnwindSuiteResult *out) {
  int rc = 0;
  const char *why = "plugin ok";
  if (g_metrics.captures < iterations * 96) {
    rc = 40;
    why = "plugin suite captured too few traces";
  } else if (g_metrics.destructors < iterations * 32) {
    rc = 41;
    why = "plugin suite saw too few cleanup destructors";
  } else if (g_metrics.min_depth < 5 || g_metrics.shallow_traces != 0) {
    rc = 42;
    why = "plugin suite saw shallow or broken traces";
  } else if ((flags & UNWIND_SUITE_STRICT_DSO_FRAMES) != 0 &&
             g_metrics.own_library_traces == 0) {
    rc = 43;
    why = "plugin suite did not observe frames in plugin shared object";
  }

  if (out != nullptr) {
    memset(out, 0, sizeof(*out));
    out->version = 1;
    out->flags = flags;
    out->rc = rc;
    out->captures = g_metrics.captures;
    out->min_depth = g_metrics.min_depth;
    out->shallow_traces = g_metrics.shallow_traces;
    out->own_library_traces = g_metrics.own_library_traces;
    out->exceptions_thrown = g_metrics.exceptions_thrown;
    out->exceptions_caught = g_metrics.exceptions_caught;
    out->destructors = g_metrics.destructors;
    out->checksum = g_metrics.checksum ^ static_cast<uint64_t>(g_sink);
    snprintf(out->message, sizeof(out->message),
             "%s captures=%d min_depth=%d own_dso_traces=%d thrown=%d "
             "caught=%d destructors=%d checksum=0x%llx",
             why, out->captures, out->min_depth, out->own_library_traces,
             out->exceptions_thrown, out->exceptions_caught, out->destructors,
             static_cast<unsigned long long>(out->checksum));
  }
  if ((flags & UNWIND_SUITE_VERBOSE) != 0) {
    fprintf(stderr, "unwind_plugin_cases: %s\n",
            out != nullptr ? out->message : why);
  }
  return rc;
}

} // namespace

extern "C" EXPORT int run_unwind_plugin_suite(int iterations, uint32_t flags,
                                               UnwindSuiteResult *result) {
  if (iterations <= 0) {
    iterations = 1;
  }
  g_metrics = PluginMetrics{};
  g_sink = 0x452821e638d01377ULL;
  uint64_t checksum = 0;
  for (int i = 0; i < iterations; ++i) {
    for (int j = 0; j < 32; ++j) {
      try {
        checksum ^= kPluginCases[j](i * 97 + j);
      } catch (const PluginError &error) {
        ++g_metrics.exceptions_caught;
        PLUGIN_CAPTURE(error.code);
        checksum += static_cast<uint64_t>(error.code) * 89;
      }
    }
  }
  g_metrics.checksum = checksum;
  return finishResult(iterations, flags, result);
}
