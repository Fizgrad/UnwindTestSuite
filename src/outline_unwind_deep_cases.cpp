#include "unwind_outline_api.h"

#include <algorithm>
#include <array>
#include <deque>
#include <dlfcn.h>
#include <map>
#include <memory>
#include <numeric>
#include <optional>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <tuple>
#include <unwind.h>
#include <variant>
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

constexpr int kMaxTraceFrames = 160;
constexpr const char *kLibraryNeedle = "libunwind_outline_cases";

struct DeepMetrics {
  int captures = 0;
  int min_depth = 1000000;
  int shallow_traces = 0;
  int own_library_traces = 0;
  int exceptions_thrown = 0;
  int exceptions_caught = 0;
  int rethrows = 0;
  int destructors = 0;
  int visits = 0;
  int recursion_entries = 0;
  uint64_t checksum = 0;
};

struct TraceState {
  int depth = 0;
  int own_frames = 0;
};

struct DeepError {
  virtual ~DeepError() = default;
  int code = 0;
};

struct RecursiveError : DeepError {};
struct ContainerError : DeepError {};
struct VariantError : DeepError {};
struct NodeError : DeepError {};

static DeepMetrics g_metrics;
static volatile uint64_t g_sink = 0x13198a2e03707344ULL;

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

NOINLINE USED static void captureDeepUnwind(int tag) noexcept {
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
  uint64_t mix = g_sink + static_cast<uint64_t>(tag * 257 + state.depth);
  mix ^= mix << 13;
  mix += static_cast<uint64_t>(state.own_frames * 97);
  g_sink = (g_sink >> 5) ^ mix ^ 0xa4093822299f31d0ULL;
}

NOINLINE USED static void deepMix(int tag) noexcept {
  uint64_t value = g_sink + 0x082efa98ec4e6c89ULL;
  value ^= value >> 11;
  value *= 0x9e3779b185ebca87ULL;
  value += static_cast<uint64_t>(tag * 73 + 5);
  g_sink = (g_sink << 7) ^ (value >> 3) ^ value;
}

#define DEEP_PAYLOAD(TAG)                                                     \
  do {                                                                        \
    deepMix(TAG);                                                             \
    deepMix((TAG) + 17);                                                      \
    g_sink ^= static_cast<uint64_t>((TAG) * 0x45d9f3b);                       \
  } while (0)

#define DEEP_CAPTURE(TAG)                                                     \
  do {                                                                        \
    DEEP_PAYLOAD(TAG);                                                        \
    captureDeepUnwind(TAG);                                                   \
    DEEP_PAYLOAD((TAG) + 31);                                                 \
  } while (0)

struct DeepGuard {
  explicit DeepGuard(int t) noexcept : tag(t) {
    DEEP_PAYLOAD(tag);
  }

  ~DeepGuard() noexcept {
    ++g_metrics.destructors;
    DEEP_CAPTURE(tag + 10000);
  }

  int tag;
};

using VariantValue =
    std::variant<int, uint64_t, std::string, std::vector<int>, std::array<int, 8>>;

NOINLINE USED static VariantValue makeVariantValue(int seed) {
  switch (seed % 5) {
  case 0:
    return seed * 3;
  case 1:
    return static_cast<uint64_t>(seed) * 0x9e3779b1ULL;
  case 2:
    return std::string("variant-") + std::to_string(seed);
  case 3: {
    std::vector<int> values;
    for (int i = 0; i < 10; ++i) {
      values.push_back(seed + i * 3);
    }
    return values;
  }
  default: {
    std::array<int, 8> values{};
    for (int i = 0; i < 8; ++i) {
      values[static_cast<size_t>(i)] = seed ^ (i * 17);
    }
    return values;
  }
  }
}

NOINLINE USED static uint64_t visitVariant(const VariantValue &value, int tag) {
  ++g_metrics.visits;
  DEEP_CAPTURE(tag);
  return std::visit(
      [tag](const auto &entry) -> uint64_t {
        using T = std::decay_t<decltype(entry)>;
        if constexpr (std::is_same<T, int>::value) {
          return static_cast<uint64_t>(entry * 11 + tag);
        } else if constexpr (std::is_same<T, uint64_t>::value) {
          return entry ^ static_cast<uint64_t>(tag * 13);
        } else if constexpr (std::is_same<T, std::string>::value) {
          return static_cast<uint64_t>(entry.size() * 17 + entry[0]);
        } else {
          return std::accumulate(entry.begin(), entry.end(), uint64_t{0}) ^
                 static_cast<uint64_t>(tag);
        }
      },
      value);
}

NOINLINE USED static uint64_t runContainerCase(int seed) {
  DeepGuard guard(seed + 10);
  std::deque<VariantValue> queue;
  std::map<int, uint64_t> ordered;
  for (int i = 0; i < 14; ++i) {
    queue.push_back(makeVariantValue(seed + i));
  }

  uint64_t result = 0;
  int index = 0;
  for (const auto &entry : queue) {
    result ^= visitVariant(entry, seed + index);
    ordered.emplace(seed + index, result + static_cast<uint64_t>(index));
    ++index;
  }

  for (const auto &entry : ordered) {
    DEEP_PAYLOAD(entry.first);
    result += entry.second ^ static_cast<uint64_t>(entry.first * 19);
  }

  if ((seed % 29) == 7) {
    ++g_metrics.exceptions_thrown;
    ContainerError error;
    error.code = seed + 700;
    throw error;
  }
  DEEP_CAPTURE(seed + 100);
  return result;
}

struct NodeBase {
  virtual ~NodeBase() = default;
  virtual uint64_t eval(int seed) = 0;
};

struct Printable {
  virtual ~Printable() = default;
  virtual const char *name() const = 0;
};

#define DEFINE_NODE(ID, OP)                                                   \
  struct Node_##ID final : NodeBase, Printable {                              \
    NOINLINE USED uint64_t eval(int seed) override {                          \
      DeepGuard guard(seed + ID * 41);                                        \
      DEEP_CAPTURE(seed + ID);                                                \
      uint64_t value = runContainerCase(seed + ID * 3);                       \
      if (((seed + ID) % 31) == 11) {                                         \
        ++g_metrics.exceptions_thrown;                                        \
        NodeError error;                                                      \
        error.code = seed + ID * 900 + 11;                                    \
        throw error;                                                          \
      }                                                                       \
      return (value OP static_cast<uint64_t>(seed + ID + 1));                 \
    }                                                                         \
    const char *name() const override { return "Node_" #ID; }                 \
  };

DEFINE_NODE(0, +)
DEFINE_NODE(1, ^)
DEFINE_NODE(2, +)
DEFINE_NODE(3, ^)
DEFINE_NODE(4, +)
DEFINE_NODE(5, ^)
DEFINE_NODE(6, +)
DEFINE_NODE(7, ^)
DEFINE_NODE(8, +)
DEFINE_NODE(9, ^)
DEFINE_NODE(10, +)
DEFINE_NODE(11, ^)

NOINLINE USED static uint64_t runNodeGraph(int seed) {
  Node_0 n0;
  Node_1 n1;
  Node_2 n2;
  Node_3 n3;
  Node_4 n4;
  Node_5 n5;
  Node_6 n6;
  Node_7 n7;
  Node_8 n8;
  Node_9 n9;
  Node_10 n10;
  Node_11 n11;
  NodeBase *nodes[] = {&n0, &n1, &n2, &n3, &n4, &n5,
                       &n6, &n7, &n8, &n9, &n10, &n11};

  uint64_t result = 0;
  for (int i = 0; i < 12; ++i) {
    try {
      result += nodes[i]->eval(seed + i * 5);
    } catch (const ContainerError &error) {
      ++g_metrics.exceptions_caught;
      DEEP_CAPTURE(error.code);
      result ^= static_cast<uint64_t>(error.code) * 23;
    } catch (const NodeError &error) {
      ++g_metrics.exceptions_caught;
      DEEP_CAPTURE(error.code + 1);
      if ((error.code & 1) != 0) {
        ++g_metrics.rethrows;
        throw;
      }
      result += static_cast<uint64_t>(error.code) * 29;
    }
  }
  return result;
}

template <int Depth>
struct DeepRecursor {
  NOINLINE USED static uint64_t run(int seed) {
    ++g_metrics.recursion_entries;
    DeepGuard guard(seed + Depth * 101);
    DEEP_CAPTURE(seed + Depth);
    if ((seed + Depth) % 97 == 13) {
      ++g_metrics.exceptions_thrown;
      RecursiveError error;
      error.code = seed + Depth * 1000;
      throw error;
    }
    return DeepRecursor<Depth - 1>::run(seed + Depth) ^
           static_cast<uint64_t>(seed * 7 + Depth);
  }
};

template <>
struct DeepRecursor<0> {
  NOINLINE USED static uint64_t run(int seed) {
    ++g_metrics.recursion_entries;
    DeepGuard guard(seed);
    DEEP_CAPTURE(seed + 999);
    return g_sink ^ static_cast<uint64_t>(seed * 37 + 1);
  }
};

NOINLINE USED static uint64_t runOptionalTupleCase(int seed) {
  DeepGuard guard(seed + 333);
  std::optional<std::tuple<int, std::string, uint64_t>> maybe;
  if ((seed & 1) == 0) {
    maybe.emplace(seed, std::string("tuple-") + std::to_string(seed),
                  static_cast<uint64_t>(seed) * 0x100000001b3ULL);
  }
  DEEP_CAPTURE(seed + 444);
  if (!maybe.has_value()) {
    return runNodeGraph(seed + 7);
  }

  const auto &[a, b, c] = *maybe;
  uint64_t result = static_cast<uint64_t>(a) + c + b.size();
  result ^= runNodeGraph(seed + static_cast<int>(b.size()));
  return result;
}

NOINLINE USED static uint64_t runDeepIteration(int seed) {
  uint64_t result = 0;
  try {
    result ^= DeepRecursor<36>::run(seed + 1);
  } catch (const RecursiveError &error) {
    ++g_metrics.exceptions_caught;
    DEEP_CAPTURE(error.code);
    result += static_cast<uint64_t>(error.code) * 31;
  }

  try {
    result += runOptionalTupleCase(seed + 3);
  } catch (const DeepError &error) {
    ++g_metrics.exceptions_caught;
    DEEP_CAPTURE(error.code + 2);
    result ^= static_cast<uint64_t>(error.code) * 43;
  }

  try {
    result ^= runContainerCase(seed + 5);
  } catch (const ContainerError &error) {
    ++g_metrics.exceptions_caught;
    DEEP_CAPTURE(error.code + 3);
    result += static_cast<uint64_t>(error.code) * 47;
  }
  return result;
}

static int finishResult(int iterations, uint32_t flags, UnwindSuiteResult *out) {
  int rc = 0;
  const char *why = "deep ok";
  if (g_metrics.captures < iterations * 180) {
    rc = 30;
    why = "deep suite captured too few traces";
  } else if (g_metrics.destructors < iterations * 50) {
    rc = 31;
    why = "deep suite saw too few cleanup destructors";
  } else if (g_metrics.visits < iterations * 40 ||
             g_metrics.recursion_entries < iterations * 20) {
    rc = 32;
    why = "deep suite did not execute enough container/recursion cases";
  } else if (g_metrics.min_depth < 5 || g_metrics.shallow_traces != 0) {
    rc = 33;
    why = "deep suite saw shallow or broken traces";
  } else if ((flags & UNWIND_SUITE_STRICT_DSO_FRAMES) != 0 &&
             g_metrics.own_library_traces == 0) {
    rc = 34;
    why = "deep suite did not observe frames in the active shared object";
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
    out->rethrows = g_metrics.rethrows;
    out->destructors = g_metrics.destructors;
    out->checksum = g_metrics.checksum ^ static_cast<uint64_t>(g_sink);
    snprintf(out->message, sizeof(out->message),
             "%s captures=%d min_depth=%d own_dso_traces=%d thrown=%d "
             "caught=%d rethrows=%d destructors=%d visits=%d recursion=%d "
             "checksum=0x%llx",
             why, out->captures, out->min_depth, out->own_library_traces,
             out->exceptions_thrown, out->exceptions_caught, out->rethrows,
             out->destructors, g_metrics.visits, g_metrics.recursion_entries,
             static_cast<unsigned long long>(out->checksum));
  }

  if ((flags & UNWIND_SUITE_VERBOSE) != 0) {
    fprintf(stderr, "unwind_deep_cases: %s\n",
            out != nullptr ? out->message : why);
  }
  return rc;
}

} // namespace

extern "C" EXPORT int run_unwind_deep_suite(int iterations, uint32_t flags,
                                             UnwindSuiteResult *result) {
  if (iterations <= 0) {
    iterations = 1;
  }

  g_metrics = DeepMetrics{};
  g_sink = 0x13198a2e03707344ULL;
  uint64_t checksum = 0;
  for (int i = 0; i < iterations; ++i) {
    checksum ^= runDeepIteration(i * 101 + 17);
  }
  g_metrics.checksum = checksum;
  return finishResult(iterations, flags, result);
}
