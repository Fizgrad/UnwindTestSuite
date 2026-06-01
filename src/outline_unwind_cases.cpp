#include "unwind_outline_api.h"

#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unwind.h>

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
constexpr const char *kLibraryNeedle = "libunwind_outline_cases";

struct Metrics {
  int captures = 0;
  int min_depth = 1000000;
  int shallow_traces = 0;
  int own_library_traces = 0;
  int exceptions_thrown = 0;
  int exceptions_caught = 0;
  int rethrows = 0;
  int destructors = 0;
  uint64_t checksum = 0;
};

struct TraceState {
  int depth = 0;
  int own_frames = 0;
};

struct BaseError {
  virtual ~BaseError() = default;
  int code;
};

struct LeafError : BaseError {};
struct BranchError : BaseError {};

static Metrics g_metrics;
static volatile uint64_t g_sink = 0x6a09e667f3bcc909ULL;

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

NOINLINE USED static void captureUnwind(int tag) noexcept {
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

  uint64_t mix = g_sink;
  mix ^= static_cast<uint64_t>(tag) * 0x9e3779b185ebca87ULL;
  mix += static_cast<uint64_t>(state.depth * 131 + state.own_frames * 17);
  g_sink = (g_sink << 7) ^ (mix >> 3) ^ 0xbf58476d1ce4e5b9ULL;
}

#define OUTLINE_PURE_PAYLOAD(TAG)                                             \
  do {                                                                        \
    uint64_t a = g_sink + 0x9e3779b97f4a7c15ULL;                              \
    a ^= a >> 17;                                                             \
    a *= 0xbf58476d1ce4e5b9ULL;                                               \
    uint64_t b = a + static_cast<uint64_t>((TAG) + 0x1234);                   \
    b ^= b << 11;                                                             \
    b += 0x94d049bb133111ebULL;                                               \
    g_sink = (g_sink + a) ^ (b >> 7) ^ (b << 3);                              \
  } while (0)

#define OUTLINE_CAPTURE_PAYLOAD(TAG)                                          \
  do {                                                                        \
    OUTLINE_PURE_PAYLOAD(TAG);                                                \
    captureUnwind(TAG);                                                       \
    OUTLINE_PURE_PAYLOAD(TAG);                                                \
  } while (0)

struct FrameGuard {
  explicit FrameGuard(int value) noexcept : tag(value) {
    OUTLINE_PURE_PAYLOAD(tag);
  }

  ~FrameGuard() noexcept {
    ++g_metrics.destructors;
    OUTLINE_PURE_PAYLOAD(tag);
    captureUnwind(tag + 7000);
  }

  int tag;
};

#define DEFINE_OUTLINE_CASE(ID)                                               \
  NOINLINE USED static uint64_t repeated_leaf_##ID(int n) {                   \
    FrameGuard guard(n + 11);                                                 \
    OUTLINE_CAPTURE_PAYLOAD(n);                                               \
    OUTLINE_PURE_PAYLOAD(n + 1);                                              \
    if ((n & 31) == 7) {                                                       \
      ++g_metrics.exceptions_thrown;                                          \
      LeafError error;                                                        \
      error.code = n + 1000;                                                  \
      throw error;                                                            \
    }                                                                         \
    if ((n & 63) == 11) {                                                      \
      ++g_metrics.exceptions_thrown;                                          \
      BranchError error;                                                      \
      error.code = n + 2000;                                                  \
      throw error;                                                            \
    }                                                                         \
    OUTLINE_CAPTURE_PAYLOAD(n + 2);                                           \
    return g_sink ^ static_cast<uint64_t>(n * 17 + 5);                        \
  }                                                                           \
                                                                              \
  NOINLINE USED static uint64_t repeated_mid_##ID(int n) {                    \
    FrameGuard guard(n + 23);                                                 \
    uint64_t result = 0;                                                       \
    try {                                                                     \
      OUTLINE_CAPTURE_PAYLOAD(n + 3);                                         \
      result ^= repeated_leaf_##ID(n + 1);                                    \
      OUTLINE_CAPTURE_PAYLOAD(n + 4);                                         \
    } catch (const LeafError &error) {                                        \
      ++g_metrics.exceptions_caught;                                          \
      OUTLINE_CAPTURE_PAYLOAD(error.code);                                    \
      if ((error.code & 2) != 0) {                                             \
        ++g_metrics.rethrows;                                                 \
        throw;                                                                \
      }                                                                       \
      result += static_cast<uint64_t>(error.code) * 13;                       \
    }                                                                         \
    OUTLINE_PURE_PAYLOAD(n + 5);                                              \
    return result + (g_sink ^ static_cast<uint64_t>(n * 19 + 7));             \
  }                                                                           \
                                                                              \
  NOINLINE USED static uint64_t repeated_root_##ID(int n) {                   \
    FrameGuard guard(n + 37);                                                 \
    uint64_t result = 0;                                                       \
    try {                                                                     \
      OUTLINE_CAPTURE_PAYLOAD(n + 6);                                         \
      result += repeated_mid_##ID(n + 2);                                     \
      OUTLINE_CAPTURE_PAYLOAD(n + 7);                                         \
    } catch (const BranchError &error) {                                      \
      ++g_metrics.exceptions_caught;                                          \
      OUTLINE_CAPTURE_PAYLOAD(error.code);                                    \
      result ^= static_cast<uint64_t>(error.code) * 31;                       \
    } catch (const BaseError &error) {                                        \
      ++g_metrics.exceptions_caught;                                          \
      OUTLINE_CAPTURE_PAYLOAD(error.code + 1);                                \
      result += static_cast<uint64_t>(error.code) * 43;                       \
    }                                                                         \
    OUTLINE_PURE_PAYLOAD(n + 8);                                              \
    return result ^ static_cast<uint64_t>(n * 29 + 3);                        \
  }

DEFINE_OUTLINE_CASE(00)
DEFINE_OUTLINE_CASE(01)
DEFINE_OUTLINE_CASE(02)
DEFINE_OUTLINE_CASE(03)
DEFINE_OUTLINE_CASE(04)
DEFINE_OUTLINE_CASE(05)
DEFINE_OUTLINE_CASE(06)
DEFINE_OUTLINE_CASE(07)
DEFINE_OUTLINE_CASE(08)
DEFINE_OUTLINE_CASE(09)
DEFINE_OUTLINE_CASE(10)
DEFINE_OUTLINE_CASE(11)
DEFINE_OUTLINE_CASE(12)
DEFINE_OUTLINE_CASE(13)
DEFINE_OUTLINE_CASE(14)
DEFINE_OUTLINE_CASE(15)
DEFINE_OUTLINE_CASE(16)
DEFINE_OUTLINE_CASE(17)
DEFINE_OUTLINE_CASE(18)
DEFINE_OUTLINE_CASE(19)
DEFINE_OUTLINE_CASE(20)
DEFINE_OUTLINE_CASE(21)
DEFINE_OUTLINE_CASE(22)
DEFINE_OUTLINE_CASE(23)
DEFINE_OUTLINE_CASE(24)
DEFINE_OUTLINE_CASE(25)
DEFINE_OUTLINE_CASE(26)
DEFINE_OUTLINE_CASE(27)
DEFINE_OUTLINE_CASE(28)
DEFINE_OUTLINE_CASE(29)
DEFINE_OUTLINE_CASE(30)
DEFINE_OUTLINE_CASE(31)
DEFINE_OUTLINE_CASE(32)
DEFINE_OUTLINE_CASE(33)
DEFINE_OUTLINE_CASE(34)
DEFINE_OUTLINE_CASE(35)
DEFINE_OUTLINE_CASE(36)
DEFINE_OUTLINE_CASE(37)
DEFINE_OUTLINE_CASE(38)
DEFINE_OUTLINE_CASE(39)
DEFINE_OUTLINE_CASE(40)
DEFINE_OUTLINE_CASE(41)
DEFINE_OUTLINE_CASE(42)
DEFINE_OUTLINE_CASE(43)
DEFINE_OUTLINE_CASE(44)
DEFINE_OUTLINE_CASE(45)
DEFINE_OUTLINE_CASE(46)
DEFINE_OUTLINE_CASE(47)

using RootFn = uint64_t (*)(int);

static RootFn kRoots[] = {
    repeated_root_00, repeated_root_01, repeated_root_02, repeated_root_03,
    repeated_root_04, repeated_root_05, repeated_root_06, repeated_root_07,
    repeated_root_08, repeated_root_09, repeated_root_10, repeated_root_11,
    repeated_root_12, repeated_root_13, repeated_root_14, repeated_root_15,
    repeated_root_16, repeated_root_17, repeated_root_18, repeated_root_19,
    repeated_root_20, repeated_root_21, repeated_root_22, repeated_root_23,
    repeated_root_24, repeated_root_25, repeated_root_26, repeated_root_27,
    repeated_root_28, repeated_root_29, repeated_root_30, repeated_root_31,
    repeated_root_32, repeated_root_33, repeated_root_34, repeated_root_35,
    repeated_root_36, repeated_root_37, repeated_root_38, repeated_root_39,
    repeated_root_40, repeated_root_41, repeated_root_42, repeated_root_43,
    repeated_root_44, repeated_root_45, repeated_root_46, repeated_root_47,
};

NOINLINE USED static uint64_t rethrowLeaf(int n) {
  FrameGuard guard(n + 101);
  OUTLINE_CAPTURE_PAYLOAD(n + 102);
  ++g_metrics.exceptions_thrown;
  if ((n & 1) == 0) {
    LeafError error;
    error.code = n + 3000;
    throw error;
  }
  BranchError error;
  error.code = n + 4000;
  throw error;
}

NOINLINE USED static uint64_t rethrowBridge2(int n) {
  FrameGuard guard(n + 201);
  try {
    OUTLINE_CAPTURE_PAYLOAD(n + 202);
    return rethrowLeaf(n + 1);
  } catch (const LeafError &error) {
    ++g_metrics.exceptions_caught;
    OUTLINE_CAPTURE_PAYLOAD(error.code);
    ++g_metrics.rethrows;
    throw;
  }
}

NOINLINE USED static uint64_t rethrowBridge1(int n) {
  FrameGuard guard(n + 301);
  try {
    OUTLINE_CAPTURE_PAYLOAD(n + 302);
    return rethrowBridge2(n + 2);
  } catch (const BranchError &error) {
    ++g_metrics.exceptions_caught;
    OUTLINE_CAPTURE_PAYLOAD(error.code);
    return static_cast<uint64_t>(error.code) ^ g_sink;
  } catch (const BaseError &error) {
    ++g_metrics.exceptions_caught;
    OUTLINE_CAPTURE_PAYLOAD(error.code + 1);
    return static_cast<uint64_t>(error.code) + g_sink;
  }
}

NOINLINE USED static uint64_t dispatchRoots(int iterations) {
  uint64_t result = 0;
  const int root_count = static_cast<int>(sizeof(kRoots) / sizeof(kRoots[0]));
  for (int iter = 0; iter < iterations; ++iter) {
    for (int i = 0; i < root_count; ++i) {
      const int value = iter * 97 + i * 3 + 1;
      try {
        result ^= kRoots[i](value);
      } catch (const BaseError &error) {
        ++g_metrics.exceptions_caught;
        OUTLINE_CAPTURE_PAYLOAD(error.code + i);
        result += static_cast<uint64_t>(error.code) * 59;
      }
    }
  }
  return result;
}

NOINLINE USED static uint64_t runRethrowTower(int iterations) {
  uint64_t result = 0;
  for (int i = 0; i < iterations * 16; ++i) {
    result += rethrowBridge1(i + 5);
  }
  return result;
}

static void resetMetrics() {
  g_metrics = Metrics{};
  g_sink = 0x6a09e667f3bcc909ULL;
}

static int finishResult(int iterations, uint32_t flags, UnwindSuiteResult *out) {
  const int min_captures = iterations * 48 * 4;
  const int min_exceptions = iterations * 16;
  const int min_destructors = iterations * 96;
  int rc = 0;
  const char *why = "ok";

  if (g_metrics.captures < min_captures) {
    rc = 2;
    why = "too few _Unwind_Backtrace captures";
  } else if (g_metrics.exceptions_thrown < min_exceptions ||
             g_metrics.exceptions_caught < min_exceptions) {
    rc = 3;
    why = "too few C++ exception unwind events";
  } else if (g_metrics.destructors < min_destructors) {
    rc = 4;
    why = "too few cleanup destructors ran during unwind";
  } else if (g_metrics.min_depth < 5 || g_metrics.shallow_traces != 0) {
    rc = 5;
    why = "shallow or broken stack traces";
  } else if ((flags & UNWIND_SUITE_STRICT_DSO_FRAMES) != 0 &&
             g_metrics.own_library_traces == 0) {
    rc = 6;
    why = "dladdr did not observe frames in the active shared object";
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
             "caught=%d rethrows=%d destructors=%d checksum=0x%llx",
             why, out->captures, out->min_depth, out->own_library_traces,
             out->exceptions_thrown, out->exceptions_caught, out->rethrows,
             out->destructors,
             static_cast<unsigned long long>(out->checksum));
  }

  if ((flags & UNWIND_SUITE_VERBOSE) != 0) {
    fprintf(stderr, "unwind_outline_cases: %s\n",
            out != nullptr ? out->message : why);
  }
  return rc;
}

} // namespace

extern "C" EXPORT int run_unwind_outline_suite(int iterations, uint32_t flags,
                                                UnwindSuiteResult *result) {
  if (iterations <= 0) {
    iterations = 1;
  }

  resetMetrics();
  uint64_t result_mix = 0;
  try {
    result_mix ^= dispatchRoots(iterations);
    result_mix += runRethrowTower(iterations);
  } catch (const BaseError &error) {
    ++g_metrics.exceptions_caught;
    OUTLINE_CAPTURE_PAYLOAD(error.code + 9000);
    result_mix ^= static_cast<uint64_t>(error.code) * 0x45d9f3bULL;
  } catch (...) {
    ++g_metrics.exceptions_caught;
    OUTLINE_CAPTURE_PAYLOAD(9999);
    result_mix ^= 0xfeedfacecafebeefULL;
  }

  g_metrics.checksum = result_mix ^ static_cast<uint64_t>(g_sink);
  return finishResult(iterations, flags, result);
}
