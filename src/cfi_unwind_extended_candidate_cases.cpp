#include "unwind_cfi_api.h"

#include <algorithm>
#include <array>
#include <deque>
#include <dlfcn.h>
#include <memory>
#include <numeric>
#include <optional>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <tuple>
#include <type_traits>
#include <unwind.h>
#include <utility>
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

constexpr int kMaxTraceFrames = 224;
constexpr const char *kLibraryNeedle = "libunwind_cfi_cases";

struct ExtMetrics {
  int captures = 0;
  int min_depth = 1000000;
  int shallow_traces = 0;
  int own_library_traces = 0;
  int exceptions_thrown = 0;
  int exceptions_caught = 0;
  int rethrows = 0;
  int destructors = 0;
  int programs_completed = 0;
  uint64_t checksum = 0;
};

struct TraceState {
  int depth = 0;
  int own_frames = 0;
};

struct ExtError {
  virtual ~ExtError() = default;
  int code = 0;
};

struct MinorExtError : ExtError {};
struct MajorExtError : ExtError {};
struct CallbackExtError : ExtError {};

static ExtMetrics g_metrics;
static volatile uint64_t g_sink = 0xd6e8feb86659fd93ULL;

static bool isOwnLibraryIp(uintptr_t ip) noexcept {
  Dl_info info;
  memset(&info, 0, sizeof(info));
  if (dladdr(reinterpret_cast<void *>(ip), &info) == 0 ||
      info.dli_fname == nullptr) {
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

NOINLINE USED static void extMix(int tag) noexcept {
  uint64_t a = g_sink + 0x9e3779b185ebca87ULL;
  a ^= a >> 23;
  a *= 0xbf58476d1ce4e5b9ULL;
  uint64_t b = a + static_cast<uint64_t>(tag * 193 + 0x7f4a7c15);
  b ^= b << 17;
  b *= 0x94d049bb133111ebULL;
  g_sink = (a << 9) ^ (b >> 11) ^ static_cast<uint64_t>(tag);
}

NOINLINE USED static void captureExtUnwind(int tag) noexcept {
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
  g_metrics.checksum ^= static_cast<uint64_t>(tag + state.depth * 41 +
                                              state.own_frames * 101);
  extMix(tag + state.depth + state.own_frames);
}

static void countThrown() noexcept { ++g_metrics.exceptions_thrown; }
static void countCaught() noexcept { ++g_metrics.exceptions_caught; }
static void countRethrow() noexcept { ++g_metrics.rethrows; }
static void countProgram() noexcept { ++g_metrics.programs_completed; }

#define EXT_PAYLOAD(TAG)                                                      \
  do {                                                                        \
    uint64_t p0 = g_sink + 0x243f6a8885a308d3ULL;                             \
    uint64_t p1 = p0 ^ (p0 >> 19);                                            \
    uint64_t p2 = p1 * 0x9e3779b97f4a7c15ULL;                                \
    uint64_t p3 = p2 + static_cast<uint64_t>((TAG) * 53 + 0x4f1bbcdc);        \
    uint64_t p4 = (p3 << 7) ^ (p2 >> 13);                                     \
    g_sink = p4 + (p1 ^ static_cast<uint64_t>(TAG));                          \
  } while (0)

#define EXT_CAPTURE(TAG)                                                      \
  do {                                                                        \
    EXT_PAYLOAD(TAG);                                                         \
    captureExtUnwind(TAG);                                                    \
    EXT_PAYLOAD((TAG) + 1);                                                   \
  } while (0)

struct ExtGuard {
  explicit ExtGuard(int value) noexcept : tag(value) { EXT_PAYLOAD(tag); }

  ~ExtGuard() noexcept {
    ++g_metrics.destructors;
    EXT_PAYLOAD(tag + 7000);
    captureExtUnwind(tag + 9100);
  }

  int tag;
};

static void throwMinor(int code) {
  countThrown();
  MinorExtError error;
  error.code = code;
  throw error;
}

static void throwMajor(int code) {
  countThrown();
  MajorExtError error;
  error.code = code;
  throw error;
}

static void throwCallback(int code) {
  countThrown();
  CallbackExtError error;
  error.code = code;
  throw error;
}

using ExtCaseFn = uint64_t (*)(int);

#define DEFINE_WIDE_CASE(ID)                                                  \
  NOINLINE USED static uint64_t wideCase_##ID(int seed) {                     \
    ExtGuard guard(seed + (ID) * 17);                                         \
    std::array<uint64_t, 10> regs = {                                         \
        static_cast<uint64_t>(seed + (ID)),                                   \
        static_cast<uint64_t>(seed * 3 + (ID) * 5),                           \
        static_cast<uint64_t>(seed * 7 + (ID) * 11),                          \
        static_cast<uint64_t>(seed * 13 + (ID) * 17),                         \
        static_cast<uint64_t>(seed * 19 + (ID) * 23),                         \
        static_cast<uint64_t>(seed * 29 + (ID) * 31),                         \
        static_cast<uint64_t>(seed * 37 + (ID) * 41),                         \
        static_cast<uint64_t>(seed * 43 + (ID) * 47),                         \
        static_cast<uint64_t>(seed * 53 + (ID) * 59),                         \
        static_cast<uint64_t>(seed * 61 + (ID) * 67),                         \
    };                                                                        \
    for (uint64_t &reg : regs) {                                              \
      reg ^= g_sink + static_cast<uint64_t>((ID) * 97);                       \
      reg = (reg << 5) ^ (reg >> 9);                                          \
      EXT_PAYLOAD(static_cast<int>(reg + (ID)));                              \
    }                                                                         \
    EXT_CAPTURE(seed + (ID) + 30000);                                         \
    if (((seed + (ID)) % 11) == ((ID) % 3)) {                                 \
      throwMinor(seed + (ID) + 3000);                                         \
    }                                                                         \
    return std::accumulate(regs.begin(), regs.end(), uint64_t{0}) ^ g_sink;   \
  }

DEFINE_WIDE_CASE(0)
DEFINE_WIDE_CASE(1)
DEFINE_WIDE_CASE(2)
DEFINE_WIDE_CASE(3)
DEFINE_WIDE_CASE(4)
DEFINE_WIDE_CASE(5)
DEFINE_WIDE_CASE(6)
DEFINE_WIDE_CASE(7)
DEFINE_WIDE_CASE(8)
DEFINE_WIDE_CASE(9)
DEFINE_WIDE_CASE(10)
DEFINE_WIDE_CASE(11)
DEFINE_WIDE_CASE(12)
DEFINE_WIDE_CASE(13)
DEFINE_WIDE_CASE(14)
DEFINE_WIDE_CASE(15)
DEFINE_WIDE_CASE(16)
DEFINE_WIDE_CASE(17)
DEFINE_WIDE_CASE(18)
DEFINE_WIDE_CASE(19)

static ExtCaseFn kWideCases[] = {
    wideCase_0,  wideCase_1,  wideCase_2,  wideCase_3,  wideCase_4,
    wideCase_5,  wideCase_6,  wideCase_7,  wideCase_8,  wideCase_9,
    wideCase_10, wideCase_11, wideCase_12, wideCase_13, wideCase_14,
    wideCase_15, wideCase_16, wideCase_17, wideCase_18, wideCase_19,
};

NOINLINE USED static uint64_t program11WideRegisterPressure(int seed) {
  uint64_t total = 0;
  for (size_t i = 0; i < sizeof(kWideCases) / sizeof(kWideCases[0]); ++i) {
    try {
      total ^= kWideCases[i](seed + static_cast<int>(i * 13));
    } catch (const MinorExtError &error) {
      countCaught();
      EXT_CAPTURE(error.code + 31000);
      total += static_cast<uint64_t>(error.code) * 3;
    }
  }
  countProgram();
  return total;
}

struct MemberCluster {
#define DEFINE_MEMBER_OP(ID)                                                  \
  NOINLINE USED uint64_t op##ID(int seed) {                                   \
    ExtGuard guard(seed + (ID) * 71);                                         \
    EXT_CAPTURE(seed + (ID) + 32000);                                         \
    uint64_t value = g_sink ^ static_cast<uint64_t>(seed * ((ID) + 5));       \
    for (int i = 0; i < 5; ++i) {                                             \
      value += static_cast<uint64_t>((seed + i) * ((ID) + 7));                \
      EXT_PAYLOAD(seed + i + (ID));                                           \
    }                                                                         \
    if (((seed + (ID)) % 13) == 4) {                                          \
      throwMajor(seed + (ID) + 3200);                                         \
    }                                                                         \
    return value ^ g_sink;                                                    \
  }

  DEFINE_MEMBER_OP(0)
  DEFINE_MEMBER_OP(1)
  DEFINE_MEMBER_OP(2)
  DEFINE_MEMBER_OP(3)
  DEFINE_MEMBER_OP(4)
  DEFINE_MEMBER_OP(5)
  DEFINE_MEMBER_OP(6)
  DEFINE_MEMBER_OP(7)
  DEFINE_MEMBER_OP(8)
  DEFINE_MEMBER_OP(9)
  DEFINE_MEMBER_OP(10)
  DEFINE_MEMBER_OP(11)
#undef DEFINE_MEMBER_OP
};

using MemberOp = uint64_t (MemberCluster::*)(int);

static MemberOp kMemberOps[] = {
    &MemberCluster::op0,  &MemberCluster::op1,  &MemberCluster::op2,
    &MemberCluster::op3,  &MemberCluster::op4,  &MemberCluster::op5,
    &MemberCluster::op6,  &MemberCluster::op7,  &MemberCluster::op8,
    &MemberCluster::op9,  &MemberCluster::op10, &MemberCluster::op11,
};

NOINLINE USED static uint64_t program12MemberPointers(int seed) {
  MemberCluster cluster;
  uint64_t total = 0;
  for (size_t i = 0; i < sizeof(kMemberOps) / sizeof(kMemberOps[0]); ++i) {
    try {
      total += (cluster.*kMemberOps[i])(seed + static_cast<int>(i * 17));
    } catch (const MajorExtError &error) {
      countCaught();
      EXT_CAPTURE(error.code + 33000);
      total ^= static_cast<uint64_t>(error.code) * 5;
    }
  }
  countProgram();
  return total;
}

#define DEFINE_SCOPE_CASE(ID)                                                 \
  NOINLINE USED static uint64_t scopeCase_##ID(int seed) {                    \
    ExtGuard outer(seed + (ID) * 79);                                         \
    uint64_t total = 0;                                                       \
    {                                                                         \
      ExtGuard mid(seed + (ID) * 83);                                         \
      {                                                                       \
        ExtGuard inner(seed + (ID) * 89);                                     \
        EXT_CAPTURE(seed + (ID) + 34000);                                     \
        auto nested = [seed]() NOINLINE -> uint64_t {                         \
          ExtGuard lambda_guard(seed + 34100);                                \
          EXT_CAPTURE(seed + 34200);                                          \
          return g_sink ^ static_cast<uint64_t>(seed * 101);                  \
        };                                                                    \
        total ^= nested();                                                    \
        if (((seed + (ID)) & 15) == 5) {                                      \
          throwMajor(seed + (ID) + 3400);                                     \
        }                                                                     \
      }                                                                       \
      EXT_CAPTURE(seed + (ID) + 34300);                                       \
    }                                                                         \
    EXT_CAPTURE(seed + (ID) + 34400);                                         \
    return total + g_sink;                                                    \
  }

DEFINE_SCOPE_CASE(0)
DEFINE_SCOPE_CASE(1)
DEFINE_SCOPE_CASE(2)
DEFINE_SCOPE_CASE(3)
DEFINE_SCOPE_CASE(4)
DEFINE_SCOPE_CASE(5)
DEFINE_SCOPE_CASE(6)
DEFINE_SCOPE_CASE(7)
DEFINE_SCOPE_CASE(8)
DEFINE_SCOPE_CASE(9)
DEFINE_SCOPE_CASE(10)
DEFINE_SCOPE_CASE(11)

static ExtCaseFn kScopeCases[] = {
    scopeCase_0, scopeCase_1, scopeCase_2,  scopeCase_3,
    scopeCase_4, scopeCase_5, scopeCase_6,  scopeCase_7,
    scopeCase_8, scopeCase_9, scopeCase_10, scopeCase_11,
};

NOINLINE USED static uint64_t program13NestedCleanupScopes(int seed) {
  uint64_t total = 0;
  for (size_t i = 0; i < sizeof(kScopeCases) / sizeof(kScopeCases[0]); ++i) {
    try {
      total ^= kScopeCases[i](seed + static_cast<int>(i * 19));
    } catch (const MajorExtError &error) {
      countCaught();
      EXT_CAPTURE(error.code + 35000);
      total += static_cast<uint64_t>(error.code) * 7;
    }
  }
  countProgram();
  return total;
}

template <int N>
NOINLINE USED static uint64_t tupleCase(int seed) {
  ExtGuard guard(seed + N * 97);
  auto values = std::make_tuple(seed + N, seed * 3 + N * 5,
                                static_cast<uint64_t>(seed * 7 + N * 11),
                                seed * 13 + N * 17,
                                static_cast<uint64_t>(seed * 19 + N * 23));
  uint64_t total = std::apply(
      [](const auto &...items) {
        uint64_t local = 0;
        ((local += static_cast<uint64_t>(items)), ...);
        return local;
      },
      values);
  EXT_CAPTURE(seed + N + 36000);
  if (((seed + N) % 17) == 8) {
    throwMinor(seed + N + 3600);
  }
  return total ^ g_sink;
}

static ExtCaseFn kTupleCases[] = {
    tupleCase<0>, tupleCase<1>, tupleCase<2>, tupleCase<3>, tupleCase<4>,
    tupleCase<5>, tupleCase<6>, tupleCase<7>, tupleCase<8>, tupleCase<9>,
};

NOINLINE USED static uint64_t program14TupleApply(int seed) {
  uint64_t total = 0;
  for (size_t i = 0; i < sizeof(kTupleCases) / sizeof(kTupleCases[0]); ++i) {
    try {
      total += kTupleCases[i](seed + static_cast<int>(i * 23));
    } catch (const MinorExtError &error) {
      countCaught();
      EXT_CAPTURE(error.code + 37000);
      total ^= static_cast<uint64_t>(error.code) * 11;
    }
  }
  countProgram();
  return total;
}

template <int N>
NOINLINE USED static uint64_t dequeCase(int seed) {
  ExtGuard guard(seed + N * 103);
  std::deque<uint64_t> deque;
  std::vector<uint64_t> vector;
  for (int i = 0; i < 18; ++i) {
    uint64_t value = static_cast<uint64_t>(seed + i * (N + 3));
    deque.push_back(value ^ g_sink);
    vector.push_back(value + static_cast<uint64_t>(N));
    EXT_PAYLOAD(seed + N + i);
  }
  std::rotate(vector.begin(), vector.begin() + (N % 5 + 1), vector.end());
  EXT_CAPTURE(seed + N + 38000);
  uint64_t total = std::accumulate(vector.begin(), vector.end(), uint64_t{0});
  for (uint64_t value : deque) {
    total ^= value + 0x517cc1b727220a95ULL;
  }
  if (((seed + N) % 19) == 6) {
    throwCallback(seed + N + 3800);
  }
  return total ^ g_sink;
}

static ExtCaseFn kDequeCases[] = {
    dequeCase<0>, dequeCase<1>, dequeCase<2>, dequeCase<3>,
    dequeCase<4>, dequeCase<5>, dequeCase<6>, dequeCase<7>,
};

NOINLINE USED static uint64_t program15DequeVectorChurn(int seed) {
  uint64_t total = 0;
  for (size_t i = 0; i < sizeof(kDequeCases) / sizeof(kDequeCases[0]); ++i) {
    try {
      total ^= kDequeCases[i](seed + static_cast<int>(i * 29));
    } catch (const CallbackExtError &error) {
      countCaught();
      EXT_CAPTURE(error.code + 39000);
      total += static_cast<uint64_t>(error.code) * 13;
    }
  }
  countProgram();
  return total;
}

NOINLINE USED static uint64_t program16StateMachineSwitch(int seed) {
  ExtGuard guard(seed + 40000);
  uint64_t total = 0;
  int state = seed & 7;
  for (int i = 0; i < 56; ++i) {
    switch (state) {
    case 0:
      EXT_CAPTURE(seed + i + 40000);
      total += g_sink ^ 0x101ULL;
      state = (state + 3 + i) & 7;
      break;
    case 1:
      EXT_PAYLOAD(seed + i + 40100);
      total ^= g_sink + 0x202ULL;
      state = (state + 5 + i) & 7;
      break;
    case 2:
      EXT_CAPTURE(seed + i + 40200);
      total += g_sink ^ 0x303ULL;
      state = (state + 1 + i) & 7;
      break;
    case 3:
      EXT_PAYLOAD(seed + i + 40300);
      total ^= g_sink + 0x404ULL;
      state = (state + 6 + i) & 7;
      break;
    case 4:
      EXT_CAPTURE(seed + i + 40400);
      total += g_sink ^ 0x505ULL;
      state = (state + 7 + i) & 7;
      break;
    case 5:
      EXT_PAYLOAD(seed + i + 40500);
      total ^= g_sink + 0x606ULL;
      state = (state + 2 + i) & 7;
      break;
    case 6:
      try {
        if (((seed + i) % 31) == 3) {
          throwMinor(seed + i + 4060);
        }
        EXT_CAPTURE(seed + i + 40600);
      } catch (const MinorExtError &error) {
        countCaught();
        EXT_CAPTURE(error.code + 40600);
        total += static_cast<uint64_t>(error.code) * 17;
      }
      state = (state + 4 + i) & 7;
      break;
    default:
      EXT_CAPTURE(seed + i + 40700);
      total ^= g_sink + 0x707ULL;
      state = (state + i) & 7;
      break;
    }
  }
  countProgram();
  return total;
}

template <int N>
struct ExtRecursor {
  NOINLINE USED static uint64_t run(int seed) {
    ExtGuard guard(seed + N * 109);
    EXT_CAPTURE(seed + N + 41000);
    uint64_t total = g_sink ^ static_cast<uint64_t>(seed + N);
    try {
      total += ExtRecursor<N - 1>::run(seed + N);
    } catch (const MinorExtError &error) {
      countCaught();
      EXT_CAPTURE(error.code + 41100);
      if ((N & 3) == 0) {
        countRethrow();
        throw;
      }
      total ^= static_cast<uint64_t>(error.code) * 19;
    }
    return total;
  }
};

template <>
struct ExtRecursor<0> {
  NOINLINE USED static uint64_t run(int seed) {
    ExtGuard guard(seed + 410);
    EXT_CAPTURE(seed + 41200);
    if ((seed & 7) == 2) {
      throwMinor(seed + 4100);
    }
    return g_sink ^ static_cast<uint64_t>(seed);
  }
};

NOINLINE USED static uint64_t program17CatchLadderRecursion(int seed) {
  try {
    uint64_t total = ExtRecursor<16>::run(seed + 5);
    countProgram();
    return total;
  } catch (const MinorExtError &error) {
    countCaught();
    EXT_CAPTURE(error.code + 41300);
    countProgram();
    return static_cast<uint64_t>(error.code) * 23;
  }
}

template <int N>
NOINLINE USED static uint64_t optionalHeapCase(int seed) {
  ExtGuard guard(seed + N * 113);
  std::optional<int> maybe;
  if (((seed + N) & 1) == 0) {
    maybe = seed + N * 3;
  }
  std::unique_ptr<int[]> buffer(new int[12]);
  for (int i = 0; i < 12; ++i) {
    buffer[i] = seed + i * (N + 1);
    EXT_PAYLOAD(buffer[i] + N);
  }
  EXT_CAPTURE(seed + N + 42000);
  uint64_t total = static_cast<uint64_t>(maybe.value_or(seed));
  for (int i = 0; i < 12; ++i) {
    total += static_cast<uint64_t>(buffer[i]);
  }
  if (((seed + N) % 23) == 10) {
    throwMajor(seed + N + 4200);
  }
  return total ^ g_sink;
}

static ExtCaseFn kOptionalHeapCases[] = {
    optionalHeapCase<0>, optionalHeapCase<1>, optionalHeapCase<2>,
    optionalHeapCase<3>, optionalHeapCase<4>, optionalHeapCase<5>,
    optionalHeapCase<6>, optionalHeapCase<7>,
};

NOINLINE USED static uint64_t program18OptionalHeapPaths(int seed) {
  uint64_t total = 0;
  for (size_t i = 0; i < sizeof(kOptionalHeapCases) / sizeof(kOptionalHeapCases[0]);
       ++i) {
    try {
      total += kOptionalHeapCases[i](seed + static_cast<int>(i * 31));
    } catch (const MajorExtError &error) {
      countCaught();
      EXT_CAPTURE(error.code + 43000);
      total ^= static_cast<uint64_t>(error.code) * 29;
    }
  }
  countProgram();
  return total;
}

struct CallbackContext {
  int seed = 0;
  uint64_t total = 0;
};

using CallbackFn = void (*)(CallbackContext *, int);

#define DEFINE_CALLBACK_CASE(ID)                                              \
  NOINLINE USED static void callbackCase_##ID(CallbackContext *context,       \
                                              int value) {                    \
    ExtGuard guard(context->seed + value + (ID) * 127);                       \
    EXT_CAPTURE(context->seed + value + (ID) + 44000);                        \
    context->total ^= g_sink + static_cast<uint64_t>((value + (ID)) * 31);    \
    if (((context->seed + value + (ID)) % 29) == 12) {                        \
      throwCallback(context->seed + value + (ID) + 4400);                     \
    }                                                                         \
  }

DEFINE_CALLBACK_CASE(0)
DEFINE_CALLBACK_CASE(1)
DEFINE_CALLBACK_CASE(2)
DEFINE_CALLBACK_CASE(3)
DEFINE_CALLBACK_CASE(4)
DEFINE_CALLBACK_CASE(5)
DEFINE_CALLBACK_CASE(6)
DEFINE_CALLBACK_CASE(7)
DEFINE_CALLBACK_CASE(8)
DEFINE_CALLBACK_CASE(9)
DEFINE_CALLBACK_CASE(10)
DEFINE_CALLBACK_CASE(11)

static CallbackFn kCallbacks[] = {
    callbackCase_0, callbackCase_1, callbackCase_2,  callbackCase_3,
    callbackCase_4, callbackCase_5, callbackCase_6,  callbackCase_7,
    callbackCase_8, callbackCase_9, callbackCase_10, callbackCase_11,
};

NOINLINE USED static uint64_t program19CallbackMesh(int seed) {
  CallbackContext context;
  context.seed = seed;
  for (int i = 0; i < 32; ++i) {
    size_t index = static_cast<size_t>((seed + i * 7) % 12);
    try {
      kCallbacks[index](&context, i);
    } catch (const CallbackExtError &error) {
      countCaught();
      EXT_CAPTURE(error.code + 45000);
      context.total += static_cast<uint64_t>(error.code) * 31;
    }
  }
  countProgram();
  return context.total ^ g_sink;
}

#define DEFINE_EPILOGUE_CASE(ID)                                              \
  NOINLINE USED static uint64_t epilogueCase_##ID(int seed) {                 \
    ExtGuard g0(seed + (ID) * 131);                                           \
    uint64_t total = 0;                                                       \
    try {                                                                     \
      ExtGuard g1(seed + (ID) * 137);                                         \
      EXT_CAPTURE(seed + (ID) + 46000);                                       \
      total ^= g_sink + static_cast<uint64_t>(seed * ((ID) + 3));             \
      if (((seed + (ID)) & 15) == 9) {                                        \
        throwMajor(seed + (ID) + 4600);                                       \
      }                                                                       \
      EXT_CAPTURE(seed + (ID) + 46100);                                       \
    } catch (const MajorExtError &error) {                                    \
      countCaught();                                                          \
      EXT_CAPTURE(error.code + 46200);                                        \
      if (((error.code + (ID)) & 7) == 1) {                                   \
        countRethrow();                                                       \
        throw;                                                                \
      }                                                                       \
      total += static_cast<uint64_t>(error.code) * 37;                        \
    }                                                                         \
    EXT_PAYLOAD(seed + (ID) + 46300);                                         \
    EXT_CAPTURE(seed + (ID) + 46400);                                         \
    return total ^ g_sink;                                                    \
  }

DEFINE_EPILOGUE_CASE(0)
DEFINE_EPILOGUE_CASE(1)
DEFINE_EPILOGUE_CASE(2)
DEFINE_EPILOGUE_CASE(3)
DEFINE_EPILOGUE_CASE(4)
DEFINE_EPILOGUE_CASE(5)
DEFINE_EPILOGUE_CASE(6)
DEFINE_EPILOGUE_CASE(7)
DEFINE_EPILOGUE_CASE(8)
DEFINE_EPILOGUE_CASE(9)

static ExtCaseFn kEpilogueCases[] = {
    epilogueCase_0, epilogueCase_1, epilogueCase_2, epilogueCase_3,
    epilogueCase_4, epilogueCase_5, epilogueCase_6, epilogueCase_7,
    epilogueCase_8, epilogueCase_9,
};

NOINLINE USED static uint64_t program20SharedEpilogueCleanup(int seed) {
  uint64_t total = 0;
  for (size_t i = 0; i < sizeof(kEpilogueCases) / sizeof(kEpilogueCases[0]); ++i) {
    try {
      total ^= kEpilogueCases[i](seed + static_cast<int>(i * 37));
    } catch (const MajorExtError &error) {
      countCaught();
      EXT_CAPTURE(error.code + 47000);
      total += static_cast<uint64_t>(error.code) * 41;
    }
  }
  countProgram();
  return total;
}

static void resetMetrics() {
  g_metrics = ExtMetrics{};
  g_sink = 0xd6e8feb86659fd93ULL;
}

static uint64_t runAllPrograms(int seed) {
  uint64_t total = 0;
  total ^= program11WideRegisterPressure(seed + 11);
  total += program12MemberPointers(seed + 12);
  total ^= program13NestedCleanupScopes(seed + 13);
  total += program14TupleApply(seed + 14);
  total ^= program15DequeVectorChurn(seed + 15);
  total += program16StateMachineSwitch(seed + 16);
  total ^= program17CatchLadderRecursion(seed + 17);
  total += program18OptionalHeapPaths(seed + 18);
  total ^= program19CallbackMesh(seed + 19);
  total += program20SharedEpilogueCleanup(seed + 20);
  return total;
}

static int finishResult(int iterations, uint32_t flags, UnwindSuiteResult *out) {
  const int min_programs = iterations * 10;
  const int min_captures = iterations * 520;
  const int min_exceptions = iterations * 10;
  const int min_destructors = iterations * 300;
  int rc = 0;
  const char *why = "cfi_ext ok";

  if (g_metrics.programs_completed < min_programs) {
    rc = 50;
    why = "cfi_ext suite did not complete enough programs";
  } else if (g_metrics.captures < min_captures) {
    rc = 51;
    why = "cfi_ext suite captured too few traces";
  } else if (g_metrics.exceptions_thrown < min_exceptions ||
             g_metrics.exceptions_caught < min_exceptions) {
    rc = 52;
    why = "cfi_ext suite saw too few exception events";
  } else if (g_metrics.destructors < min_destructors) {
    rc = 53;
    why = "cfi_ext suite saw too few cleanup destructors";
  } else if (g_metrics.min_depth < 5 || g_metrics.shallow_traces != 0) {
    rc = 54;
    why = "cfi_ext suite saw shallow or broken traces";
  } else if ((flags & UNWIND_SUITE_STRICT_DSO_FRAMES) != 0 &&
             g_metrics.own_library_traces == 0) {
    rc = 55;
    why = "cfi_ext suite did not observe frames in the active shared object";
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
             "caught=%d rethrows=%d destructors=%d programs=%d "
             "checksum=0x%llx",
             why, out->captures, out->min_depth, out->own_library_traces,
             out->exceptions_thrown, out->exceptions_caught, out->rethrows,
             out->destructors, g_metrics.programs_completed,
             static_cast<unsigned long long>(out->checksum));
  }

  if ((flags & UNWIND_SUITE_VERBOSE) != 0) {
    fprintf(stderr, "unwind_cfi_ext_cases: %s\n",
            out != nullptr ? out->message : why);
  }
  return rc;
}

} // namespace

extern "C" EXPORT int run_unwind_cfi_ext_suite(int iterations, uint32_t flags,
                                                UnwindSuiteResult *result) {
  if (iterations <= 0) {
    iterations = 1;
  }

  resetMetrics();
  uint64_t total = 0;
  const int rounds = iterations + 2;
  for (int round = 0; round < rounds; ++round) {
    try {
      total ^= runAllPrograms(round * 313 + iterations * 19);
    } catch (const ExtError &error) {
      countCaught();
      EXT_CAPTURE(error.code + 48000);
      total += static_cast<uint64_t>(error.code) * 43;
    } catch (...) {
      countCaught();
      EXT_CAPTURE(48999);
      total ^= 0xc3a5c85c97cb3127ULL;
    }
  }

  g_metrics.checksum ^= total ^ static_cast<uint64_t>(g_sink);
  return finishResult(iterations, flags, result);
}

