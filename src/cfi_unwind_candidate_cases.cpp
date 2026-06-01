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

constexpr int kMaxTraceFrames = 192;
constexpr const char *kLibraryNeedle = "libunwind_cfi_cases";

struct CfiMetrics {
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

struct CfiError {
  virtual ~CfiError() = default;
  int code = 0;
};

struct SoftCfiError : CfiError {};
struct HardCfiError : CfiError {};
struct TableCfiError : CfiError {};

static CfiMetrics g_metrics;
static volatile uint64_t g_sink = 0x9e3779b97f4a7c15ULL;

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

NOINLINE USED static void mixCfi(int tag) noexcept {
  uint64_t a = g_sink + 0xbf58476d1ce4e5b9ULL;
  a ^= a >> 27;
  a *= 0x94d049bb133111ebULL;
  uint64_t b = a + static_cast<uint64_t>(tag * 131 + 0x51ed2705);
  b ^= b << 13;
  b += 0x2545f4914f6cdd1dULL;
  g_sink = (a << 7) ^ (b >> 9) ^ static_cast<uint64_t>(tag);
}

NOINLINE USED static void captureCfiUnwind(int tag) noexcept {
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
  g_metrics.checksum ^= static_cast<uint64_t>(tag + state.depth * 29 +
                                              state.own_frames * 97);
  mixCfi(tag + state.depth + state.own_frames);
}

static void countThrown() noexcept { ++g_metrics.exceptions_thrown; }
static void countCaught() noexcept { ++g_metrics.exceptions_caught; }
static void countRethrow() noexcept { ++g_metrics.rethrows; }
static void countProgram() noexcept { ++g_metrics.programs_completed; }

#define CFI_PAYLOAD(TAG)                                                      \
  do {                                                                        \
    uint64_t p0 = g_sink + 0x6a09e667f3bcc909ULL;                             \
    uint64_t p1 = p0 ^ (p0 >> 17);                                            \
    uint64_t p2 = p1 * 0xbf58476d1ce4e5b9ULL;                                \
    uint64_t p3 = p2 + static_cast<uint64_t>((TAG) * 37 + 0x1234);            \
    uint64_t p4 = (p3 << 11) ^ (p2 >> 7);                                     \
    g_sink = p4 + (p1 ^ static_cast<uint64_t>(TAG));                          \
  } while (0)

#define CFI_CAPTURE(TAG)                                                      \
  do {                                                                        \
    CFI_PAYLOAD(TAG);                                                         \
    captureCfiUnwind(TAG);                                                    \
    CFI_PAYLOAD((TAG) + 1);                                                   \
  } while (0)

struct CfiGuard {
  explicit CfiGuard(int value) noexcept : tag(value) { CFI_PAYLOAD(tag); }

  ~CfiGuard() noexcept {
    ++g_metrics.destructors;
    CFI_PAYLOAD(tag + 7000);
    captureCfiUnwind(tag + 9000);
  }

  int tag;
};

static void throwSoft(int code) {
  countThrown();
  SoftCfiError error;
  error.code = code;
  throw error;
}

static void throwHard(int code) {
  countThrown();
  HardCfiError error;
  error.code = code;
  throw error;
}

static void throwTable(int code) {
  countThrown();
  TableCfiError error;
  error.code = code;
  throw error;
}

#define DEFINE_LINEAR_CASE(ID)                                                \
  NOINLINE USED static uint64_t linearCase_##ID(int seed) {                   \
    CfiGuard guard(seed + (ID) * 11);                                         \
    CFI_CAPTURE(seed + (ID));                                                 \
    CFI_PAYLOAD(seed + (ID) + 101);                                           \
    if (((seed + (ID)) & 15) == ((ID) & 3)) {                                 \
      throwSoft(seed + (ID) + 1000);                                          \
    }                                                                         \
    CFI_CAPTURE(seed + (ID) + 200);                                           \
    return g_sink ^ static_cast<uint64_t>(seed * 17 + (ID));                  \
  }

DEFINE_LINEAR_CASE(0)
DEFINE_LINEAR_CASE(1)
DEFINE_LINEAR_CASE(2)
DEFINE_LINEAR_CASE(3)
DEFINE_LINEAR_CASE(4)
DEFINE_LINEAR_CASE(5)
DEFINE_LINEAR_CASE(6)
DEFINE_LINEAR_CASE(7)
DEFINE_LINEAR_CASE(8)
DEFINE_LINEAR_CASE(9)
DEFINE_LINEAR_CASE(10)
DEFINE_LINEAR_CASE(11)
DEFINE_LINEAR_CASE(12)
DEFINE_LINEAR_CASE(13)
DEFINE_LINEAR_CASE(14)
DEFINE_LINEAR_CASE(15)

using CfiCaseFn = uint64_t (*)(int);

static CfiCaseFn kLinearCases[] = {
    linearCase_0,  linearCase_1,  linearCase_2,  linearCase_3,
    linearCase_4,  linearCase_5,  linearCase_6,  linearCase_7,
    linearCase_8,  linearCase_9,  linearCase_10, linearCase_11,
    linearCase_12, linearCase_13, linearCase_14, linearCase_15,
};

NOINLINE USED static uint64_t program01LinearBlocks(int seed) {
  uint64_t total = 0;
  for (size_t i = 0; i < sizeof(kLinearCases) / sizeof(kLinearCases[0]); ++i) {
    try {
      total ^= kLinearCases[i](seed + static_cast<int>(i * 13));
    } catch (const SoftCfiError &error) {
      countCaught();
      CFI_CAPTURE(error.code + 11000);
      total += static_cast<uint64_t>(error.code) * 3;
    }
  }
  countProgram();
  return total;
}

template <int N>
NOINLINE USED uint64_t templateCandidate(int seed) {
  CfiGuard guard(seed + N * 19);
  std::array<uint64_t, 6> values = {
      static_cast<uint64_t>(seed + N),
      static_cast<uint64_t>(seed * 3 + N * 5),
      static_cast<uint64_t>(seed * 7 + N * 11),
      static_cast<uint64_t>(seed * 13 + N * 17),
      static_cast<uint64_t>(seed * 19 + N * 23),
      static_cast<uint64_t>(seed * 29 + N * 31),
  };
  for (uint64_t &value : values) {
    value ^= g_sink + static_cast<uint64_t>(N);
    value = (value << 5) ^ (value >> 3);
    CFI_PAYLOAD(static_cast<int>(value + N));
  }
  CFI_CAPTURE(seed + N + 12000);
  if (((seed ^ N) % 17) == 5) {
    throwHard(seed + N + 1200);
  }
  return std::accumulate(values.begin(), values.end(), uint64_t{0}) ^ g_sink;
}

static CfiCaseFn kTemplateCases[] = {
    templateCandidate<0>,  templateCandidate<1>,  templateCandidate<2>,
    templateCandidate<3>,  templateCandidate<4>,  templateCandidate<5>,
    templateCandidate<6>,  templateCandidate<7>,  templateCandidate<8>,
    templateCandidate<9>,  templateCandidate<10>, templateCandidate<11>,
    templateCandidate<12>, templateCandidate<13>, templateCandidate<14>,
    templateCandidate<15>,
};

NOINLINE USED static uint64_t program02TemplateClones(int seed) {
  uint64_t total = 0;
  for (size_t i = 0; i < sizeof(kTemplateCases) / sizeof(kTemplateCases[0]); ++i) {
    try {
      total += kTemplateCases[i](seed + static_cast<int>(i * 7));
    } catch (const HardCfiError &error) {
      countCaught();
      CFI_CAPTURE(error.code + 13000);
      total ^= static_cast<uint64_t>(error.code) * 5;
    }
  }
  countProgram();
  return total;
}

#define DEFINE_TOWER_CASE(ID)                                                 \
  NOINLINE USED static uint64_t towerLeaf_##ID(int seed) {                    \
    CfiGuard guard(seed + (ID) * 23);                                         \
    CFI_CAPTURE(seed + (ID) + 14000);                                         \
    if (((seed + (ID)) & 7) == ((ID) & 1)) {                                  \
      throwSoft(seed + (ID) + 1400);                                          \
    }                                                                         \
    return g_sink + static_cast<uint64_t>(seed + (ID));                       \
  }                                                                           \
  NOINLINE USED static uint64_t towerMid_##ID(int seed) {                     \
    CfiGuard guard(seed + (ID) * 29);                                         \
    try {                                                                     \
      CFI_CAPTURE(seed + (ID) + 14100);                                       \
      return towerLeaf_##ID(seed + 3) ^ g_sink;                               \
    } catch (const SoftCfiError &error) {                                     \
      countCaught();                                                          \
      CFI_CAPTURE(error.code + 14100);                                        \
      if (((error.code + (ID)) & 3) == 0) {                                   \
        countRethrow();                                                       \
        throw;                                                                \
      }                                                                       \
      return static_cast<uint64_t>(error.code) * 7;                           \
    }                                                                         \
  }                                                                           \
  NOINLINE USED static uint64_t towerRoot_##ID(int seed) {                    \
    CfiGuard guard(seed + (ID) * 31);                                         \
    try {                                                                     \
      CFI_CAPTURE(seed + (ID) + 14200);                                       \
      return towerMid_##ID(seed + 5) + g_sink;                                \
    } catch (const CfiError &error) {                                         \
      countCaught();                                                          \
      CFI_CAPTURE(error.code + 14200);                                        \
      return static_cast<uint64_t>(error.code) * 11;                          \
    }                                                                         \
  }

DEFINE_TOWER_CASE(0)
DEFINE_TOWER_CASE(1)
DEFINE_TOWER_CASE(2)
DEFINE_TOWER_CASE(3)
DEFINE_TOWER_CASE(4)
DEFINE_TOWER_CASE(5)
DEFINE_TOWER_CASE(6)
DEFINE_TOWER_CASE(7)

static CfiCaseFn kTowerCases[] = {
    towerRoot_0, towerRoot_1, towerRoot_2, towerRoot_3,
    towerRoot_4, towerRoot_5, towerRoot_6, towerRoot_7,
};

NOINLINE USED static uint64_t program03RethrowTowers(int seed) {
  uint64_t total = 0;
  for (size_t i = 0; i < sizeof(kTowerCases) / sizeof(kTowerCases[0]); ++i) {
    total ^= kTowerCases[i](seed + static_cast<int>(i * 11));
  }
  countProgram();
  return total;
}

struct PolyBase {
  virtual ~PolyBase() = default;
  virtual uint64_t eval(int seed) = 0;
};

template <int N>
struct PolyNode final : PolyBase {
  NOINLINE USED uint64_t eval(int seed) override {
    CfiGuard guard(seed + N * 37);
    CFI_CAPTURE(seed + N + 15000);
    uint64_t total = g_sink ^ static_cast<uint64_t>(seed + N);
    for (int i = 0; i < 4; ++i) {
      total += static_cast<uint64_t>((seed + i) * (N + 3));
      CFI_PAYLOAD(seed + N + i);
    }
    if (((seed + N) % 19) == 7) {
      throwHard(seed + N + 1500);
    }
    return total;
  }
};

static PolyNode<0> g_poly0;
static PolyNode<1> g_poly1;
static PolyNode<2> g_poly2;
static PolyNode<3> g_poly3;
static PolyNode<4> g_poly4;
static PolyNode<5> g_poly5;
static PolyNode<6> g_poly6;
static PolyNode<7> g_poly7;
static PolyNode<8> g_poly8;
static PolyNode<9> g_poly9;

static PolyBase *kPolyNodes[] = {
    &g_poly0, &g_poly1, &g_poly2, &g_poly3, &g_poly4,
    &g_poly5, &g_poly6, &g_poly7, &g_poly8, &g_poly9,
};

NOINLINE USED static uint64_t program04VirtualDispatch(int seed) {
  uint64_t total = 0;
  for (size_t i = 0; i < sizeof(kPolyNodes) / sizeof(kPolyNodes[0]); ++i) {
    try {
      total ^= kPolyNodes[i]->eval(seed + static_cast<int>(i * 17));
    } catch (const HardCfiError &error) {
      countCaught();
      CFI_CAPTURE(error.code + 16000);
      total += static_cast<uint64_t>(error.code) * 13;
    }
  }
  countProgram();
  return total;
}

#define DEFINE_TABLE_CASE(ID)                                                 \
  NOINLINE USED static uint64_t tableCase_##ID(int seed) {                    \
    CfiGuard guard(seed + (ID) * 41);                                         \
    CFI_CAPTURE(seed + (ID) + 17000);                                         \
    uint64_t local = g_sink;                                                  \
    local ^= static_cast<uint64_t>((seed + (ID)) * 43);                       \
    CFI_PAYLOAD(seed + (ID) + 17100);                                         \
    if (((seed + (ID)) % 23) == 9) {                                          \
      throwTable(seed + (ID) + 1700);                                         \
    }                                                                         \
    return local + g_sink;                                                    \
  }

DEFINE_TABLE_CASE(0)
DEFINE_TABLE_CASE(1)
DEFINE_TABLE_CASE(2)
DEFINE_TABLE_CASE(3)
DEFINE_TABLE_CASE(4)
DEFINE_TABLE_CASE(5)
DEFINE_TABLE_CASE(6)
DEFINE_TABLE_CASE(7)
DEFINE_TABLE_CASE(8)
DEFINE_TABLE_CASE(9)
DEFINE_TABLE_CASE(10)
DEFINE_TABLE_CASE(11)
DEFINE_TABLE_CASE(12)
DEFINE_TABLE_CASE(13)
DEFINE_TABLE_CASE(14)
DEFINE_TABLE_CASE(15)

static CfiCaseFn kTableCases[] = {
    tableCase_0,  tableCase_1,  tableCase_2,  tableCase_3,
    tableCase_4,  tableCase_5,  tableCase_6,  tableCase_7,
    tableCase_8,  tableCase_9,  tableCase_10, tableCase_11,
    tableCase_12, tableCase_13, tableCase_14, tableCase_15,
};

NOINLINE USED static uint64_t program05FunctionPointerTable(int seed) {
  uint64_t total = 0;
  for (int step = 0; step < 24; ++step) {
    size_t index = static_cast<size_t>((seed + step * 5) & 15);
    try {
      total ^= kTableCases[index](seed + step);
    } catch (const TableCfiError &error) {
      countCaught();
      CFI_CAPTURE(error.code + 18000);
      total += static_cast<uint64_t>(error.code) * 17;
    }
  }
  countProgram();
  return total;
}

template <int N>
struct Recursor {
  NOINLINE USED static uint64_t run(int seed) {
    CfiGuard guard(seed + N * 47);
    CFI_CAPTURE(seed + N + 19000);
    uint64_t total = g_sink ^ static_cast<uint64_t>(seed + N);
    if ((N % 5) == 0) {
      CFI_PAYLOAD(seed + N + 19100);
    }
    return total + Recursor<N - 1>::run(seed + N);
  }
};

template <>
struct Recursor<0> {
  NOINLINE USED static uint64_t run(int seed) {
    CfiGuard guard(seed + 190);
    CFI_CAPTURE(seed + 19200);
    if ((seed & 3) == 0) {
      throwSoft(seed + 1900);
    }
    return g_sink ^ static_cast<uint64_t>(seed);
  }
};

NOINLINE USED static uint64_t program06RecursiveFrames(int seed) {
  try {
    uint64_t total = Recursor<18>::run(seed + 3);
    countProgram();
    return total;
  } catch (const SoftCfiError &error) {
    countCaught();
    CFI_CAPTURE(error.code + 19300);
    countProgram();
    return static_cast<uint64_t>(error.code) * 19;
  }
}

template <int N>
NOINLINE USED static uint64_t containerCase(int seed) {
  CfiGuard guard(seed + N * 53);
  std::array<int, 16> values{};
  for (size_t i = 0; i < values.size(); ++i) {
    values[i] = seed + static_cast<int>(i * (N + 3));
  }
  std::rotate(values.begin(), values.begin() + (N % 7 + 1), values.end());
  std::transform(values.begin(), values.end(), values.begin(), [seed](int value) {
    return (value * 3) ^ (seed + 0x55);
  });
  CFI_CAPTURE(seed + N + 20000);
  uint64_t total = static_cast<uint64_t>(
      std::accumulate(values.begin(), values.end(), 0));
  if (((seed + N) % 29) == 11) {
    throwTable(seed + N + 2000);
  }
  return total ^ g_sink;
}

static CfiCaseFn kContainerCases[] = {
    containerCase<0>,  containerCase<1>,  containerCase<2>,  containerCase<3>,
    containerCase<4>,  containerCase<5>,  containerCase<6>,  containerCase<7>,
    containerCase<8>,  containerCase<9>,  containerCase<10>, containerCase<11>,
};

NOINLINE USED static uint64_t program07ContainerAlgorithms(int seed) {
  uint64_t total = 0;
  for (size_t i = 0; i < sizeof(kContainerCases) / sizeof(kContainerCases[0]); ++i) {
    try {
      total += kContainerCases[i](seed + static_cast<int>(i * 19));
    } catch (const TableCfiError &error) {
      countCaught();
      CFI_CAPTURE(error.code + 21000);
      total ^= static_cast<uint64_t>(error.code) * 23;
    }
  }
  countProgram();
  return total;
}

template <int N>
NOINLINE USED static uint64_t variantCase(int seed) {
  CfiGuard guard(seed + N * 59);
  using Payload = std::variant<int, uint64_t, std::array<int, 4>, std::optional<int>>;
  Payload payload;
  switch ((seed + N) & 3) {
  case 0:
    payload = seed + N;
    break;
  case 1:
    payload = static_cast<uint64_t>(seed) * static_cast<uint64_t>(N + 5);
    break;
  case 2:
    payload = std::array<int, 4>{{seed, seed + N, seed * 2, seed * 3}};
    break;
  default:
    payload = std::optional<int>{seed + N * 3};
    break;
  }
  uint64_t total = std::visit(
      [seed](const auto &value) -> uint64_t {
        using T = std::decay_t<decltype(value)>;
        if constexpr (std::is_same<T, int>::value) {
          return static_cast<uint64_t>(value + seed);
        } else if constexpr (std::is_same<T, uint64_t>::value) {
          return value ^ static_cast<uint64_t>(seed);
        } else if constexpr (std::is_same<T, std::array<int, 4>>::value) {
          return static_cast<uint64_t>(
              std::accumulate(value.begin(), value.end(), 0));
        } else {
          return static_cast<uint64_t>(value.value_or(seed));
        }
      },
      payload);
  CFI_CAPTURE(seed + N + 22000);
  return total ^ g_sink;
}

static CfiCaseFn kVariantCases[] = {
    variantCase<0>, variantCase<1>, variantCase<2>, variantCase<3>,
    variantCase<4>, variantCase<5>, variantCase<6>, variantCase<7>,
};

NOINLINE USED static uint64_t program08VariantOptional(int seed) {
  uint64_t total = 0;
  for (size_t i = 0; i < sizeof(kVariantCases) / sizeof(kVariantCases[0]); ++i) {
    total ^= kVariantCases[i](seed + static_cast<int>(i * 23));
  }
  countProgram();
  return total;
}

NOINLINE USED static uint64_t program09SwitchForest(int seed) {
  CfiGuard guard(seed + 23000);
  uint64_t total = 0;
  for (int i = 0; i < 40; ++i) {
    switch ((seed + i) & 15) {
    case 0:
      CFI_CAPTURE(seed + i + 23000);
      total += g_sink ^ 0x11ULL;
      break;
    case 1:
      CFI_CAPTURE(seed + i + 23100);
      total += g_sink ^ 0x22ULL;
      break;
    case 2:
      CFI_CAPTURE(seed + i + 23200);
      total += g_sink ^ 0x33ULL;
      break;
    case 3:
      CFI_CAPTURE(seed + i + 23300);
      total += g_sink ^ 0x44ULL;
      break;
    case 4:
      CFI_PAYLOAD(seed + i + 23400);
      total ^= g_sink + 0x55ULL;
      break;
    case 5:
      CFI_PAYLOAD(seed + i + 23500);
      total ^= g_sink + 0x66ULL;
      break;
    case 6:
      CFI_PAYLOAD(seed + i + 23600);
      total ^= g_sink + 0x77ULL;
      break;
    case 7:
      CFI_PAYLOAD(seed + i + 23700);
      total ^= g_sink + 0x88ULL;
      break;
    case 8:
      CFI_CAPTURE(seed + i + 23800);
      total += g_sink ^ 0x99ULL;
      break;
    case 9:
      CFI_CAPTURE(seed + i + 23900);
      total += g_sink ^ 0xaaULL;
      break;
    case 10:
      CFI_PAYLOAD(seed + i + 24000);
      total ^= g_sink + 0xbbULL;
      break;
    case 11:
      CFI_PAYLOAD(seed + i + 24100);
      total ^= g_sink + 0xccULL;
      break;
    case 12:
      CFI_CAPTURE(seed + i + 24200);
      total += g_sink ^ 0xddULL;
      break;
    case 13:
      CFI_CAPTURE(seed + i + 24300);
      total += g_sink ^ 0xeeULL;
      break;
    case 14:
      CFI_PAYLOAD(seed + i + 24400);
      total ^= g_sink + 0xffULL;
      break;
    default:
      CFI_PAYLOAD(seed + i + 24500);
      total ^= g_sink + 0x101ULL;
      break;
    }
  }
  countProgram();
  return total;
}

#define DEFINE_CLEANUP_CASE(ID)                                               \
  NOINLINE USED static uint64_t cleanupCase_##ID(int seed) {                  \
    CfiGuard g0(seed + (ID) * 61);                                            \
    CfiGuard g1(seed + (ID) * 67);                                            \
    CfiGuard g2(seed + (ID) * 71);                                            \
    CFI_CAPTURE(seed + (ID) + 25000);                                         \
    auto local = [seed]() NOINLINE -> uint64_t {                              \
      CfiGuard lambda_guard(seed + 250);                                      \
      CFI_CAPTURE(seed + 25100);                                              \
      return g_sink ^ static_cast<uint64_t>(seed * 31);                       \
    };                                                                        \
    uint64_t total = local();                                                 \
    if (((seed + (ID)) & 7) == 3) {                                           \
      throwHard(seed + (ID) + 2500);                                          \
    }                                                                         \
    CFI_CAPTURE(seed + (ID) + 25200);                                         \
    return total + g_sink;                                                    \
  }

DEFINE_CLEANUP_CASE(0)
DEFINE_CLEANUP_CASE(1)
DEFINE_CLEANUP_CASE(2)
DEFINE_CLEANUP_CASE(3)
DEFINE_CLEANUP_CASE(4)
DEFINE_CLEANUP_CASE(5)
DEFINE_CLEANUP_CASE(6)
DEFINE_CLEANUP_CASE(7)
DEFINE_CLEANUP_CASE(8)
DEFINE_CLEANUP_CASE(9)

static CfiCaseFn kCleanupCases[] = {
    cleanupCase_0, cleanupCase_1, cleanupCase_2, cleanupCase_3, cleanupCase_4,
    cleanupCase_5, cleanupCase_6, cleanupCase_7, cleanupCase_8, cleanupCase_9,
};

NOINLINE USED static uint64_t program10CleanupStorm(int seed) {
  uint64_t total = 0;
  for (size_t i = 0; i < sizeof(kCleanupCases) / sizeof(kCleanupCases[0]); ++i) {
    try {
      total ^= kCleanupCases[i](seed + static_cast<int>(i * 29));
    } catch (const HardCfiError &error) {
      countCaught();
      CFI_CAPTURE(error.code + 26000);
      total += static_cast<uint64_t>(error.code) * 29;
    }
  }
  countProgram();
  return total;
}

static void resetMetrics() {
  g_metrics = CfiMetrics{};
  g_sink = 0x9e3779b97f4a7c15ULL;
}

static uint64_t runAllPrograms(int seed) {
  uint64_t total = 0;
  total ^= program01LinearBlocks(seed + 1);
  total += program02TemplateClones(seed + 2);
  total ^= program03RethrowTowers(seed + 3);
  total += program04VirtualDispatch(seed + 4);
  total ^= program05FunctionPointerTable(seed + 5);
  total += program06RecursiveFrames(seed + 6);
  total ^= program07ContainerAlgorithms(seed + 7);
  total += program08VariantOptional(seed + 8);
  total ^= program09SwitchForest(seed + 9);
  total += program10CleanupStorm(seed + 10);
  return total;
}

static int finishResult(int iterations, uint32_t flags, UnwindSuiteResult *out) {
  const int min_programs = iterations * 10;
  const int min_captures = iterations * 420;
  const int min_exceptions = iterations * 12;
  const int min_destructors = iterations * 260;
  int rc = 0;
  const char *why = "cfi ok";

  if (g_metrics.programs_completed < min_programs) {
    rc = 40;
    why = "cfi suite did not complete enough programs";
  } else if (g_metrics.captures < min_captures) {
    rc = 41;
    why = "cfi suite captured too few traces";
  } else if (g_metrics.exceptions_thrown < min_exceptions ||
             g_metrics.exceptions_caught < min_exceptions) {
    rc = 42;
    why = "cfi suite saw too few exception events";
  } else if (g_metrics.destructors < min_destructors) {
    rc = 43;
    why = "cfi suite saw too few cleanup destructors";
  } else if (g_metrics.min_depth < 5 || g_metrics.shallow_traces != 0) {
    rc = 44;
    why = "cfi suite saw shallow or broken traces";
  } else if ((flags & UNWIND_SUITE_STRICT_DSO_FRAMES) != 0 &&
             g_metrics.own_library_traces == 0) {
    rc = 45;
    why = "cfi suite did not observe frames in the active shared object";
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
    fprintf(stderr, "unwind_cfi_cases: %s\n",
            out != nullptr ? out->message : why);
  }
  return rc;
}

} // namespace

extern "C" EXPORT int run_unwind_cfi_suite(int iterations, uint32_t flags,
                                            UnwindSuiteResult *result) {
  if (iterations <= 0) {
    iterations = 1;
  }

  resetMetrics();
  uint64_t total = 0;
  const int rounds = iterations + 2;
  for (int round = 0; round < rounds; ++round) {
    try {
      total ^= runAllPrograms(round * 257 + iterations * 17);
    } catch (const CfiError &error) {
      countCaught();
      CFI_CAPTURE(error.code + 27000);
      total += static_cast<uint64_t>(error.code) * 31;
    } catch (...) {
      countCaught();
      CFI_CAPTURE(27999);
      total ^= 0x95a5a5a55a5a5a5aULL;
    }
  }

  g_metrics.checksum ^= total ^ static_cast<uint64_t>(g_sink);
  return finishResult(iterations, flags, result);
}

