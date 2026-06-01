#include "unwind_cfi_api.h"

#include <algorithm>
#include <atomic>
#include <dlfcn.h>
#include <functional>
#include <mutex>
#include <numeric>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <thread>
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

constexpr int kMaxTraceFrames = 128;
constexpr const char *kLibraryNeedle = "libunwind_cfi_cases";

struct StressMetrics {
  std::mutex lock;
  int captures = 0;
  int min_depth = 1000000;
  int shallow_traces = 0;
  int own_library_traces = 0;
  int exceptions_thrown = 0;
  int exceptions_caught = 0;
  int rethrows = 0;
  int destructors = 0;
  int virtual_calls = 0;
  int thread_rounds = 0;
  uint64_t checksum = 0;

  void reset() {
    std::lock_guard<std::mutex> guard(lock);
    captures = 0;
    min_depth = 1000000;
    shallow_traces = 0;
    own_library_traces = 0;
    exceptions_thrown = 0;
    exceptions_caught = 0;
    rethrows = 0;
    destructors = 0;
    virtual_calls = 0;
    thread_rounds = 0;
    checksum = 0;
  }
};

struct TraceState {
  int depth = 0;
  int own_frames = 0;
};

struct StressError {
  virtual ~StressError() = default;
  int code = 0;
};

struct VectorError : StressError {};
struct VirtualError : StressError {};
struct PointerError : StressError {};
struct ThreadError : StressError {};

static StressMetrics g_metrics;
static std::atomic<uint64_t> g_sink{0x243f6a8885a308d3ULL};

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

NOINLINE USED static void stressMix(int tag) noexcept {
  uint64_t old = g_sink.load(std::memory_order_relaxed);
  uint64_t value = old + 0x9e3779b97f4a7c15ULL;
  value ^= value >> 12;
  value *= 0xbf58476d1ce4e5b9ULL;
  value += static_cast<uint64_t>(tag * 131 + 17);
  value ^= value << 9;
  g_sink.fetch_xor(value, std::memory_order_relaxed);
}

NOINLINE USED static void captureStressUnwind(int tag) noexcept {
  TraceState state;
  _Unwind_Backtrace(traceFrame, &state);
  stressMix(tag + state.depth + state.own_frames);

  std::lock_guard<std::mutex> guard(g_metrics.lock);
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
}

static void addChecksum(uint64_t value) {
  std::lock_guard<std::mutex> guard(g_metrics.lock);
  g_metrics.checksum ^= value + 0x517cc1b727220a95ULL;
}

static void countThrown() {
  std::lock_guard<std::mutex> guard(g_metrics.lock);
  ++g_metrics.exceptions_thrown;
}

static void countCaught() {
  std::lock_guard<std::mutex> guard(g_metrics.lock);
  ++g_metrics.exceptions_caught;
}

static void countRethrow() {
  std::lock_guard<std::mutex> guard(g_metrics.lock);
  ++g_metrics.rethrows;
}

static void countDestructor() {
  std::lock_guard<std::mutex> guard(g_metrics.lock);
  ++g_metrics.destructors;
}

static void countVirtualCall() {
  std::lock_guard<std::mutex> guard(g_metrics.lock);
  ++g_metrics.virtual_calls;
}

static void countThreadRound() {
  std::lock_guard<std::mutex> guard(g_metrics.lock);
  ++g_metrics.thread_rounds;
}

#define STRESS_PAYLOAD(TAG)                                                   \
  do {                                                                        \
    stressMix(TAG);                                                           \
    uint64_t local = g_sink.load(std::memory_order_relaxed);                  \
    local += 0x94d049bb133111ebULL;                                           \
    local ^= local >> 17;                                                     \
    local *= 0x9e3779b185ebca87ULL;                                           \
    stressMix(static_cast<int>(local) ^ (TAG));                               \
  } while (0)

#define STRESS_CAPTURE(TAG)                                                   \
  do {                                                                        \
    STRESS_PAYLOAD(TAG);                                                      \
    captureStressUnwind(TAG);                                                 \
    STRESS_PAYLOAD((TAG) + 3);                                                \
  } while (0)

struct StressGuard {
  explicit StressGuard(int value) noexcept : tag(value) {
    STRESS_PAYLOAD(tag + 1);
  }

  ~StressGuard() noexcept {
    countDestructor();
    STRESS_PAYLOAD(tag + 2);
    captureStressUnwind(tag + 5000);
  }

  int tag;
};

NOINLINE USED static std::string makeStringPayload(int tag, int width) {
  std::string text = "case:";
  text += std::to_string(tag);
  for (int i = 0; i < width; ++i) {
    text.push_back(static_cast<char>('a' + ((tag + i) % 26)));
  }
  std::reverse(text.begin(), text.end());
  return text;
}

#define DEFINE_VECTOR_CASE(ID)                                                \
  NOINLINE USED static uint64_t vectorCase_##ID(int n) {                      \
    StressGuard guard(n + ID * 17);                                           \
    std::vector<std::string> values;                                          \
    values.reserve(8);                                                        \
    for (int i = 0; i < 8; ++i) {                                             \
      values.push_back(makeStringPayload(n + ID * 13 + i, 6 + (i & 3)));      \
    }                                                                         \
    std::sort(values.begin(), values.end());                                  \
    STRESS_CAPTURE(n + ID);                                                   \
    uint64_t result = static_cast<uint64_t>(values.size() * 31 + n);          \
    for (const auto &value : values) {                                        \
      result += static_cast<uint64_t>(value.size() * 7 + value[0]);           \
    }                                                                         \
    if (((n + ID) % 17) == 3) {                                               \
      countThrown();                                                          \
      VectorError error;                                                      \
      error.code = n + ID * 100 + 7;                                          \
      throw error;                                                            \
    }                                                                         \
    STRESS_CAPTURE(n + ID + 100);                                             \
    return result ^ g_sink.load(std::memory_order_relaxed);                   \
  }

DEFINE_VECTOR_CASE(0)
DEFINE_VECTOR_CASE(1)
DEFINE_VECTOR_CASE(2)
DEFINE_VECTOR_CASE(3)
DEFINE_VECTOR_CASE(4)
DEFINE_VECTOR_CASE(5)
DEFINE_VECTOR_CASE(6)
DEFINE_VECTOR_CASE(7)
DEFINE_VECTOR_CASE(8)
DEFINE_VECTOR_CASE(9)
DEFINE_VECTOR_CASE(10)
DEFINE_VECTOR_CASE(11)
DEFINE_VECTOR_CASE(12)
DEFINE_VECTOR_CASE(13)
DEFINE_VECTOR_CASE(14)
DEFINE_VECTOR_CASE(15)
DEFINE_VECTOR_CASE(16)
DEFINE_VECTOR_CASE(17)
DEFINE_VECTOR_CASE(18)
DEFINE_VECTOR_CASE(19)
DEFINE_VECTOR_CASE(20)
DEFINE_VECTOR_CASE(21)
DEFINE_VECTOR_CASE(22)
DEFINE_VECTOR_CASE(23)

using VectorFn = uint64_t (*)(int);

static VectorFn kVectorCases[] = {
    vectorCase_0,  vectorCase_1,  vectorCase_2,  vectorCase_3,
    vectorCase_4,  vectorCase_5,  vectorCase_6,  vectorCase_7,
    vectorCase_8,  vectorCase_9,  vectorCase_10, vectorCase_11,
    vectorCase_12, vectorCase_13, vectorCase_14, vectorCase_15,
    vectorCase_16, vectorCase_17, vectorCase_18, vectorCase_19,
    vectorCase_20, vectorCase_21, vectorCase_22, vectorCase_23,
};

template <int Level>
struct TemplateStepper {
  NOINLINE USED static uint64_t run(int n, int depth) {
    StressGuard guard(n + Level * 19);
    STRESS_CAPTURE(n + Level);
    uint64_t value = static_cast<uint64_t>(n * 11 + Level);
    if (depth <= 0) {
      return value ^ g_sink.load(std::memory_order_relaxed);
    }
    return value + TemplateStepper<Level - 1>::run(n + Level, depth - 1);
  }
};

template <>
struct TemplateStepper<0> {
  NOINLINE USED static uint64_t run(int n, int) {
    StressGuard guard(n + 333);
    STRESS_CAPTURE(n + 77);
    return g_sink.load(std::memory_order_relaxed) ^ static_cast<uint64_t>(n);
  }
};

struct Actor {
  virtual ~Actor() = default;
  virtual uint64_t act(int n) = 0;
};

#define DEFINE_ACTOR(ID)                                                      \
  struct Actor_##ID final : Actor {                                           \
    NOINLINE USED uint64_t act(int n) override {                              \
      countVirtualCall();                                                     \
      StressGuard guard(n + ID * 23);                                         \
      STRESS_CAPTURE(n + ID);                                                 \
      uint64_t result = vectorCase_##ID(n + ID * 5);                          \
      if (((n + ID) % 19) == 5) {                                             \
        countThrown();                                                        \
        VirtualError error;                                                   \
        error.code = n + ID * 200 + 9;                                        \
        throw error;                                                          \
      }                                                                       \
      STRESS_CAPTURE(n + ID + 200);                                           \
      return result ^ static_cast<uint64_t>(ID * 97 + n);                    \
    }                                                                         \
  };

DEFINE_ACTOR(0)
DEFINE_ACTOR(1)
DEFINE_ACTOR(2)
DEFINE_ACTOR(3)
DEFINE_ACTOR(4)
DEFINE_ACTOR(5)
DEFINE_ACTOR(6)
DEFINE_ACTOR(7)
DEFINE_ACTOR(8)
DEFINE_ACTOR(9)
DEFINE_ACTOR(10)
DEFINE_ACTOR(11)
DEFINE_ACTOR(12)
DEFINE_ACTOR(13)
DEFINE_ACTOR(14)
DEFINE_ACTOR(15)

NOINLINE USED static uint64_t runVirtualMatrix(int n) {
  Actor_0 a0;
  Actor_1 a1;
  Actor_2 a2;
  Actor_3 a3;
  Actor_4 a4;
  Actor_5 a5;
  Actor_6 a6;
  Actor_7 a7;
  Actor_8 a8;
  Actor_9 a9;
  Actor_10 a10;
  Actor_11 a11;
  Actor_12 a12;
  Actor_13 a13;
  Actor_14 a14;
  Actor_15 a15;
  Actor *actors[] = {&a0, &a1, &a2, &a3, &a4, &a5, &a6, &a7,
                     &a8, &a9, &a10, &a11, &a12, &a13, &a14, &a15};
  uint64_t result = 0;
  for (int i = 0; i < 16; ++i) {
    try {
      result ^= actors[i]->act(n + i);
    } catch (const VirtualError &error) {
      countCaught();
      STRESS_CAPTURE(error.code);
      result += static_cast<uint64_t>(error.code) * 41;
    } catch (const VectorError &error) {
      countCaught();
      STRESS_CAPTURE(error.code + 1);
      countRethrow();
      if ((error.code & 1) != 0) {
        throw;
      }
      result ^= static_cast<uint64_t>(error.code) * 43;
    }
  }
  return result;
}

#define DEFINE_POINTER_CASE(ID)                                               \
  NOINLINE USED static uint64_t pointerCase_##ID(int n) {                     \
    StressGuard guard(n + ID * 29);                                           \
    STRESS_CAPTURE(n + ID + 300);                                             \
    std::function<uint64_t(int)> fn = [](int value) -> uint64_t {             \
      STRESS_PAYLOAD(value + ID);                                             \
      return g_sink.load(std::memory_order_relaxed) ^                         \
             static_cast<uint64_t>(value * (ID + 3));                         \
    };                                                                        \
    uint64_t result = fn(n + ID);                                             \
    if (((n + ID) % 23) == 9) {                                               \
      countThrown();                                                          \
      PointerError error;                                                     \
      error.code = n + ID * 300 + 11;                                         \
      throw error;                                                            \
    }                                                                         \
    STRESS_CAPTURE(n + ID + 400);                                             \
    return result;                                                            \
  }

DEFINE_POINTER_CASE(0)
DEFINE_POINTER_CASE(1)
DEFINE_POINTER_CASE(2)
DEFINE_POINTER_CASE(3)
DEFINE_POINTER_CASE(4)
DEFINE_POINTER_CASE(5)
DEFINE_POINTER_CASE(6)
DEFINE_POINTER_CASE(7)
DEFINE_POINTER_CASE(8)
DEFINE_POINTER_CASE(9)
DEFINE_POINTER_CASE(10)
DEFINE_POINTER_CASE(11)
DEFINE_POINTER_CASE(12)
DEFINE_POINTER_CASE(13)
DEFINE_POINTER_CASE(14)
DEFINE_POINTER_CASE(15)

using PointerFn = uint64_t (*)(int);

static PointerFn kPointerCases[] = {
    pointerCase_0,  pointerCase_1,  pointerCase_2,  pointerCase_3,
    pointerCase_4,  pointerCase_5,  pointerCase_6,  pointerCase_7,
    pointerCase_8,  pointerCase_9,  pointerCase_10, pointerCase_11,
    pointerCase_12, pointerCase_13, pointerCase_14, pointerCase_15,
};

NOINLINE USED static uint64_t runPointerTable(int n) {
  uint64_t result = 0;
  for (int i = 0; i < 16; ++i) {
    try {
      result += kPointerCases[i](n + i * 7);
    } catch (const PointerError &error) {
      countCaught();
      STRESS_CAPTURE(error.code);
      result ^= static_cast<uint64_t>(error.code) * 47;
    }
  }
  return result;
}

NOINLINE USED static uint64_t runVectorTable(int n) {
  uint64_t result = 0;
  for (int i = 0; i < 24; ++i) {
    try {
      result ^= kVectorCases[i](n + i * 5);
    } catch (const VectorError &error) {
      countCaught();
      STRESS_CAPTURE(error.code + i);
      result += static_cast<uint64_t>(error.code) * 53;
    }
  }
  return result;
}

NOINLINE USED static uint64_t runTemplateTower(int n) {
  uint64_t result = 0;
  result ^= TemplateStepper<24>::run(n + 1, 24);
  result += TemplateStepper<18>::run(n + 3, 18);
  result ^= TemplateStepper<12>::run(n + 5, 12);
  return result;
}

NOINLINE USED static void threadWorker(int worker, int iterations,
                                       std::atomic<uint64_t> *result) {
  uint64_t local = static_cast<uint64_t>(worker + 1) * 0x45d9f3bULL;
  for (int i = 0; i < iterations; ++i) {
    try {
      StressGuard guard(worker * 1000 + i);
      local ^= runPointerTable(worker * 100 + i * 17);
      local += runTemplateTower(worker * 200 + i * 19);
      if (((worker + i) % 11) == 4) {
        countThrown();
        ThreadError error;
        error.code = worker * 5000 + i;
        throw error;
      }
    } catch (const StressError &error) {
      countCaught();
      STRESS_CAPTURE(error.code + 6000);
      local ^= static_cast<uint64_t>(error.code) * 61;
    } catch (...) {
      countCaught();
      STRESS_CAPTURE(worker + i + 7000);
      local ^= 0xbadf00d123456789ULL;
    }
    countThreadRound();
  }
  result->fetch_xor(local, std::memory_order_relaxed);
}

NOINLINE USED static uint64_t runThreadedStress(int iterations) {
  std::atomic<uint64_t> result{0};
  const int thread_iterations = std::max(1, iterations / 2);
  std::thread t0(threadWorker, 0, thread_iterations, &result);
  std::thread t1(threadWorker, 1, thread_iterations, &result);
  std::thread t2(threadWorker, 2, thread_iterations, &result);
  t0.join();
  t1.join();
  t2.join();
  return result.load(std::memory_order_relaxed);
}

NOINLINE USED static uint64_t runLongStressBody(int iterations) {
  uint64_t result = 0;
  for (int i = 0; i < iterations; ++i) {
    try {
      StressGuard guard(i + 900);
      result ^= runVectorTable(i * 31 + 1);
      result += runVirtualMatrix(i * 37 + 3);
      result ^= runPointerTable(i * 41 + 5);
      result += runTemplateTower(i * 43 + 7);
    } catch (const StressError &error) {
      countCaught();
      STRESS_CAPTURE(error.code + 8000);
      result ^= static_cast<uint64_t>(error.code) * 67;
    }
  }
  result ^= runThreadedStress(iterations);
  addChecksum(result);
  return result;
}

static int finishResult(int iterations, uint32_t flags, UnwindSuiteResult *out) {
  int captures = 0;
  int min_depth = 0;
  int shallow = 0;
  int own = 0;
  int thrown = 0;
  int caught = 0;
  int rethrows = 0;
  int destructors = 0;
  int virtual_calls = 0;
  int thread_rounds = 0;
  uint64_t checksum = 0;
  {
    std::lock_guard<std::mutex> guard(g_metrics.lock);
    captures = g_metrics.captures;
    min_depth = g_metrics.min_depth;
    shallow = g_metrics.shallow_traces;
    own = g_metrics.own_library_traces;
    thrown = g_metrics.exceptions_thrown;
    caught = g_metrics.exceptions_caught;
    rethrows = g_metrics.rethrows;
    destructors = g_metrics.destructors;
    virtual_calls = g_metrics.virtual_calls;
    thread_rounds = g_metrics.thread_rounds;
    checksum = g_metrics.checksum ^ g_sink.load(std::memory_order_relaxed);
  }

  int rc = 0;
  const char *why = "stress ok";
  const int min_exception_events = std::max(6, iterations * 4);
  if (captures < iterations * 320) {
    rc = 20;
    why = "stress suite captured too few traces";
  } else if (thrown < min_exception_events || caught < min_exception_events) {
    rc = 21;
    why = "stress suite saw too few exception events";
  } else if (destructors < iterations * 180) {
    rc = 22;
    why = "stress suite saw too few cleanup destructors";
  } else if (virtual_calls < iterations * 8 || thread_rounds < std::max(1, iterations)) {
    rc = 23;
    why = "stress suite did not run enough virtual/thread cases";
  } else if (min_depth < 5 || shallow != 0) {
    rc = 24;
    why = "stress suite saw shallow or broken traces";
  } else if ((flags & UNWIND_SUITE_STRICT_DSO_FRAMES) != 0 && own == 0) {
    rc = 25;
    why = "stress suite did not observe frames in the active shared object";
  }

  if (out != nullptr) {
    memset(out, 0, sizeof(*out));
    out->version = 1;
    out->flags = flags;
    out->rc = rc;
    out->captures = captures;
    out->min_depth = min_depth;
    out->shallow_traces = shallow;
    out->own_library_traces = own;
    out->exceptions_thrown = thrown;
    out->exceptions_caught = caught;
    out->rethrows = rethrows;
    out->destructors = destructors;
    out->checksum = checksum;
    snprintf(out->message, sizeof(out->message),
             "%s captures=%d min_depth=%d own_dso_traces=%d thrown=%d "
             "caught=%d rethrows=%d destructors=%d virtual=%d threads=%d "
             "checksum=0x%llx",
             why, captures, min_depth, own, thrown, caught, rethrows,
             destructors, virtual_calls, thread_rounds,
             static_cast<unsigned long long>(checksum));
  }

  if ((flags & UNWIND_SUITE_VERBOSE) != 0) {
    fprintf(stderr, "unwind_stress_cases: %s\n",
            out != nullptr ? out->message : why);
  }
  return rc;
}

} // namespace

extern "C" EXPORT int run_unwind_stress_suite(int iterations, uint32_t flags,
                                               UnwindSuiteResult *result) {
  if (iterations <= 0) {
    iterations = 1;
  }

  g_metrics.reset();
  g_sink.store(0x243f6a8885a308d3ULL, std::memory_order_relaxed);

  try {
    uint64_t value = runLongStressBody(iterations);
    addChecksum(value);
  } catch (const StressError &error) {
    countCaught();
    STRESS_CAPTURE(error.code + 9000);
    addChecksum(static_cast<uint64_t>(error.code) * 71);
  } catch (...) {
    countCaught();
    STRESS_CAPTURE(9999);
    addChecksum(0xdeadbeefcafef00dULL);
  }

  return finishResult(iterations, flags, result);
}
