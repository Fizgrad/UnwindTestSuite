#ifndef UNWIND_OUTLINE_API_H
#define UNWIND_OUTLINE_API_H

#include <stdint.h>

extern "C" {

enum UnwindSuiteFlags : uint32_t {
  UNWIND_SUITE_VERBOSE = 1u << 0,
  UNWIND_SUITE_STRICT_DSO_FRAMES = 1u << 1,
};

struct UnwindSuiteResult {
  uint32_t version;
  uint32_t flags;
  int32_t rc;
  int32_t captures;
  int32_t min_depth;
  int32_t shallow_traces;
  int32_t own_library_traces;
  int32_t exceptions_thrown;
  int32_t exceptions_caught;
  int32_t rethrows;
  int32_t destructors;
  uint64_t checksum;
  char message[256];
};

using RunUnwindOutlineSuiteFn =
    int (*)(int iterations, uint32_t flags, UnwindSuiteResult *result);

int run_unwind_outline_suite(int iterations, uint32_t flags,
                             UnwindSuiteResult *result);

int run_unwind_stress_suite(int iterations, uint32_t flags,
                            UnwindSuiteResult *result);

int run_unwind_deep_suite(int iterations, uint32_t flags,
                          UnwindSuiteResult *result);

int run_unwind_plugin_suite(int iterations, uint32_t flags,
                            UnwindSuiteResult *result);

}

#endif
