#include "unwind_outline_api.h"

#include <dlfcn.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <unistd.h>

namespace {

struct Options {
  const char *library = "./libunwind_outline_cases.so";
  const char *plugin = nullptr;
  int iterations = 6;
  int dlclose_rounds = 64;
  uint32_t flags = UNWIND_SUITE_STRICT_DSO_FRAMES;
  bool use_plugin = true;
};

static void writeLiteral(const char *text) {
  ssize_t ignored = write(STDERR_FILENO, text, strlen(text));
  (void)ignored;
}

static void signalHandler(int signal_number, siginfo_t *, void *) {
  if (signal_number == SIGILL) {
    writeLiteral("unwind_driver: caught SIGILL; possible PAC/CFI failure during "
                 "unwind or dlclose\n");
  } else if (signal_number == SIGSEGV) {
    writeLiteral("unwind_driver: caught SIGSEGV during unwind test\n");
  } else if (signal_number == SIGABRT) {
    writeLiteral("unwind_driver: caught SIGABRT during unwind test\n");
  }
  _exit(128 + signal_number);
}

static void installCrashHandlers() {
  struct sigaction action;
  memset(&action, 0, sizeof(action));
  action.sa_sigaction = signalHandler;
  sigemptyset(&action.sa_mask);
  action.sa_flags = SA_SIGINFO | SA_RESETHAND;
  sigaction(SIGILL, &action, nullptr);
  sigaction(SIGSEGV, &action, nullptr);
  sigaction(SIGABRT, &action, nullptr);
}

static int parseInt(const char *text, int fallback) {
  if (text == nullptr || *text == '\0') {
    return fallback;
  }
  char *end = nullptr;
  errno = 0;
  long value = strtol(text, &end, 0);
  if (errno != 0 || end == text || *end != '\0') {
    return fallback;
  }
  return static_cast<int>(value);
}

static void usage(const char *argv0) {
  fprintf(stderr,
          "usage: %s [--lib PATH] [--plugin PATH] [--no-plugin]\n"
          "          [--iterations N] [--dlclose-rounds N]\n"
          "          [--no-strict-dso] [--verbose]\n",
          argv0);
}

static bool parseArgs(int argc, char **argv, Options *options) {
  for (int i = 1; i < argc; ++i) {
    if (strcmp(argv[i], "--lib") == 0 && i + 1 < argc) {
      options->library = argv[++i];
    } else if (strcmp(argv[i], "--plugin") == 0 && i + 1 < argc) {
      options->plugin = argv[++i];
      options->use_plugin = true;
    } else if (strcmp(argv[i], "--no-plugin") == 0) {
      options->use_plugin = false;
    } else if (strcmp(argv[i], "--iterations") == 0 && i + 1 < argc) {
      options->iterations = parseInt(argv[++i], options->iterations);
    } else if (strcmp(argv[i], "--dlclose-rounds") == 0 && i + 1 < argc) {
      options->dlclose_rounds = parseInt(argv[++i], options->dlclose_rounds);
    } else if (strcmp(argv[i], "--no-strict-dso") == 0) {
      options->flags &= ~UNWIND_SUITE_STRICT_DSO_FRAMES;
    } else if (strcmp(argv[i], "--verbose") == 0) {
      options->flags |= UNWIND_SUITE_VERBOSE;
    } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
      usage(argv[0]);
      exit(0);
    } else {
      usage(argv[0]);
      return false;
    }
  }
  if (options->iterations <= 0) {
    options->iterations = 1;
  }
  if (options->dlclose_rounds <= 0) {
    options->dlclose_rounds = 1;
  }
  return true;
}

static std::string siblingPluginPath(const char *library) {
  const char *slash = strrchr(library, '/');
  if (slash == nullptr) {
    return "libunwind_outline_plugin.so";
  }
  return std::string(library, static_cast<size_t>(slash - library + 1)) +
         "libunwind_outline_plugin.so";
}

static int callSuite(void *handle, const Options &options, int round,
                     const char *symbol_name) {
  dlerror();
  void *symbol = dlsym(handle, symbol_name);
  const char *error = dlerror();
  if (error != nullptr || symbol == nullptr) {
    fprintf(stderr, "round %d: dlsym(%s) failed: %s\n", round, symbol_name,
            error != nullptr ? error : "null symbol");
    return 11;
  }

  auto run = reinterpret_cast<RunUnwindOutlineSuiteFn>(symbol);
  UnwindSuiteResult result;
  memset(&result, 0, sizeof(result));
  int rc = run(options.iterations, options.flags, &result);
  printf("round=%d suite=%s run_rc=%d %s\n", round, symbol_name, rc,
         result.message);
  fflush(stdout);
  return rc;
}

static int runOneRound(const Options &options, int round) {
  void *handle = dlopen(options.library, RTLD_NOW | RTLD_LOCAL);
  if (handle == nullptr) {
    fprintf(stderr, "round %d: dlopen(%s) failed: %s\n", round,
            options.library, dlerror());
    return 10;
  }

  const char *suites[] = {
      "run_unwind_outline_suite",
      "run_unwind_stress_suite",
      "run_unwind_deep_suite",
  };
  for (const char *suite : suites) {
    int rc = callSuite(handle, options, round, suite);
    if (rc != 0) {
      dlclose(handle);
      return rc;
    }
  }

  if (options.use_plugin) {
    std::string plugin_path =
        options.plugin != nullptr ? options.plugin : siblingPluginPath(options.library);
    void *plugin_handle = dlopen(plugin_path.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (plugin_handle == nullptr) {
      fprintf(stderr, "round %d: dlopen plugin(%s) failed: %s\n", round,
              plugin_path.c_str(), dlerror());
      dlclose(handle);
      return 13;
    }
    int rc = callSuite(plugin_handle, options, round, "run_unwind_plugin_suite");
    int plugin_close_rc = dlclose(plugin_handle);
    if (plugin_close_rc != 0) {
      fprintf(stderr, "round %d: plugin dlclose failed: %s\n", round, dlerror());
      dlclose(handle);
      return 14;
    }
    if (rc != 0) {
      dlclose(handle);
      return rc;
    }
  }

  int close_rc = dlclose(handle);
  if (close_rc != 0) {
    fprintf(stderr, "round %d: dlclose failed: %s\n", round, dlerror());
    return 12;
  }
  return 0;
}

} // namespace

int main(int argc, char **argv) {
  installCrashHandlers();

  Options options;
  if (!parseArgs(argc, argv, &options)) {
    return 2;
  }

  int failures = 0;
  for (int round = 0; round < options.dlclose_rounds; ++round) {
    int rc = runOneRound(options, round);
    if (rc != 0) {
      ++failures;
      fprintf(stderr, "unwind_driver: stopping after failing round %d rc=%d\n",
              round, rc);
      return rc;
    }
  }

  printf("unwind_driver: ok rounds=%d iterations=%d lib=%s\n",
         options.dlclose_rounds, options.iterations, options.library);
  return failures == 0 ? 0 : 1;
}
