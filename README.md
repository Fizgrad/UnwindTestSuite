# C++ Unwind and DSO Lifecycle Test Suite

English | [中文说明](#中文说明)

## English

### Purpose

This repository contains a focused C++ test suite for validating stack unwinding
across shared-object lifecycle events. It repeatedly loads shared objects,
executes unwind-heavy C++ code, and unloads the objects again.

The suite is designed to exercise:

- `_Unwind_Backtrace` on deep and mixed C++ call stacks
- C++ exception throw, catch, cleanup, and rethrow paths
- RAII destructors that execute while unwinding
- AArch64 PAC/BTI protected code
- dynamic `.eh_frame` registration and deregistration
- `dlopen()` / `dlclose()` behavior for one main shared object and one plugin
  shared object

The main failure modes of interest are crashes or hangs during runtime unwind
metadata handling, especially `SIGILL`, `SIGSEGV`, and `SIGABRT` around shared
object unload or unwind table cleanup.

### Test Layout

The suite builds three runtime artifacts:

- `libunwind_cfi_cases.so`: the main test shared object
- `libunwind_cfi_plugin.so`: a plugin shared object loaded and unloaded on
  every round
- `unwind_driver`: the executable that drives repeated load, run, and unload
  cycles

Each test round performs this lifecycle:

1. `dlopen()` the main shared object.
2. Run the basic, stress, deep, CFI, and extended CFI unwind suites.
3. `dlopen()` the plugin shared object.
4. Run the plugin unwind suite.
5. `dlclose()` the plugin shared object.
6. `dlclose()` the main shared object.

The plugin also contains a global destructor that captures a backtrace during
`dlclose()`, which adds coverage for shared-object teardown paths.

### Coverage

The exported suites cover several categories of C++ behavior:

- Basic repeated call chains with direct `_Unwind_Backtrace` captures,
  cleanup destructors, and rethrow paths.
- Mixed C++ features such as template recursion, virtual dispatch,
  function-pointer tables, `std::function`, vectors, strings, sorting, and
  threaded workers.
- Deeper C++ cases using `std::variant`, `std::optional`, `std::tuple`,
  `std::deque`, `std::map`, multiple inheritance, virtual graph evaluation, and
  recursive calls.
- Plugin DSO execution and unload-time backtrace capture.

### Quick Start

Host smoke test:

```bash
cd <unwind_testsuite>
./scripts/build_host.sh
./scripts/run_host.sh
```

QEMU AArch64 smoke test:

```bash
cd <unwind_testsuite>
python3 scripts/unwind_testsuite.py all \
  --iterations 1 \
  --dlclose-rounds 1
```

By default, the Python runner uses:

- compiler: `aarch64-linux-gnu-g++`
- target: native compiler default unless `--target` is provided
- emulator: `qemu-aarch64`
- runtime prefix: `/usr/aarch64-linux-gnu`
- output directory: `out/qemu-arm64`

### Python Runner

The main entry point is:

```bash
python3 scripts/unwind_testsuite.py <command> [options]
```

Commands:

- `build`: build the main shared object, plugin shared object, and driver
- `run`: run the built driver through QEMU
- `inspect`: print selected ELF section, symbol, and disassembly information
- `all`: run `build`, `run`, and `inspect` in sequence

Common build options:

- `--cxx <path>`: compiler path
- `--target <triple>`: optional target triple
- `--out <dir>`: output directory
- `--opt <flag>`: optimization flag, default `-O2`
- `--cxxflag <flag>`: extra compiler flag, repeatable
- `--cxxflags "<flags>"`: shell-style compiler flag string
- `--so-cxxflag <flag>`: shared-library-only compiler flag, repeatable
- `--driver-cxxflag <flag>`: driver-only compiler flag, repeatable
- `--ldflag <flag>`: extra linker flag, repeatable
- `--ldflags "<flags>"`: shell-style linker flag string
- `--branch-protection-flags <flags...>`: branch protection flags, default
  `-mbranch-protection=pac-ret+bti`

Common run options:

- `--qemu <cmd>`: QEMU command, default `qemu-aarch64`
- `--qemu-ld-prefix <dir>`: AArch64 runtime prefix
- `--qemu-arg "<arg>"`: extra QEMU argument string, repeatable
- `--iterations <N>`: per-suite work multiplier
- `--dlclose-rounds <N>`: number of repeated load/unload rounds
- `--no-strict-dso`: disable strict `dladdr()` based frame checks

Example with a custom compiler and custom compiler flags:

```bash
python3 scripts/unwind_testsuite.py all \
  --out out/custom-aarch64 \
  --cxx <aarch64-c++> \
  --target aarch64-linux-gnu \
  --so-cxxflags "<shared-object compile flags>" \
  --ldflags "<link flags>" \
  --iterations 8 \
  --dlclose-rounds 128
```

Compatibility wrappers are also provided:

```bash
./scripts/build_qemu_arm64.sh
./scripts/run_qemu_arm64.sh
./scripts/inspect_binaries.sh
```

### Longer Runs

Use larger values for `--iterations` and `--dlclose-rounds` to increase runtime
coverage:

```bash
python3 scripts/unwind_testsuite.py run \
  --iterations 20 \
  --dlclose-rounds 500
```

### Pass Criteria

A valid run should:

- complete all requested rounds
- report success for every exported suite
- capture many `_Unwind_Backtrace` samples
- avoid unexpectedly shallow traces
- exercise exception throw, catch, cleanup, and rethrow paths
- execute virtual dispatch, threaded workers, containers, recursion, and
  multiple-inheritance cases
- load and unload the plugin shared object on every round
- resolve at least one frame from the active test shared object when strict DSO
  checking is enabled

## 中文说明

### 测试目标

本仓库提供一个 C++ 测试集，用于验证共享库加载、执行和卸载过程中的栈回溯行为。
测试程序会反复加载共享库，执行大量与 unwind 相关的 C++ 代码，然后再卸载共享库。

测试重点包括：

- 深层和混合 C++ 调用栈上的 `_Unwind_Backtrace`
- C++ 异常抛出、捕获、清理和 rethrow 路径
- unwind 过程中执行的 RAII 析构函数
- AArch64 PAC/BTI 保护代码
- 动态 `.eh_frame` 注册和注销
- 一个主共享库和一个插件共享库的 `dlopen()` / `dlclose()` 行为

主要关注的失效模式是运行时处理 unwind 元数据时出现崩溃或卡住，尤其是共享库卸载
或 unwind 表清理阶段出现 `SIGILL`、`SIGSEGV`、`SIGABRT` 等问题。

### 测试结构

测试集会构建三个运行时产物：

- `libunwind_cfi_cases.so`：主测试共享库
- `libunwind_cfi_plugin.so`：每一轮都会加载和卸载的插件共享库
- `unwind_driver`：负责反复执行加载、测试和卸载流程的可执行文件

每一轮测试执行以下流程：

1. `dlopen()` 主测试共享库。
2. 执行 basic、stress、deep、CFI 和 extended CFI unwind 测试套件。
3. `dlopen()` 插件共享库。
4. 执行 plugin unwind 测试套件。
5. `dlclose()` 插件共享库。
6. `dlclose()` 主测试共享库。

插件共享库还包含一个全局析构函数，会在 `dlclose()` 阶段采集 backtrace，用于覆盖
共享库卸载阶段的路径。

### 覆盖场景

导出的测试套件覆盖以下 C++ 行为：

- 重复调用链、直接 `_Unwind_Backtrace`、析构清理和 rethrow 路径。
- 模板递归、虚调用、函数指针表、`std::function`、vector、string、排序和线程
  worker。
- `std::variant`、`std::optional`、`std::tuple`、`std::deque`、`std::map`、
  多继承、虚图遍历和递归调用。
- 插件共享库执行，以及卸载阶段的 backtrace 采集。

### 快速开始

主机快速测试：

```bash
cd <unwind_testsuite>
./scripts/build_host.sh
./scripts/run_host.sh
```

QEMU AArch64 快速测试：

```bash
cd <unwind_testsuite>
python3 scripts/unwind_testsuite.py all \
  --iterations 1 \
  --dlclose-rounds 1
```

Python runner 默认使用：

- 编译器：`aarch64-linux-gnu-g++`
- target：使用编译器默认 target，除非显式传入 `--target`
- 模拟器：`qemu-aarch64`
- AArch64 运行时前缀：`/usr/aarch64-linux-gnu`
- 输出目录：`out/qemu-arm64`

### Python 运行入口

主入口：

```bash
python3 scripts/unwind_testsuite.py <command> [options]
```

支持的命令：

- `build`：构建主共享库、插件共享库和 driver
- `run`：通过 QEMU 运行已构建的 driver
- `inspect`：打印选定的 ELF section、符号和反汇编信息
- `all`：依次执行 `build`、`run` 和 `inspect`

常用构建参数：

- `--cxx <path>`：编译器路径
- `--target <triple>`：可选 target triple
- `--out <dir>`：输出目录
- `--opt <flag>`：优化选项，默认 `-O2`
- `--cxxflag <flag>`：额外编译参数，可重复传入
- `--cxxflags "<flags>"`：shell 风格的额外编译参数字符串
- `--so-cxxflag <flag>`：仅用于共享库的额外编译参数，可重复传入
- `--driver-cxxflag <flag>`：仅用于 driver 的额外编译参数，可重复传入
- `--ldflag <flag>`：额外链接参数，可重复传入
- `--ldflags "<flags>"`：shell 风格的额外链接参数字符串
- `--branch-protection-flags <flags...>`：分支保护参数，默认
  `-mbranch-protection=pac-ret+bti`

常用运行参数：

- `--qemu <cmd>`：QEMU 命令，默认 `qemu-aarch64`
- `--qemu-ld-prefix <dir>`：AArch64 运行时前缀
- `--qemu-arg "<arg>"`：额外 QEMU 参数字符串，可重复传入
- `--iterations <N>`：每个测试套件的工作量倍数
- `--dlclose-rounds <N>`：重复加载和卸载轮数
- `--no-strict-dso`：关闭基于 `dladdr()` 的严格栈帧归属检查

使用自定义编译器和自定义编译参数的示例：

```bash
python3 scripts/unwind_testsuite.py all \
  --out out/custom-aarch64 \
  --cxx <aarch64-c++> \
  --target aarch64-linux-gnu \
  --so-cxxflags "<shared-object compile flags>" \
  --ldflags "<link flags>" \
  --iterations 8 \
  --dlclose-rounds 128
```

兼容 wrapper：

```bash
./scripts/build_qemu_arm64.sh
./scripts/run_qemu_arm64.sh
./scripts/inspect_binaries.sh
```

### 长时间运行

可以增大 `--iterations` 和 `--dlclose-rounds` 以提高运行覆盖量：

```bash
python3 scripts/unwind_testsuite.py run \
  --iterations 20 \
  --dlclose-rounds 500
```

### 通过标准

一次有效运行应满足：

- 完成所有请求的轮次
- 所有导出测试套件均报告成功
- 采集大量 `_Unwind_Backtrace` 样本
- 不出现异常过浅的调用栈
- 覆盖异常抛出、捕获、清理和 rethrow 路径
- 执行虚调用、线程 worker、容器、递归和多继承场景
- 每一轮都加载并卸载插件共享库
- 启用严格 DSO 检查时，至少解析到一个来自当前测试共享库的栈帧
