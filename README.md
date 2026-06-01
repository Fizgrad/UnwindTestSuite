# C++ unwind and DSO lifecycle test suite

# C++ unwind 与动态库生命周期测试集

## Purpose / 测试目标

This suite checks whether C++ stack unwinding remains correct while shared
objects are repeatedly loaded, executed, and unloaded. It focuses on
`_Unwind_Backtrace`, C++ exception propagation, RAII cleanup, PAC/BTI protected
AArch64 code, and dynamic `.eh_frame` registration or deregistration.

本测试集用于检查共享库在反复加载、执行和卸载过程中，C++ 栈回溯是否仍然正确。
测试重点包括 `_Unwind_Backtrace`、C++ 异常传播、RAII 析构清理、AArch64
PAC/BTI 保护代码，以及动态 `.eh_frame` 注册和注销路径。

The target failure mode is a process crash during runtime unwind metadata
handling, especially `SIGILL`, `SIGSEGV`, or `SIGABRT` around shared-object
unload and unwind table cleanup.

重点覆盖的失效模式是运行时处理 unwind 元数据时崩溃，尤其是共享库卸载和 unwind
表清理阶段出现的 `SIGILL`、`SIGSEGV` 或 `SIGABRT`。

## Test coverage / 测试覆盖

The main shared object contains many noinline C++ functions with repeated stack
frames, arithmetic work, backtrace captures, exception throw/catch paths, and
cleanup destructors. These functions are intentionally numerous and similar so
that the generated code has many unwind-sensitive call paths.

主测试共享库包含大量 `noinline` C++ 函数，这些函数会构造重复调用栈、执行计算、
采集 backtrace、触发异常抛出/捕获，并执行析构清理。函数数量和结构刻意做得较多，
用于形成大量对 unwind 敏感的调用路径。

The exported suites cover:

导出的测试套件覆盖：

- focused repeated call chains, direct `_Unwind_Backtrace`, cleanup destructors,
  and rethrow paths;
- mixed C++ features, including template recursion, virtual dispatch,
  function-pointer tables, `std::function`, vectors, strings, sorting, and
  threaded workers;
- deeper C++ cases, including `std::variant`, `std::optional`, `std::tuple`,
  `std::deque`, `std::map`, multiple inheritance, virtual graph evaluation, and
  recursive calls;
- a second plugin shared object that is loaded and unloaded every round;
- a plugin global destructor that captures a backtrace during `dlclose()`.

- 重复调用链、直接 `_Unwind_Backtrace`、析构清理和 rethrow 路径；
- 混合 C++ 特性，包括模板递归、虚调用、函数指针表、`std::function`、vector、
  string、排序和线程 worker；
- 更深的 C++ 场景，包括 `std::variant`、`std::optional`、`std::tuple`、
  `std::deque`、`std::map`、多继承、虚图遍历和递归调用；
- 第二个插件共享库，每一轮都会加载并卸载；
- 插件共享库的全局析构函数会在 `dlclose()` 阶段采集 backtrace。

## Host smoke test / 主机快速测试

```bash
cd <unwind_testsuite>
./scripts/build_host.sh
./scripts/run_host.sh
```

## Python runner / Python 运行入口

The main entry is `scripts/unwind_testsuite.py`. It accepts the compiler path,
target, compiler flags, linker flags, QEMU command, and QEMU arguments from the
command line. Architecture-specific experiments should be passed as ordinary
compiler or linker flags.

主入口是 `scripts/unwind_testsuite.py`。它从命令行接收编译器路径、target、
编译参数、链接参数、QEMU 命令和 QEMU 参数。架构相关实验参数应作为普通编译或链接
参数传入。

```bash
cd <unwind_testsuite>
python3 scripts/unwind_testsuite.py all \
  --cxx <aarch64-c++> \
  --target aarch64-linux-gnu \
  --cxxflag <compile-flag> \
  --ldflag <link-flag> \
  --qemu qemu-aarch64 \
  --qemu-ld-prefix /usr/aarch64-linux-gnu \
  --iterations 8 \
  --dlclose-rounds 128
```

Actions:

动作：

- `build`: compile the main shared object, plugin shared object, and driver.
- `run`: run the built AArch64 driver through QEMU.
- `inspect`: print selected section, symbol, and disassembly information.
- `all`: run `build`, `run`, and `inspect` in sequence.

- `build`：编译主测试共享库、插件共享库和 driver。
- `run`：通过 QEMU 运行已构建的 AArch64 driver。
- `inspect`：打印选定的 section、符号和反汇编信息。
- `all`：依次执行 `build`、`run` 和 `inspect`。

Common options:

常用选项：

- `--cxx`: compiler path. Default: `aarch64-linux-gnu-g++`.
- `--target`: optional target triple. When set, it is passed as
  `--target=<triple>`.
- `--out`: output directory. Default: `out/qemu-arm64`.
- `--opt`: optimization flag. Default: `-O2`.
- `--cxxflag`: extra compiler flag. Repeatable.
- `--cxxflags`: shell-style extra compiler flag string.
- `--so-cxxflag`: extra shared-library-only compiler flag. Repeatable.
- `--driver-cxxflag`: extra driver-only compiler flag. Repeatable.
- `--ldflag`: extra linker flag. Repeatable.
- `--ldflags`: shell-style extra linker flag string.
- `--qemu`: emulator command. Default: `qemu-aarch64`.
- `--qemu-ld-prefix`: AArch64 runtime prefix. Default:
  `/usr/aarch64-linux-gnu`.
- `--qemu-arg`: extra QEMU argument string. Repeatable.
- `--iterations`: per-suite work multiplier. Default: `8`.
- `--dlclose-rounds`: repeated load/unload rounds. Default: `128`.

- `--cxx`：编译器路径，默认：`aarch64-linux-gnu-g++`。
- `--target`：可选 target triple；设置后会传入 `--target=<triple>`。
- `--out`：输出目录，默认：`out/qemu-arm64`。
- `--opt`：优化选项，默认：`-O2`。
- `--cxxflag`：额外编译参数，可重复传入。
- `--cxxflags`：shell 风格的额外编译参数字符串。
- `--so-cxxflag`：仅用于共享库的额外编译参数，可重复传入。
- `--driver-cxxflag`：仅用于 driver 的额外编译参数，可重复传入。
- `--ldflag`：额外链接参数，可重复传入。
- `--ldflags`：shell 风格的额外链接参数字符串。
- `--qemu`：模拟器命令，默认：`qemu-aarch64`。
- `--qemu-ld-prefix`：AArch64 运行时前缀，默认：`/usr/aarch64-linux-gnu`。
- `--qemu-arg`：额外 QEMU 参数字符串，可重复传入。
- `--iterations`：每个测试套件的工作量倍数，默认：`8`。
- `--dlclose-rounds`：重复加载/卸载轮数，默认：`128`。

The compatibility wrappers still exist:

兼容 wrapper 仍然保留：

```bash
./scripts/build_qemu_arm64.sh
./scripts/run_qemu_arm64.sh
./scripts/inspect_binaries.sh
```

Each round performs this lifecycle:

每一轮执行以下生命周期：

1. `dlopen()` the main test shared object.
2. Run the focused, stress, and deep unwind suites.
3. `dlopen()` the plugin shared object.
4. Run the plugin unwind suite.
5. `dlclose()` the plugin shared object.
6. `dlclose()` the main test shared object.

1. `dlopen()` 主测试共享库。
2. 执行 focused、stress 和 deep unwind 测试套件。
3. `dlopen()` 插件共享库。
4. 执行 plugin unwind 测试套件。
5. `dlclose()` 插件共享库。
6. `dlclose()` 主测试共享库。

The driver installs short signal diagnostics for `SIGILL`, `SIGSEGV`, and
`SIGABRT`, then exits immediately after reporting the failing signal.

driver 会为 `SIGILL`、`SIGSEGV` 和 `SIGABRT` 安装简短诊断处理函数，在报告失败
信号后立即退出。

## Longer runs / 长时间运行

Override `ITERATIONS` and `DLCLOSE_ROUNDS` for quick smoke tests or longer
stability runs:

可以通过覆盖 `ITERATIONS` 和 `DLCLOSE_ROUNDS` 进行快速冒烟测试或更长时间的稳定性测试：

```bash
ITERATIONS=20 DLCLOSE_ROUNDS=500 ./scripts/run_qemu_arm64.sh
```

## Inspect generated binaries / 检查生成的二进制

```bash
./scripts/inspect_binaries.sh
```

This prints `.text`, `.eh_frame`, `.eh_frame_hdr`, `.gcc_except_table`, selected
test helper symbols, and selected disassembly markers from both generated
shared objects.

该脚本会打印两个共享库中的 `.text`、`.eh_frame`、`.eh_frame_hdr`、
`.gcc_except_table`、部分测试辅助函数符号和部分反汇编标记。

## Pass criteria / 通过标准

Each run is expected to complete all rounds and report successful results for
all exported suites. A valid run should include:

每次运行应完成所有轮次，并报告所有导出测试套件成功。有效运行应包含：

- many successful `_Unwind_Backtrace` captures;
- no unexpectedly shallow traces;
- many C++ exception throws, catches, and cleanup destructors;
- virtual dispatch and threaded worker cases in the stress suite;
- container, variant, optional, tuple, recursion, and multiple-inheritance cases
  in the deep suite;
- a second shared object loaded and unloaded on every round;
- at least one resolved frame from the active test shared object when strict DSO
  frame checking is enabled.

- 大量成功的 `_Unwind_Backtrace` 采集；
- 不应出现异常过浅的调用栈；
- 大量 C++ 异常抛出、捕获和析构清理；
- stress 套件中的虚调用和线程 worker 场景；
- deep 套件中的容器、variant、optional、tuple、递归和多继承场景；
- 每一轮都加载并卸载第二个共享库；
- 启用严格 DSO frame 检查时，至少应解析到一个来自当前测试共享库的栈帧。

The strict DSO-frame check can be disabled with `--no-strict-dso` if the target
libc or loader does not provide useful `dladdr()` results.

如果目标 libc 或加载器无法提供有效的 `dladdr()` 结果，可以使用
`--no-strict-dso` 关闭严格 DSO frame 检查。
