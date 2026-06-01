#!/usr/bin/env python3
import argparse
import os
import shlex
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

MAIN_SO = "libunwind_outline_cases.so"
PLUGIN_SO = "libunwind_outline_plugin.so"
DRIVER = "unwind_driver"

MAIN_SOURCES = [
    ROOT / "src" / "outline_unwind_cases.cpp",
    ROOT / "src" / "outline_unwind_extra_cases.cpp",
    ROOT / "src" / "outline_unwind_deep_cases.cpp",
]
PLUGIN_SOURCES = [ROOT / "src" / "outline_unwind_plugin_cases.cpp"]
DRIVER_SOURCES = [ROOT / "src" / "driver.cpp"]


def split_flags(value):
    if not value:
        return []
    return shlex.split(value)


def rel(path):
    try:
        return str(Path(path).resolve().relative_to(ROOT))
    except ValueError:
        return str(path)


def run_cmd(cmd, *, cwd=None, env=None, dry_run=False):
    printable = " ".join(shlex.quote(str(part)) for part in cmd)
    print(f"+ {printable}")
    if dry_run:
        return
    try:
        subprocess.run([str(part) for part in cmd], cwd=cwd, env=env, check=True)
    except subprocess.CalledProcessError as error:
        raise SystemExit(error.returncode) from None


def target_flags(args):
    if not args.target:
        return []
    return [f"--target={args.target}"]


def default_common_cxxflags(args):
    if args.no_default_cxxflags:
        return []
    return [
        "-std=c++17",
        args.opt,
        "-g",
        "-fPIC",
        "-fno-omit-frame-pointer",
        "-fexceptions",
        "-funwind-tables",
        "-fasynchronous-unwind-tables",
        "-pthread",
        f"-I{ROOT / 'include'}",
        f"-ffile-prefix-map={ROOT}=.",
        f"-fdebug-prefix-map={ROOT}=.",
        "-Wall",
        "-Wextra",
    ]


def default_so_cxxflags(args):
    if args.no_default_cxxflags:
        return []
    return ["-fvisibility=hidden"]


def default_ldflags(args):
    if args.no_default_ldflags:
        return []
    return [
        "-Wl,--build-id=sha1",
        "-Wl,-z,relro",
        "-Wl,-z,now",
        "-Wl,--gc-sections",
    ]


def collect_cxxflags(args):
    flags = []
    flags += split_flags(args.cxxflags)
    flags += args.cxxflag
    return flags


def collect_so_cxxflags(args):
    flags = []
    flags += split_flags(args.so_cxxflags)
    flags += args.so_cxxflag
    return flags


def collect_driver_cxxflags(args):
    flags = []
    flags += split_flags(args.driver_cxxflags)
    flags += args.driver_cxxflag
    return flags


def collect_ldflags(args):
    flags = []
    flags += split_flags(args.ldflags)
    flags += args.ldflag
    return flags


def build_shared(args, out, name, sources):
    cmd = [
        args.cxx,
        *target_flags(args),
        *default_common_cxxflags(args),
        *args.branch_protection_flags,
        *collect_cxxflags(args),
        *default_so_cxxflags(args),
        *collect_so_cxxflags(args),
        "-shared",
        *sources,
        *default_ldflags(args),
        *collect_ldflags(args),
        f"-Wl,-soname,{name}",
        "-o",
        out / name,
        "-ldl",
        "-pthread",
    ]
    run_cmd(cmd, dry_run=args.dry_run)


def build_driver(args, out):
    cmd = [
        args.cxx,
        *target_flags(args),
        *default_common_cxxflags(args),
        *args.branch_protection_flags,
        *collect_cxxflags(args),
        *collect_driver_cxxflags(args),
        *DRIVER_SOURCES,
        *default_ldflags(args),
        *collect_ldflags(args),
        "-Wl,-rpath,$ORIGIN",
        "-o",
        out / DRIVER,
        "-ldl",
        "-pthread",
    ]
    run_cmd(cmd, dry_run=args.dry_run)


def build(args):
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    build_shared(args, out, MAIN_SO, MAIN_SOURCES)
    build_shared(args, out, PLUGIN_SO, PLUGIN_SOURCES)
    build_driver(args, out)
    print(f"built suite in {rel(out)}")
    print(f"compiler: {args.cxx}")


def qemu_command(args, out):
    command = [args.qemu]
    if args.qemu_ld_prefix:
        command += ["-L", args.qemu_ld_prefix]
    for item in args.qemu_arg:
        command += shlex.split(item)
    command += [
        "-E",
        f"LD_LIBRARY_PATH=.:{os.environ.get('LD_LIBRARY_PATH', '')}",
        f"./{DRIVER}",
        "--lib",
        f"./{MAIN_SO}",
        "--plugin",
        f"./{PLUGIN_SO}",
        "--iterations",
        str(args.iterations),
        "--dlclose-rounds",
        str(args.dlclose_rounds),
    ]
    if args.verbose:
        command.append("--verbose")
    if args.no_strict_dso:
        command.append("--no-strict-dso")
    command += args.driver_arg
    return command


def run_suite(args):
    out = Path(args.out)
    driver = out / DRIVER
    if not driver.exists():
        raise SystemExit(f"missing {rel(driver)}; run build first")
    run_cmd(qemu_command(args, out), cwd=out, dry_run=args.dry_run)


def inspect_one(args, so, label):
    if not so.exists():
        print(f"skip {label}: missing {rel(so)}")
        return

    print(f"== {label} sections ==")
    readelf = subprocess.run(
        [args.readelf, "-SW", str(so)],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    )
    for line in readelf.stdout.splitlines():
        if any(section in line for section in (".text", ".eh_frame", ".eh_frame_hdr", ".gcc_except_table")):
            print(line)

    print(f"\n== {label} test helper symbols ==")
    nm = subprocess.run(
        [args.nm, "-anC", str(so)],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    )
    printed = 0
    for line in nm.stdout.splitlines():
        if any(token in line for token in ("compiler_helper", "repeated_", "vectorCase_", "pluginCase_", "run_unwind_")):
            print(line)
            printed += 1
            if printed >= args.inspect_limit:
                break

    print(f"\n== {label} selected disassembly markers ==")
    objdump = subprocess.run(
        [args.objdump, "-dr", "--no-show-raw-insn", str(so)],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    )
    printed = 0
    for line in objdump.stdout.splitlines():
        if "compiler_helper" in line or "run_unwind_" in line:
            print(line)
            printed += 1
            if printed >= args.inspect_disasm_limit:
                break


def inspect(args):
    out = Path(args.out)
    inspect_one(args, out / MAIN_SO, "main")
    print()
    inspect_one(args, out / PLUGIN_SO, "plugin")


def add_common_args(parser):
    parser.add_argument("--out", default=str(ROOT / "out" / "qemu-arm64"))
    parser.add_argument("--dry-run", action="store_true")


def add_build_args(parser):
    parser.add_argument("--cxx", default=os.environ.get("CXX", "aarch64-linux-gnu-g++"))
    parser.add_argument("--target", default=os.environ.get("TARGET", ""))
    parser.add_argument("--opt", default=os.environ.get("OPT_FLAGS", "-O2"))
    parser.add_argument("--cxxflag", action="append", default=[], help="extra compiler flag; repeatable")
    parser.add_argument("--cxxflags", default=os.environ.get("EXTRA_CXXFLAGS", ""), help="shell-style extra compiler flags")
    parser.add_argument("--so-cxxflag", action="append", default=[], help="extra shared-library compile flag; repeatable")
    parser.add_argument("--so-cxxflags", default="", help="shell-style shared-library compile flags")
    parser.add_argument("--driver-cxxflag", action="append", default=[], help="extra driver compile flag; repeatable")
    parser.add_argument("--driver-cxxflags", default="", help="shell-style driver compile flags")
    parser.add_argument("--ldflag", action="append", default=[], help="extra link flag; repeatable")
    parser.add_argument("--ldflags", default=os.environ.get("EXTRA_LDFLAGS", ""), help="shell-style extra link flags")
    parser.add_argument(
        "--branch-protection-flags",
        default=split_flags(os.environ.get("BRANCH_PROTECTION_FLAGS", "-mbranch-protection=pac-ret+bti")),
        nargs="*",
    )
    parser.add_argument("--no-default-cxxflags", action="store_true")
    parser.add_argument("--no-default-ldflags", action="store_true")


def add_run_args(parser):
    parser.add_argument("--qemu", default=os.environ.get("QEMU", "qemu-aarch64"))
    parser.add_argument("--qemu-ld-prefix", default=os.environ.get("QEMU_LD_PREFIX", "/usr/aarch64-linux-gnu"))
    parser.add_argument("--qemu-arg", action="append", default=[], help="extra qemu argument string; repeatable")
    parser.add_argument("--iterations", type=int, default=int(os.environ.get("ITERATIONS", "8")))
    parser.add_argument("--dlclose-rounds", type=int, default=int(os.environ.get("DLCLOSE_ROUNDS", "128")))
    parser.add_argument("--driver-arg", action="append", default=[], help="extra unwind_driver argument; repeatable")
    parser.add_argument("--no-strict-dso", action="store_true")
    parser.add_argument("--verbose", action=argparse.BooleanOptionalAction, default=True)


def add_inspect_args(parser):
    parser.add_argument("--readelf", default=os.environ.get("READELF", "aarch64-linux-gnu-readelf"))
    parser.add_argument("--nm", default=os.environ.get("NM", "aarch64-linux-gnu-nm"))
    parser.add_argument("--objdump", default=os.environ.get("OBJDUMP", "aarch64-linux-gnu-objdump"))
    parser.add_argument("--inspect-limit", type=int, default=180)
    parser.add_argument("--inspect-disasm-limit", type=int, default=100)


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Build, run, and inspect the C++ unwind DSO lifecycle suite.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    build_parser = subparsers.add_parser("build")
    add_common_args(build_parser)
    add_build_args(build_parser)

    run_parser = subparsers.add_parser("run")
    add_common_args(run_parser)
    add_run_args(run_parser)

    inspect_parser = subparsers.add_parser("inspect")
    add_common_args(inspect_parser)
    add_inspect_args(inspect_parser)

    all_parser = subparsers.add_parser("all")
    add_common_args(all_parser)
    add_build_args(all_parser)
    add_run_args(all_parser)
    add_inspect_args(all_parser)

    return parser.parse_args(argv)


def main(argv):
    args = parse_args(argv)
    if args.command == "build":
        build(args)
    elif args.command == "run":
        run_suite(args)
    elif args.command == "inspect":
        inspect(args)
    elif args.command == "all":
        build(args)
        run_suite(args)
        inspect(args)
    else:
        raise AssertionError(args.command)


if __name__ == "__main__":
    main(sys.argv[1:])
