#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${OUT:-"$ROOT/out/host"}"
ITERATIONS="${ITERATIONS:-6}"
DLCLOSE_ROUNDS="${DLCLOSE_ROUNDS:-32}"

cd "$OUT"

LD_LIBRARY_PATH=".:${LD_LIBRARY_PATH:-}" ./unwind_driver \
  --lib ./libunwind_outline_cases.so \
  --plugin ./libunwind_outline_plugin.so \
  --iterations "$ITERATIONS" \
  --dlclose-rounds "$DLCLOSE_ROUNDS" \
  --verbose
