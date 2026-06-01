#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${OUT:-"$ROOT/out/host"}"
CXX="${CXX:-clang++}"
OPT_FLAGS="${OPT_FLAGS:--O2}"

mkdir -p "$OUT"

read -r -a EXTRA_CXXFLAGS_ARRAY <<< "${EXTRA_CXXFLAGS:-}"

COMMON_FLAGS=(
  -std=c++17
  "$OPT_FLAGS"
  -g
  -fPIC
  -fno-omit-frame-pointer
  -fexceptions
  -funwind-tables
  -fasynchronous-unwind-tables
  -pthread
  -I"$ROOT/include"
  -ffile-prefix-map="$ROOT"=.
  -fdebug-prefix-map="$ROOT"=.
  -Wall
  -Wextra
)

"$CXX" "${COMMON_FLAGS[@]}" -fvisibility=hidden \
  "${EXTRA_CXXFLAGS_ARRAY[@]}" \
  -shared "$ROOT/src/outline_unwind_cases.cpp" \
  "$ROOT/src/outline_unwind_extra_cases.cpp" \
  "$ROOT/src/outline_unwind_deep_cases.cpp" \
  -Wl,-soname,libunwind_outline_cases.so \
  -o "$OUT/libunwind_outline_cases.so" -ldl -pthread

"$CXX" "${COMMON_FLAGS[@]}" -fvisibility=hidden \
  "${EXTRA_CXXFLAGS_ARRAY[@]}" \
  -shared "$ROOT/src/outline_unwind_plugin_cases.cpp" \
  -Wl,-soname,libunwind_outline_plugin.so \
  -o "$OUT/libunwind_outline_plugin.so" -ldl -pthread

"$CXX" "${COMMON_FLAGS[@]}" \
  "${EXTRA_CXXFLAGS_ARRAY[@]}" \
  "$ROOT/src/driver.cpp" \
  -Wl,-rpath,'$ORIGIN' \
  -o "$OUT/unwind_driver" -ldl -pthread

printf 'built host suite in %s\n' "${OUT#"$ROOT/"}"
