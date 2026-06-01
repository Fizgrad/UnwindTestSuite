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
  -shared "$ROOT/src/cfi_unwind_basic_cases.cpp" \
  "$ROOT/src/cfi_unwind_stress_cases.cpp" \
  "$ROOT/src/cfi_unwind_deep_cases.cpp" \
  "$ROOT/src/cfi_unwind_candidate_cases.cpp" \
  "$ROOT/src/cfi_unwind_extended_candidate_cases.cpp" \
  -Wl,-soname,libunwind_cfi_cases.so \
  -o "$OUT/libunwind_cfi_cases.so" -ldl -pthread

"$CXX" "${COMMON_FLAGS[@]}" -fvisibility=hidden \
  "${EXTRA_CXXFLAGS_ARRAY[@]}" \
  -shared "$ROOT/src/cfi_unwind_plugin_cases.cpp" \
  -Wl,-soname,libunwind_cfi_plugin.so \
  -o "$OUT/libunwind_cfi_plugin.so" -ldl -pthread

"$CXX" "${COMMON_FLAGS[@]}" \
  "${EXTRA_CXXFLAGS_ARRAY[@]}" \
  "$ROOT/src/driver.cpp" \
  -Wl,-rpath,'$ORIGIN' \
  -o "$OUT/unwind_driver" -ldl -pthread

printf 'built host suite in %s\n' "${OUT#"$ROOT/"}"
