#!/usr/bin/env bash
# Phase 0 RUSTC_WRAPPER: the Kani/Charon/MIRAI pattern on a stable toolchain.
# Cargo calls: $0 <rustc> <args...>. For every real crate compile we
#   1. compile normally, adding -Zprint-mono-items (the compiler's monomorphization
#      collector, the same data rustc_public exposes as Instance), stdout -> <crate>.mono
#   2. re-run with -Zunpretty=mir to dump MIR, incl. named static allocations, -> <crate>.mir
# Build scripts and proc macros are compiled untouched (they run on the host).
set -u
RUSTC="$1"; shift
OUT="${RCBOM_OUT:?set RCBOM_OUT}"
crate=""; kind=""; prev=""
for a in "$@"; do
  [ "$prev" = "--crate-name" ] && crate="$a"
  [ "$prev" = "--crate-type" ] && kind="$a"
  prev="$a"
done
if [ -z "$crate" ] || [ "$kind" = "proc-macro" ] || [[ "$crate" == build_script_* ]]; then
  exec "$RUSTC" "$@"
fi
mkdir -p "$OUT"
"$RUSTC" "$@" -Zunpretty=mir >"$OUT/$crate.mir" 2>/dev/null || true
exec "$RUSTC" "$@" -Zprint-mono-items >"$OUT/$crate.mono"
