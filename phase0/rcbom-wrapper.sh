#!/usr/bin/env bash
# Phase 0 RUSTC_WRAPPER: the Kani/Charon/MIRAI pattern on a stable toolchain.
# Cargo calls: $0 <rustc> <args...>. For every real crate compile we
#   1. re-run with -Zunpretty=mir -Zmir-include-spans=yes to dump MIR, incl. named static
#      allocations and a `// scope N at FILE:LINE:COL: LINE:COL` span on every statement,
#      -> <crate>-<version>.mir
#   2. compile normally, adding -Zprint-mono-items (the compiler's monomorphization
#      collector, the same data rustc_public exposes as Instance), stdout -> <crate>-<version>.mono
#   3. record where rustc ran and which package it was, -> <crate>-<version>.meta, so the
#      extractor can turn span paths (relative to rustc's cwd) into source locations.
# Files carry the package version because a lockfile can hold two versions of one crate
# (realapp has sha2 0.10 and 0.11); keyed by crate name alone, the second overwrote the first.
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
base="$OUT/$crate-${CARGO_PKG_VERSION:-0.0.0}"
printf 'crate=%s\nversion=%s\npackage=%s\ncwd=%s\nmanifest_dir=%s\nprimary=%s\n' \
  "$crate" "${CARGO_PKG_VERSION:-}" "${CARGO_PKG_NAME:-}" "$PWD" "${CARGO_MANIFEST_DIR:-}" \
  "${CARGO_PRIMARY_PACKAGE:-}" >"$base.meta"
"$RUSTC" "$@" -Zunpretty=mir -Zmir-include-spans=yes >"$base.mir" 2>/dev/null || true
exec "$RUSTC" "$@" -Zprint-mono-items >"$base.mono"
