#!/usr/bin/env bash
# Formatting and lints are enforced: rustfmt and clippy with warnings as errors, for the stable
# workspace and for the nightly driver (its own cargo project), then the unit tests.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
cargo fmt --all --check
cargo clippy -q --workspace --all-targets -- -D warnings
cargo test -q --workspace
cd crates/rcbom-driver
cargo fmt --check
cargo clippy -q --all-targets -- -D warnings
echo "check: ok"
