#!/usr/bin/env bash
# End-to-end check of Layers 1 and 2: build the driver (pinned nightly) and the CLI (stable),
# generate CBOMs, validate them, verify every cited position against the source (with the
# shifted-position self-test), and compare the fixture with its golden file.
#   scripts/e2e.sh            the fixtures
#   scripts/e2e.sh --realapp  also phase0/realapp, compared with the Phase 0 asset list
# Outputs (<name>.cbom.json, scores, logs) go to $RCBOM_RESULTS if set (results/fixtures is the
# committed copy), else to a temporary directory.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
"$root/scripts/check.sh"
(cd "$root/crates/rcbom-driver" && cargo build -q)
(cd "$root" && cargo build -q)
cbom="$root/target/debug/cargo-cbom"
out=${RCBOM_RESULTS:-$(mktemp -d)}
mkdir -p "$out"

for g in micro libonly threads; do
    echo "== fixtures/$g"
    (cd "$root/fixtures/$g" && "$cbom" cbom -o "$out/$g.cbom.json" 2> "$out/$g.log") || { cat "$out/$g.log"; exit 1; }
    (cd "$root/fixtures/$g" && "$cbom" cbom verify "$out/$g.cbom.json" --self-test)
    python3 "$root/scripts/summary.py" "$out/$g.cbom.json" > "$out/$g.txt"
    diff -u "$root/fixtures/$g/expected.txt" "$out/$g.txt" || { echo "golden file differs: fixtures/$g/expected.txt"; exit 1; }
    echo "golden file: identical"
done

for d in "$root"/fixtures/rusi/*/; do
    f=$(basename "$d")
    echo "== fixtures/rusi/$f"
    (cd "$d" && "$cbom" cbom -o "$out/$f.cbom.json" 2> "$out/$f.log") || { cat "$out/$f.log"; exit 1; }
    (cd "$d" && "$cbom" cbom verify "$out/$f.cbom.json" | tail -1)
    python3 "$root/scripts/score.py" "$d/labels.toml" "$out/$f.cbom.json" --json > "$out/$f.score.json"
    python3 - "$out/$f.score.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
print(f"score: recall {r['core_pairs_found']}/{r['core_pairs']}, precision {r['true_positive_pairs']}/{r['reported_pairs']}, fully named {r['fully_named']}/{r['core_pairs']}, provenance {r['provenance_exact']}/{r['provenance_total']}")
ok = r["recall"] == 1 and r["precision"] == 1 and r["fully_named"] == r["core_pairs"] and r["provenance_exact"] == r["provenance_total"]
sys.exit(0 if ok else 1)
PY
done

if [ "${1:-}" = "--realapp" ]; then
    echo "== phase0/realapp"
    (cd "$root/phase0/realapp" && "$cbom" cbom -o "$out/realapp.cbom.json" 2> "$out/realapp.log") || { cat "$out/realapp.log"; exit 1; }
    (cd "$root/phase0/realapp" && "$cbom" cbom verify "$out/realapp.cbom.json" --self-test)
    python3 - "$out/realapp.cbom.json" "$root/phase0/cbom-realapp.json" <<'PY'
import json, sys
# Phase 0 produced algorithm assets only; key material and protocol assets came later
def names(p, algorithms_only):
    return {c["name"] for c in json.load(open(p))["components"] if c["type"] == "cryptographic-asset"
            and (not algorithms_only or c["cryptoProperties"]["assetType"] == "algorithm")}
new, old = names(sys.argv[1], True), names(sys.argv[2], False)
others = sorted(names(sys.argv[1], False) - new)
print(f"algorithms: {len(new)}; same set as Phase 0: {new == old}; only now: {sorted(new - old)}; only Phase 0: {sorted(old - new)}; other assets: {others}")
sys.exit(0 if new == old else 1)
PY
fi
echo "e2e: ok ($out)"
