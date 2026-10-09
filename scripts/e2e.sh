#!/usr/bin/env bash
# End-to-end check of Layers 1 and 2: build the driver (pinned nightly) and the CLI (stable),
# generate each fixture's CBOM (validated against the CycloneDX schemas on every run), and
# fail on any of:
#   - a position that does not verify against the source, or a shifted position the
#     self-test does not reject (`cargo cbom verify --self-test`);
#   - a panic the driver caught ("N items could not be analysed"; RCBOM_DEBUG=1 prints them);
#   - a difference from the fixture's golden file (expected.txt, the whole CBOM as text:
#     scripts/summary.py);
#   - for the labelled rusi fixtures, a score that is not perfect, or that differs in any field
#     from the committed one (expected-score.json);
#   - for phase0/realapp, a Phase 0 algorithm that is no longer reported.
#   scripts/e2e.sh                       the fixtures
#   scripts/e2e.sh --realapp             also phase0/realapp
#   scripts/e2e.sh --realapp --regress   also fixtures/regress/* (the audit probes)
# Every CBOM is generated with the driver this script builds (debug, passed with --driver), not
# one $RCBOM_DRIVER names or a stale release build the CLI would otherwise prefer.
# RCBOM_BLESS=1 rewrites the golden files and committed scores instead of comparing (after a
# deliberate change, to be reviewed with git diff). Outputs go to $RCBOM_RESULTS if set
# (results/fixtures is the committed copy), else to a temporary directory.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
"$root/scripts/check.sh"
(cd "$root/crates/rcbom-driver" && cargo build -q)
(cd "$root" && cargo build -q)
cbom="$root/target/debug/cargo-cbom"
driver="$root/crates/rcbom-driver/target/debug/rcbom-driver"
unset RCBOM_DRIVER
out=${RCBOM_RESULTS:-$(mktemp -d)}
mkdir -p "$out"
realapp=0
regress=0
for a in "$@"; do
    case "$a" in
        --realapp) realapp=1 ;;
        --regress) regress=1 ;;
        *) echo "unknown option $a" >&2; exit 2 ;;
    esac
done

# generate, verify (every position, every shift), and compare with the golden file
run() {
    local dir=$1 name=$2
    echo "== ${dir#"$root"/}"
    (cd "$dir" && "$cbom" cbom --driver "$driver" -o "$out/$name.cbom.json" 2> "$out/$name.log") || { cat "$out/$name.log"; exit 1; }
    if grep 'could not be analysed' "$out/$name.log"; then
        echo "the driver caught panics: each is a bug (RCBOM_DEBUG=1 prints them)"; exit 1
    fi
    (cd "$dir" && "$cbom" cbom verify "$out/$name.cbom.json" --self-test) > "$out/$name.verify" || {
        cat "$out/$name.verify"; exit 1; }
    python3 - "$out/$name.verify" <<'PY'
import re, sys
text = open(sys.argv[1]).read()
v = re.search(r"(\d+) positions verified, (\d+) mismatched", text)
shifts = [tuple(map(int, m)) for m in re.findall(r"(\d+)/(\d+) shifted positions rejected", text)]
caught, total = sum(a for a, _ in shifts), sum(b for _, b in shifts)
print(f"positions: {v.group(1)} verified, {v.group(2)} mismatched; self-test: {caught}/{total} shifted positions rejected")
for line in text.splitlines():
    if line.startswith(("MISMATCH", "ACCEPTED")):
        print("  " + line)
sys.exit(0 if v.group(2) == "0" and caught == total else 1)
PY
    python3 "$root/scripts/summary.py" "$out/$name.cbom.json" > "$out/$name.txt"
    if [ -n "${RCBOM_BLESS:-}" ]; then
        cp "$out/$name.txt" "$dir/expected.txt"
        echo "golden file: written"
    else
        diff -u "$dir/expected.txt" "$out/$name.txt" > "$out/$name.diff" || {
            head -80 "$out/$name.diff"; echo "golden file differs: ${dir#"$root"/}/expected.txt"; exit 1; }
        echo "golden file: identical"
    fi
}

for g in micro libonly threads; do
    run "$root/fixtures/$g" "$g"
done

for d in "$root"/fixtures/rusi/*/; do
    f=$(basename "$d")
    run "${d%/}" "$f"
    python3 "$root/scripts/score.py" "$d/labels.toml" "$out/$f.cbom.json" --json > "$out/$f.score.json"
    if [ -n "${RCBOM_BLESS:-}" ]; then
        cp "$out/$f.score.json" "$d/expected-score.json"
    else
        diff -u "$d/expected-score.json" "$out/$f.score.json" || { echo "score differs: $f"; exit 1; }
    fi
    python3 - "$out/$f.score.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
print(f"score: recall {r['core_pairs_found']}/{r['core_pairs']}, precision {r['true_positive_pairs']}/{r['reported_pairs']}, fully named {r['fully_named']}/{r['core_pairs']}, provenance {r['provenance_exact']}/{r['provenance_total']}, crates {r['crates_found']}")
c_found, c_all = map(int, r["crates_found"].split("/"))
ok = (r["recall"] == 1 and r["precision"] == 1 and r["fully_named"] == r["core_pairs"]
      and r["provenance_exact"] == r["provenance_total"] and c_found == c_all)
sys.exit(0 if ok else 1)
PY
done

if [ "$realapp" = 1 ]; then
    run "$root/phase0/realapp" realapp
    python3 - "$out/realapp.cbom.json" "$root/phase0/cbom-realapp.json" <<'PY'
import json, sys
# Phase 0 produced algorithm assets only; knowledge-base growth may add, never lose, some
def names(p, algorithms_only):
    return {c["name"] for c in json.load(open(p))["components"] if c["type"] == "cryptographic-asset"
            and (not algorithms_only or c["cryptoProperties"]["assetType"] == "algorithm")}
new, old = names(sys.argv[1], True), names(sys.argv[2], False)
print(f"algorithms: {len(new)}; Phase 0's {len(old)} all present: {old <= new}; added since: {sorted(new - old)}; missing: {sorted(old - new)}")
sys.exit(0 if old <= new else 1)
PY
fi

if [ "$regress" = 1 ]; then
    for d in "$root"/fixtures/regress/*/; do
        run "${d%/}" "regress-$(basename "$d")"
    done
fi
echo "e2e: ok ($out)"
