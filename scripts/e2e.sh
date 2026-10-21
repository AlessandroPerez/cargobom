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
#   scripts/e2e.sh --suite               also fixtures/suite/* (the ground-truth suite: labels
#                                        written from source before any tool run; its score must
#                                        equal the committed fixtures/suite/expected-score.json)
#   --only GLOB                          only the fixtures whose path in the repo matches GLOB
#                                        (repeatable: --only 'fixtures/regress/analysis-0*'); the
#                                        suite score is checked only when every program ran
# Every CBOM is generated with the binaries this script builds (cargo profile `e2e`: optimised,
# with overflow checks and debug assertions), passed with --driver, not one $RCBOM_DRIVER names
# or another build the CLI would otherwise prefer.
# Fixtures run $RCBOM_JOBS at a time (default 3), each cargo with its share of the cores; every
# fixture runs to the end, and the failures are printed together. A fixture's whole output is
# in <outputs>/<name>.e2e.log (all of them, in order, in e2e.log), its time on its `==` line.
# RCBOM_E2E_CACHE=dir keeps each fixture's build cache and facts in dir/<name> instead of the
# fixture's own target/ (for a directory outside the sources and their snapshots). Either way a
# cache built by the same driver binary is reused: after a change to the analysis, the CLI or
# the verifier only, a run compiles nothing and replays the recorded facts.
# RCBOM_BLESS=1 rewrites the golden files and committed scores instead of comparing (after a
# deliberate change, to be reviewed with git diff). Outputs go to $RCBOM_RESULTS if set
# (results/fixtures is the committed copy), else to a temporary directory.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)

# generate and verify (every position, every shift)
generate() {
    local dir=$1 name=$2
    echo "== ${dir#"$root"/}"
    local env=()
    if [ -n "${RCBOM_E2E_CACHE:-}" ]; then
        env=(env "CARGO_TARGET_DIR=$RCBOM_E2E_CACHE/$name")
    fi
    (cd "$dir" && ${env[@]+"${env[@]}"} "$cbom" cbom --driver "$driver" -o "$out/$name.cbom.json" 2> "$out/$name.log") || { cat "$out/$name.log"; return 1; }
    if grep 'could not be analysed' "$out/$name.log"; then
        echo "the driver caught panics: each is a bug (RCBOM_DEBUG=1 prints them)"; return 1
    fi
    # the CBOM named by its file name, as it sits next to the report in the results
    # (with known verifier limits, the check below decides)
    local status=0
    (cd "$dir" && ${env[@]+"${env[@]}"} "$cbom" cbom verify "$out/$name.cbom.json" --self-test) | sed "s#^$out/##" > "$out/$name.verify" || status=$?
    if [ "$status" -ne 0 ] && [ ! -f "$dir/verify-known" ]; then
        cat "$out/$name.verify"; return 1
    fi
    # (a fixture's `verify-known`: the mismatches of correct positions the verifier cannot
    # confirm, checked by hand, one `MISMATCH` line each; exactly those may occur)
    python3 - "$out/$name.verify" "$dir/verify-known" <<'PY'
import os, re, sys
text = open(sys.argv[1]).read()
v = re.search(r"(\d+) positions verified, (\d+) mismatched", text)
shifts = [tuple(map(int, m)) for m in re.findall(r"(\d+)/(\d+) shifted positions rejected", text)]
caught, total = sum(a for a, _ in shifts), sum(b for _, b in shifts)
print(f"positions: {v.group(1)} verified, {v.group(2)} mismatched; self-test: {caught}/{total} shifted positions rejected")
known = set()
if os.path.exists(sys.argv[2]):
    known = {l.strip() for l in open(sys.argv[2]) if l.strip() and not l.startswith("#")}
found = set()
for line in text.splitlines():
    if line.startswith(("MISMATCH", "ACCEPTED")):
        print("  " + line + ("  (known verifier limit)" if line.strip() in known else ""))
    if line.startswith("MISMATCH"):
        found.add(line.strip())
for line in sorted(known - found):
    print("  stale verify-known entry (the position now verifies, or changed): " + line)
sys.exit(0 if found == known and caught == total else 1)
PY
}

# generate, verify, and compare with the golden file
run() {
    local dir=$1 name=$2
    generate "$dir" "$name" || return 1
    python3 "$root/scripts/summary.py" "$out/$name.cbom.json" > "$out/$name.txt"
    if [ -n "${RCBOM_BLESS:-}" ]; then
        cp "$out/$name.txt" "$dir/expected.txt"
        echo "golden file: written"
    else
        diff -u "$dir/expected.txt" "$out/$name.txt" > "$out/$name.diff" || {
            head -80 "$out/$name.diff"; echo "golden file differs: ${dir#"$root"/}/expected.txt"; return 1; }
        rm -f "$out/$name.diff"
        echo "golden file: identical"
    fi
}

# a labelled rusi fixture: its golden file, and its score, perfect and as committed
rusi() {
    local dir=$1 f=$2
    run "$dir" "$f" || return 1
    python3 "$root/scripts/score.py" "$dir/labels.toml" "$out/$f.cbom.json" --json > "$out/$f.score.json"
    if [ -n "${RCBOM_BLESS:-}" ]; then
        cp "$out/$f.score.json" "$dir/expected-score.json"
    else
        diff -u "$dir/expected-score.json" "$out/$f.score.json" || { echo "score differs: $f"; return 1; }
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
}

# phase0/realapp: its golden file, and every algorithm Phase 0 found
realapp() {
    run "$1" "$2" || return 1
    python3 - "$out/$2.cbom.json" "$root/phase0/cbom-realapp.json" <<'PY'
import json, sys
# Phase 0 produced algorithm assets only; knowledge-base growth may add, never lose, some
def names(p, algorithms_only):
    return {c["name"] for c in json.load(open(p))["components"] if c["type"] == "cryptographic-asset"
            and (not algorithms_only or c["cryptoProperties"]["assetType"] == "algorithm")}
new, old = names(sys.argv[1], True), names(sys.argv[2], False)
print(f"algorithms: {len(new)}; Phase 0's {len(old)} all present: {old <= new}; added since: {sorted(new - old)}; missing: {sorted(old - new)}")
sys.exit(0 if old <= new else 1)
PY
}

# one fixture, run by the loop below: its output to <name>.e2e.log, its verdict on one line
if [ "${1:-}" = --one ]; then
    kind=$2 dir=$3 name=$4
    t0=$(date +%s)
    status=0
    "$kind" "$dir" "$name" > "$out/$name.e2e.log" 2>&1 || status=$?
    t=$(( $(date +%s) - t0 ))
    # (the verdict is the log's last line: a fixture whose run was cut short has none)
    if [ "$status" -eq 0 ]; then
        echo "e2e fixture: ok" >> "$out/$name.e2e.log"
        echo "== ${dir#"$root"/}: ok ($t s)"
    else
        echo "e2e fixture: FAILED" >> "$out/$name.e2e.log"
        echo "== ${dir#"$root"/}: FAILED ($t s)"
    fi
    exit 0
fi

realapp=0
regress=0
suite=0
only=()
while [ $# -gt 0 ]; do
    case "$1" in
        --realapp) realapp=1 ;;
        --regress) regress=1 ;;
        --suite) suite=1 ;;
        --only) only+=("$2"); shift ;;
        *) echo "unknown option $1" >&2; exit 2 ;;
    esac
    shift
done

"$root/scripts/check.sh"
(cd "$root/crates/rcbom-driver" && cargo build -q --profile e2e)
(cd "$root" && cargo build -q --profile e2e)
export cbom="$root/target/e2e/cargo-cbom"
export driver="$root/crates/rcbom-driver/target/e2e/rcbom-driver"
export root
unset RCBOM_DRIVER
out=${RCBOM_RESULTS:-$(mktemp -d)}
mkdir -p "$out" "$out/suite"
# absolute: the generator and the verifier run in each fixture's directory
out=$(cd "$out" && pwd)
export out
jobs=${RCBOM_JOBS:-3}
export CARGO_BUILD_JOBS=$(( $(nproc) / jobs > 0 ? $(nproc) / jobs : 1 ))

# the fixtures to run, in order: kind, directory, output name
list=()
add() {
    local rel=${2#"$root"/} p
    if [ ${#only[@]} -gt 0 ]; then
        for p in "${only[@]}"; do
            # shellcheck disable=SC2053
            if [[ $rel == $p ]]; then
                list+=("$1" "$2" "$3")
                return 0
            fi
        done
        return 0
    fi
    list+=("$1" "$2" "$3")
}
for g in micro libonly threads; do
    add run "$root/fixtures/$g" "$g"
done
for d in "$root"/fixtures/rusi/*/; do
    add rusi "${d%/}" "$(basename "$d")"
done
if [ "$realapp" = 1 ]; then
    add realapp "$root/phase0/realapp" realapp
fi
if [ "$regress" = 1 ]; then
    for d in "$root"/fixtures/regress/*/; do
        add run "${d%/}" "regress-$(basename "$d")"
    done
fi
suite_all=0
if [ "$suite" = 1 ]; then
    n=$(( ${#list[@]} / 3 ))
    for d in "$root"/fixtures/suite/*/; do
        add generate "${d%/}" "suite/$(basename "$d")"
    done
    [ $(( ${#list[@]} / 3 - n )) -eq "$(ls -d "$root"/fixtures/suite/*/ | wc -l)" ] && suite_all=1
fi
[ ${#list[@]} -gt 0 ] || { echo "no fixture matches"; exit 2; }

echo "e2e: $(( ${#list[@]} / 3 )) fixtures, $jobs at a time (outputs in $out)"
printf '%s\0' "${list[@]}" | xargs -0 -n 3 -P "$jobs" "$0" --one

# every fixture's output, in order, and the failures
failed=()
: > "$out/e2e.log"
for (( i = 0; i < ${#list[@]}; i += 3 )); do
    name=${list[i+2]}
    cat "$out/$name.e2e.log" >> "$out/e2e.log" 2> /dev/null || true
    [ "$(tail -1 "$out/$name.e2e.log" 2> /dev/null)" = "e2e fixture: ok" ] || failed+=("$name")
done
if [ "$suite" = 1 ]; then
    if [ "$suite_all" = 1 ]; then
        python3 "$root/scripts/suite.py" "$out/suite" "$root"/fixtures/suite/*/ --json > "$out/suite-score.json"
        python3 "$root/scripts/suite.py" "$out/suite" "$root"/fixtures/suite/*/ > "$out/suite-score.txt"
        head -1 "$out/suite-score.txt"
        if [ -n "${RCBOM_BLESS:-}" ]; then
            cp "$out/suite-score.json" "$root/fixtures/suite/expected-score.json"
            echo "suite score: written"
        elif diff -u "$root/fixtures/suite/expected-score.json" "$out/suite-score.json"; then
            echo "suite score: identical"
        else
            echo "suite score differs: fixtures/suite/expected-score.json"; failed+=("suite score")
        fi
    else
        echo "suite score: not checked (not every suite program ran)"
    fi
fi
if [ ${#failed[@]} -gt 0 ]; then
    for name in "${failed[@]}"; do
        if [ -f "$out/$name.e2e.log" ]; then echo; cat "$out/$name.e2e.log"; fi
    done
    echo
    echo "e2e: ${#failed[@]} failed: ${failed[*]} ($out)"
    exit 1
fi
echo "e2e: ok ($out)"
