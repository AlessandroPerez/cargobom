#!/usr/bin/env python3
"""Ablation of the monomorphized walk: run cargo-cbom with and without `--no-walk` on each
project and compare what the CBOM says.

usage: ablation.py OUT_DIR PROJECT_DIR...
Columns: assets with code evidence, code occurrences, of which reachable, of which found
inside a monomorphized generic instance ("instantiated by"), and (asset, line) pairs in the
project's own sources (src/).
"""
import json, pathlib, subprocess, sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
CBOM = ROOT / "target" / "debug" / "cargo-cbom"


def stats(path):
    d = json.load(open(path))
    crypto = [c for c in d["components"] if c["type"] == "cryptographic-asset"]
    occ = [(c["name"], o) for c in crypto for o in c["evidence"]["occurrences"]
           if not o["additionalContext"].startswith("[manifest]")]
    own = {(n, o["line"]) for n, o in occ if o["location"].startswith("src/")}
    return {
        "assets": len({n for n, _ in occ}),
        "occurrences": len(occ),
        "reachable": sum(1 for _, o in occ if o["additionalContext"].startswith("[reachable]")),
        "in_generic_instance": sum(1 for _, o in occ if "instantiated by" in o["additionalContext"]),
        "own_pairs": own,
    }


def main():
    out = pathlib.Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    print(f"{'project':28} {'mode':8} {'assets':>6} {'occ':>5} {'reach':>5} {'in-mono':>7} {'own (asset,line)':>16}")
    rows = []
    for proj in map(pathlib.Path, sys.argv[2:]):
        res = {}
        for mode, flags in (("full", []), ("no-walk", ["--no-walk"])):
            path = out / f"{proj.name}.{mode}.json"
            subprocess.run([str(CBOM), "cbom", *flags, "-o", str(path)], cwd=proj, check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            res[mode] = stats(path)
            s = res[mode]
            print(f"{proj.name:28} {mode:8} {s['assets']:6} {s['occurrences']:5} {s['reachable']:5} "
                  f"{s['in_generic_instance']:7} {len(s['own_pairs']):16}")
        lost = sorted(res["full"]["own_pairs"] - res["no-walk"]["own_pairs"])
        if lost:
            print(f"   only with the walk: {lost}")
        rows.append({"project": proj.name, **{m: {k: v for k, v in r.items() if k != "own_pairs"} | {"own_pairs": len(r["own_pairs"])} for m, r in res.items()}, "only_with_walk": lost})
    json.dump(rows, open(out / "ablation.json", "w"), indent=2)


if __name__ == "__main__":
    main()
