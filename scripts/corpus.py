#!/usr/bin/env python3
"""Feasibility run on real projects: time and memory against a plain `cargo check`, what the
CBOM contains, and whether every cited position verifies.

usage: corpus.py OUT_DIR PROJECT_DIR... [--rusi PATH_TO_RUSI]
Writes OUT_DIR/<project>.cbom.json and prints one table row per project. Each project is
built from a cold cache (its rcbom target directory is removed first).
"""
import json, os, pathlib, re, shutil, subprocess, sys, time

ROOT = pathlib.Path(__file__).resolve().parent.parent
CBOM = ROOT / "target" / "debug" / "cargo-cbom"
DRIVER = ROOT / "crates" / "rcbom-driver" / "target" / "debug" / "rcbom-driver"
TOOLCHAIN = "nightly-2026-09-25"


def run(cmd, cwd, env=None):
    """Wall time and peak RSS (MiB) of the largest process in the tree."""
    probe = ("import resource,subprocess,sys,time;t=time.time();"
             "r=subprocess.run(sys.argv[1:],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE);"
             "print(r.returncode,time.time()-t,resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss);"
             "sys.stderr.write(r.stderr.decode(errors='replace'))")
    p = subprocess.run([sys.executable, "-c", probe, *cmd], cwd=cwd, env=env, capture_output=True, text=True)
    code, secs, rss = p.stdout.split()
    return int(code), float(secs), int(rss) / 1024, p.stderr


def stats(path):
    d = json.load(open(path))
    crypto = [c for c in d["components"] if c["type"] == "cryptographic-asset"]
    kinds = {}
    for c in crypto:
        t = c["cryptoProperties"]["assetType"]
        kinds[t] = kinds.get(t, 0) + 1
    occ = [o for c in crypto for o in c["evidence"]["occurrences"] if not o["additionalContext"].startswith("[manifest]")]
    props = [(p["name"], p["value"]) for c in crypto for p in c.get("properties", [])]
    findings = sorted({v for n, v in props if n == "rcbom:finding"})
    reach_assets = sum(1 for c in crypto for p in c.get("properties", []) if p["name"] == "rcbom:reachability" and p["value"] == "reachable")
    libs = [c for c in d["components"] if c["type"] in ("library", "application")]
    return {
        "algorithms": kinds.get("algorithm", 0),
        "material": kinds.get("related-crypto-material", 0),
        "protocols": kinds.get("protocol", 0),
        "reachable_assets": reach_assets,
        "reachable_algorithms": sum(1 for c in crypto
                                    if c["cryptoProperties"]["assetType"] == "algorithm"
                                    and any(p["name"] == "rcbom:reachability" and p["value"] == "reachable"
                                            for p in c.get("properties", []))),
        "occurrences": len(occ),
        "reachable_occurrences": sum(1 for o in occ if o["additionalContext"].startswith("[reachable]")),
        "findings": findings,
        "crypto_crates": sum(1 for c in libs if any(p["name"] == "rcbom:crypto-role" for p in c.get("properties", []))),
        "instances": next((p["value"] for p in d["metadata"].get("properties", []) if p["name"] == "rcbom:run:reachable-instances"), "0"),
    }


def main():
    args = sys.argv[1:]
    rusi = None
    if "--rusi" in args:
        i = args.index("--rusi")
        rusi = args[i + 1]
        del args[i:i + 2]
    out = pathlib.Path(args[0])
    out.mkdir(parents=True, exist_ok=True)
    rows = []
    for proj in map(pathlib.Path, args[1:]):
        name = proj.name
        plain_dir = out / f"{name}.plain-target"
        shutil.rmtree(plain_dir, ignore_errors=True)
        c0, t_plain, rss_plain, err0 = run(["cargo", f"+{TOOLCHAIN}", "check", "--release", "--locked", "--quiet", "--target-dir", str(plain_dir)], proj)
        shutil.rmtree(plain_dir, ignore_errors=True)
        shutil.rmtree(proj / "target" / "rcbom", ignore_errors=True)
        cbom = out / f"{name}.cbom.json"
        # the driver built from this tree, not $RCBOM_DRIVER or a stale release build
        c1, t_cbom, rss_cbom, err1 = run([str(CBOM), "cbom", "--driver", str(DRIVER), "-o", str(cbom)], proj)
        # the packages of the build Layer 1 resolved (normal and build edges, host platform,
        # only the optional dependencies features activate), as the CBOM records them
        packages = -1
        if c1 == 0:
            props = json.load(open(cbom))["metadata"].get("properties", [])
            packages = int(next((p["value"] for p in props if p["name"] == "rcbom:run:packages"), -1))
        row = {"project": name, "packages": packages, "plain_check_s": round(t_plain, 1), "cbom_s": round(t_cbom, 1),
               "overhead": round(t_cbom / t_plain, 2) if t_plain else None, "plain_peak_rss_mib": round(rss_plain),
               "peak_rss_mib": round(rss_cbom),
               "plain_ok": c0 == 0, "cbom_ok": c1 == 0,
               # panics the driver caught: each is a bug (rcbom-driver: <crate>: N items could not be analysed)
               "items_not_analysed": sum(int(n) for n in re.findall(r"rcbom-driver: \S+: (\d+) items? could not be analysed", err1))}
        if c1 != 0:
            row["error"] = err1.strip().splitlines()[-1] if err1.strip() else "failed"
            rows.append(row)
            print(json.dumps(row), flush=True)
            continue
        v = subprocess.run([str(CBOM), "cbom", "verify", str(cbom), "--self-test"], cwd=proj, capture_output=True, text=True)
        m = re.search(r"(\d+) positions verified, (\d+) mismatched", v.stdout)
        row["positions_verified"] = int(m.group(1)) if m else None
        row["positions_mismatched"] = int(m.group(2)) if m else None
        shifted = [tuple(map(int, x)) for x in re.findall(r"(\d+)/(\d+) shifted positions rejected", v.stdout)]
        row["shift_rejected"] = f"{sum(a for a, _ in shifted)}/{sum(b for _, b in shifted)}"
        row.update(stats(cbom))
        if rusi:
            r_out = out / f"{name}.rusi-report.json"
            c2, t_rusi, _, _ = run([rusi, "cryptos", "--dir", ".", "-o", str(r_out)], proj)
            if c2 == 0:
                rep = json.load(open(r_out))
                row["rusi_s"] = round(t_rusi, 1)
                row["rusi_components"] = len(rep["crypto"]["components"])
                row["rusi_algorithms"] = sorted({c["algorithm"] for c in rep["crypto"]["components"]})
        rows.append(row)
        print(json.dumps(row), flush=True)
    json.dump(rows, open(out / "corpus.json", "w"), indent=2)


if __name__ == "__main__":
    main()
