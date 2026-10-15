#!/usr/bin/env python3
"""Score the CBOMs of real projects against their ground truth (fixtures/corpus/<project>.toml).

usage: corpus_score.py CBOM_DIR LABELS.toml... [--json] [--against OLD_CBOM_DIR]
CBOM_DIR/<project>.cbom.json is scored against fixtures/corpus/<project>.toml:
- Layer 1: the labelled crypto packages (kind other than `support`) against the CBOM's library
  components with a crypto role (algorithm, trait, protocol, unmodelled): recall, precision,
  and agreement on support crates;
- Layer 2: each labelled operation site in the project's own source, with suite.py's verdicts;
- with --against OLD_CBOM_DIR (the previous round's CBOMs): at each labelled site, the label
  kinds that changed (a run-time selector, a member's kind, a possible or partial set, the
  set's size), which the verdicts do not see.
"""
import collections, importlib.util, json, pathlib, re, sys, tomllib

spec = importlib.util.spec_from_file_location("suite", pathlib.Path(__file__).with_name("suite.py"))
suite = importlib.util.module_from_spec(spec)
spec.loader.exec_module(suite)


def layer1(labels, cbom):
    labelled = {(p["name"], p["version"]): p["kind"] for p in labels.get("package", [])}
    listed = {}
    for c in cbom["components"]:
        if c["type"] not in ("library", "application"):
            continue
        role = next((p["value"] for p in c.get("properties", []) if p["name"] == "rcbom:crypto-role"), None)
        if role:
            listed[(c["name"], c.get("version", ""))] = role
    crypto = {k for k, v in labelled.items() if v != "support"}
    support = {k for k, v in labelled.items() if v == "support"}
    reported = {k for k, v in listed.items() if v != "support"}
    reported_support = {k for k, v in listed.items() if v == "support"}
    # crypto against crypto, support against support: a crypto package listed only as
    # support is not found, a support crate reported as crypto is not correct
    return {
        "crypto_labelled": len(crypto),
        "crypto_found": len(crypto & reported),
        "crypto_missed": sorted(f"{n} {v}" for n, v in crypto - reported),
        "reported": len(reported),
        "reported_correct": len(reported & crypto),
        "reported_not_crypto": sorted(f"{n} {v}" for n, v in reported - crypto),
        "support_labelled": len(support),
        "support_listed": len(reported_support),
        "support_agree": len(support & reported_support),
    }


def layer2(labels, cbom):
    at = suite.occurrences(cbom)
    sites = labels.get("site", [])
    lines = collections.Counter((s["file"], s["line"]) for s in sites)
    verdicts, details = collections.Counter(), []
    for s in sites:
        occ = at.get((s["file"], s["line"]), [])
        if lines[(s["file"], s["line"])] > 1:
            occ = [o for o in occ if o[1].endswith(s["callee"])]
        v = suite.verdict(s, occ)
        if v == "correct" and not suite.function_matches(s, occ):
            v = "function-mismatch"
        verdicts[v] += 1
        if v != "correct":
            details.append({"line": f"{s['file']}:{s['line']}", "callee": s["callee"], "verdict": v,
                            "reported": sorted({o[0] for o in occ}),
                            "must": sorted(s["must"]), "may": sorted(s.get("may", []))})
    return {"sites": len(sites),
            "verdicts": {v: verdicts[v] for v in suite.VERDICTS + ["function-mismatch"]},
            "not_correct": details}


# the parts of a call occurrence's text that say how its algorithm reaches the call
LABEL_KINDS = [r"selector: [\w-]+", r"member: [\w-]+", r"\bpossible\b", r"beside others not followed",
               r"hit its bound", r"algorithm one of \d+", r"algorithm unresolved"]


def label_kinds(cbom, sites):
    """(file, line, asset) -> the label kinds of its call occurrences, at the labelled sites."""
    at = suite.occurrences(cbom)
    out = {}
    for s in sites:
        for o in at.get((s["file"], s["line"]), []):
            kinds = {m.group(0) for k in LABEL_KINDS for m in re.finditer(k, o[6])}
            out.setdefault((s["file"], s["line"], o[0]), set()).update(kinds)
    return out


def main():
    argv = sys.argv[1:]
    against = None
    if "--against" in argv:
        i = argv.index("--against")
        against = pathlib.Path(argv[i + 1])
        del argv[i:i + 2]
    args = [a for a in argv if not a.startswith("--")]
    cbom_dir = pathlib.Path(args[0])
    out = {}
    for lp in sorted(map(pathlib.Path, args[1:])):
        name = lp.stem
        cbom = json.load(open(cbom_dir / f"{name}.cbom.json"))
        labels = tomllib.load(open(lp, "rb"))
        out[name] = {"layer1": layer1(labels, cbom), "layer2": layer2(labels, cbom)}
        if against is not None:
            old = json.load(open(against / f"{name}.cbom.json"))
            sites = labels.get("site", [])
            a, b = label_kinds(old, sites), label_kinds(cbom, sites)
            out[name]["label_changes"] = [
                f"{f}:{l} {asset}: {sorted(a.get((f, l, asset), set()))} -> {sorted(b.get((f, l, asset), set()))}"
                for (f, l, asset) in sorted(set(a) | set(b))
                if a.get((f, l, asset)) != b.get((f, l, asset))]
    if "--json" in sys.argv:
        print(json.dumps(out, indent=1, sort_keys=True))
        return
    for name, r in out.items():
        l1, l2 = r["layer1"], r["layer2"]
        print(f"== {name}: L1 crypto packages {l1['crypto_found']}/{l1['crypto_labelled']} found, "
              f"{l1['reported_correct']}/{l1['reported']} reported are crypto, support {l1['support_agree']} "
              f"agree ({l1['support_labelled']} labelled, {l1['support_listed']} listed); L2 {l2['sites']} sites: "
              + ", ".join(f"{k} {v}" for k, v in l2["verdicts"].items() if v))
        if l1["crypto_missed"]:
            print("   L1 missed:", ", ".join(l1["crypto_missed"]))
        if l1["reported_not_crypto"]:
            print("   L1 reported, not labelled:", ", ".join(l1["reported_not_crypto"]))
        for d in l2["not_correct"]:
            print(f"   L2 {d['line']} {d['callee']}: {d['verdict']}: reported {d['reported']}, must {d['must'][:6]}{'…' if len(d['must'])>6 else ''}")
        for c in r.get("label_changes", []):
            print(f"   label changed: {c}")


if __name__ == "__main__":
    main()
