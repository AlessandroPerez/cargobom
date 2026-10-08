#!/usr/bin/env python3
"""Score a CycloneDX CBOM against a fixture's labels.toml (any tool's CBOM, not only ours).

usage: score.py LABELS.toml CBOM.json [--json]

Line level, in the fixture's src/main.rs:
  recall     core (asset, line) pairs the CBOM reports at the right line, by an accepted name
  precision  (asset, line) pairs the CBOM reports in src/main.rs that match a label (core or
             extended, direct or component line); everything else is a false positive
Asset level: core assets found at any of their lines. Findings located in dependencies are
classified against the labelled capability set (credited) or listed as unexpected.
"""
import json, re, sys, tomllib

def norm(s):
    return re.sub(r"[\s_]", "", s).upper()

def main(labels_path, cbom_path, as_json=False):
    labels = tomllib.load(open(labels_path, "rb"))
    bom = json.load(open(cbom_path))
    assets = labels["asset"]
    caps = {norm(a) for c in labels.get("capability", []) for a in c.get("algorithms", [])}

    # (name, line) the CBOM reports in src/main.rs, and everything it reports elsewhere
    reported, elsewhere = set(), set()
    contexts = {}  # (name, line) -> additionalContext texts, for provenance
    for c in bom.get("components", []):
        if c.get("type") != "cryptographic-asset":
            continue
        for o in c.get("evidence", {}).get("occurrences", []):
            loc, line = o.get("location", ""), o.get("line")
            if loc == "src/main.rs" or loc.endswith("/src/main.rs") and labels["fixture"] in loc:
                if line is not None:
                    reported.add((c["name"], line))
                    contexts.setdefault((c["name"], line), []).append(o.get("additionalContext", ""))
            elif not loc.endswith(("Cargo.toml", "Cargo.lock")):
                elsewhere.add(c["name"])
    names_reported = {n for n, _ in reported}

    def accepts(a, name):
        # registry patterns make trailing parameters optional: "PBKDF2-SHA-256-1000" is a valid,
        # less specific name for "PBKDF2-SHA-256-1000-32"
        n = norm(name)
        return any(n == norm(x) or norm(x).startswith(n + "-") for x in a["accept"])

    # recall over core (asset, line) pairs
    core_pairs = [(a, l) for a in assets if a["tier"] == "core" for l in a["lines"]]
    hit = [(a, l) for a, l in core_pairs if any(accepts(a, n) and ln == l for n, ln in reported)]
    family_only = [
        (a, l) for a, l in core_pairs if (a, l) not in hit
        and any(ln == l and norm(a["family"]) in norm(n) for n, ln in reported)
    ]
    # precision over reported pairs in src/main.rs
    def matches_label(n, ln):
        return any(accepts(a, n) and (ln in a["lines"] or ln in a.get("component_lines", [])) for a in assets)
    negatives = {l for neg in labels.get("negative", []) for l in neg["lines"]}
    tp = [(n, l) for n, l in sorted(reported) if matches_label(n, l)]
    fp = [(n, l) for n, l in sorted(reported) if not matches_label(n, l)]
    fp_on_negative = [(n, l) for n, l in fp if l in negatives]
    extended_hit = [
        (a["name"], l) for a in assets if a["tier"] == "extended"
        for l in a["lines"] + a.get("component_lines", [])
        if any(accepts(a, n) and ln == l for n, ln in reported)
    ]
    component_hit = [
        (a["name"], l) for a in assets for l in a.get("component_lines", [])
        if any(accepts(a, n) and ln == l for n, ln in reported)
    ]
    # specificity: the core finding carries the label's full registry name, parameters included
    exact = [(a, l) for a, l in hit if any(norm(n) == norm(a["accept"][0]) and ln == l for n, ln in reported)]
    core_assets = [a for a in assets if a["tier"] == "core"]
    assets_found = [a["name"] for a in core_assets if any(accepts(a, n) and l in a["lines"] for n, l in reported)]
    cap_credit = sorted(n for n in elsewhere if norm(n) in caps)
    unexpected_elsewhere = sorted(n for n in elsewhere if norm(n) not in caps and not any(accepts(a, n) for a in assets))

    # provenance: per labelled (asset, line, role), the set of origin kinds the CBOM states
    # (cargo-cbom writes "role: kind (..) or kind (..)" in additionalContext)
    kinds_re = r"\b(hard-coded|environment|file|rng|parameter|derived|computed)\b"
    prov_total, prov_exact, prov_wrong = 0, 0, []
    for a in assets:
        for role, truth in a.get("provenance", {}).items():
            for l in a["lines"]:
                prov_total += 1
                said = set()
                for (n, ln), texts in contexts.items():
                    if ln == l and accepts(a, n):
                        for t in texts:
                            for part in t.split("; "):
                                if part.startswith(f"{role}: "):
                                    said |= set(re.findall(kinds_re, part))
                if said == set(truth):
                    prov_exact += 1
                else:
                    prov_wrong.append(f"{a['name']} @ {l} {role}: said {sorted(said) or 'nothing'}, truth {sorted(truth)}")

    libs = {c["name"] for c in bom.get("components", []) if c.get("type") in ("library", "application", "framework")}
    crates = labels.get("crate", [])
    crates_found = [c["package"] for c in crates if c["package"] in libs]

    r = {
        "fixture": labels["fixture"],
        "core_pairs": len(core_pairs), "core_pairs_found": len(hit),
        "recall": round(len(hit) / len(core_pairs), 3) if core_pairs else None,
        "reported_pairs": len(reported), "true_positive_pairs": len(tp),
        "precision": round(len(tp) / len(reported), 3) if reported else None,
        "fully_named": len(exact),
        "core_assets": len(core_assets), "core_assets_found": len(assets_found),
        "named_less_specifically": [f"{a['name']} @ {l} as {', '.join(sorted({n for n, ln in reported if ln == l and accepts(a, n)}))}" for a, l in hit if (a, l) not in exact],
        "missed": [f"{a['name']} @ {l}" for a, l in core_pairs if (a, l) not in hit],
        "family_only": [f"{a['name']} @ {l}" for a, l in family_only],
        "false_positives": [f"{n} @ {l}" + (" (negative line)" if (n, l) in fp_on_negative else "") for n, l in fp],
        "extended_found": [f"{n} @ {l}" for n, l in extended_hit],
        "components_found": [f"{n} @ {l}" for n, l in component_hit],
        "capability_credited": cap_credit,
        "unexpected_in_dependencies": unexpected_elsewhere,
        "crates_found": f"{len(crates_found)}/{len(crates)}",
        "provenance_total": prov_total, "provenance_exact": prov_exact, "provenance_wrong": prov_wrong,
    }
    if as_json:
        print(json.dumps(r, indent=2))
        return r
    print(f"== {r['fixture']}")
    print(f"  line-level recall    {r['core_pairs_found']}/{r['core_pairs']} core (asset, line) pairs" + (f" = {r['recall']:.0%}" if r['recall'] is not None else ""))
    print(f"  line-level precision {r['true_positive_pairs']}/{r['reported_pairs']} reported pairs in src/main.rs" + (f" = {r['precision']:.0%}" if r['precision'] is not None else ""))
    print(f"  core assets found    {r['core_assets_found']}/{r['core_assets']}")
    print(f"  fully named          {r['fully_named']}/{r['core_pairs']} core findings with the full registry name")
    for k in ("missed", "named_less_specifically", "family_only", "false_positives", "extended_found", "components_found", "capability_credited", "unexpected_in_dependencies"):
        if r[k]:
            print(f"  {k.replace('_', ' ')}: {', '.join(r[k])}")
    if prov_total:
        print(f"  provenance           {prov_exact}/{prov_total} labelled (asset, line, role) origins stated exactly")
        for w in prov_wrong:
            print(f"    {w}")
    print(f"  crates in CBOM       {r['crates_found']}")
    return r

if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2], "--json" in sys.argv[3:])
