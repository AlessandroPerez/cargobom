#!/usr/bin/env python3
"""Markdown review sheet for second-annotator review of fixture labels: every label next to the
source line it cites. usage: review_sheet.py FIXTURE_DIR... > sheet.md"""
import pathlib, sys, tomllib

print("# Label review sheet\n")
print("For each row: does the line use that asset, with that use and those parameters? "
      "Mark ✔ or write the correction. `core` must be found by a tool; `extended` is credited "
      "if found. Negative lines must stay empty.\n")
for d in map(pathlib.Path, sys.argv[1:]):
    labels = tomllib.load(open(d / "labels.toml", "rb"))
    src = (d / "src/main.rs").read_text().split("\n")
    print(f"## {labels['fixture']}\n\nSource: {labels['source']}  \nStatus: {labels['status']}\n")
    print("| line | code | asset | tier | use | parameters | provenance | why | review |")
    print("|---|---|---|---|---|---|---|---|---|")
    rows = []
    for a in labels["asset"]:
        params = ", ".join(f"{k}={v}" for k, v in {**a.get("params", {}), **a.get("material", {})}.items())
        prov = "; ".join(f"{k}: {' or '.join(v)}" for k, v in a.get("provenance", {}).items())
        for l in a["lines"]:
            rows.append((l, a["name"], a["tier"], ", ".join(a["functions"]) or "set up only", params, prov, a["why"]))
        for l in a.get("component_lines", []):
            rows.append((l, a["name"], f"{a['tier']} (component)", "", "", "", a["why"]))
    for n in labels.get("negative", []):
        for l in n["lines"]:
            rows.append((l, "— none —" + (f" (not {', '.join(n['names'])})" if n.get("names") else ""), "negative", "", "", "", n["why"]))
    for l, name, tier, use, params, prov, why in sorted(rows, key=lambda r: (r[0], r[2])):
        code = src[l - 1].strip().replace("|", "\\|")
        print(f"| {l} | `{code}` | {name} | {tier} | {use} | {params} | {prov} | {why.replace('|', '/')} | |")
    for c in labels.get("capability", []):
        tier = "reachable" if c.get("reachable", True) else "present only"
        print(f"\nCapability via line {c['via_line']} ({tier}){': ' + c['source'] if c.get('source') else ''}: "
              + ", ".join(c.get("algorithms", [])))
        if c.get("cipher_suites"):
            print(f"\n- cipher suites: {', '.join(c['cipher_suites'])}\n- key exchange groups: {', '.join(c['kx_groups'])}")
    print("\nCrates: " + ", ".join(f"{c['package']} ({c['usage']})" for c in labels.get("crate", [])) + "\n")
