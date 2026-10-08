#!/usr/bin/env python3
"""A CBOM as sorted text lines, for golden files (fixtures/*/expected.txt): every asset with its
crypto properties and rcbom properties, every occurrence with its full context, every library
component's properties, and the dependency graph. Anything a reader of the CBOM sees is here,
so any change shows in a diff; only the serial number (a hash of the rest) is left out."""
import json, sys

doc = json.load(open(sys.argv[1]))
rows = []
for c in doc["components"]:
    props = sorted(f'{p["name"]}={p["value"]}' for p in c.get("properties", []))
    name = c.get("name")
    if c["type"] == "cryptographic-asset":
        rows.append(f'asset {name} | {c["bom-ref"]} | {json.dumps(c["cryptoProperties"], sort_keys=True)}')
    else:
        rows.append(f'component {c["type"]} {name} {c.get("version", "")} | {c["bom-ref"]}')
    for p in props:
        rows.append(f"  prop {name} | {p}")
    for o in c.get("evidence", {}).get("occurrences", []):
        rows.append(
            f'  occ {name} | {o["location"]}:{o.get("line")}:{o.get("offset")} | {o["symbol"]} | {o.get("additionalContext", "")}'
        )
for d in doc.get("dependencies", []):
    for t in d.get("dependsOn", []):
        rows.append(f'dep {d["ref"]} -> {t}')
    for t in d.get("provides", []):
        rows.append(f'provides {d["ref"]} -> {t}')
meta = doc.get("metadata", {})
rows.append(f'root {json.dumps(meta.get("component"), sort_keys=True)}')
for p in meta.get("properties", []):
    rows.append(f'run {p["name"]}={p["value"]}')
print("\n".join(sorted(rows)))
