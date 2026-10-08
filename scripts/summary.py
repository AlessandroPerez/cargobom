#!/usr/bin/env python3
"""One line per evidence occurrence of a CBOM: asset, position, tier and kind. Used to compare
a run with a fixture's golden file (fixtures/*/expected.txt)."""
import json, re, sys

doc = json.load(open(sys.argv[1]))
rows = []
for c in doc["components"]:
    for o in c.get("evidence", {}).get("occurrences", []):
        tags = " ".join(re.findall(r"\[[^\]]+\]", o.get("additionalContext", ""))[:3])
        rows.append(f'{c["name"]:<22} {o["location"]}:{o.get("line")}:{o.get("offset")}  {tags}  {o["symbol"].split("::")[-1]}')
print("\n".join(sorted(rows)))
