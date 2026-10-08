#!/usr/bin/env python3
"""Convert a rusi `cryptos` report into a minimal CycloneDX document for scripts/score.py.

Every rusi crypto component becomes an occurrence of an asset named by rusi's `algorithm`, at
rusi's position. No filtering: cdxgen's own conversion drops algorithms it cannot map to an
OID, so this view is at least as generous to rusi as cdxgen's CBOM.

usage: rusi_to_cbom.py RUSI_REPORT.json > cbom.json
"""
import collections, json, sys

report = json.load(open(sys.argv[1]))
by_name = collections.defaultdict(list)
for c in report["crypto"]["components"]:
    p = c["position"]
    by_name[c["algorithm"]].append({
        "location": c["file_path"], "line": p["line"], "offset": max(p["column"] - 1, 0),
        "symbol": c["symbol"], "additionalContext": f"[{c['kind']}] {c.get('operation', '')}",
    })
components = [
    {"type": "cryptographic-asset", "name": n, "bom-ref": f"rusi:{n}",
     "cryptoProperties": {"assetType": "algorithm"}, "evidence": {"occurrences": occ}}
    for n, occ in sorted(by_name.items())
]
components += [{"type": "library", "name": l["path"].replace("_", "-"), "bom-ref": f"lib:{l['path']}"}
               for l in report["crypto"]["libraries"]]
print(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.7", "version": 1,
                  "metadata": {"tools": {"components": [{"type": "application", "name": "rusi", "version": report["tool"]["version"]}]}},
                  "components": components}, indent=2))
