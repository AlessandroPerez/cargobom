#!/usr/bin/env python3
"""A CBOM as sorted text lines, for golden files (fixtures/*/expected.txt): the document's
format fields, the tools, the root component and the run properties; every component with its
type, name, version, purl, crypto properties and rcbom properties; every occurrence with its
full context; and the dependency graph. Each line of a component names it by bom-ref (and by
name, for reading), so two components of one name (the HMAC algorithm and the HMAC key
material, two versions of a crate) are told apart. A field this script does not know is
printed as JSON. Anything a reader of the CBOM sees is here, so any change shows in a diff;
only the serial number (a hash of the rest) is left out."""
import json, sys


def js(v):
    return json.dumps(v, sort_keys=True)


def prop(p):
    # a property is a name and a value; anything else it holds is shown as JSON
    if set(p) == {"name", "value"}:
        return f'{p["name"]}={p["value"]}'
    return js(p)


# the fields each kind of component line shows; any other is printed as a field line
ASSET = {"type", "bom-ref", "name", "cryptoProperties", "properties", "evidence"}
PACKAGE = {"type", "bom-ref", "name", "version", "purl", "properties", "evidence"}
OCCURRENCE = {"location", "line", "offset", "symbol", "additionalContext"}

doc = json.load(open(sys.argv[1]))
rows = []
for k, v in doc.items():
    if k not in {"components", "dependencies", "metadata", "serialNumber"}:
        rows.append(f"doc {k}={js(v)}")
for c in doc.get("components", []):
    name, ref = c.get("name"), c.get("bom-ref")
    key = f"{name} | {ref}"
    if c.get("type") == "cryptographic-asset":
        rows.append(f'asset {key} | {js(c.get("cryptoProperties"))}')
        shown = ASSET
    else:
        rows.append(f'component {c.get("type")} {name} {c.get("version", "")} | {ref} | purl {c.get("purl", "(none)")}')
        shown = PACKAGE
    for f in sorted(set(c) - shown):
        rows.append(f"  field {key} | {f}={js(c[f])}")
    for p in c.get("properties", []):
        rows.append(f"  prop {key} | {prop(p)}")
    ev = c.get("evidence", {})
    for f in sorted(set(ev) - {"occurrences"}):
        rows.append(f"  field {key} | evidence.{f}={js(ev[f])}")
    for o in ev.get("occurrences", []):
        extra = {f: o[f] for f in set(o) - OCCURRENCE}
        rows.append(
            f'  occ {key} | {o.get("location")}:{o.get("line")}:{o.get("offset")} | {o.get("symbol")} | {o.get("additionalContext", "")}'
            + (f" | {js(extra)}" if extra else "")
        )
for d in doc.get("dependencies", []):
    r = d.get("ref")
    rows.append(f"dependency {r}")
    for t in d.get("dependsOn", []):
        rows.append(f"dep {r} -> {t}")
    for t in d.get("provides", []):
        rows.append(f"provides {r} -> {t}")
    for f in sorted(set(d) - {"ref", "dependsOn", "provides"}):
        rows.append(f"depfield {r} | {f}={js(d[f])}")
meta = doc.get("metadata", {})
rows.append(f'root {js(meta.get("component"))}')
rows.append(f'tools {js(meta.get("tools"))}')
for p in meta.get("properties", []):
    rows.append(f"run {prop(p)}")
for f in sorted(set(meta) - {"component", "tools", "properties"}):
    rows.append(f"meta {f}={js(meta[f])}")
print("\n".join(sorted(rows)))
