#!/usr/bin/env python3
"""Check every evidence occurrence that carries a line against the source it cites.

usage: verify_lines.py OUT_DIR cbom.json [-v]

For each occurrence with `line`/`offset`, resolves `location` back to a file (through the
<crate>-<version>.meta files the wrapper wrote), reads that line, and checks that the code
starting at column `offset` names what `symbol` says was matched: the static's name for
[mir-static], the callee's final path segment for [mir-type] and [mir-call]. This does not
reuse the extractor's span parsing, so an off-by-one line or column shows up as a failure.
"""
import json, pathlib, re, sys

def strip_generics(path):
    while True:
        n = re.sub(r"<[^<>]*>", "", path)
        if n == path:
            return n
        path = n

def expected_ident(kind, symbol):
    if kind == "mir-static":
        return symbol.split("::")[-1]
    # `seal::<AesGcm<Aes256, 12>>` -> `seal::` -> `seal`
    return strip_generics(symbol).rstrip(":").split("::")[-1]

def main(out_dir, cbom_path, verbose=False):
    metas = []
    for m in pathlib.Path(out_dir).glob("*.meta"):
        metas.append(dict(l.split("=", 1) for l in m.read_text().splitlines() if "=" in l))
    by_prefix = {f"{m['package']}-{m['version']}/": pathlib.Path(m["manifest_dir"]) for m in metas}
    primary_roots = [pathlib.Path(m["cwd"]) for m in metas if m.get("primary") == "1"]

    def resolve(location):
        for prefix, root in by_prefix.items():
            if location.startswith(prefix):
                return root / location[len(prefix):]
        p = pathlib.Path(location)
        if p.is_absolute():
            return p
        for root in primary_roots:
            if (root / p).exists():
                return root / p
        return None

    cache, ok, bad, no_line, unresolved = {}, 0, [], 0, []
    doc = json.load(open(cbom_path))
    for c in doc["components"]:
        if c["type"] != "cryptographic-asset":
            continue
        for o in c.get("evidence", {}).get("occurrences", []):
            if "line" not in o:
                no_line += 1
                continue
            kind = re.match(r"\[([\w-]+)\]", o.get("additionalContext", "")).group(1)
            path = resolve(o["location"])
            if path is None or not path.exists():
                unresolved.append((c["name"], o["location"]))
                continue
            lines = cache.setdefault(path, path.read_text(errors="replace").split("\n"))
            text = lines[o["line"] - 1] if 0 < o["line"] <= len(lines) else ""
            ident = expected_ident(kind, o["symbol"])
            if not ident:
                bad.append((c["name"], o["location"], o["line"], o["offset"], ident, "(no identifier in symbol)"))
                continue
            # MIR names the resolved item; the source may use an import alias
            # (age: `use scrypt::{scrypt as scrypt_inner}`), so accept `ident as alias` names too
            whole = "\n".join(lines)
            names = [ident] + re.findall(rf"\b{re.escape(ident)}\s+as\s+(\w+)", whole)
            # the span must start a token, and the code there must be a path ending in the name:
            # `AES_256_GCM`, `aead::AES_256_GCM`, `seal::<Aes256Gcm>(..)`,
            # `<Hmac<Sha256> as Mac>::new_from_slice(..)`, `update(..)` in `m.update(..)`
            off = o["offset"]
            at = text[off:]
            starts_token = off == 0 or (off <= len(text) and not re.match(r"[\w:]", text[off - 1]))
            path = r"(?:<.*?>::)?(?:\w+(?:::<.*?>)?::)*"
            good = starts_token and any(re.match(rf"{path}{re.escape(n)}\b", at) for n in names)
            if good:
                ok += 1
                if verbose:
                    print(f"ok   {c['name']:22} {o['location']}:{o['line']}:{o['offset']}  {ident!r} in {text.strip()[:90]!r}")
            else:
                bad.append((c["name"], o["location"], o["line"], o["offset"], ident, text.strip()[:120]))
    print(f"{cbom_path}: {ok} occurrences verified, {len(bad)} mismatched, {len(unresolved)} unresolved files, {no_line} without line (mono items)")
    for b in bad:
        print("  MISMATCH %s %s:%d:%d expected %r in %r" % b)
    for u in unresolved:
        print("  UNRESOLVED %s %s" % u)
    return 0 if not bad and not unresolved else 1

if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2], "-v" in sys.argv[3:]))
