#!/usr/bin/env python3
"""Phase 0 extractor: compiler facts (.mono = monomorphization collector, .mir = MIR dump
with spans, .meta = where rustc ran) -> CycloneDX 1.7 CBOM. Throwaway spike code; the real
tool reads the same facts through rustc_public instead of parsing text dumps.

usage: extract.py OUT_DIR CRATE[,CRATE...] > cbom.json
CRATE is a crate name (all versions found in OUT_DIR) or name-version.
RCBOM_MAX_OCC caps the occurrences listed per asset and crate (default 8, 0 = all).

Evidence occurrences from MIR carry the source position of the matched operand:
  location  file path; relative to the workspace root for workspace crates,
            <package>-<version>/<path in package> for dependencies
  line      1-based line of the span start
  offset    0-based character column of the span start on that line (CBOMkit convention)
  symbol    the static or callee that matched
Mono items have no span in -Zprint-mono-items, so their occurrences carry only the crate.
"""
import json, os, re, sys, uuid, pathlib, collections

def decode_typenum(s):
    """Replace typenum chains like UInt<UInt<UTerm, B1>, B0> with integers."""
    s = re.sub(r'[\w:]*UTerm', '0', s)
    pat = re.compile(r'[\w:]*UInt<(\d+), [\w:]*B([01])>')
    while True:
        n = pat.sub(lambda m: str(2 * int(m.group(1)) + int(m.group(2))), s)
        if n == s:
            return s
        s = n

# Seed knowledge base: (source, regex, registry name, family, primitive, functions, extra)
# source: 'static' = named static allocation in MIR (ring/aws-lc-rs style)
#         'type'   = monomorphized instance, or a MIR call whose callee has concrete
#                    generic arguments (RustCrypto style); MIR prints a type in expression
#                    position with a turbofish (`Hkdf::<Sha256>::new`), hence the optional `::`
#         'call'   = call edge in MIR to a non-generic function
# extra values may use {0}; an unmatched optional group takes the entry's "default_0".
AE = ["encrypt", "decrypt"]
KB = [
    ("static", r"AES_256_GCM$", "AES-256-GCM", "AES", "ae", AE, {"mode": "gcm", "parameterSetIdentifier": "256"}),
    ("static", r"AES_128_GCM$", "AES-128-GCM", "AES", "ae", AE, {"mode": "gcm", "parameterSetIdentifier": "128"}),
    ("static", r"CHACHA20_POLY1305$", "ChaCha20-Poly1305", "ChaCha20", "ae", AE, {}),
    ("static", r"(^|::)AES_256$", "AES-256", "AES", "block-cipher", ["encrypt"], {"parameterSetIdentifier": "256", "note": "QUIC header protection"}),
    ("static", r"(^|::)AES_128$", "AES-128", "AES", "block-cipher", ["encrypt"], {"parameterSetIdentifier": "128", "note": "QUIC header protection"}),
    ("static", r"HMAC_SHA(256|384|512)$", "HMAC-SHA-{0}", "HMAC", "mac", ["tag"], {}),
    ("static", r"HKDF_SHA(256|384|512)$", "HKDF-SHA-{0}", "HKDF", "kdf", ["keyderive"], {}),
    ("static", r"(?:^|::)SHA(256|384|512)$", "SHA-{0}", "SHA-2", "hash", ["digest"], {}),
    ("static", r"ECDSA_P256_SHA256", "ECDSA-P-256-SHA-256", "ECDSA", "signature", ["sign", "verify"], {"curve": "P-256"}),
    ("static", r"ECDSA_P384_SHA384", "ECDSA-P-384-SHA-384", "ECDSA", "signature", ["sign", "verify"], {"curve": "P-384"}),
    ("static", r"ECDSA_P256_SHA384", "ECDSA-P-256-SHA-384", "ECDSA", "signature", ["verify"], {"curve": "P-256"}),
    ("static", r"ECDSA_P384_SHA256", "ECDSA-P-384-SHA-256", "ECDSA", "signature", ["verify"], {"curve": "P-384"}),
    ("static", r"^ED25519$", "Ed25519", "EdDSA", "signature", ["sign", "verify"], {"curve": "Ed25519"}),
    ("static", r"RSA_PKCS1_(?:2048_8192_)?SHA(256|384|512)", "RSA-PKCS1-1.5-SHA-{0}", "RSASSA-PKCS1", "signature", ["sign", "verify"], {}),
    ("static", r"RSA_PSS_(?:2048_8192_)?SHA(256|384|512)", "RSA-PSS-SHA-{0}", "RSASSA-PSS", "signature", ["sign", "verify"], {}),
    ("static", r"^(ECDH_P256|SECP256R1)$", "ECDH-P-256", "ECDH", "key-agree", ["keygen"], {"curve": "P-256"}),
    ("static", r"^(ECDH_P384|SECP384R1)$", "ECDH-P-384", "ECDH", "key-agree", ["keygen"], {"curve": "P-384"}),
    ("static", r"^X25519$", "x25519", "ECDH", "key-agree", ["keygen"], {"curve": "Curve25519"}),
    ("type", r"AesGcm(?:::)?<[\w:]*Aes256, (\d+)", "AES-256-GCM", "AES", "ae", AE, {"mode": "gcm", "parameterSetIdentifier": "256", "nonce_bytes": "{0}"}),
    ("type", r"AesGcm(?:::)?<[\w:]*Aes128, (\d+)", "AES-128-GCM", "AES", "ae", AE, {"mode": "gcm", "parameterSetIdentifier": "128", "nonce_bytes": "{0}"}),
    # chacha20poly1305 0.10 prints its nonce size only when it differs from the default U12
    ("type", r"ChaChaPoly1305(?:::)?<[^ ]*ChaChaCore<10>>(?:, (\d+))?>", "ChaCha20-Poly1305", "ChaCha20", "ae", AE, {"nonce_bytes": "{0}", "default_0": "12"}),
    ("type", r"Hkdf(?:::)?<[^ ]*Sha256VarCore", "HKDF-SHA-256", "HKDF", "kdf", ["keyderive"], {}),
    ("type", r"HmacCore(?:::)?<[^ ]*Sha256VarCore", "HMAC-SHA-256", "HMAC", "mac", ["tag"], {}),
    ("type", r"Sha256VarCore", "SHA-256", "SHA-2", "hash", ["digest"], {}),
    ("call", r"(StaticSecret|EphemeralSecret)::diffie_hellman$", "x25519", "ECDH", "key-agree", ["keygen"], {"curve": "Curve25519"}),
    ("call", r"(^|::)scrypt::scrypt$", "scrypt", "scrypt", "kdf", ["keyderive"], {"params": "unresolved (runtime work factor)"}),
]
KB = [(src, re.compile(rx), *rest) for src, rx, *rest in KB]

def kb_meta(m, fam, prim, funcs, extra):
    default = extra.get("default_0")
    groups = [default if g is None else g for g in m.groups()]
    vals = {k: v.format(*groups) for k, v in extra.items() if k != "default_0"}
    return (fam, prim, funcs, {k: v for k, v in vals.items() if v != "None"})

def merge(h, meta):
    if h["meta"] is None:
        h["meta"] = meta
    else:
        h["meta"][3].update({k: v for k, v in meta[3].items() if k not in h["meta"][3]})

SPAN = re.compile(r"^(.+):(\d+):(\d+): (\d+):(\d+)$")
STMT_SPAN = re.compile(r"^(.*?);?\s+// scope \d+ at (.+)$")

def read_meta(path):
    return dict(l.split("=", 1) for l in path.read_text().splitlines() if "=" in l)

def find_units(out_dir, crates):
    """Each requested crate -> list of (meta, base path). A name matches every version."""
    units = []
    for c in crates:
        metas = sorted(pathlib.Path(out_dir).glob(f"{c}.meta")) or sorted(pathlib.Path(out_dir).glob(f"{c}-[0-9]*.meta"))
        if not metas:
            sys.exit(f"extract.py: no dumps for crate {c!r} in {out_dir} (re-run the build with rcbom-wrapper.sh)")
        units += [(read_meta(m), str(m)[:-len(".meta")]) for m in metas]
    return units

class Locator:
    """Turns a rustc span path into a CBOM location. rustc prints paths as it was given them:
    relative to its cwd for workspace crates, absolute for registry crates."""
    def __init__(self, meta):
        self.meta = meta
        self.cwd = pathlib.Path(meta["cwd"])
        self.root = pathlib.Path(meta["manifest_dir"])
        self.primary = meta.get("primary") == "1"

    def __call__(self, span_path):
        p = pathlib.Path(span_path)
        absp = p if p.is_absolute() else self.cwd / p
        if self.primary and not p.is_absolute():
            return str(p)
        try:
            rel = absp.relative_to(self.root)
        except ValueError:
            return span_path  # std library, generated code under OUT_DIR, another package
        return f"{self.meta['package']}-{self.meta['version']}/{rel}"

def statements(text):
    """Yield (fn, code, stmt_span, operands) for each MIR line that carries a span.
    operands lists [span, const_text] for each ConstOperand printed below the statement,
    in operand order (for a call, the callee comes first)."""
    fn, cur = None, None
    for line in text.splitlines():
        s = line.strip()
        if cur is not None and s == "// mir::ConstOperand":
            cur[3].append([None, ""])
            continue
        if cur is not None and cur[3] and s.startswith("// + span: "):
            m = SPAN.match(s[len("// + span: "):])
            cur[3][-1][0] = m.groups() if m else None
            continue
        if cur is not None and cur[3] and s.startswith("// + const_: "):
            cur[3][-1][1] = s
            continue
        if s.startswith("//"):
            continue
        if cur is not None:
            yield cur
            cur = None
        if line.startswith(("fn ", "static ", "const ")):
            m0 = re.match(r"(fn [^(]+|(?:static|const) [^:]+(?:::promoted\[\d+\])?)", line)
            fn = m0.group(1).strip() if m0 else line[:60]
            continue
        m = STMT_SPAN.match(line)
        if m:
            sp = SPAN.match(m.group(2).strip())
            cur = [fn, m.group(1).strip(), sp.groups() if sp else None, []]
    if cur is not None:
        yield cur

def strip_generics(path):
    """`<AesGcm<Aes256, 12> as KeyInit>::new_from_slice` -> `::new_from_slice`."""
    while True:
        n = re.sub(r"<[^<>]*>", "", path)
        if n == path:
            return n
        path = n

def callee(code):
    """Callee path of a MIR call terminator `_5 = path(args) -> [...]`, or None."""
    if " -> " not in code:
        return None
    rhs = code.split(" = ", 1)[1] if re.match(r"^_\d+ = ", code) else code
    depth = 0
    for i, ch in enumerate(rhs):
        if ch == "<": depth += 1
        elif ch == ">" and rhs[i - 1] != "-": depth -= 1
        elif ch == "(" and depth == 0:
            return rhs[:i]
    return None

def type_matches(text):
    """All 'type' entries matching a type-bearing string, outermost first. The first match is
    the asset itself; later ones are its components (the SHA-256 inside Hmac<Sha256>) and are
    reported at the same place, marked with what they are part of."""
    found = []
    for src, rx, name, fam, prim, funcs, extra in KB:
        m = rx.search(text) if src == "type" else None
        if m:
            n = name.format(*m.groups())
            if all(n != f[0] for f in found):
                note = f" (component of {found[0][0]})" if found else ""
                found.append((n, kb_meta(m, fam, prim, funcs, extra), note))
    return found

def scan(out_dir, crates):
    hits = collections.defaultdict(lambda: {"occ": set(), "meta": None})
    units = find_units(out_dir, crates)
    for meta, base in units:
        unit = f"{meta['package']}-{meta['version']}"
        loc = Locator(meta)
        def occ(kind, span, symbol, ctx):
            if span is None:
                return (unit, kind, unit, None, None, symbol, ctx)
            path, l0, c0, _, _ = span
            return (unit, kind, loc(path), int(l0), int(c0) - 1, symbol, ctx)

        mono = pathlib.Path(base + ".mono")
        if mono.exists():
            for line in mono.read_text(errors="replace").splitlines():
                if not line.startswith("MONO_ITEM fn "):
                    continue
                item = decode_typenum(line[len("MONO_ITEM fn "):].split(" @@ ")[0])
                for n, meta_, note in type_matches(item):
                    hits[n]["occ"].add(occ("mono", None, item, "monomorphized instance" + note))
                    merge(hits[n], meta_)

        mir = pathlib.Path(base + ".mir")
        if not mir.exists():
            continue
        text = mir.read_text(errors="replace")
        # named statics referenced from function bodies: map alloc id -> static name
        allocs = dict(re.findall(r"^(alloc\d+) \(static: ([\w:]+)", text, re.M))
        nested = collections.defaultdict(set)
        for blk in re.finditer(r"^(alloc\d+) \([^)]*\) \{(.*?)^\}", text, re.M | re.S):
            nested[blk.group(1)] |= set(re.findall(r"alloc\d+", blk.group(2))) - {blk.group(1)}
        def closure(a, seen=None):
            seen = set() if seen is None else seen
            for b in nested.get(a, ()):
                if b not in seen:
                    seen.add(b); closure(b, seen)
            return seen

        for fn, code, sspan, operands in statements(text):
            # 1. static allocations: `_6 = const {alloc6: &ring::aead::Algorithm}`; the
            #    operand span points at the path expression naming the static.
            consts = re.findall(r"const \{(alloc\d+):", code)
            for a0 in consts:
                outer = allocs.get(a0)
                span = next((sp for sp, ct in operands if "{" + a0 + ":" in ct), None) or sspan
                for a in [a0] + sorted(closure(a0)):
                    sname = allocs.get(a)
                    if not sname:
                        continue
                    for src, rx, name, fam, prim, funcs, extra in KB:
                        m = rx.search(sname.split("::")[-1]) if src == "static" else None
                        if m:
                            n = name.format(*m.groups())
                            # a digest nested inside another static (SHA-256 inside
                            # ECDSA_P256_SHA256_FIXED) is located where the outer static is named
                            sym = outer if outer else sname
                            ctx = f"{fn} -> {sname}" if a == a0 else f"{fn} -> {sym} -> {sname} (nested)"
                            hits[n]["occ"].add(occ("mir-static", span, sym, ctx))
                            merge(hits[n], kb_meta(m, fam, prim, funcs, extra))
                            break
            # 2. calls: callee path with concrete generic arguments ('type') or a known
            #    non-generic function ('call'); the callee operand span is the first one.
            c = callee(code)
            if c is None:
                continue
            span = (operands[0][0] if operands else None) or sspan
            decoded = decode_typenum(c)
            for n, meta_, note in type_matches(decoded):
                hits[n]["occ"].add(occ("mir-type", span, decoded, fn + note))
                merge(hits[n], meta_)
            for src, rx, name, fam, prim, funcs, extra in KB:
                m = rx.search(strip_generics(c)) if src == "call" else None
                if m:
                    n = name.format(*m.groups())
                    hits[n]["occ"].add(occ("mir-call", span, decoded, fn))
                    merge(hits[n], kb_meta(m, fam, prim, funcs, extra))
                    break
    return hits, units

def occ_key(o):
    unit, kind, location, line, offset, symbol, ctx = o
    return (unit, line is None, location, line or 0, offset or 0, kind, symbol, ctx)

def cbom(hits, units):
    cap = int(os.environ.get("RCBOM_MAX_OCC", "8"))
    comps, deps = [], collections.defaultdict(set)
    for meta, _ in units:
        pkg, ver = meta["package"], meta["version"]
        comps.append({"type": "library", "name": pkg, "version": ver, "bom-ref": f"crate:{pkg}@{ver}",
                      "purl": f"pkg:cargo/{pkg}@{ver}"})
    for name in sorted(hits):
        h = hits[name]
        fam, prim, funcs, extra = h["meta"]
        ref = f"crypto:{name}"
        props = [{"name": "rcbom:detection:method", "value": "type-resolved"}]
        props += [{"name": f"rcbom:{k}", "value": v} for k, v in extra.items() if k not in ("mode", "parameterSetIdentifier")]
        ap = {"primitive": prim, "algorithmFamily": fam, "cryptoFunctions": funcs}
        if "mode" in extra: ap["mode"] = extra["mode"]
        if "parameterSetIdentifier" in extra: ap["parameterSetIdentifier"] = extra["parameterSetIdentifier"]
        # one occurrence per asset and source line: `<Hmac<Sha256> as Mac>::new_from_slice(k).unwrap()`
        # is one use, not two; the earliest column on the line is kept
        occ, seen = [], set()
        for o in sorted(h["occ"], key=occ_key):
            if o[3] is not None:
                if (o[0], o[2], o[3]) in seen:
                    continue
                seen.add((o[0], o[2], o[3]))
            occ.append(o)
        per_unit = collections.defaultdict(list)
        for o in occ:
            per_unit[o[0]].append(o)
        shown = [o for u in sorted(per_unit) for o in (per_unit[u][:cap] if cap else per_unit[u])]
        occurrences = []
        for unit, kind, location, line, offset, symbol, ctx in shown:
            o = {"location": location}
            if line is not None:
                o["line"], o["offset"] = line, offset
            o["symbol"] = symbol[:200]
            o["additionalContext"] = f"[{kind}] {ctx}"[:200]
            occurrences.append(o)
        comps.append({
            "type": "cryptographic-asset", "name": name, "bom-ref": ref,
            "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": ap},
            "evidence": {"occurrences": occurrences},
            "properties": props + [{"name": "rcbom:occurrences", "value": str(len(occ))}],
        })
        for o in occ:
            deps[o[0]].add(ref)
    unit_ref = {f"{m['package']}-{m['version']}": f"crate:{m['package']}@{m['version']}" for m, _ in units}
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.7", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {"tools": {"components": [{"type": "application", "name": "rcbom-phase0-spike"}]}},
        "components": comps,
        "dependencies": [{"ref": unit_ref[u], "provides": sorted(p)} for u, p in sorted(deps.items())],
    }

if __name__ == "__main__":
    out_dir, crates = sys.argv[1], sys.argv[2].split(",")
    print(json.dumps(cbom(*scan(out_dir, crates)), indent=2))
