#!/usr/bin/env python3
"""Phase 0 extractor: compiler facts (.mono = monomorphization collector, .mir = MIR dump)
-> CycloneDX 1.7 CBOM. Throwaway spike code; the real tool reads the same facts through
rustc_public instead of parsing text dumps.

usage: extract.py OUT_DIR CRATE[,CRATE...] > cbom.json
"""
import json, re, sys, uuid, pathlib, collections

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
#         'type'   = monomorphized instance (RustCrypto style)
#         'call'   = call edge in MIR to a non-generic function
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
    ("type", r"AesGcm<[\w:]*Aes256, (\d+)", "AES-256-GCM", "AES", "ae", AE, {"mode": "gcm", "parameterSetIdentifier": "256", "nonce_bytes": "{0}"}),
    ("type", r"AesGcm<[\w:]*Aes128, (\d+)", "AES-128-GCM", "AES", "ae", AE, {"mode": "gcm", "parameterSetIdentifier": "128", "nonce_bytes": "{0}"}),
    ("type", r"ChaChaPoly1305<[^ ]*ChaChaCore<10>>(?:, (\d+))?>", "ChaCha20-Poly1305", "ChaCha20", "ae", AE, {"nonce_bytes": "{0}"}),
    ("type", r"Hkdf<[^ ]*Sha256VarCore", "HKDF-SHA-256", "HKDF", "kdf", ["keyderive"], {}),
    ("type", r"HmacCore<[^ ]*Sha256VarCore", "HMAC-SHA-256", "HMAC", "mac", ["tag"], {}),
    ("type", r"Sha256VarCore", "SHA-256", "SHA-2", "hash", ["digest"], {}),
    ("call", r"(StaticSecret|EphemeralSecret)::diffie_hellman\(", "x25519", "ECDH", "key-agree", ["keygen"], {"curve": "Curve25519"}),
    ("call", r"\bscrypt::scrypt\(", "scrypt", "scrypt", "kdf", ["keyderive"], {"params": "unresolved (runtime work factor)"}),
]
KB = [(src, re.compile(rx), *rest) for src, rx, *rest in KB]

def merge(h, meta):
    if h["meta"] is None:
        h["meta"] = meta
    else:
        h["meta"][3].update({k: v for k, v in meta[3].items() if k not in h["meta"][3]})

def scan(out_dir, crates):
    hits = collections.defaultdict(lambda: {"occ": set(), "meta": None})
    for crate in crates:
        mono = pathlib.Path(out_dir, crate + ".mono")
        mir = pathlib.Path(out_dir, crate + ".mir")
        if mono.exists():
            for line in mono.read_text(errors="replace").splitlines():
                if not line.startswith("MONO_ITEM fn "):
                    continue
                item = decode_typenum(line[len("MONO_ITEM fn "):].split(" @@ ")[0])
                for src, rx, name, fam, prim, funcs, extra in KB:
                    if src != "type":
                        continue
                    m = rx.search(item)
                    if m:
                        n = name.format(*m.groups())
                        h = hits[n]
                        h["occ"].add((crate, "mono", item[:160]))
                        groups = [g if g is not None else "12" for g in m.groups()]
                        merge(h, (fam, prim, funcs, {k: v.format(*groups) for k, v in extra.items()}))
                        break
        if mir.exists():
            text = mir.read_text(errors="replace")
            # named statics referenced from function bodies: map alloc id -> static name
            allocs = dict(re.findall(r"^(alloc\d+) \(static: ([\w:]+)", text, re.M))
            nested = collections.defaultdict(set)
            for blk in re.finditer(r"^(alloc\d+) \([^)]*\) \{(.*?)^\}", text, re.M | re.S):
                nested[blk.group(1)] |= set(re.findall(r"alloc\d+", blk.group(2))) - {blk.group(1)}
            def closure(a, seen=None):
                seen = seen or set()
                for b in nested.get(a, ()):
                    if b not in seen:
                        seen.add(b); closure(b, seen)
                return seen
            fn = None
            for line in text.splitlines():
                if line.startswith(("fn ", "static ", "const ")):
                    m0 = re.match(r"(fn [^(]+|(?:static|const) [^:]+(?:::promoted\[\d+\])?)", line)
                    fn = m0.group(1).strip() if m0 else line[:60]
                for a0 in re.findall(r"const \{(alloc\d+):", line):
                  for a in [a0] + sorted(closure(a0)):
                    sname = allocs.get(a)
                    if not sname:
                        continue
                    for src, rx, name, fam, prim, funcs, extra in KB:
                        if src == "static" and rx.search(sname.split("::")[-1] if src == "static" else sname):
                            m = rx.search(sname.split("::")[-1])
                            n = name.format(*m.groups())
                            hits[n]["occ"].add((crate, "mir-static", f"{fn} -> {sname}"))
                            merge(hits[n], (fam, prim, funcs, extra))
                            break
                for src, rx, name, fam, prim, funcs, extra in KB:
                    if src == "call" and rx.search(line) and "->" in line:
                        hits[name]["occ"].add((crate, "mir-call", f"{fn}: {rx.search(line).group(0)}"))
                        merge(hits[name], (fam, prim, funcs, extra))
    return hits

def cbom(hits, crates):
    comps, deps = [], collections.defaultdict(set)
    for crate in crates:
        comps.append({"type": "library", "name": crate, "bom-ref": f"crate:{crate}", "purl": f"pkg:cargo/{crate}"})
    for name in sorted(hits):
        h = hits[name]
        fam, prim, funcs, extra = h["meta"]
        ref = f"crypto:{name}"
        props = [{"name": "rcbom:detection:method", "value": "type-resolved"}]
        props += [{"name": f"rcbom:{k}", "value": v} for k, v in extra.items() if k not in ("mode", "parameterSetIdentifier")]
        ap = {"primitive": prim, "algorithmFamily": fam, "cryptoFunctions": funcs}
        if "mode" in extra: ap["mode"] = extra["mode"]
        if "parameterSetIdentifier" in extra: ap["parameterSetIdentifier"] = extra["parameterSetIdentifier"]
        occ = sorted(h["occ"])
        per_crate = collections.defaultdict(list)
        for o in occ:
            per_crate[o[0]].append(o)
        shown = [o for c in sorted(per_crate) for o in per_crate[c][:8]]
        comps.append({
            "type": "cryptographic-asset", "name": name, "bom-ref": ref,
            "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": ap},
            "evidence": {"occurrences": [{"location": c, "additionalContext": f"[{k}] {ctx}"} for c, k, ctx in shown]},
            "properties": props + [{"name": "rcbom:occurrences", "value": str(len(occ))}],
        })
        for c, _, _ in occ:
            deps[f"crate:{c}"].add(ref)
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.7", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {"tools": {"components": [{"type": "application", "name": "rcbom-phase0-spike"}]}},
        "components": comps,
        "dependencies": [{"ref": r, "provides": sorted(p)} for r, p in sorted(deps.items())],
    }

if __name__ == "__main__":
    out_dir, crates = sys.argv[1], sys.argv[2].split(",")
    print(json.dumps(cbom(scan(out_dir, crates), crates), indent=2))
