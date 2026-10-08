# Phase 0 spike — results

## Verdict

**Gate passed at the data level, not yet at the API level.** The compiler resolves all three Phase 0 patterns in a synthetic crate and in three real crates. A wrapper around every rustc invocation turns those facts into a CycloneDX 1.7 CBOM that validates against the official schema. The `rustc_public` API itself was **not** exercised: the sandbox's egress policy blocks `static.rust-lang.org`, so no nightly or `rustc-dev` component could be installed.

The spike reads the same facts that `rustc_public` exposes as `Instance` and static allocations, through the compiler's own debug outputs. It runs stable rustc in bootstrap mode (`RUSTC_BOOTSTRAP=1`) with `-Zprint-mono-items` (the monomorphization collector) and `-Zunpretty=mir -Zmir-include-spans=yes` (MIR, including named static allocations, with a source span on every statement). So the open question for F1 is no longer whether the compiler can attribute these call sites; it can. What remains is the cost of reading the same data through `rustc_public` on a pinned nightly.

## What was tested

**Synthetic spike crate (`spike/`), RustCrypto 0.10 generation plus ring 0.17:**

1. Generic wrapper `fn seal<A: Aead + AeadCore + KeyInit>`. Resolved to two concrete instances, `AesGcm<Aes256, 12>` and `ChaChaPoly1305<ChaCha20Core<10>>` (nonce size 12 via the elided default). The 12-byte nonce is decoded from the typenum chain in the type.
2. `dyn Sealer` chosen at runtime from `argv`. Both impls are in the mono-item set: sound and over-approximate, as expected (F5).
3. ring constant `UnboundKey::new(&AES_256_GCM, key)`. MIR shows `const {alloc6: &ring::aead::Algorithm}`, and the allocation section names it `alloc6 (static: AES_256_GCM)`. Its function pointers lead to `aes_gcm_init_256` and `aes_gcm_seal`, which independently confirms the algorithm.
4. `Hmac<Sha256>`. The composition is visible in the type (`HmacCore<CoreWrapper<CtVariableCoreWrapper<Sha256VarCore, …>>>`).
5. Bonus: the hard-coded nonce `[const 0_u8; 12]` passed to `Nonce::assume_unique_for_key` is visible in MIR, which is the raw material for provenance (F6).

**Real crates, built as dependencies of a small app (`realapp/`, 174 packages in the graph, 136 compiled through the wrapper):**

- **age 0.11 / age-core.** ChaCha20-Poly1305 and `Hkdf<Sha256>` appear as instances in `age_core`, and as type-resolved calls at their source lines (`ChaCha20Poly1305::new` in `primitives.rs:16`, `Hkdf::<Sha256>::new` at `primitives.rs:50`). X25519 `diffie_hellman` and `scrypt::scrypt` appear as MIR call edges in `age`; the scrypt call is found at `primitives.rs:68` even though the source calls it through the alias `scrypt_inner`. scrypt's work factor is computed at runtime, so its parameters are reported as unresolved.
- **jsonwebtoken 9.3 (ring backend).** All 23 ring algorithm constants of the JWT algorithm table were found (HMAC-SHA-256/384/512, RSA PKCS#1 and PSS with SHA-256/384/512, ECDSA P-256 and P-384, Ed25519, SHA-2), each attributed to the function that selects it (`alg_to_rsa_signing`, `crypto::sign`, `alg_to_ec_signing`, …). Digests nested inside other statics, such as the SHA-256 inside `ECDSA_P256_SHA256_FIXED`, are found by following allocation pointers.
- **rustls 0.23 (ring provider).** All 9 cipher suites (3 TLS 1.3, 6 TLS 1.2), the KX groups and the signature schemes appear as named statics. `TLS13_AES_256_GCM_SHA384` decomposes from its MIR body into SHA-384, HMAC-SHA384, HKDF-SHA384, AES-256-GCM and AES-256 (QUIC header protection), plus its TLS confidentiality limit (`1<<24`) and its QUIC packet-protection limits (`1<<23` confidentiality, `1<<52` integrity).

**Output:** `cbom-spike.json` (4 assets) and `cbom-realapp.json` (28 assets), with registry-family names, cryptoFunctions, mode, parameter set, nonce size, curve, evidence and `dependencies[].provides` (versioned `pkg:cargo` purls). Both validate against the official CycloneDX 1.7 schema with the cryptography-registry enum enforced; a negative control with a bogus `algorithmFamily` is rejected.

**Evidence locations.** Every occurrence read from MIR carries `location` (path relative to the workspace root for workspace crates, `<package>-<version>/<path>` for dependencies), `line` (1-based), `offset` (0-based column, the CBOMkit convention) and `symbol` (the static or callee matched); `additionalContext` names the enclosing function. Mono items have no span in `-Zprint-mono-items`, so they carry only the crate. Default output lists at most 8 occurrences per asset and crate (`RCBOM_MAX_OCC=0` lists all); 9 of 32 listed occurrences in the spike and 176 of 206 in realapp carry a line. `verify_lines.py` reopens each cited file and checks that the code at `line`/`offset` names the symbol (accepting `use … as` aliases): all 185 pass. As a control, shifting every line by ±1 or every column by ±1 makes all of them fail. Spike positions, checked by hand: `seal::<Aes256Gcm>` at `src/main.rs:23:8`, `seal::<ChaCha20Poly1305>` at 28:8, `AES_256_GCM` at 38:46, `Hmac<Sha256>` at 45:16, 46:6 and 47:6 (SHA-256 is reported at the same places as a component of HMAC-SHA-256).

## Measurements

- Wrapped build of `realapp`: 100 s versus 64 s plain (×1.56). Re-measured on 7 October 2026 on a 6-core machine with stable 1.97.1 and spans enabled: 28.2 s versus 18.0 s (×1.56). The cost is the second rustc pass for the MIR dump; reading through `rustc_public` inside a single compile would remove it.
- Text dumps: 101 MB for 126 crates without spans; 392 MB for 136 crates with `-Zmir-include-spans=yes`. Extraction: 2 s without spans, 3 s with them.
- `-Zalways-encode-mir` under `cargo check`: dependency metadata grows 25–45% (aes-gcm 33→43 KB, ring 1.76→2.56 MB, sha2 636→868 KB) with no measurable time cost. This is consistent with dependency MIR being encoded; reading it back needs `rustc_private`, so it is indirect evidence only.

## Findings that change the plan

1. **Capability versus use.** Per-crate analysis lists what each library *can* do: all 23 JWT algorithms, all 9 rustls suites, both `dyn` impls. The app actually uses HS256 and one `Sealer`. The CBOM needs two tiers, "present in a linked crate" and "reachable from the application's entry points", and the second needs the call graph and enum/constant propagation planned for Layers 2 and 4. Without that, a CBOM over-reports, which is the same failure mode Olewinski et al. measured in existing tools.
2. **Two data sources are both required.** Mono items catch generic instantiations codegened in a crate (RustCrypto). Calls to non-generic functions in other crates (`diffie_hellman`, `scrypt`) appear only as MIR call edges, and ring/aws-lc-rs algorithms only as static allocations. A tool reading only one of these misses a whole API style.
3. **Name matching produces false PQC.** `X25519MLKEM768` appears in rustls MIR as a `NamedGroup` enum variant even though the ring provider does not implement it. Keying on static allocations and instances, not strings, avoided this false positive.
4. **Knowledge-base entries are version- and printing-sensitive.** chacha20poly1305 0.10 prints its nonce-size parameter as an elided default, so the first regex missed it. Types in expression position print with a turbofish (`Hkdf::<Sha256>::new`), which the first `Hkdf<`/`AesGcm<` regexes also missed. Real entries must key on definition paths and generic arguments, which `rustc_public` provides structurally.
5. **Nested statics.** Digests referenced only from inside other statics need pointer-following through allocation data.
6. **Text dumps are a viable zero-install fallback but a poor foundation.** They work on any stable toolchain with `RUSTC_BOOTSTRAP=1`, but the formats are unstable, paths are trimmed (`StaticSecret::diffie_hellman` without its crate), mono items carry no source spans (MIR statements do, with `-Zmir-include-spans=yes`, at four times the dump size), and `RUSTC_BOOTSTRAP` is officially discouraged. Macro-expanded code reports spans inside the macro definition, not at the call site. This keeps `rustc_public` as the primary front end; the text route could serve as a no-nightly degraded mode.

## Not tested

- The `rustc_public` API (toolchain download blocked).
- Reading dependency MIR back from metadata.
- aws-lc-rs, which is rustls's default provider, and the openssl crate.
- Interprocedural provenance, the sandbox, and reachability pruning from `main`.

## Next step

On a machine that can reach `static.rust-lang.org`, install `nightly-2026-09-25` (Kani's pin) with `rustc-dev` and `llvm-tools`, then port `extract.py`'s three matchers (instances, static allocations, call edges) to a `rustc_public` driver. Use the same corpus and compare against these two CBOMs as the oracle. Add a reachability pass from the binary's entry points to produce the "used" tier. Expected: one to two weeks.

## Files

- `spike/`: synthetic target crate.
- `realapp/`: app pulling in age, jsonwebtoken and rustls (ring).
- `rcbom-wrapper.sh`: the `RUSTC_WRAPPER` (skips build scripts and proc macros). Writes `<crate>-<version>.{mir,mono,meta}`; the version keeps two versions of one crate (realapp has sha2 0.10 and 0.11) from overwriting each other, and `.meta` records rustc's working directory so span paths can be resolved.
- `extract.py`: compiler facts to CycloneDX 1.7, with a seed knowledge base of about 26 entries and typenum decoding.
- `verify_lines.py`: checks every cited `location`/`line`/`offset` against the source file.
- `cbom-spike.json`, `cbom-realapp.json`: outputs.

To reproduce, from `phase0/` (a clean build, since the wrapper only sees crates cargo compiles):

```
(cd realapp && cargo clean && RUSTC_BOOTSTRAP=1 RCBOM_OUT=$PWD/../out-realapp RUSTC_WRAPPER=$PWD/../rcbom-wrapper.sh cargo build)
python3 extract.py out-realapp age,age_core,jsonwebtoken,rustls,realapp > cbom-realapp.json
python3 verify_lines.py out-realapp cbom-realapp.json
```

The same with `spike` and crate list `spike` gives `cbom-spike.json`.
