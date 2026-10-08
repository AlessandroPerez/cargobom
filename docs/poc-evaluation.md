# cargo-cbom: proof-of-concept evaluation

*8 October 2026. cargo-cbom 0.1.0 (driver on `nightly-2026-09-25`), knowledge base 0.1.0.*

This is the evaluation of the first, deliberately narrow paper: Layers 1 and 2 of
`docs/rust-cbom-proposal2.md`, intraprocedural provenance, and a small labelled test set. A
labelled benchmark, a held-out test set and broader knowledge-base coverage are the subject of
the follow-up paper (section 9).

## 1. Questions

- **RQ1 Evidence.** Are the reported positions (file, line, column) correct?
- **RQ2 Detection.** On labelled programs, does the tool find the algorithms used, at the right line, with their parameters, and without false positives? How does it compare with rusi, cdxgen's Rust inspector?
- **RQ3 Provenance.** Does it say correctly where key material comes from?
- **RQ4 Ablation.** What do monomorphization and reachability add over a per-item scan?
- **RQ5 Feasibility.** Does it run on real projects, at what cost?

## 2. Setup

**Tool.** Layer 1 reads `cargo metadata` and the manifests. Layer 2 is a `RUSTC_WRAPPER` on `rustc_public` that records, in every crate:
- calls into knowledge-base crates, with their generic arguments as type trees
- references to algorithm statics and consts
- the intraprocedural origin of each call argument

It then walks the monomorphized instance graph from `main`, or from the public API of a library: vtables for `dyn`, function pointers, drop glue, statics. The stable analysis matches these facts against the knowledge base structurally (crate, item, generic-argument positions, version ranges), and emits CycloneDX 1.7, validated against the official schemas on every run.

**Knowledge base.** One coherent seed rather than the long tail:
- RustCrypto, 0.10 generation: AES-GCM, ChaCha20-Poly1305, HMAC, HKDF, SHA-1/2
- md5, blake3, pbkdf2, argon2, rsa (key generation), ed25519-dalek, x25519-dalek, scrypt
- ring 0.17, aws-lc-rs 1.x
- rustls 0.23 (protocol), jsonwebtoken 9

Crypto crates in other versions are reported as `unsupported-version` rather than guessed.

**Test programs.**

| set | origin | programs | labels |
|---|---|---|---|
| micro, libonly, threads | written for this work | 3 | golden files (designed cases) |
| rusi fixtures | cdxgen-plugins-bin@6a64635, MIT, unchanged | 3 | `labels.toml`, written from source before scoring |
| realapp | Phase 0 corpus (age, jsonwebtoken, rustls/ring) | 1 | Phase 0 output as oracle |
| corpus | crates.io releases: rage, jwt-cli, rcgen, minisign, xh | 5 | none (feasibility) |

The cases micro and libonly cover:
- a generic wrapper, and `dyn` dispatch
- ring statics, and `Hmac<Sha256>` composition
- a crypto call inside a `macro_rules!`
- comments and multi-line chains
- an aliased import, and a static table of algorithms
- dead code, and an unused crypto dependency
- a library with no `main`, and a public generic function
- crypto reached only through `std::thread::spawn`, a `Box<dyn FnOnce>` and a function pointer (threads)

**Baseline.** rusi 4.1.1, stable (syntax) backend, built from the same commit. Its report is converted to CycloneDX by `scripts/rusi_to_cbom.py`, keeping everything it reports.

## 3. RQ1: evidence positions

Every occurrence carries `location` (workspace-relative, or `<package>-<version>/<path>` in a dependency), `line`, `offset` (0-based column) and `symbol`. `cargo cbom verify` reopens each cited file and checks that the code at that position names the symbol, accepting:
- import aliases (`use … as …`)
- macro call sites (`hash_all!`)
- derive and attribute positions

With `--self-test` it shifts every position by ±1 line and ±1 column and requires the check to fail.

| set | positions | verified | shifted positions rejected |
|---|---|---|---|
| micro | 51 | 51 | 204/204 |
| libonly | 20 | 20 | 80/80 |
| threads | 15 | 15 | 60/60 |
| rusi fixtures (3) | 573 | 573 | 2289/2292 |
| realapp | 358 | 358 | 1432/1432 |
| corpus (5 projects) | 724 | 724 | 2882/2896 |
| **total** | **1741** | **1741** | **6947/6964** |

Positions come from rustc's spans, which are offsets into the original files, so comments and formatting cannot shift them. Code from a function-like macro is attributed to the outermost call site in the user's source, with the definition site kept in the context.

The self-test is a property of the verifier, not of the positions. When the same identifier sits at the same column on adjacent lines, as rustls's suite tables do, a shifted position can still look valid. That happened for 17 of 6,964 shifts (0.24%), in rustls and age sources.

## 4. RQ2: detection on labelled programs

Labels (`fixtures/rusi/*/labels.toml`) give, per program line:
- the asset with its registry name and parameters
- its tier: `core` (must be found) or `extended` (credited if found)
- the use, and the origin of its key material
- negative lines, which must stay empty (imports, a secret's provenance, a length constant `SHA256_OUTPUT_LEN`)

The scorer (`scripts/score.py`) counts (asset, line) pairs. A name counts if it is any registry-valid name for the algorithm (`AES-GCM` for AES-256-GCM), and "fully named" means the complete registry name with parameters.

| | recall | precision | fully named |
|---|---|---|---|
| cargo-cbom, seed knowledge base (held out) | 7/14 | 9/9 | 7/14 |
| cargo-cbom, current | 14/14 | 17/17 | 14/14 |
| rusi 4.1.1 | 13/14 | 13/15 | 7/14 |

The first row is the honest held-out number: it was measured before the knowledge base covered these crates, and every miss is a missing entry. The second row is a development-set score, because the entries for md5, blake3, pbkdf2, argon2, rsa, ed25519-dalek and aws-lc-rs were written after that run. Neither tool falls for `SHA256_OUTPUT_LEN`.

Both tools find nearly the same lines. The difference is what they say:

| line | cargo-cbom | rusi |
|---|---|---|
| `Aes256Gcm::new_from_slice` | AES-256-GCM (nonce 12, tag 16) | AES-GCM |
| `Hmac::<Sha256>::new_from_slice` | HMAC-SHA-256, SHA-256 as component | HMAC |
| `blake3::hash` | BLAKE3-256 | BLAKE3 |
| `pbkdf2_hmac::<Sha256>(.., 1_000, &mut [0u8; 32])` | PBKDF2-SHA-256-1000-32 | PBKDF2 |
| `Argon2::default().hash_password` | Argon2id-19456-2-1 | Argon2 |
| `RsaPrivateKey::new(&mut rng, 2048)` | RSA-2048 private key (material) | RSA |
| `UnboundKey::new(&AES_256_GCM, ..)` (ring) | AES-256-GCM | Ring-AEAD |
| `EncodingKey::from_secret` | HMAC secret key (algorithm set by the header) | JWT |
| `ClientConfig::builder()` | TLS 1.2/1.3, aws-lc-rs, 9 suites, X25519MLKEM768 + 3 groups | TLS |

The TLS row checks against the rustls 0.23.40 source: the default features select aws-lc-rs and prefer the post-quantum hybrid group. The provider's algorithms are reported as reachable capability, ML-KEM-768 included; QUIC header protection is reachable; `ALL_KX_GROUPS` extras such as ML-KEM-1024 are present only.

realapp, against its Phase 0 oracle, gives the same 28 algorithms. Beyond those it adds two asset kinds Phase 0 did not have: the JWT key as material, and TLS as a protocol with backend ring.

## 5. RQ3: provenance

For the knowledge base's roles (key, nonce, IV, salt, password, rng), the driver records each argument's origin inside the enclosing function. Closures defined there are followed one level. The analysis classifies the origin as hard-coded, environment, file, rng, parameter, derived or computed.

| | labelled (asset, line, role) origins stated exactly |
|---|---|
| cargo-cbom | 11/11 |
| rusi | 0/11 (origins not reported) |

The labels include the hard case of these fixtures: secrets read with `env::var("…").unwrap_or_else(|_| "literal".to_string())`. The right answer is "environment or hard-coded", which needs the closure. Findings are emitted for hard-coded key material.

On realapp this finds two real patterns:
- **A hard-coded HMAC key:** the program's own `EncodingKey::from_secret(b"secret")`.
- **A hard-coded nonce in age-core:** `c.encrypt(&[0; 12].into(), …)`. It is correct by design, because age uses each file key once. That is the case Layer 3 (purpose) exists for.

## 6. RQ4: ablation

`--no-walk` keeps the per-item scan and drops the monomorphized walk from the entry points (`scripts/ablation.py`).

| program | code occurrences (full / no walk) | found in a monomorphized generic instance | reachable (full) | own-source (asset, line) pairs (full / no walk) |
|---|---|---|---|---|
| micro | 25 / 19 | 6 | 24 | 24 / 18 |
| libonly | 12 / 4 | 8 | 11 | 10 / 4 |
| threads | 9 / 9 | 0 | 9 | 7 / 7 |
| rusi crates-app | 508 / 508 | 0 | 249 | 11 / 11 |
| realapp | 335 / 335 | 0 | 255 | 2 / 2 |
| rcgen (library) | 86 / 86 | 0 | 78 | 85 / 85 |
| rage | 84 / 66 | 35 | 77 | 0 / 0 |

The walk does two things.

- **Generic code.** Crypto written inside generic code is attributed only through monomorphization:
  - the designed cases: `fn seal<A: Aead>` (micro) and `pub fn tag<M: Mac>` (libonly)
  - in rage, 34 occurrences, 40% of its total, all in dependencies. age's SSH key decryption, `aes_gcm::<C: AeadMut + KeyInit>`, is AES-256-GCM `decrypt` only once instantiated. The hpke crate, generic over its KDF and AEAD, resolves to HKDF-SHA-256, HMAC-SHA-256, SHA-256 and ChaCha20-Poly1305 (one of them inside the `nistp_dhkex!` macro).

  A syntax-level tool cannot name any of these.
- **Tiers.** It separates capability from use. In realapp, scrypt and both age `diffie_hellman` calls are present but not reachable from `main`. In xh, ML-KEM-1024 and HMAC-SHA-512 are present only, while the default provider's algorithms are reachable through reqwest's client builder.

Programs that call crypto APIs directly from non-generic code (the rusi fixtures, realapp's own `main`, rcgen) lose nothing without the walk except the tier split.

## 7. RQ5: feasibility on real projects

Five crates.io applications and libraries (`scripts/corpus.py`). Each was built from a cold cache with the pinned nightly, against a plain `cargo check` with the same toolchain, on a 6-core machine.

| project | packages | plain check | cargo cbom | overhead | peak RSS | instances walked | algorithms (reachable) | other assets | occurrences (reachable) | findings |
|---|---|---|---|---|---|---|---|---|---|---|
| rage 0.12.1 | 277 | 16.5 s | 31.2 s | ×1.90 | 449 MiB | 47,413 | 10 (8) | – | 84 (77) | hard-coded nonce |
| jwt-cli 6.2.0 | 125 | 9.1 s | 16.7 s | ×1.84 | 382 MiB | 17,134 | 15 (15) | HMAC key | 43 (43) | hard-coded key |
| rcgen 0.14.10 (library) | 68 | 4.5 s | 6.7 s | ×1.48 | 261 MiB | 2,051 | 9 (9) | – | 86 (78) | – |
| minisign 0.10.0 | 37 | 2.2 s | 8.5 s | ×3.92 | 250 MiB | 1,311 | 1 (1) | – | 1 (1) | – |
| xh 0.26.2 | 312 | 36.4 s | 65.1 s | ×1.79 | 815 MiB | 57,351 | 34 (32) | TLS (aws-lc-rs) | 462 (242) | – |

- **Cost.** On the four projects larger than minisign the overhead is ×1.5 to ×1.9. minisign's ×3.9 is fixed per-crate cost on a two-second build. Memory peaks at 815 MiB, for xh.
- **Evidence.** All 724 positions verify.
- **rusi.** rusi (stable backend) reports 2 crypto components across the five projects (`JWT` in jwt-cli, `SHA-256` in xh). These programs reach their crypto through dependencies (age, jsonwebtoken, reqwest/rustls), which a source-level scan of the workspace does not enter.
- **Findings.** Both are real and intentional, and both show why purpose (Layer 3) matters:
  - age-core's `[0; 12]` nonce: age uses each file key once.
  - jwt-cli's `DecodingKey::from_secret("")`: used only when signature validation is explicitly disabled.
- **Coverage limit.** minisign implements Ed25519 and BLAKE2b in its own source. A knowledge-base tool sees only its use of the scrypt crate.

The first corpus runs exposed problems the fixtures could not. All are fixed (each with a fixture or a regression check), and the table is from the fixed tool:

1. **Optimisation profile.** minisign sets `[profile.dev] opt-level = 3`. At that level rustc's MIR inliner folds crypto calls into their callers, and the call sites disappear. The driver now pins `-Zmir-opt-level=1`, the debug-build MIR, whatever the profile; section 6.1 of the proposal anticipated this.
2. **Extern statics.** Evaluating an FFI static's initializer (xh links oniguruma) panics in rustc; the panic was caught but rustc's ICE hook failed the build. Foreign statics are skipped, and the driver silences the hook during its own analysis, so a panic stays a counted analysis error.
3. **Derives.** A `#[derive(Clone)]` produced a `Clone::clone` "use" of SHA-512, located at the derive. `Clone` of a crypto type is not a use: std trait calls are kept only for `Default::default`, which selects parameters (Argon2). Positions inside derives and attribute macros are now tagged, and `verify` checks them.
4. **Out-parameters.** `let mut nonce = [0u8; 12]; rng.fill_bytes(&mut nonce);` would have read as a hard-coded nonce. A local passed by `&mut` to a call is now also defined by that call, and its constant initialization is ignored.
5. **Shims.** In xh almost nothing was reachable: reqwest builds its TLS client inside a thread, and the walk stopped at the thread's `Box<dyn FnOnce>`. `rustc_public`'s `Instance::has_body()` asks about the instance's definition, which for a vtable or closure shim is a trait method without a body, so it returns `false` although `Instance::body()` builds the shim. The walk now relies on `body()`. The threads fixture covers the case, and the behaviour is worth reporting upstream.
6. **Error values.** In age's SSH key decryption, `derive_key_material(..).ok_or(DecryptError::KeyDecryptionFailed)?` read as a hard-coded key, because the error constant passed to `ok_or` was treated as data. In standard-library calls the value now comes from the receiver only, except in fallbacks such as `unwrap_or` and `unwrap_or_else`.

## 8. Limitations and threats

- **Labels.** One annotator so far; the second review is pending (`docs/rusi-fixtures-review.md`). The labelled set is small (3 programs, 14 core findings, 11 provenance roles), and its programs were written by rusi's authors, for rusi.
- **Development set.** The current scores in RQ2 and RQ3 were measured on the programs that guided the knowledge base and the provenance rules. The seed-knowledge-base row is the only held-out result.
- **Baseline.** rusi was run with its default syntax backend only; its compiler backend needs a stable ≥ 1.98 with `rustc-dev`.
- **Reachability is not value-sensitive.** jsonwebtoken's `encode` matches on a run-time algorithm, so all its signing algorithms are reachable.
- **Reachability is not proven sound.** It over-approximates within what it walks, like rustc's mono-item collector: vtables of every unsized type, function pointers, drop glue. It can still miss edges through non-generic std code, or through function pointers it cannot see created. A crypto use the walk misses is reported `present`, not dropped. The xh case (section 7) shows how a single missing edge kind changes the tier picture, and why the threads fixture now guards it.
- **Provenance is intraprocedural.** Values crossing a function boundary are reported as `parameter` or `computed`.
- **Standard library.** Non-generic std code has no MIR without a std sysroot, so the walk does not enter it. Generic std code (threads, iterators, closures, `dyn` calls) is walked.
- **Knowledge-base tool.** Self-implemented cryptography is invisible (minisign's own Ed25519 and BLAKE2b), and so are crates outside the seed. Trait-based inference (any `Digest` or `Aead` implementation) is future work.
- **Corpus.** Five projects, chosen by us for their crypto dependencies; the feasibility numbers say nothing about recall on them, which is unlabelled.
- **Execution.** Layer 2 compiles the project, so build scripts and proc macros run. Run it on trusted code, or in a container.
- **Toolchain.** The driver needs one pinned nightly with `rustc-dev`.
  - `rustc_public` does not yet expose promoted MIR, unevaluated consts in monomorphic bodies, vtable entries, macro call sites, impl self types or def-path hashes, so those go through `rustc_middle`.
  - Its `Instance::has_body()` answers for the definition rather than the instance, which hides shims (section 7); the driver uses `Instance::body()` instead.

## 9. Toward the second paper

- A labelled benchmark in CycloneDX form, labelled before the tool is run, with two annotators, built from:
  - CodeQL's line-labelled Rust crypto tests
  - translated CryptoAPI-Bench cases
  - 20–30 real projects
- Knowledge base: the long tail, both RustCrypto generations, openssl and the PQC crates.
- Value-sensitive reachability, interprocedural provenance, Layer 3 (purpose) and Layer 4 (reachability-filtered VEX).
- More baselines: rusi's compiler backend, cdxgen's conversion, CodeQL's queries, through BF-CBOM.
