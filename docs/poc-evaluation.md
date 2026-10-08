# cargo-cbom: proof-of-concept evaluation

*8 October 2026. cargo-cbom 0.1.0 (driver on `nightly-2026-09-25`), knowledge base 0.2.0, facts version 7.*

This is the evaluation of the first, deliberately narrow paper: Layers 1 and 2 of
`docs/rust-cbom-proposal2.md`, intraprocedural provenance, and a small labelled test set. A
labelled benchmark, a held-out test set and broader knowledge-base coverage are the subject of
the follow-up paper (section 10).

All outputs behind the tables (CBOMs, scores, baseline reports, corpus and ablation data) are in
`results/`, with the command that regenerates each part in `results/README.md`.

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
- RustCrypto, 0.10 generation: AES-GCM, (X)ChaCha20-Poly1305, AES-CBC and AES-CTR modes, HMAC, HKDF, SHA-1/2 (SHA-512/t included), and the trait crates (aead, digest, cipher, crypto-common, signature, password-hash)
- md5, blake3, pbkdf2, argon2, rsa (key generation, PKCS#1 v1.5, PSS, OAEP), ed25519-dalek, x25519-dalek, scrypt
- ring 0.17, aws-lc-rs 1.x (AEADs, digests, HMAC, HKDF, PBKDF2, ECDSA, Ed25519, RSA, ECDH, ML-KEM, ML-DSA, CMAC, key wrap)
- rustls 0.23 (protocol), jsonwebtoken 9
- rand, rand_chacha, rand_core, getrandom, as the random generators (provenance sources)

Asset names are checked against the Cryptography Registry's own patterns
(`schema/cryptography-defs.json`); a name with no pattern is flagged in the CBOM.

Crypto crates in other versions are reported as `unsupported-version` rather than guessed.

**Test programs.**

| set | origin | programs | labels |
|---|---|---|---|
| micro, libonly, threads | written for this work | 3 | golden files (designed cases) |
| rusi fixtures | cdxgen-plugins-bin@6a64635, MIT, unchanged | 3 | `labels.toml`, written from source before scoring |
| realapp | Phase 0 corpus (age, jsonwebtoken, rustls/ring) | 1 | Phase 0 output as oracle |
| regression probes | written by three independent audits of the pipeline, and after the corpus runs (section 8) | 21 | golden files (each case commented) |
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

Every occurrence carries `location` (workspace-relative, or `<package>-<version>/<path>` in a dependency), `line`, `offset` (0-based column), `symbol`, and in its context the source line and the exact text at the position (`line: \`let d = Sha512_256::digest(data);\`; code: \`Sha512_256::digest\``). `cargo cbom verify` reopens each cited file and checks, from the CBOM and the sources only:
- that the position starts a token in code, not in a comment or a literal;
- that the line is the recorded line, and the source at the position starts with the recorded text and is a path whose last segment is the symbol's name or an import alias of it (aliases read from `use` items only);
- macro call sites (`hash_all!`, `ml::sha512_of!`), derive and attribute positions;
- that a component is where the asset it is part of is, that one asset has one occurrence per position and symbol, and that a qualifier imported from a crate of the CBOM belongs to a crate providing the asset;
- for manifests, the exact key, and in `Cargo.lock` the package's name and version lines.

With `--self-test` it shifts every position by ±1 line and ±1 column and counts how often the check then fails. A shift that would leave the first line or column is skipped, so the column −1 direction has fewer shifted positions than the others (many manifest and item positions start at column 0).

| set | positions | verified | shifted positions rejected |
|---|---|---|---|
| micro | 54 | 54 | 188/188 |
| libonly | 20 | 20 | 72/72 |
| threads | 15 | 15 | 54/54 |
| rusi fixtures (3) | 613 | 613 | 2,385/2,385 |
| realapp | 395 | 395 | 1,553/1,553 |
| regression probes (21) | 2,038 | 2,038 | 7,924/7,924 |
| corpus (5 projects) | 812 | 812 | 3,187/3,187 |
| **total** | **3,947** | **3,947** | **15,363/15,363** |

Positions come from rustc's spans, which are offsets into the original files, so comments and formatting cannot shift them. Code from a function-like macro is attributed to the outermost call site in the user's source, with the definition site kept in the context.

The self-test measures the verifier, not the positions: a shifted position the verifier accepts means the CBOM's evidence did not pin the position down. Every shift is now rejected. Earlier rounds accepted some: 17 of 6,881 shifts in the first evaluation, where the same identifier sat at the same column on adjacent lines (adjacent `new_from_slice` calls in the crates-app fixture, rcgen's `sign_algo.rs`, the hpke crate's `kdf.rs`). The audits removed those by recording the exact text at each position (section 8). One more appeared in the re-run after them, in rcgen: `KeyPairKind::Ec(kp) => kp.public_key()` above `KeyPairKind::Ed(kp) => kp.public_key()`, the same text at the same column. Only the line tells them apart, so each occurrence now records its line too (section 7, item 8).

## 4. RQ2: detection on labelled programs

Labels (`fixtures/rusi/*/labels.toml`) give, per program line:
- the asset with its registry name and parameters
- its tier: `core` (must be found) or `extended` (credited if found)
- the use, and the origin of its key material
- negative lines, which must stay empty (imports, a secret's provenance, a length constant `SHA256_OUTPUT_LEN`)

The scorer (`scripts/score.py`) counts (asset, line) pairs. A name counts if it is listed in the label's `accept` list: the complete registry name and the valid less specific registry names (`AES-GCM`, `AES` for AES-256-GCM; `HMAC` for HMAC-SHA-256; not `Argon2`, which has no registry pattern). "Fully named" means the complete registry name with parameters. Provenance is scored on the core assets.

| | recall | precision | fully named |
|---|---|---|---|
| cargo-cbom, seed knowledge base (held out) | 7/14 | 9/9 | 7/14 |
| cargo-cbom, current | 14/14 | 17/17 | 14/14 |
| rusi 4.1.1 | 12/14 | 12/15 | 7/14 |

The first row is the honest held-out number: it was measured before the knowledge base covered these crates, and every miss is a missing entry. The second row is a development-set score, because the entries for md5, blake3, pbkdf2, argon2, rsa, ed25519-dalek and aws-lc-rs were written after that run. rusi's two misses are names the registry has no pattern for, which the scorer does not accept: `Argon2` for the Argon2id use, and `Ring-AEAD` for ring's AES-256-GCM. Both count again as false positives. Neither tool falls for `SHA256_OUTPUT_LEN`.

Both tools find nearly the same lines. The difference is what they say:

| line | cargo-cbom | rusi |
|---|---|---|
| `Aes256Gcm::new_from_slice` | AES-256-GCM (nonce 12, tag 16) | AES-GCM |
| `Hmac::<Sha256>::new_from_slice` | HMAC-SHA-256, SHA-256 as component | HMAC |
| `blake3::hash` | BLAKE3-256 | BLAKE3 |
| `pbkdf2_hmac::<Sha256>(.., 1_000, &mut [0u8; 32])` | PBKDF2-SHA-256-1000-32 | PBKDF2 |
| `Argon2::default().hash_password` | Argon2id-19456-2-1 | Argon2 (no registry pattern) |
| `RsaPrivateKey::new(&mut rng, 2048)` | RSA-2048 private key (material) | RSA |
| `UnboundKey::new(&AES_256_GCM, ..)` (ring) | AES-256-GCM | Ring-AEAD |
| `EncodingKey::from_secret` | HMAC secret key (algorithm set by the header) | JWT |
| `ClientConfig::builder()` | TLS 1.2/1.3, aws-lc-rs, 9 suites, X25519MLKEM768 + 3 groups | TLS |

The TLS row checks against the rustls 0.23.40 source: the default features select aws-lc-rs and prefer the post-quantum hybrid group. The provider's algorithms are reported as reachable capability, ML-KEM-768 included; QUIC header protection is reachable; `ALL_KX_GROUPS` extras such as ML-KEM-1024 are present only.

realapp, against its Phase 0 oracle, gives the same 28 algorithms, and one more: ChaCha20, the QUIC header protection of rustls's TLS 1.3 ChaCha20-Poly1305 suite, which the knowledge base did not list in Phase 0. Beyond those it adds two asset kinds Phase 0 did not have: the JWT key as material, and TLS as a protocol with backend ring.

## 5. RQ3: provenance

For the knowledge base's roles (key, nonce, IV, salt, password, rng), the driver records each argument's origin inside the enclosing function. Closures defined there are followed one level. The analysis classifies the origin as hard-coded, environment, file, rng, parameter, derived or computed.

| | labelled (asset, line, role) origins of core assets stated exactly |
|---|---|
| cargo-cbom | 10/10 |
| rusi | 0/10 (origins not reported) |

The labels include the hard case of these fixtures: secrets read with `env::var("…").unwrap_or_else(|_| "literal".to_string())`. The right answer is "environment or hard-coded", which needs the closure. Findings are emitted for hard-coded key material.

On realapp this finds two real patterns:
- **A hard-coded HMAC key:** the program's own `EncodingKey::from_secret(b"secret")`.
- **A hard-coded nonce in age-core:** `c.encrypt(&[0; 12].into(), …)`. It is correct by design, because age uses each file key once. That is the case Layer 3 (purpose) exists for.

## 6. RQ4: ablation

`--no-walk` keeps the per-item scan and drops the monomorphized walk from the entry points (`scripts/ablation.py`).

| program | code occurrences (full / no walk) | found in a monomorphized generic instance | reachable (full) | own-source (asset, line) pairs (full / no walk) |
|---|---|---|---|---|
| micro | 26 / 20 | 6 | 25 | 24 / 18 |
| libonly | 12 / 4 | 8 | 11 | 10 / 4 |
| threads | 9 / 9 | 0 | 9 | 7 / 7 |
| rusi crates-app | 538 / 538 | 0 | 264 | 11 / 11 |
| rusi asymmetric-app | 6 / 6 | 0 | 6 | 4 / 4 |
| rusi modern-app | 2 / 2 | 0 | 2 | 2 / 2 |
| realapp | 368 / 368 | 0 | 275 | 2 / 2 |
| rcgen (library) | 92 / 92 | 0 | 84 | 91 / 91 |
| rage | 117 / 84 | 36 | 117 | 0 / 0 |

The walk does two things.

- **Generic code.** Crypto written inside generic code is attributed only through monomorphization:
  - the designed cases: `fn seal<A: Aead>` (micro) and `pub fn tag<M: Mac>` (libonly)
  - in rage, 36 occurrences, 31% of its total, all in dependencies. age decrypts passphrase-protected OpenSSH keys with generic helpers, `aes_gcm::<C: AeadMut + KeyInit>`, `aes_ctr::<C>` and `aes_cbc::<C>`: they are AES-256-GCM, AES-128/192/256-CTR and AES-256-CBC only once instantiated. The hpke crate, generic over its KDF and AEAD, resolves to HKDF-SHA-256, HMAC-SHA-256, SHA-256 and ChaCha20-Poly1305 (one of them inside the `nistp_dhkex!` macro); bcrypt-pbkdf to SHA-512.

  A syntax-level tool cannot name any of these.
- **Tiers.** It separates capability from use. In realapp, scrypt and both age `diffie_hellman` calls are present but not reachable from `main`. In xh, ML-KEM-1024 and HMAC-SHA-512 are present only, while the default provider's algorithms are reachable through reqwest's client builder.

Programs that call crypto APIs directly from non-generic code (the rusi fixtures, realapp's own `main`, rcgen) lose nothing without the walk except the tier split.

## 7. RQ5: feasibility on real projects

Five crates.io applications and libraries (`scripts/corpus.py`). Each was built from a cold cache with the pinned nightly, against a plain `cargo check` with the same toolchain, on a 6-core machine.

| project | packages | plain check | cargo cbom | overhead | peak RSS | instances walked | algorithms (reachable) | other assets | occurrences (reachable) | findings |
|---|---|---|---|---|---|---|---|---|---|---|
| rage 0.12.1 | 223 | 17.4 s | 33.8 s | ×1.94 | 517 MiB | 48,161 | 13 (13) | – | 117 (117) | hard-coded nonce |
| jwt-cli 6.2.0 | 76 | 9.0 s | 17.2 s | ×1.90 | 430 MiB | 17,272 | 15 (15) | HMAC key | 45 (45) | hard-coded key |
| rcgen 0.14.10 (library) | 57 | 4.5 s | 8.3 s | ×1.82 | 316 MiB | 2,074 | 9 (9) | – | 92 (84) | – |
| minisign 0.10.0 | 22 | 2.1 s | 8.2 s | ×3.81 | 311 MiB | 1,360 | 1 (1) | – | 1 (1) | – |
| xh 0.26.2 | 251 | 36.4 s | 72.7 s | ×2.00 | 968 MiB | 57,460 | 37 (34) | TLS (aws-lc-rs) | 489 (256) | – |

- **Cost.** On the four projects larger than minisign the overhead is ×1.8 to ×2.0. minisign's ×3.8 is fixed per-crate cost on a two-second build. Memory peaks at 968 MiB, for xh. Packages are those a host build resolves (`cargo metadata --filter-platform`), as Layer 1 counts them.
- **Evidence.** All 812 positions verify, and the self-test rejects all 3,187 shifted ones. The driver caught no panic in any of the five builds.
- **rusi.** rusi (stable backend) reports 2 crypto components across the five projects: `JWT` in jwt-cli, and `SHA-256` in xh's `src/message_signature.rs`, a module compiled only with the non-default feature `http-message-signatures` (which cargo-cbom, analysing default features, does not see). These programs reach their crypto through dependencies (age, jsonwebtoken, reqwest/rustls), which a source-level scan of the workspace does not enter.
- **Findings.** Both are real and intentional, and both show why purpose (Layer 3) matters:
  - age-core's `[0; 12]` nonce: age uses each file key once.
  - jwt-cli's `DecodingKey::from_secret("")`: used only when signature validation is explicitly disabled.
- **Coverage limit.** minisign implements Ed25519 and BLAKE2b in its own source. A knowledge-base tool sees only its use of the scrypt crate.

The first corpus runs exposed problems the fixtures could not. All are fixed (each with a fixture or a regression check), and the table is from the fixed tool:

1. **Optimisation profile.** minisign sets `[profile.dev] opt-level = 3`, which raises every crate to MIR opt-level 2. At that level the GVN pass rebuilds constant operands without a source span, the callee of every call included, so no call has a position and the driver drops it. In crates not compiled incrementally (all registry dependencies), the MIR inliner also folds calls into their callers. Disabling passes one at a time shows GVN is the cause: without GVN all of minisign's calls come back, and without the inliner none do. Level 1 still runs `RemoveZsts`, which erases zero-sized values (a callee held in a local, `OsRng`), and copy propagation, which merges the definitions argument origins follow (found in the audit, section 8). The driver now pins `-Zmir-opt-level=0`, the least transformed MIR, whatever the profile. Section 6.1 of the proposal anticipated a dependence on the MIR level, but for inlining only.
2. **Extern statics.** Evaluating an FFI static's initializer (xh links oniguruma) panics in rustc; the panic was caught but rustc's ICE hook failed the build. Foreign statics are skipped, and the driver silences the hook during its own analysis, so a panic stays a counted analysis error.
3. **Derives.** A `#[derive(Clone)]` produced a `Clone::clone` "use" of SHA-512, located at the derive. `Clone` of a crypto type is not a use: std trait calls are kept only for `Default::default`, which selects parameters (Argon2). Positions inside derives and attribute macros are now tagged, and `verify` checks them.
4. **Out-parameters.** `let mut nonce = [0u8; 12]; rng.fill_bytes(&mut nonce);` would have read as a hard-coded nonce. A local passed by `&mut` to a call is now also defined by that call, and its constant initialization is ignored.
5. **Shims.** In xh almost nothing was reachable: reqwest builds its TLS client inside a thread, and the walk stopped at the thread's `Box<dyn FnOnce>`. `rustc_public`'s `Instance::has_body()` asks about the instance's definition, which for a vtable or closure shim is a trait method without a body, so it returns `false` although `Instance::body()` builds the shim. The walk now relies on `body()`. The threads fixture covers the case, and the behaviour is worth reporting upstream.
6. **Error values.** In age's SSH key decryption, `derive_key_material(..).ok_or(DecryptError::KeyDecryptionFailed)?` read as a hard-coded key, because the error constant passed to `ok_or` was treated as data. In standard-library calls the value now comes from the receiver only, except in fallbacks such as `unwrap_or` and `unwrap_or_else`.

The re-run after the audits (section 8) found seven more. All are fixed, and each is covered by a regression probe, a golden file or the corpus run:

7. **Panics inside compiler queries.** rage did not build. Before the build failed, the driver had caught panics in 122 items of rage, its `rage-keygen` binary and one dependency (flate2). Two bugs caused them. An inline `const { .. }` was read with the enclosing function's generic arguments instead of its own (it surfaced in standard-library MIR that inlines such blocks). And a dependency's *trivial* constant, an enum discriminant such as `Ordering::Less`, has no MIR stored for it, and asking for it panics inside the query. A panic inside a query leaves it marked as running, and in an incremental build, which cargo uses for workspace members, rustc then aborts. `cargo cbom` also hid the reason: it captured cargo's error output and dropped it. The driver now reads inline consts with their own arguments, and trivial constants by their value. `scripts/e2e.sh` and `scripts/corpus.py` treat any caught panic as a failure, and `RCBOM_DEBUG=1` prints each one with the driver's frames.
8. **The same text on the next line.** In rcgen, `KeyPairKind::Ec(kp) => kp.public_key()` sits above `KeyPairKind::Ed(kp) => kp.public_key()`: the same callee name at the same column, and only the second is Ed25519. The self-test moved the Ed25519 position one line up, and the verifier accepted it. Each occurrence now records its source line (`line: \`..\``), and the verifier requires it.
9. **A derived key read as hard-coded.** age derives an X25519 key with its own helper, `hkdf(ssh_key, LABEL, &[]).into()`. The classification looked through any call into the union of its arguments, so the constant label and the empty salt made the key "hard-coded". Calls outside the knowledge base are now `computed`, as an intraprocedural analysis should say. A knowledge-base call is hard-coded only when every argument carrying data is.
10. **Two descriptions of one fact.** The walk read a monomorphic function's instance body, in which named constants are already evaluated, while the per-item scan read the item body; the same argument was "static `LABEL`" in one and "literal at line 119" in the other, and the merged occurrence listed both. The walk now scans monomorphic functions in their item bodies too.
11. **A slow analysis.** minisign took 204 s instead of 9: the argument-origin analysis was computed for every function, and minisign's own unrolled BLAKE2b compression function took 103 s on its own, once in the per-item scan and once in the walk. That function calls no crypto API, so nothing needs its origins. The analysis now runs only when an origin is asked for, and solves each block's effect once (section 23 of `docs/poc_workflow.md`): 0.4 s.
12. **Names and uses in code first analysed.** With rage's items analysed, four rules proved wrong or too narrow. age encrypts with `RsaPublicKey::encrypt(.., Oaep::new_with_label::<Sha256, _>(label), ..)`: the call was a bare RSA-OAEP, because `Oaep` keeps its digest at run time, and only the constructor on the next line was RSA-OAEP-SHA-256. A call now takes the name of a same-family constructor found in its arguments, located by position. `decrypt_blinded` was "setup, not a use", and a stream cipher's `apply_keystream`, in age's SSH-key *decryption*, was `encrypt`. It is now `encrypt or decrypt`. Last, a call matching a `[[fn]]` entry also matched its own type, of the same family, as a component of itself: age's x25519 `diffie_hellman` calls read "part of x25519" in the golden files. That type match is now skipped.
13. **Machine paths.** Standard-library positions in `instantiated by` details named the local rust-src directory (`/home/<user>/.rustup/...`). They are now named as rustc names them, `/rustc/<commit>/library/...`, so a CBOM no longer depends on the machine that made it.

## 8. Three independent audits

The pipeline is deterministic, so every wrong position, classification or accepted shifted
position is a bug in the code, not noise. To look for them systematically, three independent
reviewers (separate agent sessions with different scopes, none of which had written the code
under review) audited one part each. They reproduced every confirmed finding with a small program:
- **the compiler driver:** positions, which calls and statics are recorded, the walk, argument origins, robustness (26 findings, 23 reproduced);
- **Layer 1, the knowledge base, matching, provenance and CBOM assembly:** checked against the crates' sources and the registry (8 high, 15 medium and 8 low findings);
- **verification, scoring, harness and the evaluation's numbers:** every position the self-test accepted, and the scorer's rules.

What they found, by kind, and what changed:
- **Positions.** A static found inside an evaluated constant took the constant's span (`Self::ALG`); a callee held in a local lost its span to `RemoveZsts`; a byte-order mark shifted line 1; path-qualified macros broke the tag. Static and const sites now come only from unevaluated MIR, the driver reads MIR level 0, and macro kinds are data.
- **Recording.** Missed: `From`/`TryFrom` constructors of crypto types, functions used as values or through local pointers, associated and inline consts, statics built by a `const fn`. Spurious: generic projections, a crypto value in a third-party container. All fixed.
- **Walk.** Code that ring calls back (a key-derivation closure), generic functions' per-item sites, `#[used]` constructors and exported statics were not reachable. All are now.
- **Argument origins.** Locals were tracked whole and without flow: a closure's capture read as a parameter, a struct literal's constant field as the key, a later write as an earlier origin. Origins are now a reaching-definitions analysis over field paths, with captures mapped to the parent's values, writes through references, and out-parameters that replace initializations.
- **Classification.** KDF output and plumbing (`context`, `decode`, `format!`) produced false hard-coded keys; descriptors were linked from any argument at any depth (a buffer's hash became the cipher); SHA-512/t and XChaCha were misnamed; a material and an algorithm of the same name merged; one occurrence hid another at the same position; and the result depended on the order facts files were read. Fixed with KDF sources, passthroughs, receiver-only linking, registry-aware templates, asset keys by primitive and material, occurrences by position and symbol, and sorted input with defining paths.
- **Stale facts.** A crate compiled by an earlier build with other dependencies left a facts file that was still read; only the current build's cargo units are read now.
- **Verification.** All 17 shifted positions the verifier accepted were its own laxness, not wrong positions: names inside strings and comments, generic arguments crossing expressions, two calls of one name on adjacent lines. The verifier now lexes the source, checks the exact source text the CBOM records at each position, and checks component placement and the receiver's crate. It rejects every shifted position.
- **Scoring and harness.** The scorer accepted names no registry pattern produces and counted extended assets' provenance; e2e did not fail on golden-file differences or on accepted shifts. Fixed; the golden files now hold the whole CBOM.

The probes are kept as regression fixtures (`fixtures/regress`, run by `scripts/e2e.sh
--regress`), each compared with its reviewed CBOM: 19 from the audits, and 2 from the corpus
re-run (section 7).

## 9. Limitations and threats

- **Labels.** One annotator so far; the second review is pending (`docs/rusi-fixtures-review.md`). The labelled set is small (3 programs, 14 core findings, 10 provenance roles of core assets), and its programs were written by rusi's authors, for rusi.
- **Development set.** The current scores in RQ2 and RQ3 were measured on the programs that guided the knowledge base and the provenance rules. The seed-knowledge-base row is the only held-out result.
- **Baseline.** rusi was run with its default syntax backend only; its compiler backend needs a stable ≥ 1.98 with `rustc-dev`.
- **Reachability is not value-sensitive.** jsonwebtoken's `encode` matches on a run-time algorithm, so all its signing algorithms are reachable.
- **Reachability is not proven sound.** It over-approximates within what it walks, like rustc's mono-item collector: vtables of every unsized type, function pointers, drop glue, code that crypto crates call back. It can still miss edges through non-generic std code, or through function pointers it cannot see created. A crypto use the walk misses is reported `present`, not dropped. The xh case (section 7) shows how a single missing edge kind changes the tier picture, and why the threads fixture now guards it.
- **Provenance is intraprocedural.** Values crossing a function boundary are reported as `parameter` or `computed`; only what a closure or `async` body captured is traced into its parent.
- **Run-time parameters.** A name says what the code determines: `Argon2::new` with costs in a `Params` value is `Argon2i`, an aws-lc-rs block-cipher key whose mode a separate constructor picks is `AES-128`. A bare family name has no registry pattern and is flagged.
- **Standard library.** Non-generic std code has no MIR without a std sysroot, so the walk does not enter it. Generic std code (threads, iterators, closures, `dyn` calls) is walked.
- **Knowledge-base tool.** Self-implemented cryptography is invisible (minisign's own Ed25519 and BLAKE2b), and so are crates outside the seed. Trait-based inference (any `Digest` or `Aead` implementation) is future work.
- **Corpus.** Five projects, chosen by us for their crypto dependencies; the feasibility numbers say nothing about recall on them, which is unlabelled.
- **Execution.** Layer 2 compiles the project, so build scripts and proc macros run. Run it on trusted code, or in a container.
- **Toolchain.** The driver needs one pinned nightly with `rustc-dev`.
  - `rustc_public` does not yet expose promoted MIR, unevaluated consts in monomorphic bodies, vtable entries, macro call sites, impl self types, source snippets, where-clauses, defining paths or def-path hashes, so those go through `rustc_middle`.
  - Its `Instance::has_body()` answers for the definition rather than the instance, which hides shims (section 7); the driver uses `Instance::body()` instead.

## 10. Toward the second paper

- A labelled benchmark in CycloneDX form, labelled before the tool is run, with two annotators, built from:
  - CodeQL's line-labelled Rust crypto tests
  - translated CryptoAPI-Bench cases
  - 20–30 real projects
- Knowledge base: the long tail, both RustCrypto generations, openssl and the PQC crates.
- Value-sensitive reachability, interprocedural provenance, Layer 3 (purpose) and Layer 4 (reachability-filtered VEX).
- More baselines: rusi's compiler backend, cdxgen's conversion, CodeQL's queries, through BF-CBOM.
