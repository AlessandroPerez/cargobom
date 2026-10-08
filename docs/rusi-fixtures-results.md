# Scoring against labelled rusi fixtures

> Part of the PoC evaluation; see `docs/poc-evaluation.md` for the whole picture.

*8 October 2026. cargo-cbom (this repository), rusi 4.1.1 at cdxgen-plugins-bin@6a64635.*

## The test set

No vetted CBOM of Rust code is published. The closest material is the three `cbom-real-*` fixtures in rusi, cdxgen's Rust source inspector. They are small real programs, MIT-licensed, and come without expected results. We copied them unchanged into `fixtures/rusi/` and labelled them in `labels.toml`. Labelling happened before any tool was scored, from the source and the locked crate sources; each label states its reason.

| fixture | crates | core findings | extended | negative lines |
|---|---|---|---|---|
| cbom-real-crates-app | aes-gcm, argon2, blake3, hmac, jsonwebtoken, md5, pbkdf2, rustls (aws-lc-rs), sha2 | 8 | 1 + TLS capability | 10 |
| cbom-real-asymmetric-app | ring, rsa, ed25519-dalek, rand | 4 | 2 | 7 |
| cbom-real-modern-app | chacha20poly1305, sha1, ring | 2 | 0 | 6 (incl. `digest::SHA256_OUTPUT_LEN`) |

`core` findings must be found at their line. `extended` findings (a JWT key with no algorithm yet, the CSPRNG, SHA-512 inside Ed25519) are credited when found and not counted as misses. Negative lines (imports, a secret's provenance, a length constant) must stay empty. Capability reachable through rustls's default provider is listed separately. Two things were added during adjudication after the first run, marked as such in the files: jsonwebtoken's linked algorithm table, and QUIC header protection.

**Status: one annotator.** `docs/rusi-fixtures-review.md` puts every label beside its source line for the second review.

## Scoring

`scripts/score.py labels.toml cbom.json` works on any CycloneDX CBOM. It counts (asset, line) pairs in the fixture's `src/main.rs`:
- **recall:** core pairs reported at the right line under an accepted name;
- **precision:** reported pairs that match some label;
- **fully named:** core pairs reported with the label's full registry name, parameters included.

Accepted names are the registry-valid names for the algorithm at any specificity. `AES-GCM` and `AES-256` count for AES-256-GCM, because the registry pattern `AES[-(128|192|256)][-(GCM|CCM)]` makes both segments optional; `HMAC` counts for HMAC-SHA-256. Non-registry names (`Ring-AEAD`, `JWT`) do not count.

rusi's report is converted by `scripts/rusi_to_cbom.py`, keeping every crypto component it reports. That is at least as generous as cdxgen's own conversion, which drops algorithms it cannot map to an OID. rusi ran with its default `stable` (syntax) backend; its `compiler` backend needs the `rustc-dev` component for a stable ≥ 1.98 toolchain and was not run.

## Results

Totals over the three fixtures (14 core findings, 11 labelled provenance roles):

| | recall | precision | fully named | provenance |
|---|---|---|---|---|
| cargo-cbom, seed knowledge base (held out) | 7/14 | 9/9 | 7/14 | (not implemented) |
| cargo-cbom, current | 14/14 | 17/17 | 14/14 | 11/11 |
| rusi 4.1.1, stable backend | 13/14 | 13/15 | 7/14 | 0/11 (not reported) |

Per fixture (recall, precision, fully named, provenance):

| fixture | cargo-cbom (seed) | cargo-cbom (current) | rusi |
|---|---|---|---|
| crates-app | 3/8, 5/5, 3/8, – | 8/8, 11/11, 8/8, 7/7 | 8/8, 8/9, 3/8, 0/7 |
| asymmetric-app | 2/4, 2/2, 2/4, – | 4/4, 4/4, 4/4, 3/3 | 3/4, 3/4, 2/4, 0/3 |
| modern-app | 2/2, 2/2, 2/2, – | 2/2, 2/2, 2/2, 1/1 | 2/2, 2/2, 2/2, 0/1 |

**Read the second row as a development-set score, not an accuracy claim.** The knowledge-base entries for md5, blake3, pbkdf2, argon2, rsa, ed25519-dalek and aws-lc-rs were written after the first run, on these fixtures. The first row is the held-out result. Every miss there is a crate the seed did not cover, and every reported finding was correct. An honest accuracy figure needs fixtures labelled after the tool is frozen.

What separates the two tools on the same lines:

- **Parameters.**
  - cargo-cbom reads parameters from types and constants: `AES-256-GCM` (nonce 12, tag 16), `HMAC-SHA-256`, `BLAKE3-256`, `Argon2id-19456-2-1` (from `Argon2::default()` and the crate's defaults), `PBKDF2-SHA-256-1000` (iterations from the constant argument), `RSA-2048` (a constant argument, reported as key material).
  - rusi reports `AES-GCM`, `HMAC`, `BLAKE3`, `Argon2`, `PBKDF2`, `RSA`.
  - PBKDF2's output length (32) comes from the array type behind the `&mut [u8]` argument.
- **ring.** `UnboundKey::new(&AES_256_GCM, ..)` is AES-256-GCM for cargo-cbom (the static) and `Ring-AEAD` for rusi.
- **Not an algorithm.** rusi reports `JWT` at `EncodingKey::from_secret`. The label calls it an HMAC key whose algorithm is not chosen yet (extended); cargo-cbom reports it as `HMAC` secret-key material, with its provenance.
- **Provenance.** cargo-cbom states where each labelled key, password, salt or RNG comes from. Examples: the secrets come from `env::var` *or* the literal fallback in the `unwrap_or_else` closure; the salts are literals at lines 33 and 35; the Ed25519 key is `[42u8; 32]`; RSA's randomness comes from `thread_rng`. rusi lists variables that look like key material (`app_secret`, `app_salt`), without their origin.
- **The trap.** Neither tool reports SHA-256 for `ring::digest::SHA256_OUTPUT_LEN`.
- **TLS.** Both report TLS at line 38. cargo-cbom also reports the aws-lc-rs backend, versions 1.2 and 1.3, the 9 default cipher suites and the default groups X25519MLKEM768, X25519, SECP256R1 and SECP384R1, all matching the labels. It also reports the provider's algorithms, including ML-KEM-768, as reachable capability. QUIC header protection is reachable too, while `ALL_KX_GROUPS` extras such as ML-KEM-1024 are present only.

## What the fixtures changed in the tool

The first run exposed gaps beyond knowledge-base coverage:

- **aws-lc-rs defines its algorithms as `pub const`, not `static`.** A const is copied by value and leaves no allocation, so rustls's default backend was invisible. The driver now records references to const items from MIR before evaluation: function bodies, static and const initializers, and their promoted constants.
- **Per-item findings inside reached functions** now get the reachable tier, and data those functions name seeds the reachable closure.
- **New knowledge-base forms:** call parameters from integer constant arguments; trait impls of a crypto type (`<Argon2 as Default>::default`); key material assets (`related-crypto-material`); protocol assets (rustls `ClientConfig::builder` / `ServerConfig::builder`, with versions from features, suites and offered groups from the reachable statics).
- **Provenance (added after this scoring round, labels written from the source first):**
  - intraprocedural origins of each argument, including one level into closures defined in the same function
  - knowledge-base roles (key, nonce, salt, password, rng) and sources (environment, file, rng)
  - findings for hard-coded key material
- **Same-line merge:** when a use is found with and without run-time parameters (`Argon2` from `hash_password`, `Argon2id-19456-2-1` from `default()`), the resolved name wins.
- **Locations** are normalized lexically (`aws_lc_rs/../ring/kx.rs` is `ring/kx.rs`).

All positions in all four fixture sets verified against the source at the time of this round: 966 positions. The ±1 self-test then rejected every shifted position except 3 of 1,072 line shifts in crates-app; the verifier was later made strict enough to reject all shifted positions (see `docs/poc-evaluation.md`).

## Next

1. Second annotator on the three label files, using the review sheet.
2. Held-out fixtures, labelled before the tool sees them. Candidates: CodeQL's Rust crypto tests (MIT, line-labelled: weak ciphers, weak hashes, hard-coded values) and new small programs on crates the knowledge base does not cover yet.
3. rusi's compiler backend as a second baseline, and cdxgen's own CBOM conversion.
