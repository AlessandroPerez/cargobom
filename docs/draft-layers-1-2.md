# First draft: Layers 1 and 2

*8 October 2026. Toolchains: stable 1.97.1 (tool), `nightly-2026-09-25` (driver, as in the plan).*

> Update: scored against labelled third-party fixtures in `docs/rusi-fixtures-results.md`. That work added
> const-item tracking (aws-lc-rs), constant call arguments, protocol and key-material assets.
> The tables below are this draft's; the current numbers, after the audits and the corpus
> re-run, are in `docs/poc-evaluation.md`.

## What exists

A `cargo cbom` command that takes a Cargo workspace and writes a CycloneDX 1.7 CBOM from Layer 1 (manifests) and Layer 2 (type-resolved compiler analysis), with a small knowledge base. It follows the crate layout of the proposal (section 16), trimmed to what a first draft needs:

| crate | toolchain | role |
|---|---|---|
| `rcbom-facts` | both | the facts the driver writes and the analysis reads (JSON, versioned) |
| `rcbom-driver` | nightly | `RUSTC_WRAPPER` on `rustc_public`; the only compiler-facing code |
| `rcbom-kb` + `kb/seed.toml` | stable | knowledge base: crate catalogue, types, statics, functions, uses |
| `rcbom-manifest` | stable | Layer 1: `cargo metadata`, manifest and lockfile positions |
| `rcbom-analysis` | stable | KB matching, tiers, composition, uses, CycloneDX assembly |
| `cargo-cbom` | stable | CLI; schema validation; `verify` |

Flow: Layer 1 runs `cargo metadata` (no compilation). Layer 2 runs `cargo +nightly-2026-09-25 check` with `rcbom-driver` as `RUSTC_WRAPPER` and `-Zalways-encode-mir`. In every crate, after analysis, the driver writes the places where code names a function, type or static of a crate the knowledge base knows, with source positions and structured generic arguments. In a binary crate it also walks the instance graph from `main` across crates. The analysis matches the facts against the knowledge base and assembles the CBOM. The CBOM is validated against the vendored CycloneDX 1.7 schemas on every run.

```
cd crates/rcbom-driver && cargo build          # needs: rustup toolchain install nightly-2026-09-25 --component rustc-dev,llvm-tools,rust-src
cargo build                                      # the CLI, stable
cd <project> && <repo>/target/debug/cargo-cbom cbom -o cbom.json
<repo>/target/debug/cargo-cbom cbom verify cbom.json --self-test
scripts/e2e.sh --realapp                         # scripts/check.sh, fixture golden file, Phase 0 corpus
```

Formatting and lints are enforced: `scripts/check.sh` runs `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and the unit tests for the workspace, and fmt and clippy for the driver. The driver's toolchain pin includes the clippy and rustfmt components.

## Evidence positions

Every occurrence in the CBOM carries a position:

- `location`: path relative to the workspace root for workspace files; `<package>-<version>/<path>` inside a dependency (no machine-specific paths).
- `line`: 1-based. `offset`: 0-based character column (the CBOMkit convention).
- `symbol`: what is named there: the callee (`aes_gcm::aead::Aead::encrypt`), the static (`ring::aead::AES_256_GCM`), or for Layer 1 the dependency key or `links`.
- `additionalContext`: `[reachable|present] [call|instantiation|static|via-static|component|manifest] [macro m!] in <enclosing item>; use: <function>; …`.

Positions come from rustc's spans, which are offsets into the original file, so comments, blank lines and formatting cannot shift them. Code produced by a function-like macro is attributed to the outermost call site in the user's source (`hash_all!(..)`), and the position inside the macro definition is kept in the context. Layer 1 positions come from parsing `Cargo.toml` with spans (`toml_edit`) and from the `Cargo.lock` entry.

`cargo cbom verify` reopens every cited file and checks that the code at `line`/`offset` names the symbol, accepting `use … as` aliases (age calls `scrypt::scrypt` as `scrypt_inner`). `--self-test` shifts every position by one line or column and counts how many shifted positions the check rejects (`scripts/e2e.sh` requires all of them).

## Results

| | fixtures/micro | phase0/realapp |
|---|---|---|
| crates analysed | 35 | 177 |
| crypto assets | 6 + 1 manifest-only candidate | 28 (the Phase 0 set, exactly) |
| positions verified | 49 / 49 | 357 / 357 |
| shifted ±1 line/column rejected | 49 / 49 each | 357 / 357 each |
| CycloneDX 1.7 schema | valid | valid |
| time (cold) | 6 s | 22.0 s vs 15.6 s plain `cargo check` (×1.41) |
| time (warm, no rebuild) | | 0.9 s, byte-identical output |
| facts on disk | | 5.4 MB (Phase 0 text dumps: 392 MB) |

`fixtures/micro` extends the Phase 0 spike with the cases that stress positions and tiers. Its findings are frozen in `fixtures/micro/expected.txt` and checked by `scripts/e2e.sh`. The cases:

- comments and a multi-line method chain (`.finalize()` on its own line)
- a crypto call inside `macro_rules!`
- an aliased import
- a local static table of ring algorithms
- dead code
- a declared but unused crypto crate

What the fixture shows:

- **Generic wrapper:** the `encrypt` in `fn seal<A>` is attributed to AES-256-GCM and to ChaCha20-Poly1305 at `src/main.rs:14:11`. The context names the instantiating call (`instantiated by <AesSealer as Sealer>::seal at src/main.rs:25`). `seal::<Aes256Gcm>` itself is reported at 25:8 as the place the algorithm is chosen. The 12-byte nonce and 16-byte tag come from the type's generic arguments, defaults included.
- **dyn:** both `Sealer` impls are reachable, through their vtables (sound over-approximation).
- **ring constant:** `AES_256_GCM` at 40:46.
- **Composition:** `Hmac<Sha256>` gives HMAC-SHA-256 with uses `tag` (`update`, `finalize`). SHA-256 is reported at the same places as its component, and linked with `dependsOn`.
- **Macro:** SHA-384 at the `hash_all!` call site (72:12), with the definition at line 63 in the context.
- **Static table:** `DIGESTS` gives SHA-256 and SHA-512 where the table is written (68:50, 68:64) and where it is used (71:24).
- **Tiers:** `Sha512::digest` in a function `main` never calls is `[present]`; everything else is `[reachable]`.
- **Layer 1:** `sha1` is a manifest-only candidate, `declared-not-used`, at `Cargo.toml:16` (the line cargo's own unused-dependency warning names). Building-block crates (`aes`, `ctr`, `ghash`) inherit the usage of `aes-gcm`. ring is reported with its native library (`links` at `ring-0.17.14/Cargo.toml:18`).

On realapp, tiers are kept per occurrence:
- **Present only:** age's scrypt and both x25519 `diffie_hellman` calls. `main` only generates an identity; it never wraps or unwraps a file key. jsonwebtoken's verify-side statics (`alg_to_ec_verification`) are present only too, since `main` only encodes.
- **Reachable:** everything rustls's `default_provider()` refers to. That covers the cipher suites, key-exchange groups, and the signature verification algorithms (through `SUPPORTED_SIG_ALGS` → rustls-webpki → ring). It also covers every JWT signing algorithm, because `encode` matches on the algorithm at run time; see the gaps below.
- **Asset level:** an asset is reachable if any of its occurrences is. That leaves scrypt as the only asset that is merely present.
- **Backend:** rustls's backend is reported as `ring`, from its enabled features.
- **Unsupported version:** sha2 0.11 and digest 0.11 (the 2026 RustCrypto generation, not in the seed) are flagged `rcbom:kb-coverage = unsupported-version` with usage `unknown`. Their types are not matched against 0.10 entries.

## Phase 0 issues, resolved

| Phase 0 finding | Now |
|---|---|
| `rustc_public` not exercised | The driver runs on it (pinned nightly). Monomorphized call sites (F1) resolve in-process, no text dumps. |
| Mono items have no spans | The walk monomorphizes instance bodies; every site has a span, plus the chain of calls that created the instance. |
| Capability vs use | Two tiers per occurrence: `reachable` from a workspace binary's `main` (instance graph with vtables, fn pointers, drop glue, statics), or only `present`. |
| Printing-sensitive KB (elided defaults, turbofish) | Matching is structural on generic arguments; all arguments arrive, defaults included. |
| Trimmed paths | Callees and statics carry untrimmed def paths and crate identity (name + `StableCrateId`). |
| Two versions of one crate overwrite | Facts are keyed by crate and `StableCrateId`; KB matching checks the version range of the exact crate. |
| Nested statics, by-value copies | Static initializers and their promoted constants are read with spans. rustls's `HKDF_SHA384` (copied by value into the suite) is found at `tls13.rs:50`. |
| Layer 1 positions | `Cargo.toml` declaration lines, `Cargo.lock` entries with the dependency chain, `links` lines. |

`rustc_public` did not cover everything. The driver uses `rustc_middle` for:
- macro call sites
- static initializers and promoted MIR
- vtable entries
- the self type of inherent methods
- def-path hashes

These are the places to watch when the pin moves.

## Gaps: closed for the PoC, and left for later

Closed since this draft (details in `docs/poc-evaluation.md`):
- **ring and aws-lc-rs uses** are linked to their algorithm through intraprocedural origins. `k.seal_in_place_append_tag` is AES-256-GCM `encrypt` when `k` was built from `&AES_256_GCM`.
- **Provenance:** key, nonce, IV, salt, password and RNG arguments are classified as hard-coded, environment, file, rng, parameter or derived, with findings for hard-coded key material.
- **Library-only workspaces** get a reachable tier from their public monomorphic API.
- **Protocol assets** are reported for `ClientConfig::builder`, `ServerConfig::builder`, `crypto::{ring,aws_lc_rs}::default_provider` and `CryptoProvider::install_default`. The backend is the one the call names, otherwise the one the features select.
- **Sandboxing** is out of scope for the PoC: Layer 2 compiles the project, so run it on trusted code or inside a container.

Left for the wider paper, by design:
- **Reachability is per occurrence, the summary per asset.** An asset with one reachable occurrence counts as reachable; the occurrence tags give the finer view.
- **Reachability without values.** jsonwebtoken's `encode` selects the algorithm with a `match` on a run-time value, so every signing algorithm is reachable. Pruning to HS256 needs interprocedural constant propagation through struct fields.
- **Provenance is intraprocedural.** A value that crosses a function boundary is reported as `parameter`, or as `computed` by the callee; closures are followed one level.
- **Knowledge base:** one coherent seed, not the long tail. RustCrypto 0.10 generation, md5, blake3, pbkdf2, argon2, rsa (key generation), ed25519-dalek, ring 0.17, aws-lc-rs 1.x, x25519-dalek, scrypt, rustls 0.23, jsonwebtoken 9. Crypto crates in other versions are flagged `unsupported-version`.
- **Standard library.** Non-generic std functions have no MIR without a Miri/`build-std` sysroot, so the walk does not see through them. Generic std code (iterators, closures) is walked.
- **Host target only,** default features unless `--features` is given, dev-dependencies out of scope.
