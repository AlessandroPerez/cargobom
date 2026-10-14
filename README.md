# cargo-cbom

A proof of concept that generates a CycloneDX 1.7 Cryptography Bill of Materials (CBOM) for a
Cargo workspace from the compiler's view of the code. For the artifact the workspace builds, it
reports:
- which cryptographic algorithms and key material the program uses, with their parameters
  (`AES-256-GCM`, `HMAC-SHA-256`, `ECDSA-P-256-SHA-256`), named after the CycloneDX Cryptography
  Registry;
- where: every finding is an evidence occurrence at a file, line, column and symbol, with the
  function it is in and why it was reported;
- how: what each call does (encrypt, sign, digest, keyderive, ...), whether the code is reachable
  from the program's entry points or only compiled, and where key material comes from
  (hard-coded, environment, RNG, a parameter, derived), with findings such as
  `hard-coded-key`;
- what it cannot tell: an operation whose algorithm is not determined is reported as `unknown`,
  with the reason, never dropped; when several algorithms may reach one call, each says how
  (`one of N`, `possible`, `selector: configuration` for a run-time choice).

`cargo cbom verify` checks every position a CBOM cites against the source, independently of the
generator.

## How it works

```
cargo cbom
 |- Layer 1  (rcbom-manifest)  cargo metadata + manifests: crypto packages, backends,
 |                             native libraries, the manifest line where each enters the build
 |- Layer 2a (rcbom-driver)    cargo +nightly check with the driver as RUSTC_WRAPPER: per crate,
 |                             the sites naming crypto items, the origin of their arguments, how
 |                             values move between functions, and the instances reachable from
 |                             the entry points; written as JSON facts
 |- Layer 2b (rcbom-analysis)  stable: matches the facts against the knowledge base
 |                             (kb/seed.toml), follows values across functions, applies boundary
 |                             models (jsonwebtoken), classifies key provenance, labels sets
 |- CycloneDX 1.7 JSON, validated against the vendored schemas on every run
```

- **Layer 1** finds the crypto packages that ship (by the knowledge base's `[[crate]]` entries,
  and unmodelled crypto packages by their metadata), the backend their features select and the
  native libraries they link, with the `Cargo.toml` or `Cargo.lock` line where each one enters.
- **The driver** (`crates/rcbom-driver`, its own cargo project on `nightly-2026-09-25`) compiles
  every crate normally through `rustc_public`. For each body it records the *sites* that name an
  item of a knowledge-base crate (calls with their generic arguments, statics, consts, calls
  through pointers), and for each argument an *origin* tree from the body's def-use chains
  (`&AES_256_GCM`, a literal, a parameter, a field, a call's result). It also records the
  *links* that continue origins across functions: what each function stores in struct fields,
  returns, passes to other functions and writes through `&mut`, what statics hold at run time,
  and which types are coerced to which trait objects. In a binary (or a library member) it walks
  the monomorphized instance graph from the entry points, so a site in walked code is
  `reachable`, else `present`.
- **The analysis** (`crates/rcbom-analysis`, stable) matches sites structurally: by crate, item
  path and generic-argument positions (`AesGcm<Aes256, U12>` is AES-256-GCM), descriptor statics
  (`ring::aead::AES_256_GCM`), and calls the knowledge base lists as operations. Where an
  algorithm comes from elsewhere (a field, a parameter, a trait object, a container, a static
  table), it follows the links and labels each member of the set with how it reaches the call
  and a witness. Key-material arguments are classified by the knowledge base's sources.
- **The knowledge base** (`kb/seed.toml`) is data: crates and their roles, types, statics and
  functions that are algorithms, operations, uses, argument roles, provenance sources, and
  boundary models.
- **The verifier** reopens every cited file and checks each position and detail against the
  code (the token named, the descriptor read by the call, bindings in scope, closures, macro
  rules, coercions); `--self-test` shifts every position by a line and a column and counts how
  many shifts it rejects.

## Build

```
rustup toolchain install nightly-2026-09-25 --component rustc-dev,llvm-tools,rust-src,clippy,rustfmt
(cd crates/rcbom-driver && cargo build)      # the compiler driver, pinned nightly
cargo build                                    # the CLI and libraries, stable
```

## Use

```
cd <cargo project>
<repo>/target/debug/cargo-cbom cbom -o cbom.json            # Layers 1 and 2
<repo>/target/debug/cargo-cbom cbom --manifest-only -o ...  # Layer 1 only, nothing compiled
<repo>/target/debug/cargo-cbom cbom --features f1,f2 ...    # the artifact other features build
<repo>/target/debug/cargo-cbom cbom verify cbom.json --self-test
python3 <repo>/scripts/summary.py cbom.json                 # the CBOM as one line per occurrence
RCBOM_DEBUG=1 <repo>/target/debug/cargo-cbom cbom -o ...    # also print the driver's caught panics
```

The CBOM describes the built artifact: the host target, the selected features and the
`release` profile (`--profile` to change it). Tests and build scripts are not in it.

Layer 2 compiles the project, so build scripts and procedural macros run. Run it on code you
trust, or inside a container.

## Tests and evaluation

```
scripts/check.sh                              # rustfmt, clippy -D warnings, unit tests (enforced)
scripts/e2e.sh --realapp --regress --suite    # every fixture: whole-CBOM golden files, every
                                              # position verified and every shift rejected,
                                              # labelled scores; RCBOM_BLESS=1 rewrites goldens
scripts/suite.py <out> fixtures/suite/*       # the ground-truth suite: 53 programs, 107 call
                                              # sites labelled from source before any tool run
scripts/corpus_score.py <out> fixtures/corpus/*.toml   # six real projects
scripts/score.py fixtures/rusi/<fixture>/labels.toml <cbom.json>   # any tool's CBOM
```

Verdicts: **correct**; **wrong** (an algorithm outside the labels: the bar is zero);
**less-specific**; **honest-unknown** (`unknown` reported, nothing wrong); **miss**.

## Layout

| path | content |
|---|---|
| `crates/cargo-cbom` | CLI, schema validation, `verify` |
| `crates/rcbom-manifest` | Layer 1 |
| `crates/rcbom-driver` | the nightly `rustc_public` driver: sites, origins, links, walk |
| `crates/rcbom-facts` | the facts exchanged between driver and analysis |
| `crates/rcbom-kb`, `kb/seed.toml` | knowledge base loader and data |
| `crates/rcbom-analysis` | matching, values across functions, boundary models, provenance, CycloneDX assembly |
| `fixtures/` | designed cases (`micro`, `libonly`, `threads`), labelled `rusi` fixtures, `suite/` (the ground-truth suite), `regress/` (probes from every audit round), `corpus/` (labels for six real projects); each with its golden `expected.txt` |
| `phase0/` | the realapp corpus program, and the algorithms the Phase 0 spike found in it (`cbom-realapp.json`), which the e2e checks are still reported |
| `results/` | committed outputs behind the reported numbers |
| `schema/` | CycloneDX 1.7 schemas and the Cryptography Registry (Apache-2.0) |
| `scripts/` | checks, e2e, scorers, summaries |
