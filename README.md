# cargo-cbom (rcbom)

A proof of concept that generates a CycloneDX 1.7 Cryptography Bill of Materials (CBOM) for a
Cargo workspace, from the compiler's type-resolved view of the code. It reports which
algorithms the program uses, with their parameters, where (file, line, column, symbol), and how:
- what each call does (encrypt, tag, keyderive, ...)
- whether the code is reachable from the program's entry points or only present in a compiled crate
- where the key material handed to the API comes from (hard-coded, environment, RNG, parameter, ...)

The design and its motivation are in `docs/rust-cbom-proposal2.md` (Layers 1 and 2 are built
here). The evaluation is in `docs/poc-evaluation.md`; the CBOMs and tables behind it are in
`results/` (see `results/README.md`).

## How it works

- **Layer 1** (`rcbom-manifest`) reads `cargo metadata`, `Cargo.toml` and `Cargo.lock`. It finds:
  - the crypto crates that ship, and the backend their features select
  - the native libraries they link
  - the manifest line where each one enters the build
- **Layer 2** (`rcbom-driver`) is a `RUSTC_WRAPPER` built on `rustc_public` (nightly). In every
  crate it records, with source positions and structured generic arguments:
  - the calls into knowledge-base crates
  - references to algorithm statics and consts
  - the intraprocedural origin of each argument

  In a binary, or a library workspace member, it also walks the monomorphized instance graph
  from the entry points (`main`, or the public API).
- **Analysis** (`rcbom-analysis`, stable) matches the facts against the knowledge base
  (`kb/seed.toml`). Matching is structural: crate, item and generic-argument positions, with
  version ranges. It recovers parameters, composition, uses, tiers and provenance, and
  assembles the CBOM, validated against the vendored CycloneDX 1.7 schemas on every run.

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
<repo>/target/debug/cargo-cbom cbom --no-walk -o ...        # ablation: no monomorphized walk
<repo>/target/debug/cargo-cbom cbom verify cbom.json --self-test
```

Layer 2 compiles the project, so build scripts and procedural macros run. Run it on code you
trust, or inside a container.

## Reproduce the evaluation

```
scripts/check.sh                 # rustfmt, clippy -D warnings, unit tests (enforced)
scripts/e2e.sh --realapp         # fixtures: golden files, labelled scores, position checks
scripts/score.py fixtures/rusi/<fixture>/labels.toml <cbom.json>   # any tool's CBOM
scripts/corpus.py <out> <project>... [--rusi <rusi binary>]        # real projects
scripts/ablation.py <out> <project>...                              # with and without the walk
```

## Layout

| path | content |
|---|---|
| `crates/rcbom-facts` | facts exchanged between driver and analysis |
| `crates/rcbom-driver` | the nightly `rustc_public` driver |
| `crates/rcbom-kb`, `kb/seed.toml` | knowledge base loader and seed |
| `crates/rcbom-manifest` | Layer 1 |
| `crates/rcbom-analysis` | matching, provenance, CycloneDX assembly |
| `crates/cargo-cbom` | CLI, schema validation, `verify` |
| `fixtures/` | micro, libonly, threads (designed cases, golden files); rusi fixtures (labelled) |
| `phase0/` | the Phase 0 spike and its corpus |
| `schema/` | CycloneDX 1.7 schemas (Apache-2.0) |
| `scripts/` | checks, scoring, corpus runner, rusi converter, review sheet |
