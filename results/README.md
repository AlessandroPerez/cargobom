# Results

The outputs behind `docs/poc-evaluation.md`, generated on 8 October 2026 by cargo-cbom 0.1.0
(driver on `nightly-2026-09-25`, knowledge base 0.1.0). Every `*.cbom.json` is a CycloneDX 1.7
CBOM that validated against the official schema when it was written.

| directory | content | regenerate with |
|---|---|---|
| `fixtures/` | CBOMs of the test programs (`fixtures/`, `phase0/realapp`); `*.score.json` against the labels; `*.txt` the one-line-per-occurrence summaries compared with the golden files | `RCBOM_RESULTS=$PWD/results/fixtures scripts/e2e.sh --realapp` |
| `baselines/rusi/` | rusi 4.1.1 (stable backend) on the three rusi fixtures: its report (crypto section) and the CBOM view `scripts/rusi_to_cbom.py` makes of it, with scores | `rusi cryptos --dir . -o r.json`, then `scripts/rusi_to_cbom.py r.json` |
| `baselines/cargo-cbom-seed/` | cargo-cbom with the seed knowledge base, before it covered these crates: the held-out row of the evaluation | (historical; the seed predates this tree) |
| `corpus/` | CBOMs of five crates.io projects; rusi's reports (crypto section) for the same projects; `corpus.json`, the timing and summary table | `scripts/corpus.py <out> <project dirs> --rusi <rusi>` |
| `ablation/` | each program with and without the monomorphized walk (`--no-walk`); `ablation.json`, the table | `scripts/ablation.py <out> <project dirs>` |

The corpus projects are the published crates, unpacked from
`https://static.crates.io/crates/<name>/<name>-<version>.crate` with their own `Cargo.lock`:
rage 0.12.1, jwt-cli 6.2.0, rcgen 0.14.10, minisign 0.10.0, xh 0.26.2.

Reading a CBOM: each `cryptographic-asset` has `evidence.occurrences`. In each occurrence,
`location` is a workspace-relative path, or `<package>-<version>/<path>` inside a dependency;
`line` and `offset` (0-based column) give the position. `additionalContext` starts with:
- the tier (`[reachable]` or `[present]`)
- the kind (`[call]`, `[static]`, `[instantiation]`, `[via-static]`, `[component]`, `[manifest]`)
- for macros, `[macro m!]` or `[derive D]`

It then gives the enclosing item, the use, and the provenance of key material. Asset-level
`rcbom:` properties hold parameters, reachability, provenance and findings. `cargo cbom verify
<cbom> --self-test`, run from the project directory, checks every position against the source.
