# rusi CBOM fixtures, with labelled ground truth

`cbom-real-crates-app`, `cbom-real-asymmetric-app` and `cbom-real-modern-app` are copied
unchanged (sources and lockfiles) from rusi, cdxgen's Rust source inspector:
https://github.com/cdxgen/cdxgen-plugins-bin/tree/6a646353e4fbd9d64fa115176241d7a233e19630/thirdparty/rusi/fixtures
(MIT licence, see `LICENSE`). rusi ships them without expected results.

`labels.toml` in each directory is our ground truth. It was written from the source and the
locked crate sources (each label says why), before any tool was scored, with later additions
marked as adjudication. Status: one annotator; a second review is pending.

Score any CycloneDX CBOM against them with `scripts/score.py <labels.toml> <cbom.json>`;
`scripts/rusi_to_cbom.py` turns a rusi report into one. `scripts/e2e.sh` scores cargo-cbom.
