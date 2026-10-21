//! The project's own tasks, run as `cargo xtask <task>` (the alias in `.cargo/config.toml`):
//!
//! - `check`: rustfmt and clippy `-D warnings` on the stable workspace and the nightly driver,
//!   then the unit tests;
//! - `e2e [--realapp] [--regress] [--suite] [--only GLOB]`: every fixture's CBOM, verified and
//!   compared with its golden file (`e2e.rs`);
//! - `summary CBOM.json`: a CBOM as the sorted text lines of the golden files;
//! - `suite OUT_DIR PROGRAM_DIR... [--json]`: the ground-truth suite's score;
//! - `score LABELS.toml CBOM.json [--json]`: any tool's CBOM against a rusi fixture's labels;
//! - `corpus-score CBOM_DIR LABELS.toml... [--json] [--against OLD_CBOM_DIR]`: the six real
//!   projects' labels;
//! - `rusi-to-cbom RUSI_REPORT.json`: a rusi report as a CycloneDX document, for `score`;
//! - `review-sheet FIXTURE_DIR...`: the labels next to their source lines, for review.

mod check;
mod corpus;
mod e2e;
mod pyjson;
mod review;
mod rusi;
mod score;
mod suite;
mod summary;

use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result, bail};

/// The repository's root (this crate's parent directory).
fn root() -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    dir.parent().map(PathBuf::from).unwrap_or(dir)
}

/// `cargo`, run as from a shell in its directory: without the toolchain rustup chose for this
/// task (`RUSTUP_TOOLCHAIN`, inherited), so in the driver's directory it takes the pinned nightly
/// of the driver's `rust-toolchain.toml`.
fn cargo() -> Command {
    let mut c = Command::new("cargo");
    c.env_remove("RUSTUP_TOOLCHAIN")
        .env_remove("RUSTUP_TOOLCHAIN_SOURCE");
    c
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (task, rest) = args
        .split_first()
        .context("usage: cargo xtask <check|e2e|summary|suite|score|corpus-score|rusi-to-cbom|review-sheet> ..")?;
    match task.as_str() {
        "check" => check::run(),
        "e2e" => e2e::run(rest),
        "summary" => {
            let path = rest
                .first()
                .context("usage: cargo xtask summary CBOM.json")?;
            let doc: serde_json::Value = serde_json::from_str(
                &std::fs::read_to_string(path).with_context(|| path.clone())?,
            )?;
            print!("{}", summary::summary(&doc));
            Ok(())
        }
        "suite" => suite::run(rest),
        "score" => score::run(rest),
        "corpus-score" => corpus::run(rest),
        "rusi-to-cbom" => rusi::run(rest),
        "review-sheet" => review::run(rest),
        other => bail!("unknown task {other}"),
    }
}
