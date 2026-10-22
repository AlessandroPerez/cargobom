//! The points-to engine's findings against the default run, collected from a run with
//! `RCBOM_PTA=1` (`cargo xtask pta-candidates OUT_DIR... [--against OLD.txt]`).
//!
//! Each `OUT_DIR/<name>.log` (the CLI's output of an e2e or corpus run) gives its lines
//! `rcbom-pta: outside the engine: ...` (a member of the value search outside the engine's
//! complete answer: a candidate wrong member) and `rcbom-pta: beyond a complete search: ...` (a
//! descriptor in the engine's complete answer that a search claiming completeness does not name:
//! a candidate drop), as `<name>: <finding>`, each once, sorted, on standard output. With
//! `--against OLD.txt` (a previous run's list), only the changes: `+` a new candidate, `-` one
//! gone.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Context, Result};

/// The engine's findings in an output directory's logs.
fn collect(dir: &Path, out: &mut BTreeSet<String>) -> Result<()> {
    for e in std::fs::read_dir(dir).with_context(|| dir.display().to_string())? {
        let path = e?.path();
        let Some(file) = path.file_name().and_then(|f| f.to_str()) else {
            continue;
        };
        // the CLI's own log, not the e2e's (`<name>.e2e.log`, `e2e.log`)
        let Some(name) = file.strip_suffix(".log") else {
            continue;
        };
        if name == "e2e" || name.ends_with(".e2e") {
            continue;
        }
        for line in std::fs::read_to_string(&path)?.lines() {
            if let Some(f) = line.strip_prefix("rcbom-pta: ")
                && (f.starts_with("outside the engine: ")
                    || f.starts_with("beyond a complete search: "))
            {
                out.insert(format!("{name}: {f}"));
            }
        }
    }
    Ok(())
}

pub fn run(args: &[String]) -> Result<()> {
    let mut args: Vec<String> = args.to_vec();
    let mut against = None;
    if let Some(i) = args.iter().position(|a| a == "--against") {
        against = Some(args.get(i + 1).context("--against OLD.txt")?.clone());
        args.drain(i..i + 2);
    }
    anyhow::ensure!(
        !args.is_empty(),
        "usage: cargo xtask pta-candidates OUT_DIR... [--against OLD.txt]"
    );
    let mut found = BTreeSet::new();
    for d in &args {
        collect(Path::new(d), &mut found)?;
    }
    let Some(old) = against else {
        for f in &found {
            println!("{f}");
        }
        return Ok(());
    };
    let old: BTreeSet<String> = std::fs::read_to_string(&old)
        .with_context(|| old.clone())?
        .lines()
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect();
    for f in found.difference(&old) {
        println!("+ {f}");
    }
    for f in old.difference(&found) {
        println!("- {f}");
    }
    Ok(())
}
