//! Formatting and lints are enforced (`cargo xtask check`): rustfmt and clippy with warnings as
//! errors, for the stable workspace and for the nightly driver (its own cargo project), then the
//! unit tests.

use std::path::Path;

use anyhow::{Result, bail};

use crate::root;

fn cargo(dir: &Path, args: &[&str]) -> Result<()> {
    if !crate::cargo()
        .args(args)
        .current_dir(dir)
        .status()?
        .success()
    {
        bail!("cargo {} failed in {}", args.join(" "), dir.display());
    }
    Ok(())
}

pub fn run() -> Result<()> {
    let root = root();
    cargo(&root, &["fmt", "--all", "--check"])?;
    cargo(
        &root,
        &[
            "clippy",
            "-q",
            "--workspace",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
    )?;
    cargo(&root, &["test", "-q", "--workspace"])?;
    let driver = root.join("crates/rcbom-driver");
    cargo(&driver, &["fmt", "--check"])?;
    cargo(
        &driver,
        &["clippy", "-q", "--all-targets", "--", "-D", "warnings"],
    )?;
    println!("check: ok");
    Ok(())
}
