//! Generates the CBOMs of the real projects behind the corpus and held-out labels
//! (`tests/fixtures/projects.toml`), for `corpus-score`.
//!
//! `cargo xtask corpus-run WORK_DIR OUT_DIR LABELS.toml...`: for each labels file, its project's
//! crates.io package is downloaded into `WORK_DIR` (outside the repository: a package inside it
//! would be taken for a member of its workspace), checked against its sha256 and unpacked, with
//! the Cargo.lock `lock` names; a package already unpacked in `WORK_DIR` is used as it is. Each is
//! then generated with the binaries `e2e` builds (`--check-walk`, the features it was labelled
//! with) into `OUT_DIR/<labels>.cbom.json`, and verified with the self-test
//! (`OUT_DIR/<labels>.verify`); one at a time, each with every core. A project fails on a
//! generation error, a caught driver panic, a position that does not verify, or a shifted one
//! that is not rejected.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

use anyhow::{Context, Result, bail};
use regex::Regex;

use crate::root;

/// What `projects.toml` says about one labels file.
struct Project {
    labels: PathBuf,
    path: Option<String>,
    krate: String,
    version: String,
    sha256: String,
    lock: Option<String>,
    features: Option<String>,
}

fn projects(fixtures: &Path) -> Result<Vec<Project>> {
    let file = fixtures.join("projects.toml");
    let doc: toml::Value = toml::from_str(
        &std::fs::read_to_string(&file).with_context(|| file.display().to_string())?,
    )?;
    let mut v = Vec::new();
    for p in doc
        .get("project")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
    {
        let s = |k: &str| p.get(k).and_then(|v| v.as_str()).map(String::from);
        let labels = s("labels").context("a project without labels")?;
        v.push(Project {
            labels: fixtures.join(&labels).canonicalize().context(labels)?,
            path: s("path"),
            krate: s("crate").unwrap_or_default(),
            version: s("version").unwrap_or_default(),
            sha256: s("sha256").unwrap_or_default(),
            lock: s("lock"),
            features: s("features"),
        });
    }
    Ok(v)
}

/// The project's sources: `path` in the fixtures, or its package unpacked in `work`.
fn sources(p: &Project, fixtures: &Path, work: &Path) -> Result<PathBuf> {
    if let Some(path) = &p.path {
        return Ok(fixtures.join(path));
    }
    let name = format!("{}-{}", p.krate, p.version);
    let dir = work.join(&name);
    if dir.exists() {
        return Ok(dir);
    }
    let file = work.join(format!("{name}.crate"));
    if !file.exists() {
        let url = format!("https://static.crates.io/crates/{}/{name}.crate", p.krate);
        eprintln!("fetching {url}");
        let part = work.join(format!("{name}.crate.part"));
        if !Command::new("curl")
            .args(["-sSfL", "-o"])
            .arg(&part)
            .arg(&url)
            .status()?
            .success()
        {
            bail!("download of {url} failed");
        }
        std::fs::rename(&part, &file)?;
    }
    let sum = Command::new("sha256sum").arg(&file).output()?;
    let sum = String::from_utf8_lossy(&sum.stdout);
    if sum.split_whitespace().next() != Some(p.sha256.as_str()) {
        bail!(
            "{}: sha256 {} is not the published package's {}",
            file.display(),
            sum.split_whitespace().next().unwrap_or("(none)"),
            p.sha256
        );
    }
    if !Command::new("tar")
        .arg("-xzf")
        .arg(&file)
        .arg("-C")
        .arg(work)
        .status()?
        .success()
    {
        bail!("{}: could not unpack", file.display());
    }
    if let Some(lock) = &p.lock {
        std::fs::copy(fixtures.join(lock), dir.join("Cargo.lock"))?;
    }
    Ok(dir)
}

pub fn run(args: &[String]) -> Result<()> {
    let usage = "usage: cargo xtask corpus-run WORK_DIR OUT_DIR LABELS.toml...";
    let [work, out, labels @ ..] = args else {
        bail!(usage)
    };
    if labels.is_empty() {
        bail!(usage);
    }
    let root = root();
    let fixtures = root.join("tests/fixtures");
    let all = projects(&fixtures)?;
    let mut chosen = Vec::new();
    for l in labels {
        let path = Path::new(l).canonicalize().with_context(|| l.clone())?;
        let p = all
            .iter()
            .find(|p| p.labels == path)
            .with_context(|| format!("{l}: not in tests/fixtures/projects.toml"))?;
        chosen.push(p);
    }
    std::fs::create_dir_all(work)?;
    std::fs::create_dir_all(out)?;
    // absolute: the generator and the verifier run in each project's directory
    let (work, out) = (
        Path::new(work).canonicalize()?,
        Path::new(out).canonicalize()?,
    );
    if work.starts_with(&root) {
        bail!("WORK_DIR must be outside the repository");
    }
    crate::e2e::cargo_build(&root.join("crates/rcbom-driver"))?;
    crate::e2e::cargo_build(&root)?;
    let cbom = root.join("target/e2e/cargo-cbom");
    let driver = root.join("crates/rcbom-driver/target/e2e/rcbom-driver");
    let counts = Regex::new(r"(\d+) positions verified, (\d+) mismatched").unwrap();
    let shifts = Regex::new(r"(\d+)/(\d+) shifted positions rejected").unwrap();
    let mut failed = Vec::new();
    for p in chosen {
        let name = p
            .labels
            .file_stem()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();
        let dir = sources(p, &fixtures, &work)?;
        let cbom_path = out.join(format!("{name}.cbom.json"));
        let log = out.join(format!("{name}.log"));
        let t0 = Instant::now();
        let mut cmd = Command::new(&cbom);
        cmd.current_dir(&dir).env_remove("RCBOM_DRIVER").arg("cbom");
        if let Some(f) = &p.features {
            cmd.args(["--features", f]);
        }
        let ok = cmd
            .args(["--check-walk", "--driver"])
            .arg(&driver)
            .arg("-o")
            .arg(&cbom_path)
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(&log)?)
            .status()?
            .success();
        let secs = t0.elapsed().as_secs();
        let cli_log = std::fs::read_to_string(&log).unwrap_or_default();
        if !ok {
            println!(
                "{name}: generation failed after {secs} s ({})",
                log.display()
            );
            failed.push(name);
            continue;
        }
        if cli_log.contains("could not be analysed") {
            println!("{name}: the driver caught panics ({})", log.display());
            failed.push(name);
            continue;
        }
        let v = Command::new(&cbom)
            .current_dir(&dir)
            .args(["cbom", "verify"])
            .arg(&cbom_path)
            .arg("--self-test")
            .output()?;
        let text = String::from_utf8_lossy(&v.stdout).into_owned();
        std::fs::write(out.join(format!("{name}.verify")), &text)?;
        let (verified, mismatched) = counts
            .captures(&text)
            .map(|c| (c[1].to_string(), c[2].to_string()))
            .unwrap_or_default();
        let (mut caught, mut total) = (0u64, 0u64);
        for c in shifts.captures_iter(&text) {
            caught += c[1].parse::<u64>().unwrap_or(0);
            total += c[2].parse::<u64>().unwrap_or(0);
        }
        println!(
            "{name}: {secs} s; positions: {verified} verified, {mismatched} mismatched; self-test: {caught}/{total} shifted positions rejected"
        );
        if !v.status.success() || caught != total {
            failed.push(name);
        }
    }
    if !failed.is_empty() {
        bail!("failed: {}", failed.join(", "));
    }
    Ok(())
}
