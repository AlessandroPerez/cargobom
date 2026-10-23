//! End-to-end check of Layers 1 and 2 (`cargo xtask e2e`): build the driver (pinned nightly)
//! and the CLI (stable), generate each fixture's CBOM (validated against the CycloneDX schemas
//! on every run), and fail on any of:
//! - a position that does not verify against the source, or a shifted position the self-test
//!   does not reject (`cargo cbom verify --self-test`);
//! - a panic the driver caught ("N items could not be analysed"; `RCBOM_DEBUG=1` prints them);
//! - a difference from the fixture's golden file (`expected.txt`, the whole CBOM as text:
//!   `cargo xtask summary`);
//! - for the labelled rusi fixtures, a score that is not perfect, or that differs in any field
//!   from the committed one (`expected-score.json`).
//!
//! `cargo xtask e2e [--realapp] [--regress] [--suite] [--only GLOB]...`:
//! - with no option, the designed fixtures (`micro`, `libonly`, `threads`) and the rusi ones;
//! - `--realapp`: also `tests/fixtures/realapp`;
//! - `--regress`: also `tests/fixtures/regress/*` (the audit probes);
//! - `--suite`: also `tests/fixtures/suite/*` (the ground-truth suite: labels written from
//!   source before any tool run; its score must equal the committed `expected-score.json`);
//! - `--only GLOB`: only the fixtures whose path in the repo matches GLOB (repeatable:
//!   `--only 'tests/fixtures/regress/analysis-0*'`); the suite score is checked only when every
//!   program ran.
//!
//! Every CBOM is generated with the binaries this builds (cargo profile `e2e`: optimised, with
//! overflow checks and debug assertions), passed with `--driver`, not one `$RCBOM_DRIVER` names or
//! another build the CLI would otherwise prefer. Fixtures run `$RCBOM_JOBS` at a time (default: one
//! per core, fewer when memory is short), each cargo with its share of the cores, the slowest of
//! the last run first (`target/e2e-times.tsv`); every fixture runs to the end, the failures are
//! printed together, and so is the peak memory in use. A fixture's whole output is in
//! `<outputs>/<name>.e2e.log` (all of them, in order, in `e2e.log`), its time on its `==` line.
//! `RCBOM_E2E_CACHE=dir` keeps each fixture's build cache and facts in `dir/<name>` instead of the
//! fixture's own `target/` (for a directory outside the sources and their snapshots). Either way a
//! cache built by the same driver binary is reused: after a change to the analysis, the CLI or the
//! verifier only, a run compiles nothing and replays the recorded facts. `RCBOM_BLESS=1` rewrites
//! the golden files and committed scores instead of comparing (after a deliberate change, to be
//! reviewed with git diff). Outputs go to `$RCBOM_RESULTS` if set (`results/fixtures` is the
//! committed copy), else to a temporary directory.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::Instant;

use anyhow::{Context, Result, bail};
use regex::Regex;

use crate::root;

/// What is checked for a fixture.
#[derive(Clone, Copy, PartialEq)]
enum Kind {
    /// The CBOM, its verification and its golden file.
    Golden,
    /// A rusi fixture: also its labelled score, perfect and as committed.
    Rusi,
    /// A suite program: the CBOM and its verification (scored together at the end).
    Generate,
}

struct Job {
    kind: Kind,
    dir: PathBuf,
    name: String,
}

struct Env {
    cbom: PathBuf,
    driver: PathBuf,
    out: PathBuf,
    cache: Option<PathBuf>,
    bless: bool,
    cargo_jobs: usize,
}

/// Does `path` match the shell glob `pat` (`*`, `?`, `[a-z0-9]`)?
fn glob(pat: &[char], path: &[char]) -> bool {
    match (pat.first(), path.first()) {
        (None, None) => true,
        (Some('*'), _) => glob(&pat[1..], path) || (!path.is_empty() && glob(pat, &path[1..])),
        (Some('?'), Some(_)) => glob(&pat[1..], &path[1..]),
        (Some('['), Some(c)) => {
            let Some(end) = pat.iter().position(|&x| x == ']') else {
                return false;
            };
            let class = &pat[1..end];
            let mut hit = false;
            let mut i = 0;
            while i < class.len() {
                if i + 2 < class.len() && class[i + 1] == '-' {
                    hit |= class[i] <= *c && *c <= class[i + 2];
                    i += 3;
                } else {
                    hit |= class[i] == *c;
                    i += 1;
                }
            }
            hit && glob(&pat[end + 1..], &path[1..])
        }
        (Some(p), Some(c)) if p == c => glob(&pat[1..], &path[1..]),
        _ => false,
    }
}

/// The directories inside `dir`, sorted.
fn subdirs(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir)
        .with_context(|| dir.display().to_string())?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_dir())
        .collect();
    v.sort();
    Ok(v)
}

fn base(p: &Path) -> String {
    p.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_string()
}

fn rel(p: &Path) -> String {
    p.strip_prefix(root()).unwrap_or(p).display().to_string()
}

/// `diff -u a b`, its output when they differ.
fn diff(a: &Path, b: &Path) -> Result<Option<String>> {
    let o = Command::new("diff").arg("-u").arg(a).arg(b).output()?;
    Ok((!o.status.success()).then(|| String::from_utf8_lossy(&o.stdout).into_owned()))
}

impl Env {
    /// The CLI, run in `dir` with the fixture's cache.
    fn cli(&self, dir: &Path, name: &str) -> Command {
        let mut c = Command::new(&self.cbom);
        c.current_dir(dir)
            .env_remove("RCBOM_DRIVER")
            .env("CARGO_BUILD_JOBS", self.cargo_jobs.to_string());
        if let Some(cache) = &self.cache {
            c.env("CARGO_TARGET_DIR", cache.join(name));
        }
        c
    }

    fn path(&self, name: &str, ext: &str) -> PathBuf {
        self.out.join(format!("{name}.{ext}"))
    }

    /// Generate and verify (every position, every shift).
    fn generate(&self, dir: &Path, name: &str, log: &mut String) -> Result<bool> {
        log.push_str(&format!("== {}\n", rel(dir)));
        let cbom_path = self.path(name, "cbom.json");
        let stderr = std::fs::File::create(self.path(name, "log"))?;
        let ok = self
            .cli(dir, name)
            .args(["cbom", "--driver"])
            .arg(&self.driver)
            .arg("-o")
            .arg(&cbom_path)
            .stdout(Stdio::null())
            .stderr(stderr)
            .status()?
            .success();
        let cli_log = std::fs::read_to_string(self.path(name, "log")).unwrap_or_default();
        if !ok {
            log.push_str(&cli_log);
            return Ok(false);
        }
        let caught: Vec<&str> = cli_log
            .lines()
            .filter(|l| l.contains("could not be analysed"))
            .collect();
        if !caught.is_empty() {
            log.push_str(&caught.join("\n"));
            log.push_str("\nthe driver caught panics: each is a bug (RCBOM_DEBUG=1 prints them)\n");
            return Ok(false);
        }
        // the CBOM named by its file name, as it sits next to the report in the results (with
        // known verifier limits, the check below decides)
        let v = self
            .cli(dir, name)
            .args(["cbom", "verify"])
            .arg(&cbom_path)
            .arg("--self-test")
            .output()?;
        let prefix = format!("{}/", self.out.display());
        let text: String = String::from_utf8_lossy(&v.stdout)
            .lines()
            .map(|l| format!("{}\n", l.strip_prefix(&prefix).unwrap_or(l)))
            .collect();
        std::fs::write(self.path(name, "verify"), &text)?;
        let known_path = dir.join("verify-known");
        if !v.status.success() && !known_path.exists() {
            log.push_str(&text);
            return Ok(false);
        }
        // (a fixture's `verify-known`: the mismatches of correct positions the verifier cannot
        // confirm, checked by hand, one `MISMATCH` line each; exactly those may occur)
        let counts = Regex::new(r"(\d+) positions verified, (\d+) mismatched").unwrap();
        let shifts = Regex::new(r"(\d+)/(\d+) shifted positions rejected").unwrap();
        let (verified, mismatched) = counts
            .captures(&text)
            .map(|c| (c[1].to_string(), c[2].to_string()))
            .unwrap_or_default();
        let (mut caught, mut total) = (0u64, 0u64);
        for c in shifts.captures_iter(&text) {
            caught += c[1].parse::<u64>().unwrap_or(0);
            total += c[2].parse::<u64>().unwrap_or(0);
        }
        log.push_str(&format!(
            "positions: {verified} verified, {mismatched} mismatched; self-test: {caught}/{total} shifted positions rejected\n"
        ));
        let known: BTreeSet<String> = std::fs::read_to_string(&known_path)
            .unwrap_or_default()
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(String::from)
            .collect();
        let mut found = BTreeSet::new();
        for line in text.lines() {
            if line.starts_with("MISMATCH") || line.starts_with("ACCEPTED") {
                let note = if known.contains(line.trim()) {
                    "  (known verifier limit)"
                } else {
                    ""
                };
                log.push_str(&format!("  {line}{note}\n"));
            }
            if line.starts_with("MISMATCH") {
                found.insert(line.trim().to_string());
            }
        }
        for line in known.difference(&found) {
            log.push_str(&format!(
                "  stale verify-known entry (the position now verifies, or changed): {line}\n"
            ));
        }
        Ok(found == known && caught == total)
    }

    /// Generate, verify, and compare with the golden file.
    fn golden(&self, dir: &Path, name: &str, log: &mut String) -> Result<bool> {
        if !self.generate(dir, name, log)? {
            return Ok(false);
        }
        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(self.path(name, "cbom.json"))?)?;
        let txt = self.path(name, "txt");
        std::fs::write(&txt, crate::summary::summary(&doc))?;
        let expected = dir.join("expected.txt");
        if self.bless {
            std::fs::copy(&txt, &expected)?;
            log.push_str("golden file: written\n");
            return Ok(true);
        }
        match diff(&expected, &txt)? {
            Some(d) => {
                std::fs::write(self.path(name, "diff"), &d)?;
                log.push_str(&d.lines().take(80).collect::<Vec<_>>().join("\n"));
                log.push_str(&format!("\ngolden file differs: {}\n", rel(&expected)));
                Ok(false)
            }
            None => {
                let _ = std::fs::remove_file(self.path(name, "diff"));
                log.push_str("golden file: identical\n");
                Ok(true)
            }
        }
    }

    /// A labelled rusi fixture: its golden file, and its score, perfect and as committed.
    fn rusi(&self, dir: &Path, name: &str, log: &mut String) -> Result<bool> {
        if !self.golden(dir, name, log)? {
            return Ok(false);
        }
        let labels: toml::Value =
            toml::from_str(&std::fs::read_to_string(dir.join("labels.toml"))?)?;
        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(self.path(name, "cbom.json"))?)?;
        let r = crate::score::score(&labels, &doc);
        let score_path = self.path(name, "score.json");
        std::fs::write(&score_path, crate::pyjson::dumps(&r, false, Some(2)) + "\n")?;
        let committed = dir.join("expected-score.json");
        if self.bless {
            std::fs::copy(&score_path, &committed)?;
        } else if let Some(d) = diff(&committed, &score_path)? {
            log.push_str(&d);
            log.push_str(&format!("score differs: {name}\n"));
            return Ok(false);
        }
        let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&score_path)?)?;
        let n = |k: &str| v[k].as_i64().unwrap_or(-1);
        log.push_str(&format!(
            "score: recall {}/{}, precision {}/{}, fully named {}/{}, provenance {}/{}, crates {}\n",
            n("core_pairs_found"),
            n("core_pairs"),
            n("true_positive_pairs"),
            n("reported_pairs"),
            n("fully_named"),
            n("core_pairs"),
            n("provenance_exact"),
            n("provenance_total"),
            v["crates_found"].as_str().unwrap_or("")
        ));
        let (found, all) = v["crates_found"]
            .as_str()
            .and_then(|s| s.split_once('/'))
            .unwrap_or(("0", "1"));
        Ok(v["recall"].as_f64() == Some(1.0)
            && v["precision"].as_f64() == Some(1.0)
            && n("fully_named") == n("core_pairs")
            && n("provenance_exact") == n("provenance_total")
            && found == all)
    }

    /// One fixture: its output to `<name>.e2e.log`, its verdict as the log's last line (a fixture
    /// whose run was cut short has none).
    fn job(&self, j: &Job) -> Result<(bool, u64)> {
        let t0 = Instant::now();
        let mut log = String::new();
        let ok = match j.kind {
            Kind::Golden => self.golden(&j.dir, &j.name, &mut log),
            Kind::Rusi => self.rusi(&j.dir, &j.name, &mut log),
            Kind::Generate => self.generate(&j.dir, &j.name, &mut log),
        }
        .unwrap_or_else(|e| {
            log.push_str(&format!("{e:#}\n"));
            false
        });
        log.push_str(if ok {
            "e2e fixture: ok\n"
        } else {
            "e2e fixture: FAILED\n"
        });
        std::fs::write(self.path(&j.name, "e2e.log"), &log)?;
        Ok((ok, t0.elapsed().as_secs()))
    }
}

/// The memory a fixture is given room for when choosing how many run at a time (the largest,
/// rustls with aws-lc-rs, stays well under it).
const FIXTURE_KB: u64 = 2 * 1024 * 1024;

/// A `/proc/meminfo` field, in kB (Linux; elsewhere none).
fn meminfo(field: &str) -> Option<u64> {
    std::fs::read_to_string("/proc/meminfo")
        .ok()?
        .lines()
        .find_map(|l| l.strip_prefix(field)?.strip_prefix(':'))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

pub(crate) fn cargo_build(dir: &Path) -> Result<()> {
    if !crate::cargo()
        .args(["build", "-q", "--profile", "e2e"])
        .current_dir(dir)
        .status()?
        .success()
    {
        bail!("build failed in {}", dir.display());
    }
    Ok(())
}

pub fn run(args: &[String]) -> Result<()> {
    let (mut realapp, mut regress, mut suite) = (false, false, false);
    let mut only: Vec<Vec<char>> = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--realapp" => realapp = true,
            "--regress" => regress = true,
            "--suite" => suite = true,
            "--only" => only.push(it.next().context("--only GLOB")?.chars().collect()),
            other => bail!("unknown option {other}"),
        }
    }
    let root = root();
    crate::check::run()?;
    cargo_build(&root.join("crates/rcbom-driver"))?;
    cargo_build(&root)?;
    let out = match std::env::var_os("RCBOM_RESULTS") {
        Some(o) => PathBuf::from(o),
        None => std::env::temp_dir().join(format!("rcbom-e2e-{}", std::process::id())),
    };
    std::fs::create_dir_all(out.join("suite"))?;
    // absolute: the generator and the verifier run in each fixture's directory
    let out = out.canonicalize()?;
    // as many fixtures at a time as cores (a fixture's analysis and verification are one
    // thread each, its compilation shares the cargo jobs), as far as memory allows
    let cores = std::thread::available_parallelism().map_or(1, |n| n.get());
    let by_memory = meminfo("MemAvailable").map_or(cores, |kb| (kb / FIXTURE_KB).max(1) as usize);
    let jobs: usize = std::env::var("RCBOM_JOBS")
        .ok()
        .and_then(|j| j.parse().ok())
        .unwrap_or(cores.min(by_memory))
        .max(1);
    let env = Env {
        cbom: root.join("target/e2e/cargo-cbom"),
        driver: root.join("crates/rcbom-driver/target/e2e/rcbom-driver"),
        out: out.clone(),
        cache: std::env::var_os("RCBOM_E2E_CACHE").map(PathBuf::from),
        bless: std::env::var_os("RCBOM_BLESS").is_some(),
        cargo_jobs: (cores / jobs).max(1),
    };

    // the fixtures to run, in order
    let fixtures = root.join("tests/fixtures");
    let mut list: Vec<Job> = Vec::new();
    let add = |list: &mut Vec<Job>, kind: Kind, dir: PathBuf, name: String| {
        let r: Vec<char> = rel(&dir).chars().collect();
        if only.is_empty() || only.iter().any(|p| glob(p, &r)) {
            list.push(Job { kind, dir, name });
        }
    };
    for g in ["micro", "libonly", "threads"] {
        add(&mut list, Kind::Golden, fixtures.join(g), g.into());
    }
    for d in subdirs(&fixtures.join("rusi"))? {
        add(&mut list, Kind::Rusi, d.clone(), base(&d));
    }
    if realapp {
        add(
            &mut list,
            Kind::Golden,
            fixtures.join("realapp"),
            "realapp".into(),
        );
    }
    if regress {
        for d in subdirs(&fixtures.join("regress"))? {
            add(
                &mut list,
                Kind::Golden,
                d.clone(),
                format!("regress-{}", base(&d)),
            );
        }
    }
    let programs = subdirs(&fixtures.join("suite"))?;
    let before = list.len();
    if suite {
        for d in &programs {
            add(
                &mut list,
                Kind::Generate,
                d.clone(),
                format!("suite/{}", base(d)),
            );
        }
    }
    let suite_all = suite && list.len() - before == programs.len();
    if list.is_empty() {
        bail!("no fixture matches");
    }

    println!(
        "e2e: {} fixtures, {jobs} at a time (outputs in {})",
        list.len(),
        out.display()
    );
    // the slowest first (by the last run's times; one never timed first of all), so that no
    // long fixture starts last
    let times_path = root.join("target/e2e-times.tsv");
    let mut times: HashMap<String, u64> = std::fs::read_to_string(&times_path)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            let (n, t) = l.split_once('\t')?;
            Some((n.to_string(), t.parse().ok()?))
        })
        .collect();
    let mut order: Vec<usize> = (0..list.len()).collect();
    order
        .sort_by_key(|&i| std::cmp::Reverse(times.get(&list[i].name).copied().unwrap_or(u64::MAX)));
    let queue: Mutex<VecDeque<usize>> = Mutex::new(order.into_iter().collect());
    let verdicts: Mutex<Vec<Option<bool>>> = Mutex::new(vec![None; list.len()]);
    let secs: Mutex<Vec<Option<u64>>> = Mutex::new(vec![None; list.len()]);
    // the least memory available during the run
    let done = std::sync::atomic::AtomicBool::new(false);
    let least = std::sync::atomic::AtomicU64::new(u64::MAX);
    std::thread::scope(|s| {
        s.spawn(|| {
            while !done.load(std::sync::atomic::Ordering::Relaxed) {
                if let Some(kb) = meminfo("MemAvailable") {
                    least.fetch_min(kb, std::sync::atomic::Ordering::Relaxed);
                }
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        });
        let workers: Vec<_> = (0..jobs)
            .map(|_| {
                s.spawn(|| {
                    loop {
                        let Some(i) = queue.lock().unwrap().pop_front() else {
                            break;
                        };
                        let j = &list[i];
                        let (ok, t) = env.job(j).unwrap_or((false, 0));
                        verdicts.lock().unwrap()[i] = Some(ok);
                        secs.lock().unwrap()[i] = Some(t);
                        let mut stdout = std::io::stdout().lock();
                        let _ = writeln!(
                            stdout,
                            "== {}: {} ({t} s)",
                            rel(&j.dir),
                            if ok { "ok" } else { "FAILED" }
                        );
                    }
                })
            })
            .collect();
        for w in workers {
            let _ = w.join();
        }
        done.store(true, std::sync::atomic::Ordering::Relaxed);
    });
    // the times, for the next run's order
    for (j, t) in list.iter().zip(secs.into_inner().unwrap()) {
        if let Some(t) = t {
            times.insert(j.name.clone(), t);
        }
    }
    let mut lines: Vec<String> = times.iter().map(|(n, t)| format!("{n}\t{t}")).collect();
    lines.sort();
    let _ = std::fs::write(&times_path, lines.join("\n") + "\n");
    if let (Some(total), least) = (
        meminfo("MemTotal"),
        least.load(std::sync::atomic::Ordering::Relaxed),
    ) && least != u64::MAX
    {
        println!(
            "e2e: peak memory in use {:.1} GB of {:.1} GB",
            (total - least) as f64 / 1048576.0,
            total as f64 / 1048576.0
        );
    }

    // every fixture's output, in order, and the failures
    let mut all_logs = String::new();
    let mut failed: Vec<String> = Vec::new();
    let verdicts = verdicts.into_inner().unwrap();
    for (j, v) in list.iter().zip(&verdicts) {
        all_logs
            .push_str(&std::fs::read_to_string(env.path(&j.name, "e2e.log")).unwrap_or_default());
        if *v != Some(true) {
            failed.push(j.name.clone());
        }
    }
    std::fs::write(out.join("e2e.log"), all_logs)?;
    if suite {
        if suite_all {
            let json = crate::suite::score(&out.join("suite"), &programs, true)?;
            let text = crate::suite::score(&out.join("suite"), &programs, false)?;
            std::fs::write(out.join("suite-score.json"), &json)?;
            std::fs::write(out.join("suite-score.txt"), &text)?;
            println!("{}", text.lines().next().unwrap_or(""));
            let committed = fixtures.join("suite/expected-score.json");
            if env.bless {
                std::fs::copy(out.join("suite-score.json"), &committed)?;
                println!("suite score: written");
            } else if let Some(d) = diff(&committed, &out.join("suite-score.json"))? {
                print!("{d}");
                println!("suite score differs: {}", rel(&committed));
                failed.push("suite score".into());
            } else {
                println!("suite score: identical");
            }
        } else {
            println!("suite score: not checked (not every suite program ran)");
        }
    }
    if !failed.is_empty() {
        for name in &failed {
            if let Ok(l) = std::fs::read_to_string(env.path(name, "e2e.log")) {
                println!("\n{l}");
            }
        }
        println!(
            "\ne2e: {} failed: {} ({})",
            failed.len(),
            failed.join(" "),
            out.display()
        );
        std::process::exit(1);
    }
    println!("e2e: ok ({})", out.display());
    Ok(())
}
