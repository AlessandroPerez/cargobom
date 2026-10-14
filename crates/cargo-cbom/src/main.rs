//! `cargo cbom`: CycloneDX 1.7 CBOM for a Cargo workspace (Layers 1 and 2).
//!
//!   cargo cbom [--manifest-path P] [--features F] [-o cbom.json]
//!   cargo cbom verify cbom.json [--manifest-path P] [--self-test]

mod validate;
mod verify;

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use rcbom_analysis::{RunInfo, analyze, load_facts, to_cyclonedx};
use rcbom_kb::{Kb, Role};

/// The nightly the driver is built with; it must compile the analysed project too.
const TOOLCHAIN: &str = "nightly-2026-09-25";

/// The pinned toolchain's sysroot.
pub(crate) fn sysroot() -> Result<String> {
    let out = Command::new("rustc")
        .arg(format!("+{TOOLCHAIN}"))
        .args(["--print", "sysroot"])
        .output()?;
    if !out.status.success() {
        bail!(
            "toolchain {TOOLCHAIN} missing: rustup toolchain install {TOOLCHAIN} --component rustc-dev,llvm-tools,rust-src"
        );
    }
    Ok(String::from_utf8(out.stdout)?.trim().to_string())
}

#[derive(Parser)]
#[command(
    bin_name = "cargo cbom",
    version,
    about = "Generate a CycloneDX 1.7 CBOM for a Cargo workspace"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
    #[command(flatten)]
    args: GenArgs,
}

#[derive(clap::Args)]
struct GenArgs {
    #[arg(long, default_value = "Cargo.toml")]
    manifest_path: PathBuf,
    /// Features to enable, as with cargo.
    #[arg(long, value_delimiter = ',')]
    features: Vec<String>,
    /// Output file (default: stdout).
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// The rcbom-driver binary (default: $RCBOM_DRIVER, then next to this executable).
    #[arg(long)]
    driver: Option<PathBuf>,
    /// Layer 1 only: no compilation, nothing from the project is executed by rcbom.
    #[arg(long)]
    manifest_only: bool,
    /// The cargo profile whose code is analysed. The default is what ships: `release`, where
    /// `cfg(debug_assertions)` code is not compiled.
    #[arg(long, default_value = "release")]
    profile: String,
}

#[derive(Subcommand)]
enum Cmd {
    /// Check every evidence position in a CBOM against the source it cites.
    Verify {
        cbom: PathBuf,
        #[arg(long, default_value = "Cargo.toml")]
        manifest_path: PathBuf,
        /// Also shift every verified position by one line or column and count how many shifted
        /// positions the check rejects (each accepted one is printed).
        #[arg(long)]
        self_test: bool,
    },
}

fn main() -> Result<()> {
    // `cargo cbom ...` runs us as `cargo-cbom cbom ...`
    let mut args: Vec<String> = std::env::args().collect();
    if args.get(1).is_some_and(|a| a == "cbom") {
        args.remove(1);
    }
    let cli = Cli::parse_from(args);
    match cli.cmd {
        Some(Cmd::Verify {
            cbom,
            manifest_path,
            self_test,
        }) => verify::run(&cbom, &manifest_path, self_test),
        None => generate(&cli.args),
    }
}

fn generate(a: &GenArgs) -> Result<()> {
    let kb = Kb::seed()?;
    let target = rcbom_manifest::host_triple()?;
    eprintln!("cbom: layer 1 (cargo metadata)");
    let man = rcbom_manifest::load(&a.manifest_path, &target, &a.features, &kb)?;

    let facts = if a.manifest_only {
        Vec::new()
    } else {
        let dir = man.target_directory.join("rcbom");
        let facts_dir = dir.join("facts");
        let units = run_driver(a, &man, &dir, &facts_dir)?;
        load_facts(&facts_dir, &units)?
    };
    eprintln!("cbom: layer 2 analysis ({} crates)", facts.len());
    let mut an = analyze(&kb, &man, &facts);
    an.layer2 = !a.manifest_only;
    let run = RunInfo {
        tool_version: env!("CARGO_PKG_VERSION").into(),
        toolchain: if a.manifest_only {
            "none".into()
        } else {
            TOOLCHAIN.into()
        },
        target,
        features: a.features.clone(),
        profile: if a.manifest_only {
            "none".into()
        } else {
            a.profile.clone()
        },
        packages: man.packages.len(),
        sandbox: "none (draft: run only on trusted code)".into(),
    };
    let bom = to_cyclonedx(&kb, &man, &an, &run);
    let errors = validate::validate(&bom)?;
    if !errors.is_empty() {
        for e in &errors {
            eprintln!("cbom: schema: {e}");
        }
        bail!(
            "the CBOM does not validate against CycloneDX 1.7 ({} errors)",
            errors.len()
        );
    }
    let text = serde_json::to_string_pretty(&bom)? + "\n";
    match &a.output {
        Some(p) => std::fs::write(p, text)?,
        None => print!("{text}"),
    }
    summary(&an);
    Ok(())
}

fn summary(an: &rcbom_analysis::Analysis) {
    eprintln!("cbom: {} assets (valid CycloneDX 1.7)", an.assets.len());
    for a in an.assets.values() {
        eprintln!(
            "  {:<24} {:<9} {:>3} occurrences  {}",
            a.name,
            if a.reachable() {
                "reachable"
            } else {
                "present"
            },
            a.occurrences.len(),
            a.observed_functions()
                .into_iter()
                .collect::<Vec<_>>()
                .join(",")
        );
    }
    for n in &an.notes {
        eprintln!("cbom: note: {n}");
    }
}

fn find_driver(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(p) = explicit {
        return Ok(p.to_path_buf());
    }
    let exe = std::env::current_exe()?;
    let mut candidates = vec![exe.with_file_name("rcbom-driver")];
    if let Some(p) = std::env::var_os("RCBOM_DRIVER") {
        candidates.insert(0, PathBuf::from(p));
    }
    // development layout: the driver is its own cargo project
    let dev = Path::new(env!("CARGO_MANIFEST_DIR")).join("../rcbom-driver/target");
    candidates.push(dev.join("release/rcbom-driver"));
    candidates.push(dev.join("debug/rcbom-driver"));
    candidates.into_iter().find(|p| p.exists()).context(
        "rcbom-driver not found: build it (cd crates/rcbom-driver && cargo build) or pass --driver",
    )
}

/// Runs the build with the driver; returns the units (`<crate><extra-filename>`) the build
/// consists of, fresh or rebuilt, as cargo reports them.
fn run_driver(
    a: &GenArgs,
    man: &rcbom_manifest::Manifest,
    dir: &Path,
    facts_dir: &Path,
) -> Result<std::collections::BTreeSet<String>> {
    // the program's own packages: their crates are never knowledge-base or stop crates, even
    // when named like one
    let mut local_dirs: Vec<String> = man
        .packages
        .iter()
        .filter(|p| p.local)
        .map(|p| p.manifest_dir.display().to_string())
        .collect();
    local_dirs.sort();
    let driver = find_driver(a.driver.as_deref())?;
    let sysroot = sysroot()?;
    let compiler = Command::new("rustc")
        .arg(format!("+{TOOLCHAIN}"))
        .arg("-vV")
        .output()?;
    let compiler = String::from_utf8_lossy(&compiler.stdout).to_string();
    // the crates of the build's packages, by their library names (the package md-5's library
    // is `md5`), each with its package's source directory: two packages may name their library
    // alike (md5 0.7 and md-5), and the driver tells their crates apart by where the sources
    // are. Those the knowledge base describes, any version, have their sites recorded; its
    // algorithm and trait crates are not entered by the walk.
    let entries = |pkgs: &mut dyn Iterator<Item = &rcbom_manifest::Pkg>| -> String {
        let mut v: Vec<String> = pkgs
            .filter(|p| !p.local)
            .filter_map(|p| {
                p.lib_name
                    .as_ref()
                    .map(|n| format!("{n}={}", p.manifest_dir.display()))
            })
            .collect();
        v.sort();
        v.dedup();
        v.join("\n")
    };
    // and those of crypto packages it does not model: their calls are operations of unknown
    // algorithm (`p256::ecdh::diffie_hellman` from age)
    let kb_crates = entries(
        &mut man
            .packages
            .iter()
            .filter(|p| p.role.is_some() || p.unmodelled == Some(rcbom_kb::Unmodelled::Crypto)),
    );
    let stop: Vec<&rcbom_manifest::Pkg> = man
        .packages
        .iter()
        .filter(|p| matches!(p.role, Some(Role::Algorithm | Role::Trait)))
        .collect();
    let stop_crates = entries(&mut stop.iter().copied());
    // what the stop crates depend on (curve25519-dalek under ed25519-dalek): their
    // implementation, which the walk does not enter from them
    let impl_crates = {
        let mut seen: std::collections::BTreeSet<&rcbom_manifest::PackageId> = Default::default();
        let mut stack: Vec<&rcbom_manifest::PackageId> = stop
            .iter()
            .filter(|p| !p.local)
            .flat_map(|p| p.runtime_deps.iter())
            .collect();
        while let Some(id) = stack.pop() {
            if seen.insert(id)
                && let Some(p) = man.by_id(id)
            {
                stack.extend(p.runtime_deps.iter());
            }
        }
        entries(&mut seen.into_iter().filter_map(|id| man.by_id(id)))
    };

    // Facts live next to the build cache: a crate cargo does not rebuild keeps its facts. Any
    // input of the driver other than the sources (the driver itself, the compiler, the crate
    // lists, features, profile) invalidates both.
    let stamp = format!(
        "{}\n{}\n{}\nkb={}\nstop={}\nimpl={}\n{:?}\nprofile={}\nlocal={:?}\nmax-instances={:?}\n",
        driver.display(),
        std::fs::metadata(&driver)?
            .modified()
            .map(|t| format!("{t:?}"))
            .unwrap_or_default(),
        compiler.trim(),
        kb_crates,
        stop_crates,
        impl_crates,
        a.features,
        a.profile,
        local_dirs,
        std::env::var("RCBOM_MAX_INSTANCES").ok()
    );
    let stamp_path = dir.join("stamp");
    if std::fs::read_to_string(&stamp_path).ok().as_deref() != Some(stamp.as_str()) {
        let _ = std::fs::remove_dir_all(dir);
    }
    std::fs::create_dir_all(facts_dir)?;
    std::fs::write(&stamp_path, &stamp)?;

    eprintln!("cbom: layer 2 (cargo +{TOOLCHAIN} check with rcbom-driver)");
    let ld = match std::env::var_os("LD_LIBRARY_PATH") {
        Some(old) => format!("{sysroot}/lib:{}", old.to_string_lossy()),
        None => format!("{sysroot}/lib"),
    };
    let mut cmd = Command::new("cargo");
    cmd.arg(format!("+{TOOLCHAIN}"))
        .args([
            "check",
            "--workspace",
            "--message-format=json-render-diagnostics",
            "--profile",
            a.profile.as_str(),
            "--manifest-path",
        ])
        .arg(&a.manifest_path)
        .arg("--target-dir")
        .arg(dir.join("target"))
        .env("RUSTC_WRAPPER", &driver)
        .env("RCBOM_OUT", facts_dir)
        .env("RCBOM_KB_CRATES", &kb_crates)
        .env("RCBOM_STOP_CRATES", &stop_crates)
        .env("RCBOM_IMPL_CRATES", &impl_crates)
        .env("RCBOM_LOCAL_DIRS", local_dirs.join("\n"))
        .env("RCBOM_SYSROOT", &sysroot)
        .env("LD_LIBRARY_PATH", ld);
    if !a.features.is_empty() {
        cmd.arg("--features").arg(a.features.join(","));
    }
    // cargo's JSON messages on stdout, its diagnostics rendered on stderr as usual
    let out = cmd
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .output()
        .context("running cargo")?;
    if !out.status.success() {
        bail!("the project did not build with {TOOLCHAIN} and rcbom-driver");
    }
    // `compiler-artifact` messages name every unit of the build, including those cargo did not
    // need to rebuild: `.../deps/libaes_gcm-1a2b3c.rmeta` is unit `aes_gcm-1a2b3c`
    let mut units = std::collections::BTreeSet::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let Ok(msg) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if msg["reason"] != "compiler-artifact" {
            continue;
        }
        for f in msg["filenames"].as_array().into_iter().flatten() {
            if let Some(stem) = f.as_str().and_then(|f| Path::new(f).file_stem()) {
                let stem = stem.to_string_lossy();
                units.insert(stem.strip_prefix("lib").unwrap_or(&stem).to_string());
            }
        }
    }
    Ok(units)
}
