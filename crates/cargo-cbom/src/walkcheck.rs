//! `cargo cbom --check-walk`: the walk from each binary's entry points against the linker, which
//! keeps exactly the code the binary contains.
//!
//! Each binary is linked once more, unoptimised (little is inlined) and with v0 symbol names
//! (full paths and generic arguments), into its own target directory, without the driver: every
//! unit with the arguments the build analysed gives it, the project's own compiler flags and
//! what its profile says of debug assertions included, or the two builds are not of one code. Its
//! defined function symbols, less those of the instances and shims the binary's walk reached
//! (`Reach::fns`, `Reach::shims`), are the code linked but not walked. Both sides are compared
//! demangled without crate hashes: the two builds hash a crate's dependencies differently, and
//! an instance shared between crates may be walked from one and emitted in another.
//!
//! Each symbol linked but not walked is classified by the crate that defines it (read from the
//! v0 path: the crate root of the item, of an impl for its methods, of the trait for a shim of a
//! trait method):
//! - `entry`: the standard library's glue around `main` (`lang_start`);
//! - `std`: the standard library, its shims included (drop glue, a closure's `call_once`, a
//!   tuple's `clone`), whatever types it is instantiated with;
//! - `modelled`: a crate the walk does not enter (an algorithm or trait crate of the knowledge
//!   base) and the crates implementing them;
//! - `constructor`: an enum variant's or tuple struct's constructor as a function;
//! - `uncalled object`, `behind a constant`: what only the methods of a trait object nothing
//!   calls through reach, and what only code behind a branch on a constant reaches
//!   (`Reach::uncalled`, `Reach::folded`): compiled into this binary, and never run;
//! - `other`: a crate that is neither the program's nor holds a crypto call: code there that
//!   reached the program's or crypto code would show as a gap itself;
//! - `gap`: anything else, in the program's crates, the crypto crates the knowledge base
//!   describes or flags, or a crate holding a call into one: code in the binary the walk did not
//!   reach, a missing walk edge. The target is none.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use rcbom_facts::CrateFacts;
use rcbom_kb::Role;

/// One binary's check: counts per class, and the gaps.
pub(crate) struct Report {
    pub artifact: String,
    pub linked: usize,
    pub walked: usize,
    pub classes: BTreeMap<&'static str, usize>,
    pub gaps: Vec<String>,
}

impl Report {
    /// `bin rage-keygen: linked 18121, walked 16405; not walked 2879: constructor 24, ..., gap 0`
    pub fn summary(&self) -> String {
        let n: usize = self.classes.values().sum();
        // (what a vtable nothing calls through keeps in the binary: named where there is any)
        let classes: Vec<String> = CLASSES
            .iter()
            .filter(|c| !matches!(**c, UNCALLED | FOLDED) || self.classes.contains_key(*c))
            .map(|c| format!("{c} {}", self.classes.get(c).copied().unwrap_or(0)))
            .collect();
        format!(
            "{}: linked {}, walked {}; not walked {n}: {}",
            self.artifact,
            self.linked,
            self.walked,
            classes.join(", ")
        )
    }
}

/// Linked, not walked, and no gap: reached only from the methods of trait objects the walk saw
/// made and never used (`Reach::uncalled`).
const UNCALLED: &str = "uncalled object";
/// Linked, not walked, and no gap: reached only from code behind a branch on a constant, which
/// never runs and which this build, made without optimisation, compiles all the same
/// (`Reach::folded`).
const FOLDED: &str = "behind a constant";
const CLASSES: [&str; 8] = [
    "entry",
    "std",
    "modelled",
    "constructor",
    UNCALLED,
    FOLDED,
    "other",
    "gap",
];

pub(crate) fn run(
    a: &crate::GenArgs,
    sel: &rcbom_manifest::Selection,
    man: &rcbom_manifest::Manifest,
    facts: &[CrateFacts],
    dir: &Path,
) -> Result<Vec<Report>> {
    let walks: Vec<&rcbom_facts::Reach> = facts
        .iter()
        .filter_map(|f| f.reach.as_ref())
        .filter(|r| r.artifact.starts_with("bin "))
        .collect();
    if walks.is_empty() {
        return Ok(Vec::new());
    }
    eprintln!(
        "cbom: walk check (cargo +{} build, opt-level 0)",
        crate::TOOLCHAIN
    );
    let bins = build(a, sel, &dir.join("link"))?;
    let crates = Crates::of(man, facts, &sel.target)?;
    let mut out = Vec::new();
    for w in walks {
        let name = &w.artifact["bin ".len()..];
        let Some(exe) = bins.get(name) else {
            bail!("the binary {name} was not built");
        };
        let walked: HashSet<String> = w
            .fns
            .iter()
            .chain(&w.shims)
            .filter(|s| s.starts_with("_R"))
            .map(|s| demangle(s))
            .collect();
        let uncalled: HashSet<String> = w
            .uncalled
            .iter()
            .filter(|s| s.starts_with("_R"))
            .map(|s| demangle(s))
            .collect();
        let folded: HashSet<String> = w
            .folded
            .iter()
            .filter(|s| s.starts_with("_R"))
            .map(|s| demangle(s))
            .collect();
        let data = std::fs::read(exe).with_context(|| exe.display().to_string())?;
        let linked = linked_symbols(&data)?;
        let mut r = Report {
            artifact: w.artifact.clone(),
            linked: linked.len(),
            walked: walked.len(),
            classes: BTreeMap::new(),
            gaps: Vec::new(),
        };
        for (sym, d) in &linked {
            if walked.contains(d) {
                continue;
            }
            let class = match crates.class(sym, d) {
                "gap" if uncalled.contains(d) => UNCALLED,
                "gap" if folded.contains(d) => FOLDED,
                c => c,
            };
            *r.classes.entry(class).or_default() += 1;
            if class == "gap" {
                r.gaps.push(d.clone());
            } else if class == "other" && std::env::var_os("RCBOM_DEBUG").is_some() {
                eprintln!("cbom: walk check: {}: other: {d}", w.artifact);
            }
        }
        r.gaps.sort();
        out.push(r);
    }
    Ok(out)
}

/// Set in the check's build, where cargo runs this program as its `RUSTC_WRAPPER`.
pub(crate) const AS_RUSTC: &str = "RCBOM_WALK_RUSTC";

/// As cargo's `RUSTC_WRAPPER` in the check's build (`<this> <rustc> <arguments>`): the compiler
/// with the arguments cargo gives it, which are those of the build analysed, and `unoptimised`.
pub(crate) fn rustc(mut args: Vec<String>) -> ! {
    if args.is_empty() {
        eprintln!("cbom: {AS_RUSTC} is set: expected a compiler and its arguments");
        std::process::exit(2);
    }
    let rustc = args.remove(0);
    let extra = unoptimised(&args);
    match Command::new(&rustc).args(&args).args(extra).status() {
        Ok(s) => std::process::exit(s.code().unwrap_or(1)),
        Err(e) => {
            eprintln!("cbom: running {rustc}: {e}");
            std::process::exit(1);
        }
    }
}

/// What the check's build adds to a unit's arguments: its code as the build analysed compiles
/// it, unoptimised and with v0 symbol names. Nothing for a call that compiles nothing (`-vV`,
/// `--print`).
///
/// The flags come last, and of a flag given twice the last one counts: every unit is
/// unoptimised whatever the manifest sets for it (cargo-deb's `[profile.release.package.
/// serde_json] opt-level = 2`; an optimised unit's functions are inlined and merged where their
/// code is the same). Debug assertions and overflow checks are code, and the compiler takes
/// them from the optimisation level where nothing sets them, as cargo knows and relies on: what
/// the unit's own level implied is said in full, or the unit optimised by the manifest would be
/// linked with what only its `debug_assert!`s call (cargo-deb's rayon-core).
fn unoptimised(args: &[String]) -> Vec<String> {
    let args = with_files(args);
    let compiles = args.iter().any(|a| a == "--crate-name")
        && !args
            .iter()
            .any(|a| a == "--print" || a.starts_with("--print="));
    if !compiles {
        return Vec::new();
    }
    let mut level = "0";
    let (mut assertions, mut overflow) = (None, None);
    let mut it = args.iter().map(String::as_str);
    while let Some(a) = it.next() {
        let option = match a {
            "-C" | "--codegen" => it.next(),
            "-O" => Some("opt-level=3"),
            _ => a
                .strip_prefix("--codegen=")
                .or_else(|| a.strip_prefix("-C"))
                .filter(|o| !o.is_empty()),
        };
        let Some(option) = option else { continue };
        let (key, value) = option.split_once('=').unwrap_or((option, "yes"));
        let on = matches!(value, "y" | "yes" | "on" | "true");
        match key.replace('_', "-").as_str() {
            "opt-level" => level = value,
            "debug-assertions" => assertions = Some(on),
            "overflow-checks" => overflow = Some(on),
            _ => {}
        }
    }
    let assertions = assertions.unwrap_or(level == "0");
    let overflow = overflow.unwrap_or(assertions);
    let said = |on| if on { "on" } else { "off" };
    [
        "symbol-mangling-version=v0".to_string(),
        "opt-level=0".to_string(),
        format!("debug-assertions={}", said(assertions)),
        format!("overflow-checks={}", said(overflow)),
    ]
    .into_iter()
    .flat_map(|o| ["-C".to_string(), o])
    .collect()
}

/// The arguments with those of each `@file` in its place (one a line), as the compiler reads
/// them.
fn with_files(args: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for a in args {
        match a.strip_prefix('@').map(std::fs::read_to_string) {
            Some(Ok(text)) => out.extend(text.lines().map(str::to_string)),
            _ => out.push(a.clone()),
        }
    }
    out
}

/// Builds the workspace's binaries unoptimised with v0 symbol names; their paths by name.
fn build(
    a: &crate::GenArgs,
    sel: &rcbom_manifest::Selection,
    target_dir: &Path,
) -> Result<HashMap<String, PathBuf>> {
    let profile = a.profile.to_uppercase().replace('-', "_");
    let mut cmd = Command::new("cargo");
    cmd.arg(format!("+{}", crate::TOOLCHAIN))
        .arg("build")
        .args(sel.package_args())
        .args(sel.feature_args())
        .args([
            "--bins",
            "--message-format=json-render-diagnostics",
            "--profile",
            a.profile.as_str(),
            "--manifest-path",
        ])
        .arg(&a.manifest_path)
        .arg("--target-dir")
        .arg(target_dir)
        // (each unit as the build analysed compiles it, the project's own flags included, and
        // unoptimised: `rustc` below)
        .env("RUSTC_WRAPPER", std::env::current_exe()?)
        .env(AS_RUSTC, "1")
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .env(format!("CARGO_PROFILE_{profile}_LTO"), "false")
        .env(format!("CARGO_PROFILE_{profile}_STRIP"), "none");
    if sel.cross {
        cmd.arg("--target").arg(&sel.target);
    }
    let out = cmd
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .output()
        .context("running cargo build")?;
    if !out.status.success() {
        bail!("the binaries did not build for the walk check");
    }
    let mut bins = HashMap::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let Ok(msg) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if msg["reason"] == "compiler-artifact"
            && let (Some(name), Some(exe)) =
                (msg["target"]["name"].as_str(), msg["executable"].as_str())
        {
            bins.insert(name.to_string(), PathBuf::from(exe));
        }
    }
    Ok(bins)
}

/// The defined function symbols of a binary with v0 names, each with its demangled form.
fn linked_symbols(data: &[u8]) -> Result<Vec<(String, String)>> {
    use object::{Object, ObjectSymbol, SymbolKind};
    let file = object::File::parse(data)?;
    let mut out: Vec<(String, String)> = file
        .symbols()
        .filter(|s| s.is_definition() && s.kind() == SymbolKind::Text)
        .filter_map(|s| s.name().ok())
        // Mach-O adds a leading underscore
        .filter_map(|n| {
            n.strip_prefix('_')
                .filter(|n| n.starts_with('R'))
                .map(|_| n)
        })
        .map(|n| {
            let n = n
                .strip_prefix("__R")
                .map_or(n.to_string(), |r| format!("_R{r}"));
            let d = demangle(&n);
            (n, d)
        })
        .collect();
    out.sort();
    out.dedup_by(|x, y| x.1 == y.1);
    Ok(out)
}

/// A symbol demangled without crate hashes (`{:#}`), its trait objects' bindings in one order.
fn demangle(sym: &str) -> String {
    let d: Vec<char> = format!("{:#}", rustc_demangle::demangle(sym))
        .chars()
        .collect();
    canonical(&d)
}

/// A demangled name with the associated-type bindings of each argument list (`dyn Service<Req,
/// Response = R, Error = E, Future = F>`) in the order of their names: the compiler orders a
/// trait object's bindings by a hash of their definitions, which the two builds compute
/// differently (the same instance is `Future = .., Error = .., Response = ..` in one and
/// `Response = .., Error = .., Future = ..` in the other).
fn canonical(s: &[char]) -> String {
    let mut out = String::new();
    let mut i = 0;
    while i < s.len() {
        if s[i] == '<'
            && let Some(e) = close_of(s, i)
        {
            let mut args: Vec<String> = split_args(&s[i + 1..e])
                .into_iter()
                .map(canonical)
                .collect();
            let binding = |a: &String| {
                a.split_once(" = ").is_some_and(|(n, _)| {
                    !n.is_empty() && n.chars().all(|c| c.is_alphanumeric() || c == '_')
                })
            };
            let first = args.iter().position(binding).unwrap_or(args.len());
            if args[first..].iter().all(binding) {
                args[first..].sort();
            }
            out.push('<');
            out.push_str(&args.join(", "));
            out.push('>');
            i = e + 1;
            continue;
        }
        out.push(s[i]);
        i += 1;
    }
    out
}

/// The `>` closing the `<` at `open` (not the arrow of a function type, `fn() -> T`).
fn close_of(s: &[char], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for k in open..s.len() {
        match s[k] {
            '<' => depth += 1,
            '>' if k > 0 && s[k - 1] == '-' => {}
            '>' => {
                depth -= 1;
                if depth == 0 {
                    return Some(k);
                }
            }
            _ => {}
        }
    }
    None
}

/// An argument list's arguments: split at its commas outside every bracket.
fn split_args(s: &[char]) -> Vec<&[char]> {
    let (mut out, mut depth, mut from) = (Vec::new(), 0i32, 0);
    for (k, &c) in s.iter().enumerate() {
        match c {
            '<' | '(' | '[' | '{' => depth += 1,
            '>' if k > 0 && s[k - 1] == '-' => {}
            '>' | ')' | ']' | '}' => depth -= 1,
            ',' if depth == 0 => {
                out.push(&s[from..k]);
                from = k + 1;
            }
            _ => {}
        }
    }
    out.push(&s[from..]);
    out.into_iter()
        .map(|a| {
            let lead = a.iter().take_while(|c| c.is_whitespace()).count();
            &a[lead..]
        })
        .collect()
}

/// The crates of the build by what the check makes of their code.
struct Crates {
    /// The standard library's crates, by the sysroot's libraries.
    std: HashSet<String>,
    /// The crates the walk does not enter and those implementing them.
    modelled: HashSet<String>,
    /// The program's crates, the crypto crates, and those calling into one.
    watched: HashSet<String>,
}

impl Crates {
    fn of(man: &rcbom_manifest::Manifest, facts: &[CrateFacts], target: &str) -> Result<Self> {
        let lib = |p: &rcbom_manifest::Pkg| p.lib_name.clone();
        let stop: Vec<&rcbom_manifest::Pkg> = man
            .packages
            .iter()
            .filter(|p| !p.local && matches!(p.role, Some(Role::Algorithm | Role::Trait)))
            .collect();
        let mut modelled: HashSet<String> = stop.iter().filter_map(|p| lib(p)).collect();
        let mut seen = HashSet::new();
        let mut stack: Vec<&rcbom_manifest::PackageId> =
            stop.iter().flat_map(|p| &p.runtime_deps).collect();
        while let Some(id) = stack.pop() {
            if seen.insert(id)
                && let Some(p) = man.by_id(id)
                && !p.local
            {
                modelled.extend(lib(p));
                stack.extend(&p.runtime_deps);
            }
        }
        let mut watched: HashSet<String> = man
            .packages
            .iter()
            .filter(|p| {
                p.local || p.role.is_some() || p.unmodelled == Some(rcbom_kb::Unmodelled::Crypto)
            })
            .filter_map(lib)
            .collect();
        // the program's binaries, and every crate holding a call into a crypto crate (of those
        // not the standard library's or modelled: their generic code instantiated holds some)
        for f in facts {
            if man
                .packages
                .iter()
                .any(|p| p.local && p.name == f.krate.package)
            {
                watched.insert(f.krate.name.clone());
            }
            watched.extend(
                f.sites
                    .iter()
                    // (not a call through a pointer, which the analysis follows)
                    .filter(|s| !matches!(s.target, rcbom_facts::Target::Pointer { .. }))
                    .map(|s| s.owner.krate.name.clone()),
            );
        }
        let sysroot = crate::sysroot()?;
        // (with the compiler's allocator and panic shims, `__rustc::__rust_alloc`)
        let mut std: HashSet<String> = HashSet::from(["__rustc".to_string()]);
        let libdir = Path::new(&sysroot)
            .join("lib/rustlib")
            .join(target)
            .join("lib");
        for e in std::fs::read_dir(&libdir).with_context(|| libdir.display().to_string())? {
            let name = e?.file_name().to_string_lossy().to_string();
            if let Some(n) = name
                .strip_prefix("lib")
                .and_then(|n| n.strip_suffix(".rlib"))
                .and_then(|n| n.rsplit_once('-'))
                .map(|(n, _)| n.to_string())
            {
                std.insert(n);
            }
        }
        Ok(Crates {
            std,
            modelled,
            watched,
        })
    }

    fn class(&self, sym: &str, demangled: &str) -> &'static str {
        if demangled.starts_with("std::rt::lang_start")
            || demangled.starts_with("<std::rt::lang_start")
        {
            return "entry";
        }
        let krate = defining_crate(sym, demangled).unwrap_or_default();
        if self.std.contains(&krate) {
            "std"
        } else if self.modelled.contains(&krate) {
            "modelled"
        } else if is_constructor(demangled) {
            "constructor"
        } else if self.watched.contains(&krate) {
            "gap"
        } else {
            "other"
        }
    }
}

/// `age::error::Error::Io`, `core::option::Option::<T>::Some`: the last segment of a path is a
/// type's name, or a name after a type's generic arguments, whatever its case (`select!`'s
/// `__PrivResult::<A, B>::_0` is a variant). A method's path starts at its type (`<T>::f`), so
/// a name right after that qualifier is none; a type declared inside a method has segments in
/// between (`<S<_>>::run::{closure#3}::__PrivResult::<A, ()>::_0`).
fn is_constructor(d: &str) -> bool {
    // the path's segments, generic arguments and qualifiers whole
    let (mut segs, mut depth, mut cur) = (Vec::new(), 0i32, String::new());
    let chars: Vec<char> = d.chars().collect();
    let mut k = 0;
    while k < chars.len() {
        match chars[k] {
            '<' => depth += 1,
            '>' if k == 0 || chars[k - 1] != '-' => depth -= 1,
            ':' if depth == 0 && chars.get(k + 1) == Some(&':') => {
                segs.push(std::mem::take(&mut cur));
                k += 2;
                continue;
            }
            _ => {}
        }
        cur.push(chars[k]);
        k += 1;
    }
    segs.push(cur);
    // the item's name: the last segment that is no list of generic arguments (its own come
    // after it, `Option::Some::<u8>`)
    let Some(i) = segs.iter().rposition(|g| !g.starts_with('<')) else {
        return false;
    };
    let last = &segs[i];
    if i < 1 || last.is_empty() || !last.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return false;
    }
    let qualified = segs[0].starts_with('<');
    // (after generic arguments of the segment before them, not after the qualifier)
    let after_args = i >= 2 && segs[i - 1].starts_with('<');
    after_args || (last.starts_with(char::is_uppercase) && (!qualified || i > 1))
}

/// The crate defining a v0 symbol's item: the crate root of its path, of the impl for a method
/// of an impl (`X`, `M`), of the trait for a trait method instantiated without one (`Y`: a
/// shim, `<(A, B) as core::clone::Clone>::clone`), read from the demangled text.
fn defining_crate(sym: &str, demangled: &str) -> Option<String> {
    let s = sym.strip_prefix("_R")?.as_bytes();
    let mut i = s.iter().take_while(|b| b.is_ascii_digit()).count();
    loop {
        match *s.get(i)? {
            b'C' => {
                i += 1;
                skip_disambiguator(s, &mut i)?;
                return ident(s, &mut i);
            }
            // a namespace (`N v`: a value, `N t`: a type, `N C`: a closure, `N S`: a shim)
            b'N' => i += 2,
            b'I' => i += 1,
            b'M' | b'X' => {
                i += 1;
                skip_disambiguator(s, &mut i)?;
            }
            b'Y' => return trait_crate(demangled),
            _ => return None,
        }
    }
}

/// The crate of the trait in `<T as krate::Trait>::m`.
fn trait_crate(d: &str) -> Option<String> {
    let mut depth = 0usize;
    let mut prev = ' ';
    for (i, c) in d.char_indices() {
        let arrow = prev == '-';
        prev = c;
        match c {
            '<' => depth += 1,
            // (not the arrow of a function type, `fn() -> T`)
            '>' if !arrow => depth = depth.saturating_sub(1),
            ' ' if depth == 1 && d[i..].starts_with(" as ") => {
                let rest = &d[i + 4..];
                return rest.split("::").next().map(str::to_string);
            }
            _ => {}
        }
    }
    None
}

/// `s<base-62>_`, optional.
fn skip_disambiguator(s: &[u8], i: &mut usize) -> Option<()> {
    if s.get(*i) == Some(&b's') {
        let end = s[*i..].iter().position(|&b| b == b'_')?;
        *i += end + 1;
    }
    Some(())
}

/// `[u] <decimal> [_] <bytes>`
fn ident(s: &[u8], i: &mut usize) -> Option<String> {
    if s.get(*i) == Some(&b'u') {
        *i += 1;
    }
    let digits = s[*i..].iter().take_while(|b| b.is_ascii_digit()).count();
    let n: usize = std::str::from_utf8(&s[*i..*i + digits])
        .ok()?
        .parse()
        .ok()?;
    *i += digits;
    if s.get(*i) == Some(&b'_') {
        *i += 1;
    }
    let name = std::str::from_utf8(s.get(*i..*i + n)?).ok()?.to_string();
    *i += n;
    Some(name)
}

/// The symbols a CBOM's walk check lists as gaps, for the summary on standard error.
pub(crate) fn print(reports: &[Report]) {
    for r in reports {
        eprintln!("cbom: walk check: {}", r.summary());
        for g in &r.gaps {
            eprintln!("cbom: walk check: {}: linked, not walked: {g}", r.artifact);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_unit_keeps_the_assertions_its_own_level_implied() {
        let of = |line: &str| {
            let args: Vec<String> = format!("--crate-name x {line}")
                .split_whitespace()
                .map(str::to_string)
                .collect();
            let extra = unoptimised(&args);
            assert_eq!(
                extra[..4],
                ["-C", "symbol-mangling-version=v0", "-C", "opt-level=0"]
            );
            format!("{} {}", extra[5], extra[7])
        };
        // cargo says nothing of assertions where they are what the level it gives implies
        assert_eq!(
            of("-C opt-level=2"),
            "debug-assertions=off overflow-checks=off"
        );
        assert_eq!(of(""), "debug-assertions=on overflow-checks=on");
        // and says where they are not
        assert_eq!(
            of("-C opt-level=2 -C debug-assertions=on"),
            "debug-assertions=on overflow-checks=on"
        );
        assert_eq!(
            of("-C debug-assertions=off"),
            "debug-assertions=off overflow-checks=off"
        );
        assert_eq!(
            of("-C opt-level=3 -C overflow-checks=on"),
            "debug-assertions=off overflow-checks=on"
        );
        // the project's own flags come after cargo's, in any spelling; the last one counts
        assert_eq!(
            of("-C opt-level=3 -Copt-level=0"),
            "debug-assertions=on overflow-checks=on"
        );
        assert_eq!(
            of("--codegen=opt-level=s --codegen debug_assertions"),
            "debug-assertions=on overflow-checks=on"
        );
        assert_eq!(of("-O"), "debug-assertions=off overflow-checks=off");
        assert_eq!(
            of("-C debug-assertions=on -C overflow-checks=no"),
            "debug-assertions=on overflow-checks=off"
        );
        // a call that compiles nothing is left as it is
        let probe = |line: &str| {
            let args: Vec<String> = line.split_whitespace().map(str::to_string).collect();
            unoptimised(&args)
        };
        assert!(probe("-vV").is_empty());
        assert!(probe("- --crate-name ___ --print=file-names").is_empty());
    }

    #[test]
    fn the_defining_crate_of_paths_impls_and_shims() {
        // core::fmt::write
        let d = |s: &str| defining_crate(s, &demangle(s));
        assert_eq!(d("_RNvNtCs1234_4core3fmt5write").as_deref(), Some("core"));
        assert_eq!(
            d("_RNvXs_NtCsabc_3age5errorNtB4_5ErrorNtNtCs1234_4core3fmt7Display3fmt").as_deref(),
            Some("age")
        );
        assert_eq!(
            trait_crate("<(u8, u8) as core::clone::Clone>::clone").as_deref(),
            Some("core")
        );
        assert_eq!(
            trait_crate(
                "<fn() -> std::process::ExitCode as core::ops::function::FnOnce<()>>::call_once"
            )
            .as_deref(),
            Some("core")
        );
        assert!(is_constructor("age::error::Error::Io"));
        assert!(is_constructor(
            "net::retry::{closure#0}::__PrivResult::<core::option::Option<u8>, ()>::_0"
        ));
        assert!(!is_constructor("net::retry::<u8>::{closure#0}"));
        assert!(is_constructor(
            "<s::Server<_, _>>::run::{closure#3}::__PrivResult::<core::result::Result<(), E>, ()>::_2"
        ));
        assert!(!is_constructor("<s::Server<_, _>>::run"));
        assert!(is_constructor("core::option::Option::Some::<u8>"));
        assert!(!is_constructor("<s::Server<_, _>>::run::<u8>"));
        assert!(!is_constructor("a::b::run::<u8>"));
        assert!(!is_constructor("<a::B as c::D<fn(u8) -> u8>>::e"));
        assert!(!is_constructor(
            "<age::error::Error as core::fmt::Display>::fmt"
        ));
        assert!(!is_constructor("age::decrypt"));
    }

    #[test]
    fn a_trait_objects_bindings_are_compared_in_one_order() {
        let c = |s: &str| canonical(&s.chars().collect::<Vec<_>>());
        let a = "<r::Router<Box<dyn s::Service<Req, Future = Pin<Box<dyn Future<Output = \
                 Result<Res, E>>>>, Error = E, Response = Res>>, Vec<G>>>::recognize_fn::<Req, \
                 fn(&Req) -> bool>";
        let b = "<r::Router<Box<dyn s::Service<Req, Response = Res, Error = E, Future = \
                 Pin<Box<dyn Future<Output = Result<Res, E>>>>>>, Vec<G>>>::recognize_fn::<Req, \
                 fn(&Req) -> bool>";
        assert_eq!(c(a), c(b));
        // (nothing else moves: positional arguments, a qualified path, a function type)
        let plain = "<(u8, u8) as core::ops::function::FnOnce<(A, B)>>::call_once::<fn() -> T>";
        assert_eq!(c(plain), plain);
        assert_ne!(c("f::<A, B>"), c("f::<B, A>"));
    }
}
