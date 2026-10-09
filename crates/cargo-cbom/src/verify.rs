//! `cargo cbom verify`: reopen every file a CBOM cites and check that the code at
//! `line`/`offset` names what `symbol` says was found. Independent of the driver's span
//! handling, so an off-by-one line or column fails.
//!
//! A code position must start a token (not inside an identifier, not after `::`), lie in code
//! (not in a comment or a literal), and begin a path (comments between its segments skipped, raw
//! identifiers read without `r#`) whose last segment is the symbol's name or an import alias of
//! it: from the file's `use` items, or from those of any file of its package or of the crate the
//! path goes through (`pub use ring::digest::digest as hash_it;` in `src/algs.rs`). Besides:
//! - the source line, and the text at the position, are those the context records
//!   (`line: `..``, `code: `..``), when it records them; only the leading `[..]` tags of the
//!   context are read as tags, never the recorded source text;
//! - one asset has one occurrence per (position, symbol), as the generator writes them;
//! - a `[component] .. part of X` occurrence is where X is, or on the line where X was merged
//!   into a more specific name;
//! - a path qualified by a type the source imports from a crate of the CBOM (`Hmac::<Sha256>::`)
//!   is evidence only of what that crate, or one it depends on, provides. Crate names are those
//!   the dependencies of the package owning the file have there (`cargo metadata`), so two
//!   versions of one crate, and renamed dependencies, are told apart;
//! - a `Cargo.toml` position is the start of a key (a quoted key at its opening quote; not in a
//!   comment or a string) in the table the context names, in the manifest of the package it
//!   names; a `Cargo.lock` position is the `name` line of the locked version the context names;
//!   lines are compared without the `\r` of a CRLF file;
//! - a standard-library location (`/rustc/<commit>/..`) names the pinned toolchain's commit.
//!
//! Known limits:
//! - `#[cfg(..)]` is not evaluated. A shifted position that lands on an identical line that the
//!   configuration removes (`#[cfg(any())] let d = Sha256::digest(data);` just above the same
//!   statement) is accepted by the self-test. The generator never cites such code (rustc does not
//!   compile it), so this weakens the self-test only, not the check of the CBOM's positions.
//! - Imports are read per file, not per scope. When a file binds a name to several crates
//!   (`use sha1::Sha1 as H;` in one module, `use sha2::Sha256 as H;` in another), any of them may
//!   provide the asset. When the name may be the program's own (a definition or a generic
//!   parameter in the file, a `crate::`/`self::`/`super::` import, a module, a glob import), the
//!   provider rule makes no check.
//! - Of a dependency key, the kind of table is checked, not which `[target.'cfg(..)'.*]` table it
//!   is in (the context does not record it), nor the features the context lists.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::rc::Rc;

use anyhow::Result;
use rcbom_kb::Kb;
use regex::Regex;
use serde_json::Value;

struct Occ {
    component: String,
    component_ref: String,
    location: String,
    line: usize,
    offset: usize,
    symbol: String,
    context: String,
}

macro_rules! re {
    ($s:expr) => {{
        static R: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| Regex::new($s).unwrap());
        &*R
    }};
}

/// What the CBOM says about packages: which assets each provides, and its dependencies.
struct Graph {
    /// bom-refs of the packages that are components of the CBOM
    packages: HashSet<String>,
    depends_on: HashMap<String, Vec<String>>,
    /// asset bom-ref -> package bom-refs providing it
    providers: HashMap<String, HashSet<String>>,
    /// asset bom-ref -> its algorithm family
    family: HashMap<String, String>,
}

impl Graph {
    fn closure(&self, r: &str) -> HashSet<String> {
        let mut seen = HashSet::new();
        let mut stack = vec![r.to_string()];
        while let Some(x) = stack.pop() {
            if !seen.insert(x.clone()) {
                continue;
            }
            for d in self.depends_on.get(&x).into_iter().flatten() {
                if d.starts_with("pkg:") {
                    stack.push(d.clone());
                }
            }
        }
        seen
    }
}

/// The crate names each package's code sees, from `cargo metadata`: package id -> crate
/// identifier -> bom-refs of the packages it names (its own library, its dependencies under
/// their extern names: `sha2_11 = { package = "sha2" }` is `sha2_11`).
type Externs = HashMap<String, HashMap<String, Vec<String>>>;

fn pkg_ref(name: &str, version: &str) -> String {
    format!("pkg:cargo/{name}@{version}")
}

fn load_externs(manifest_path: &Path, target: &str, features: &[String]) -> Option<Externs> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut cmd = Command::new(cargo);
    cmd.args([
        "metadata",
        "--format-version",
        "1",
        "--locked",
        "--filter-platform",
        target,
        "--manifest-path",
    ])
    .arg(manifest_path);
    if !features.is_empty() {
        cmd.arg("--features").arg(features.join(","));
    }
    let out = cmd.stderr(Stdio::null()).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let md: Value = serde_json::from_slice(&out.stdout).ok()?;
    let mut refs: HashMap<&str, String> = HashMap::new();
    let mut ext: Externs = HashMap::new();
    for p in md["packages"].as_array()? {
        let (Some(id), Some(n), Some(v)) =
            (p["id"].as_str(), p["name"].as_str(), p["version"].as_str())
        else {
            continue;
        };
        let r = pkg_ref(n, v);
        refs.insert(id, r.clone());
        // its own library, as its binaries name it
        let own = ext.entry(id.to_string()).or_default();
        for t in p["targets"].as_array().into_iter().flatten() {
            let lib = t["kind"].as_array().into_iter().flatten().any(|k| {
                matches!(
                    k.as_str(),
                    Some("lib" | "rlib" | "dylib" | "cdylib" | "staticlib" | "proc-macro")
                )
            });
            if lib && let Some(tn) = t["name"].as_str() {
                own.entry(tn.replace('-', "_")).or_default().push(r.clone());
            }
        }
    }
    for n in md["resolve"]["nodes"].as_array()? {
        let Some(id) = n["id"].as_str() else { continue };
        let m = ext.entry(id.to_string()).or_default();
        for d in n["deps"].as_array().into_iter().flatten() {
            if let (Some(name), Some(r)) = (
                d["name"].as_str(),
                d["pkg"].as_str().and_then(|p| refs.get(p)),
            ) {
                let v = m.entry(name.to_string()).or_default();
                if !v.contains(r) {
                    v.push(r.clone());
                }
            }
        }
    }
    Some(ext)
}

/// The pinned toolchain's sysroot and commit (`rustc -vV`).
fn toolchain() -> Option<(PathBuf, String)> {
    let sysroot = crate::sysroot().ok()?;
    let out = Command::new("rustc")
        .arg(format!("+{}", crate::TOOLCHAIN))
        .arg("-vV")
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let commit = text
        .lines()
        .find_map(|l| l.strip_prefix("commit-hash: "))?
        .trim()
        .to_string();
    Some((PathBuf::from(sysroot), commit))
}

pub fn run(cbom: &Path, manifest_path: &Path, self_test: bool) -> Result<()> {
    let doc: Value = serde_json::from_slice(&std::fs::read(cbom)?)?;
    let features: Vec<String> = doc["metadata"]["properties"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|p| p["name"] == "rcbom:run:features")
        .and_then(|p| p["value"].as_str())
        .map(|s| {
            s.split(',')
                .filter(|f| !f.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let kb = Kb::seed()?;
    let target = rcbom_manifest::host_triple()?;
    let man = rcbom_manifest::load_locked(manifest_path, &target, &features, &kb)?;
    let externs = load_externs(manifest_path, &target, &features);
    if externs.is_none() {
        eprintln!("verify: cargo metadata failed; crate names are resolved by package name");
    }
    let mut graph = Graph {
        packages: HashSet::new(),
        depends_on: HashMap::new(),
        providers: HashMap::new(),
        family: HashMap::new(),
    };
    for c in doc["components"].as_array().into_iter().flatten() {
        let Some(r) = c["bom-ref"].as_str() else {
            continue;
        };
        match c["type"].as_str() {
            Some("library" | "application" | "framework") => {
                graph.packages.insert(r.to_string());
            }
            Some("cryptographic-asset") => {
                // or the property for a family `algorithmFamily` cannot say (`TLS-PRF`)
                let prop = c["properties"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .find_map(|p| {
                        (p["name"] == "rcbom:algorithm-family")
                            .then(|| p["value"].as_str())
                            .flatten()
                    });
                if let Some(f) = c["cryptoProperties"]["algorithmProperties"]["algorithmFamily"]
                    .as_str()
                    .or(prop)
                {
                    graph.family.insert(r.to_string(), f.to_string());
                }
            }
            _ => {}
        }
    }
    for d in doc["dependencies"].as_array().into_iter().flatten() {
        let r = d["ref"].as_str().unwrap_or("").to_string();
        let on: Vec<String> = d["dependsOn"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|x| x.as_str().map(str::to_string))
            .collect();
        for a in d["provides"].as_array().into_iter().flatten() {
            if let Some(a) = a.as_str() {
                graph
                    .providers
                    .entry(a.to_string())
                    .or_default()
                    .insert(r.clone());
            }
        }
        graph.depends_on.insert(r, on);
    }
    let mut occs = Vec::new();
    let mut without_line = 0;
    for c in doc["components"].as_array().into_iter().flatten() {
        for o in c["evidence"]["occurrences"]
            .as_array()
            .into_iter()
            .flatten()
        {
            let (Some(line), Some(offset)) = (o["line"].as_u64(), o["offset"].as_u64()) else {
                without_line += 1;
                continue;
            };
            occs.push(Occ {
                component: c["name"].as_str().unwrap_or("").into(),
                component_ref: c["bom-ref"].as_str().unwrap_or("").into(),
                location: o["location"].as_str().unwrap_or("").into(),
                line: line as usize,
                offset: offset as usize,
                symbol: o["symbol"].as_str().unwrap_or("").into(),
                context: o["additionalContext"].as_str().unwrap_or("").into(),
            });
        }
    }
    let mut at_pos: HashMap<(String, usize, usize), Vec<usize>> = HashMap::new();
    let mut at_line: HashMap<(String, usize), Vec<usize>> = HashMap::new();
    for (i, o) in occs.iter().enumerate() {
        at_pos
            .entry((o.location.clone(), o.line, o.offset))
            .or_default()
            .push(i);
        at_line
            .entry((o.location.clone(), o.line))
            .or_default()
            .push(i);
    }
    let mut files = Files {
        man: &man,
        externs,
        toolchain: None,
        cache: HashMap::new(),
        pkg_binds: HashMap::new(),
        occs: &occs,
        at_pos,
        at_line,
        graph,
    };
    let mut bad = 0;
    let mut verified = vec![false; occs.len()];
    for (i, o) in occs.iter().enumerate() {
        match files.check(i, o.line, o.offset) {
            Ok(()) => verified[i] = true,
            Err(e) => {
                bad += 1;
                println!(
                    "MISMATCH {} {}:{}:{}: {e}",
                    o.component, o.location, o.line, o.offset
                );
            }
        }
    }
    println!(
        "{}: {} positions verified, {} mismatched, {} occurrences without a line",
        cbom.display(),
        occs.len() - bad,
        bad,
        without_line
    );
    if self_test {
        for (dl, dc, what) in [
            (1i64, 0i64, "line +1"),
            (-1, 0, "line -1"),
            (0, 1, "column +1"),
            (0, -1, "column -1"),
        ] {
            // only positions that verified: a mismatched one would count its shifts as caught
            let shifted: Vec<_> = (0..occs.len())
                .filter(|&i| verified[i])
                .filter_map(|i| {
                    let o = &occs[i];
                    let l = usize::try_from(o.line as i64 + dl)
                        .ok()
                        .filter(|&l| l >= 1)?;
                    let c = usize::try_from(o.offset as i64 + dc).ok()?;
                    Some((i, l, c))
                })
                .collect();
            let mut caught = 0;
            for &(i, l, c) in &shifted {
                if files.check(i, l, c).is_err() {
                    caught += 1;
                } else {
                    let o = &occs[i];
                    println!(
                        "ACCEPTED {what}: {} {}:{}:{} -> {}:{} symbol={}",
                        o.component, o.location, o.line, o.offset, l, c, o.symbol
                    );
                }
            }
            println!(
                "self-test {what}: {caught}/{} shifted positions rejected",
                shifted.len()
            );
        }
    }
    if bad > 0 {
        anyhow::bail!("{bad} positions do not match the source");
    }
    Ok(())
}

/// What a character of a Rust source is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Class {
    Code,
    Comment,
    /// a string or character literal
    Literal,
}

/// A name a `use` or `extern crate` item binds, and the path it imports (`use a::{b::c as d}`
/// binds `d` to `a::b::c`).
#[derive(Clone, Debug, PartialEq, Eq)]
struct Binding {
    name: String,
    path: Vec<String>,
}

struct Source {
    /// the lines, without the `\r` of a CRLF line end
    lines: Vec<String>,
    /// per line, per char
    class: Vec<Vec<Class>>,
    /// Rust: the names the file's `use` and `extern crate` items bind
    binds: Vec<Binding>,
    /// Rust: the names the file defines (types, traits, modules) or declares as generic
    /// parameters, which may shadow an import
    locals: HashSet<String>,
    /// `Cargo.toml`: its keys
    toml: Vec<TomlKey>,
}

impl Source {
    fn new(text: &str, rust: bool, toml: bool) -> Source {
        // a CRLF file: the `\r` is not part of the line
        let lines: Vec<String> = text
            .split('\n')
            .map(|l| l.strip_suffix('\r').unwrap_or(l).to_string())
            .collect();
        if !rust {
            return Source {
                class: lines
                    .iter()
                    .map(|l| vec![Class::Code; l.chars().count()])
                    .collect(),
                lines,
                binds: Vec::new(),
                locals: HashSet::new(),
                toml: if toml { toml_keys(text) } else { Vec::new() },
            };
        }
        let (mut class, code_text) = lex(text);
        for (c, l) in class.iter_mut().zip(&lines) {
            c.truncate(l.chars().count());
        }
        Source {
            lines,
            class,
            binds: bindings(&code_text),
            locals: locals(&code_text),
            toml: Vec::new(),
        }
    }
}

struct Files<'a> {
    man: &'a rcbom_manifest::Manifest,
    externs: Option<Externs>,
    /// The pinned toolchain's sysroot and commit, for `/rustc/<commit>/library/..` locations;
    /// read when first needed
    toolchain: Option<Option<(PathBuf, String)>>,
    cache: HashMap<PathBuf, Option<Rc<Source>>>,
    /// the `use` bindings of every Rust file of a package, by package directory
    pkg_binds: HashMap<PathBuf, Rc<Vec<Binding>>>,
    occs: &'a [Occ],
    at_pos: HashMap<(String, usize, usize), Vec<usize>>,
    at_line: HashMap<(String, usize), Vec<usize>>,
    graph: Graph,
}

fn strip_generics(s: &str) -> String {
    let re = re!(r"<[^<>]*>");
    let mut s = s.to_string();
    loop {
        let n = re.replace_all(&s, "").to_string();
        if n == s {
            return s;
        }
        s = n;
    }
}

fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Classifies each char of a Rust source: in a `//` or `/* */` comment (nested), in a string
/// literal (`"..."`, `b".."`, `c".."`, raw `r#".."#`) or a char literal, or code.
fn classify(text: &str) -> Vec<Class> {
    let chars: Vec<char> = text.chars().collect();
    let mut class = vec![Class::Code; chars.len()];
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        let prev_ident = i > 0 && is_ident(chars[i - 1]);
        if c == '/' && next == Some('/') {
            while i < chars.len() && chars[i] != '\n' {
                class[i] = Class::Comment;
                i += 1;
            }
        } else if c == '/' && next == Some('*') {
            let mut depth = 0;
            while i < chars.len() {
                if chars[i] == '/' && chars.get(i + 1) == Some(&'*') {
                    depth += 1;
                    class[i] = Class::Comment;
                    class[i + 1] = Class::Comment;
                    i += 2;
                } else if chars[i] == '*' && chars.get(i + 1) == Some(&'/') {
                    depth -= 1;
                    class[i] = Class::Comment;
                    class[i + 1] = Class::Comment;
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    class[i] = Class::Comment;
                    i += 1;
                }
            }
        } else if !prev_ident && (c == 'r' || ((c == 'b' || c == 'c') && next == Some('r'))) && {
            // raw string: r#*"
            let mut j = i + if c == 'r' { 1 } else { 2 };
            while chars.get(j) == Some(&'#') {
                j += 1;
            }
            chars.get(j) == Some(&'"')
        } {
            let mut j = i + if c == 'r' { 1 } else { 2 };
            let mut hashes = 0;
            while chars[j] == '#' {
                hashes += 1;
                j += 1;
            }
            j += 1; // opening quote
            loop {
                if j >= chars.len() {
                    break;
                }
                if chars[j] == '"' && (0..hashes).all(|k| chars.get(j + 1 + k) == Some(&'#')) {
                    j += 1 + hashes;
                    break;
                }
                j += 1;
            }
            for k in class.iter_mut().take(j.min(chars.len())).skip(i) {
                *k = Class::Literal;
            }
            i = j;
        } else if c == '"' {
            let mut j = i + 1;
            while j < chars.len() && chars[j] != '"' {
                if chars[j] == '\\' {
                    j += 1;
                }
                j += 1;
            }
            let end = (j + 1).min(chars.len());
            for k in class.iter_mut().take(end).skip(i) {
                *k = Class::Literal;
            }
            i = end;
        } else if c == '\'' {
            // char literal, or a lifetime / label (code)
            let end = if next == Some('\\') {
                // skip the backslash and the escaped char (`'\''`), then find the closing quote
                let mut j = i + 3;
                while j < chars.len() && chars[j] != '\'' && chars[j] != '\n' {
                    j += 1;
                }
                Some(j + 1)
            } else if next.is_some() && next != Some('\n') && chars.get(i + 2) == Some(&'\'') {
                Some(i + 3)
            } else {
                None
            };
            match end {
                Some(e) => {
                    let e = e.min(chars.len());
                    for k in class.iter_mut().take(e).skip(i) {
                        *k = Class::Literal;
                    }
                    i = e;
                }
                None => i += 1,
            }
        } else {
            i += 1;
        }
    }
    class
}

/// Per line, per char: the class of each char of a Rust source; and the file with comments and
/// literals blanked, for finding `use` items.
fn lex(text: &str) -> (Vec<Vec<Class>>, String) {
    let class = classify(text);
    let mut per_line = vec![Vec::new()];
    let mut blank = String::with_capacity(text.len());
    for (c, k) in text.chars().zip(class) {
        if c == '\n' {
            per_line.push(Vec::new());
            blank.push('\n');
        } else {
            per_line.last_mut().unwrap().push(k);
            blank.push(if k == Class::Code { c } else { ' ' });
        }
    }
    (per_line, blank)
}

/// Skips a balanced `<...>` starting at `i` (which must be `<`); `->` does not close, and
/// brackets in comments and literals do not count.
fn skip_angle(s: &[char], cls: &[Class], mut i: usize) -> Option<usize> {
    let mut depth = 0;
    while i < s.len() {
        if cls[i] == Class::Code {
            match s[i] {
                '<' => depth += 1,
                '>' if i > 0 && s[i - 1] == '-' => {}
                '>' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(i + 1);
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }
    None
}

/// Skips whitespace, line breaks and comments.
fn ws(s: &[char], cls: &[Class], mut i: usize) -> usize {
    while i < s.len() && (s[i].is_whitespace() || cls[i] == Class::Comment) {
        i += 1;
    }
    i
}

/// The path at the start of `at`: `(<T as Tr>::)? ::? (seg (::<..>)? ::)* last`, as its idents
/// (qualifiers first) and the final segment; raw identifiers (`r#digest`) without their `r#`.
/// Whitespace, line breaks and comments between tokens are allowed (rustfmt breaks long
/// turbofishes and qualified paths). None if `at` does not start with a path.
#[cfg(test)]
fn path_at(at: &str) -> Option<(Vec<String>, String)> {
    let s: Vec<char> = at.chars().collect();
    path_and_generics(&s, &classify(at)).map(|(q, l, _)| (q, l))
}

/// Like `path_at`, on chars and their classes, plus the first segment of every path written
/// inside the generic arguments (`Hmac::<sha2::Sha256>::new` gives `sha2`).
fn path_and_generics(s: &[char], cls: &[Class]) -> Option<(Vec<String>, String, Vec<String>)> {
    let mut generics: Vec<String> = Vec::new();
    let mut heads = |from: usize, to: usize| {
        let mut k = from;
        while k < to {
            if cls[k] != Class::Code || !is_ident(s[k]) || s[k].is_ascii_digit() {
                k += 1;
                continue;
            }
            let mut st = k;
            while k < to && cls[k] == Class::Code && is_ident(s[k]) {
                k += 1;
            }
            // `r#Type`
            if k - st == 1 && s[st] == 'r' && s.get(k) == Some(&'#') {
                st = k + 1;
                k = st;
                while k < to && cls[k] == Class::Code && is_ident(s[k]) {
                    k += 1;
                }
                if k == st {
                    continue;
                }
            }
            // the code chars before: not after `::` (a later segment) or `'` (a lifetime)
            let mut before = Vec::new();
            let mut b = st;
            while b > from && before.len() < 2 {
                b -= 1;
                if cls[b] == Class::Code && !s[b].is_whitespace() {
                    before.push(s[b]);
                } else if cls[b] == Class::Literal {
                    break;
                }
            }
            if before != [':', ':'] && before.first() != Some(&'\'') {
                generics.push(s[st..k].iter().collect());
            }
        }
    };
    let colons = |i: usize| {
        s.get(i) == Some(&':')
            && s.get(i + 1) == Some(&':')
            && cls[i] == Class::Code
            && cls[i + 1] == Class::Code
    };
    let ident_at = |i: usize| s.get(i).is_some_and(|&c| is_ident(c)) && cls[i] == Class::Code;
    // a segment: an identifier, or a raw identifier; its name and end
    let segment = |i: usize| -> Option<(String, usize)> {
        let start = if s.get(i) == Some(&'r') && s.get(i + 1) == Some(&'#') && ident_at(i + 2) {
            i + 2
        } else {
            i
        };
        let mut e = start;
        while ident_at(e) {
            e += 1;
        }
        (e > start).then(|| (s[start..e].iter().collect(), e))
    };
    let mut i = 0;
    if s.first() == Some(&'<') {
        let close = skip_angle(s, cls, 0)?;
        heads(1, close - 1);
        i = ws(s, cls, close);
        if !colons(i) {
            return None;
        }
        i = ws(s, cls, i + 2);
    } else if colons(0) {
        // `::sha2::Sha256`: a crate named from the root
        i = ws(s, cls, 2);
    }
    let mut segs = Vec::new();
    loop {
        let (seg, end) = segment(i)?;
        segs.push(seg);
        // `::<..>` turbofish
        let mut j = ws(s, cls, end);
        if colons(j) && s.get(ws(s, cls, j + 2)) == Some(&'<') {
            let open = ws(s, cls, j + 2);
            let close = skip_angle(s, cls, open)?;
            heads(open + 1, close - 1);
            j = ws(s, cls, close);
        }
        if colons(j) && segment(ws(s, cls, j + 2)).is_some() {
            i = ws(s, cls, j + 2);
            continue;
        }
        let last = segs.pop().unwrap();
        return Some((segs, last, generics));
    }
}

/// Whether a token starts at `col` of `line` (1-based): not inside an identifier (nor after the
/// `r#` of a raw identifier), and not after `::`, with whitespace and comments in between: a
/// path is cited at its first segment. A single `:` (`W { n:Sha256::digest(d) }`) does not
/// continue a path.
fn token_start(src: &Source, line: usize, col: usize) -> bool {
    let Some(text) = src.lines.get(line.wrapping_sub(1)) else {
        return false;
    };
    let chars: Vec<char> = text.chars().collect();
    let before = |k: usize| col.checked_sub(k).and_then(|i| chars.get(i)).copied();
    if before(1).is_some_and(is_ident) {
        return false;
    }
    if before(1) == Some('#') && before(2) == Some('r') && !before(3).is_some_and(is_ident) {
        return false;
    }
    // the two code (or literal) chars before, whitespace and comments skipped, over a few lines
    let mut prev = Vec::new();
    let (mut l, mut c) = (line - 1, col.min(chars.len()));
    loop {
        let lc: Vec<char> = src.lines[l].chars().collect();
        while c > 0 && prev.len() < 2 {
            c -= 1;
            let comment = src.class[l].get(c) == Some(&Class::Comment);
            if !comment && !lc[c].is_whitespace() {
                prev.push(lc[c]);
            }
        }
        if prev.len() == 2 || l == 0 || line - 1 - l >= 8 {
            break;
        }
        l -= 1;
        c = src.lines[l].chars().count();
    }
    prev != [':', ':']
}

/// The parts of an occurrence's context: the leading `[..]` tags, the details, and the source
/// line and text the generator recorded last.
struct Ctx<'a> {
    tags: &'a str,
    details: &'a str,
    line: Option<&'a str>,
    code: Option<&'a str>,
}

/// Reads a context back: the code text first, as the backquoted text at the very end; the line
/// is then what remains between `line: `` and the last backquote (it may hold backquotes).
fn split_context(ctx: &str) -> Ctx<'_> {
    let tags = re!(r"^(?:\[[^\[\]]*\] ?)*")
        .find(ctx)
        .map_or("", |m| m.as_str());
    let (before_code, code) = match re!(r"; code: `([^`]*)`$").captures(ctx) {
        Some(m) => (
            &ctx[..m.get(0).map_or(0, |g| g.start())],
            m.get(1).map(|g| g.as_str()),
        ),
        None => (ctx, None),
    };
    let (details, line) = match re!(r"; line: `(.*)`$").captures(before_code) {
        Some(m) => (
            &before_code[..m.get(0).map_or(0, |g| g.start())],
            m.get(1).map(|g| g.as_str()),
        ),
        None => (before_code, None),
    };
    Ctx {
        tags,
        details,
        line,
        code,
    }
}

/// Whether `name` is a more specific name `parent` was merged into on a line (the generator
/// merges `PBKDF2-SHA-256` into `PBKDF2-SHA-256-1000-32`, and the family name `Argon2` into
/// `Argon2id-19456-2-1`): strictly longer, at a `-` boundary, or extending the family name it
/// belongs to.
fn extends(name: &str, parent: &str, family: Option<&str>) -> bool {
    name.len() > parent.len()
        && name.starts_with(parent)
        && (name[parent.len()..].starts_with('-') || family == Some(parent))
}

/// A `Cargo.lock` position: the `name = "<symbol>"` line, at column 0, whose next line is the
/// version the context names (`locked sha2 0.10.9; ..`): two locked versions are told apart.
fn check_lock(
    lines: &[String],
    line: usize,
    offset: usize,
    symbol: &str,
    context: &str,
) -> Result<(), String> {
    let m = re!(r"^\[manifest\] locked (\S+) (\S+);")
        .captures(context)
        .ok_or("a Cargo.lock occurrence whose context names no locked package")?;
    if &m[1] != symbol {
        return Err(format!("the context names {}, the symbol {symbol}", &m[1]));
    }
    let text = lines.get(line.wrapping_sub(1)).ok_or("line out of range")?;
    let want = format!("name = \"{symbol}\"");
    let version = format!("version = \"{}\"", &m[2]);
    if offset == 0 && *text == want && lines.get(line).is_some_and(|l| *l == version) {
        Ok(())
    } else {
        Err(format!(
            "expected `{want}` at column 0, then `{version}`, in {text:?}"
        ))
    }
}

/// A key segment of a TOML document: where it starts (1-based line, 0-based char column; a
/// quoted key at its opening quote), the full path of keys it ends (table header and dotted
/// prefix included), and, for the last key of a key/value pair, its value if a string.
#[derive(Clone, Debug, PartialEq, Eq)]
struct TomlKey {
    line: usize,
    col: usize,
    path: Vec<String>,
    value: Option<String>,
}

/// Enough of a TOML lexer to know comments, strings, table headers and keys.
struct Toml {
    s: Vec<char>,
    i: usize,
    line: usize,
    col: usize,
    keys: Vec<TomlKey>,
}

/// Every key of a TOML document, with where it starts and its full path.
fn toml_keys(text: &str) -> Vec<TomlKey> {
    let mut t = Toml {
        s: text.chars().collect(),
        i: 0,
        line: 1,
        col: 0,
        keys: Vec::new(),
    };
    if t.peek(0) == Some('\u{feff}') {
        t.bump();
    }
    t.document();
    t.keys
}

impl Toml {
    fn peek(&self, k: usize) -> Option<char> {
        self.s.get(self.i + k).copied()
    }

    fn bump(&mut self) {
        if let Some(c) = self.peek(0) {
            if c == '\n' {
                self.line += 1;
                self.col = 0;
            } else {
                self.col += 1;
            }
            self.i += 1;
        }
    }

    fn eat(&mut self, c: char) -> bool {
        let ok = self.peek(0) == Some(c);
        if ok {
            self.bump();
        }
        ok
    }

    /// spaces and tabs
    fn blank(&mut self) {
        while matches!(self.peek(0), Some(' ' | '\t')) {
            self.bump();
        }
    }

    /// whitespace, line breaks and comments
    fn skip(&mut self) {
        loop {
            match self.peek(0) {
                Some(' ' | '\t' | '\r' | '\n') => self.bump(),
                Some('#') => self.rest_of_line(),
                _ => return,
            }
        }
    }

    fn rest_of_line(&mut self) {
        while self.peek(0).is_some_and(|c| c != '\n') {
            self.bump();
        }
    }

    fn triple(&self, q: char) -> bool {
        (0..3).all(|k| self.peek(k) == Some(q))
    }

    /// A basic (`"`) or literal (`'`) string at the cursor; its text if it is on one line.
    fn string(&mut self) -> Option<String> {
        let q = self.peek(0)?;
        if self.triple(q) {
            (0..3).for_each(|_| self.bump());
            loop {
                match self.peek(0) {
                    None => return None,
                    Some('\\') if q == '"' => {
                        self.bump();
                        self.bump();
                    }
                    Some(c) if c == q && self.triple(q) => {
                        (0..3).for_each(|_| self.bump());
                        // up to two more quotes end the content
                        for _ in 0..2 {
                            self.eat(q);
                        }
                        return None;
                    }
                    _ => self.bump(),
                }
            }
        }
        self.bump();
        let mut out = String::new();
        loop {
            match self.peek(0) {
                None | Some('\n') => return None,
                Some(c) if c == q => {
                    self.bump();
                    return Some(out);
                }
                Some('\\') if q == '"' => {
                    self.bump();
                    let e = self.peek(0)?;
                    self.bump();
                    match e {
                        'n' => out.push('\n'),
                        't' => out.push('\t'),
                        'r' => out.push('\r'),
                        'b' => out.push('\u{8}'),
                        'f' => out.push('\u{c}'),
                        'e' => out.push('\u{1b}'),
                        '"' | '\\' => out.push(e),
                        'x' | 'u' | 'U' => {
                            let n = match e {
                                'x' => 2,
                                'u' => 4,
                                _ => 8,
                            };
                            let mut h = String::new();
                            for _ in 0..n {
                                h.push(self.peek(0)?);
                                self.bump();
                            }
                            out.push(char::from_u32(u32::from_str_radix(&h, 16).ok()?)?);
                        }
                        _ => return None,
                    }
                }
                Some(c) => {
                    out.push(c);
                    self.bump();
                }
            }
        }
    }

    /// One segment of a key, bare (`A-Za-z0-9_-`) or quoted, and where it starts.
    fn segment(&mut self) -> Option<(usize, usize, String)> {
        let (line, col) = (self.line, self.col);
        match self.peek(0)? {
            q @ ('"' | '\'') if !self.triple(q) => Some((line, col, self.string()?)),
            c if c.is_ascii_alphanumeric() || c == '_' || c == '-' => {
                let mut s = String::new();
                while let Some(c) = self
                    .peek(0)
                    .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
                {
                    s.push(c);
                    self.bump();
                }
                Some((line, col, s))
            }
            _ => None,
        }
    }

    /// A dotted key; blanks around the dots.
    fn key(&mut self) -> Option<Vec<(usize, usize, String)>> {
        let mut segs = vec![self.segment()?];
        loop {
            self.blank();
            if !self.eat('.') {
                return Some(segs);
            }
            self.blank();
            segs.push(self.segment()?);
        }
    }

    fn record(&mut self, prefix: &[String], segs: &[(usize, usize, String)]) -> Vec<String> {
        let mut path = prefix.to_vec();
        for (line, col, s) in segs {
            path.push(s.clone());
            self.keys.push(TomlKey {
                line: *line,
                col: *col,
                path: path.clone(),
                value: None,
            });
        }
        path
    }

    fn document(&mut self) {
        let mut table: Vec<String> = Vec::new();
        loop {
            self.skip();
            let at = self.i;
            match self.peek(0) {
                None => return,
                Some('[') => {
                    self.bump();
                    let array = self.eat('[');
                    self.blank();
                    // what follows a malformed header belongs to no table of interest
                    table = vec!["<malformed>".into()];
                    if let Some(segs) = self.key() {
                        let path = self.record(&[], &segs);
                        self.blank();
                        if self.eat(']') && (!array || self.eat(']')) {
                            table = path;
                        }
                    }
                    self.rest_of_line();
                }
                Some(_) => {
                    if !self.keyval(&table) {
                        self.rest_of_line();
                    }
                }
            }
            if self.i == at {
                self.bump();
            }
        }
    }

    fn keyval(&mut self, prefix: &[String]) -> bool {
        let Some(segs) = self.key() else {
            return false;
        };
        let path = self.record(prefix, &segs);
        let k = self.keys.len() - 1;
        self.blank();
        if !self.eat('=') {
            return false;
        }
        self.blank();
        self.keys[k].value = self.value(&path);
        true
    }

    fn value(&mut self, path: &[String]) -> Option<String> {
        match self.peek(0)? {
            '"' | '\'' => self.string(),
            '[' => {
                self.bump();
                // the elements' keys are not keys of the table
                let mut inner = path.to_vec();
                inner.push("[]".into());
                loop {
                    self.skip();
                    match self.peek(0) {
                        None => break,
                        Some(']') => {
                            self.bump();
                            break;
                        }
                        Some(',') => self.bump(),
                        Some(_) => {
                            let at = self.i;
                            self.value(&inner);
                            if self.i == at {
                                self.bump();
                            }
                        }
                    }
                }
                None
            }
            '{' => {
                self.bump();
                loop {
                    self.skip();
                    match self.peek(0) {
                        None => break,
                        Some('}') => {
                            self.bump();
                            break;
                        }
                        Some(',') => self.bump(),
                        Some(_) => {
                            let at = self.i;
                            if !self.keyval(path) && self.i == at {
                                self.bump();
                            }
                        }
                    }
                }
                None
            }
            _ => {
                while self
                    .peek(0)
                    .is_some_and(|c| !matches!(c, ',' | ']' | '}' | '#' | '\n'))
                {
                    self.bump();
                }
                None
            }
        }
    }
}

/// A `Cargo.toml` position: the start of a key (a quoted key at its opening quote, as the
/// generator writes it) whose last segment is the symbol, and:
/// - `declared by P (K)`: a dependency key in `[K]` (`[K] sym = ..`, `[K.sym]`, `K.sym = ..`,
///   `sym.version = ..`) or `[target.<platform>.K]`, in the manifest of package P;
/// - `native library `L``: the `links` key of `[package]`, with value L.
fn check_toml(
    keys: &[TomlKey],
    text: &str,
    line: usize,
    offset: usize,
    symbol: &str,
    context: &str,
) -> Result<(), String> {
    let k = keys
        .iter()
        .find(|k| k.line == line && k.col == offset)
        .ok_or_else(|| format!("no key of `{symbol}` starts at this position in {text:?}"))?;
    let path: Vec<&str> = k.path.iter().map(String::as_str).collect();
    let dotted = path.join(".");
    if path.last() != Some(&symbol) {
        return Err(format!("the key here is `{dotted}`, not `{symbol}`"));
    }
    if let Some(m) = re!(r"^\[manifest\] declared by (\S+) \(([\w-]+)\)(?:;|$)").captures(context) {
        let (pkg, kind) = (&m[1], &m[2]);
        let in_table = match path.as_slice() {
            [t, _] | ["target", _, t, _] => *t == kind,
            _ => false,
        };
        if !in_table {
            return Err(format!(
                "the key here is `{dotted}`, not in [{kind}] or [target.<platform>.{kind}]"
            ));
        }
        let name = keys
            .iter()
            .find(|k| k.path == ["package", "name"])
            .and_then(|k| k.value.as_deref());
        if name != Some(pkg) {
            return Err(format!(
                "this is the manifest of {}, not of {pkg}",
                name.unwrap_or("no package")
            ));
        }
        Ok(())
    } else if let Some(m) = re!(r"^\[manifest\] native library `([^`]*)`").captures(context) {
        if path != ["package", "links"] || k.value.as_deref() != Some(&m[1]) {
            return Err(format!(
                "expected `links = \"{}\"` in [package], found `{dotted}`",
                &m[1]
            ));
        }
        Ok(())
    } else {
        Err(format!("unrecognized manifest context {context:?}"))
    }
}

/// Every name the `use` and `extern crate` items of a source bind (comments and literals
/// blanked: `as` renames there, not in casts).
fn bindings(code_text: &str) -> Vec<Binding> {
    re!(r"(?s)\b(?:use|extern\s+crate)\s[^;]*;")
        .find_iter(code_text)
        .flat_map(|m| use_bindings(m.as_str()))
        .collect()
}

/// The names one item binds: `use a::{b::c as d, e, f::*};` binds `d` (to `a::b::c`) and `e`
/// (to `a::e`); `extern crate x as y;` binds `y` to `x`. `as _` and globs bind no name.
fn use_bindings(item: &str) -> Vec<Binding> {
    let s: Vec<char> = item.chars().collect();
    let mut toks: Vec<String> = Vec::new();
    let mut i = 0;
    while i < s.len() {
        let c = s[i];
        if c.is_whitespace() {
            i += 1;
        } else if c == ':' && s.get(i + 1) == Some(&':') {
            toks.push("::".into());
            i += 2;
        } else if is_ident(c) || c == '$' {
            let st = if c == 'r' && s.get(i + 1) == Some(&'#') {
                i + 2
            } else {
                i
            };
            let mut e = st.max(i + 1);
            while e < s.len() && is_ident(s[e]) {
                e += 1;
            }
            toks.push(s[st..e].iter().collect());
            i = e;
        } else {
            toks.push(c.to_string());
            i += 1;
        }
    }
    let mut out = Vec::new();
    let t = |k: usize| toks.get(k).map_or("", String::as_str);
    if t(0) == "extern" && t(1) == "crate" {
        let name = if t(3) == "as" { t(4) } else { t(2) };
        if !name.is_empty() && name != "_" {
            out.push(Binding {
                name: name.into(),
                path: vec![t(2).into()],
            });
        }
        return out;
    }
    if t(0) == "use" {
        let mut k = 1;
        use_tree(&toks, &mut k, &mut Vec::new(), &mut out);
    }
    out
}

fn use_tree(toks: &[String], k: &mut usize, prefix: &mut Vec<String>, out: &mut Vec<Binding>) {
    let start = prefix.len();
    let t = |k: usize| toks.get(k).map_or("", String::as_str);
    if t(*k) == "::" {
        *k += 1;
    }
    loop {
        match t(*k) {
            "{" => {
                *k += 1;
                loop {
                    if t(*k) == "}" {
                        *k += 1;
                        break;
                    }
                    let at = *k;
                    use_tree(toks, k, prefix, out);
                    if t(*k) == "," {
                        *k += 1;
                    } else if t(*k) == "}" {
                        *k += 1;
                        break;
                    } else if *k == at || *k >= toks.len() {
                        break;
                    }
                }
                break;
            }
            "*" => {
                *k += 1;
                break;
            }
            id if id.chars().next().is_some_and(|c| is_ident(c) || c == '$') => {
                prefix.push(id.to_string());
                *k += 1;
                if t(*k) == "::" {
                    *k += 1;
                    continue;
                }
                // `a::b::{self}` binds `b`
                let mut path = prefix.clone();
                if path.last().is_some_and(|l| l == "self") && path.len() > 1 {
                    path.pop();
                }
                let name = if t(*k) == "as" {
                    *k += 2;
                    t(*k - 1).to_string()
                } else {
                    path.last().cloned().unwrap_or_default()
                };
                if !name.is_empty() && name != "_" {
                    out.push(Binding { name, path });
                }
                break;
            }
            _ => break,
        }
    }
    prefix.truncate(start);
}

/// The names a source defines as types, traits or modules, or declares as generic parameters
/// (`fn f<D: Digest>`, `impl<T>`): such a name may shadow an import.
fn locals(code_text: &str) -> HashSet<String> {
    let mut out: HashSet<String> = re!(r"\b(?:struct|enum|union|type|trait|mod)\s+(?:r#)?(\w+)")
        .captures_iter(code_text)
        .map(|c| c[1].to_string())
        .collect();
    for m in
        re!(r"\b(?:(?:fn|struct|enum|union|trait|type)\s+(?:r#)?\w+|impl)\s*<").find_iter(code_text)
    {
        let s: Vec<char> = code_text[m.end() - 1..].chars().take(4000).collect();
        let cls = vec![Class::Code; s.len()];
        let Some(end) = skip_angle(&s, &cls, 0) else {
            continue;
        };
        // the parameters, split at top-level commas
        let mut depth = 0i32;
        let mut params = vec![String::new()];
        for k in 1..end - 1 {
            match s[k] {
                '<' | '(' | '[' => depth += 1,
                '>' if s[k - 1] != '-' => depth -= 1,
                ')' | ']' => depth -= 1,
                ',' if depth == 0 => {
                    params.push(String::new());
                    continue;
                }
                _ => {}
            }
            params.last_mut().unwrap().push(s[k]);
        }
        for p in params {
            let p = p.trim();
            let p = p.strip_prefix("const ").unwrap_or(p).trim_start();
            let name: String = p.chars().take_while(|&c| is_ident(c)).collect();
            if !name.is_empty() {
                out.insert(name);
            }
        }
    }
    out
}

/// The first segments of the paths the imports bind `name` to (`use sha2::Sha256 as H;` gives
/// `sha2` for `H`; two imports of `H` from different crates give both), or `name` itself when
/// no import binds it. None when an import is relative to this crate (`crate::`, `self::`,
/// `super::`).
fn import_roots(binds: &[Binding], name: &str) -> Option<BTreeSet<String>> {
    let mut roots = BTreeSet::new();
    for b in binds.iter().filter(|b| b.name == name) {
        let head = b.path.first()?;
        if matches!(
            head.as_str(),
            "crate" | "self" | "super" | "Self" | "$crate"
        ) {
            return None;
        }
        roots.insert(head.clone());
    }
    if roots.is_empty() {
        roots.insert(name.to_string());
    }
    Some(roots)
}

/// The import aliases of `ident` (`use scrypt::scrypt as scrypt_inner;`).
fn aliases<'b>(binds: &'b [Binding], ident: &'b str) -> impl Iterator<Item = &'b String> + 'b {
    binds
        .iter()
        .filter(move |b| b.path.last().is_some_and(|l| l == ident) && b.name != ident)
        .map(|b| &b.name)
}

/// Every Rust file under a package's directory, not in `target/`, a hidden directory or
/// another package's directory.
fn package_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd.flatten() {
            let p = e.path();
            let name = e.file_name().to_string_lossy().to_string();
            let Ok(ft) = e.file_type() else {
                continue;
            };
            if ft.is_dir() {
                if name != "target" && !name.starts_with('.') && !p.join("Cargo.toml").exists() {
                    stack.push(p);
                }
            } else if name.ends_with(".rs") {
                out.push(p);
            }
        }
    }
    out
}

impl Files<'_> {
    fn source(&mut self, path: &Path) -> Option<Rc<Source>> {
        self.cache
            .entry(path.to_path_buf())
            .or_insert_with(|| {
                let mut t = std::fs::read_to_string(path).ok()?;
                let rust = path.extension().is_some_and(|e| e == "rs");
                // rustc drops a byte-order mark before counting columns
                if rust && t.starts_with('\u{feff}') {
                    t.remove(0);
                }
                let toml = path.file_name().is_some_and(|n| n == "Cargo.toml");
                Some(Rc::new(Source::new(&t, rust, toml)))
            })
            .clone()
    }

    /// The `use` bindings of every Rust file of the package in `dir`: an alias may be defined
    /// in one file (`pub use ring::digest::digest as hash_it;` in `src/algs.rs`) and used in
    /// another.
    fn package_binds(&mut self, dir: &Path) -> Rc<Vec<Binding>> {
        if let Some(b) = self.pkg_binds.get(dir) {
            return b.clone();
        }
        let mut out = Vec::new();
        for f in package_files(dir) {
            if let Ok(t) = std::fs::read_to_string(&f)
                && t.contains(" as ")
            {
                out.extend(bindings(&lex(&t).1));
            }
        }
        let b = Rc::new(out);
        self.pkg_binds.insert(dir.to_path_buf(), b.clone());
        b
    }

    /// A location's file. The standard library's sources are named as rustc names them
    /// (`/rustc/<commit>/library/core/src/ops/function.rs`); they are read from the pinned
    /// toolchain's rust-src component (`<sysroot>/lib/rustlib/src/rust/library/..`), and the
    /// commit must be that toolchain's.
    fn resolve(&mut self, location: &str) -> Result<PathBuf, String> {
        let Some(rest) = location.strip_prefix("/rustc/") else {
            return Ok(self.man.resolve(location));
        };
        let (commit, rest) = rest
            .split_once('/')
            .ok_or_else(|| format!("no commit in {location}"))?;
        let Some((sysroot, pinned)) = self.toolchain.get_or_insert_with(toolchain).clone() else {
            return Err(format!(
                "toolchain {} not available to read {location}",
                crate::TOOLCHAIN
            ));
        };
        if commit != pinned {
            return Err(format!(
                "rustc commit {commit} cited, but the pinned toolchain {} is commit {pinned}",
                crate::TOOLCHAIN
            ));
        }
        Ok(sysroot.join("lib/rustlib/src/rust").join(rest))
    }

    /// The bom-refs of the packages a crate identifier names in the code of package `owner`
    /// (by package id): one of its dependencies under its extern name, or its own library.
    /// Without `cargo metadata`, or for a file of no package, every package of that name.
    fn crate_refs(&self, owner: Option<&str>, ident: &str) -> Vec<String> {
        if let (Some(ext), Some(id)) = (&self.externs, owner)
            && let Some(m) = ext.get(id)
        {
            return m.get(ident).cloned().unwrap_or_default();
        }
        self.man
            .packages
            .iter()
            .filter(|p| p.name.replace('-', "_") == ident)
            .map(|p| pkg_ref(&p.name, &p.version.to_string()))
            .collect()
    }

    /// The packages of the CBOM a name in this file can come from: the crates its imports name
    /// (any of them, when it imports the name from several), or the crate of that name. None
    /// when the name may be the program's own (a definition or generic parameter in the file,
    /// an import relative to this crate or from one of its modules) or a crate outside the CBOM.
    fn origins(&self, src: &Source, owner: Option<&str>, name: &str) -> Option<Vec<String>> {
        if src.locals.contains(name) {
            return None;
        }
        let mut out = Vec::new();
        for r in import_roots(&src.binds, name)? {
            let refs: Vec<String> = self
                .crate_refs(owner, &r)
                .into_iter()
                .filter(|p| self.graph.packages.contains(p))
                .collect();
            if refs.is_empty() {
                return None;
            }
            out.extend(refs);
        }
        Some(out)
    }

    fn check(&mut self, oi: usize, line: usize, offset: usize) -> Result<(), String> {
        let occs = self.occs;
        let man = self.man;
        let o = &occs[oi];
        let path = self.resolve(&o.location)?;
        let src = self
            .source(&path)
            .ok_or_else(|| format!("cannot read {}", path.display()))?;
        let text = src
            .lines
            .get(line.wrapping_sub(1))
            .ok_or("line out of range")?
            .clone();
        let chars: Vec<char> = text.chars().collect();
        if offset > chars.len() {
            return Err("offset past end of line".into());
        }
        let at: String = chars[offset..].iter().collect();

        // one occurrence per asset, position and symbol (the generator deduplicates by it): a
        // shifted position that lands on another occurrence of the same name is caught here
        if self
            .at_pos
            .get(&(o.location.clone(), line, offset))
            .into_iter()
            .flatten()
            .any(|&j| {
                j != oi && occs[j].component_ref == o.component_ref && occs[j].symbol == o.symbol
            })
        {
            return Err(
                "another occurrence of the same asset and symbol is at this position".into(),
            );
        }

        if o.context.starts_with("[manifest]") {
            let file = o.location.rsplit('/').next().unwrap_or("");
            return match file {
                "Cargo.lock" => check_lock(&src.lines, line, offset, &o.symbol, &o.context),
                "Cargo.toml" => check_toml(&src.toml, &text, line, offset, &o.symbol, &o.context),
                _ => Err("a manifest occurrence outside Cargo.toml and Cargo.lock".into()),
            };
        }
        let starts_token = token_start(&src, line, offset);
        // code positions are in code, not in a comment or a literal
        if src.class[line - 1].get(offset) != Some(&Class::Code) {
            return Err(format!("position inside a comment or literal in {text:?}"));
        }
        // the generator recorded the source line and the exact text it found at the position,
        // last in the context, in that order; the line may hold backquotes, the text does not
        let ctx = split_context(&o.context);
        if let Some(l) = ctx.line
            && text.trim() != l
        {
            return Err(format!("expected the line `{l}`, found {text:?}"));
        }
        if let Some(code) = ctx.code
            && !at.starts_with(code)
        {
            return Err(format!("expected `{code}` in {text:?}"));
        }
        // the macro tags are among the leading tags, never in the recorded source text
        if let Some(m) = re!(r"\[macro ([\w:]+!)\]").captures(ctx.tags) {
            let name = &m[1];
            let ok = Regex::new(&format!(r"^(?:\w+::)*{}", regex::escape(name)))
                .unwrap()
                .is_match(&at);
            return if ok && starts_token {
                Ok(())
            } else {
                Err(format!("expected `{name}` in {text:?}"))
            };
        }
        // derive: the position is the derive's name inside `#[derive(..)]`
        if let Some(m) = re!(r"\[derive ([\w:]+)\]").captures(ctx.tags) {
            let name = m[1].rsplit("::").next().unwrap_or(&m[1]).to_string();
            let ok = Regex::new(&format!(r"^(?:\w+::)*{}\b", regex::escape(&name)))
                .unwrap()
                .is_match(&at);
            return if ok && starts_token {
                Ok(())
            } else {
                Err(format!("expected derive `{name}` in {text:?}"))
            };
        }
        // attribute macro: the position is the attribute
        if let Some(m) = re!(r"\[attribute ([\w:]+)\]").captures(ctx.tags) {
            let name = m[1].rsplit("::").next().unwrap_or(&m[1]).to_string();
            let ok = Regex::new(&format!(r"^#!?\[\s*(?:\w+::)*{}\b", regex::escape(&name)))
                .unwrap()
                .is_match(&at);
            return if at.starts_with('#') && ok && starts_token {
                Ok(())
            } else {
                Err(format!("expected an attribute in {text:?}"))
            };
        }
        // code: the callee or static, by name or by an import alias of it
        let ident = strip_generics(&o.symbol)
            .trim_end_matches(':')
            .rsplit("::")
            .next()
            .unwrap_or("")
            .to_string();
        if ident.is_empty() {
            return Err("no identifier in symbol".into());
        }
        // the path, from the position on over the next lines (rustfmt breaks long paths);
        // generic arguments balanced, so it cannot run on into the next expression
        let (rs, rc) = rest(&src, line, offset);
        let parsed = path_and_generics(&rs, &rc);
        let owner = man.owner_of(&path);
        let owner_id = owner.map(|p| p.id.repr.clone());
        let mut ok = parsed.as_ref().is_some_and(|(_, last, _)| {
            *last == ident || aliases(&src.binds, &ident).any(|a| a == last)
        });
        // an alias another file defines: of this package, or of the crate the path goes
        // through (`mylib::hash_it` for `pub use ring::digest::digest as hash_it;` in mylib)
        if !ok
            && starts_token
            && let Some((quals, last, _)) = &parsed
        {
            let mut dirs: Vec<PathBuf> =
                owner.map(|p| p.manifest_dir.clone()).into_iter().collect();
            for root in import_roots(&src.binds, quals.first().unwrap_or(last))
                .into_iter()
                .flatten()
            {
                for r in self.crate_refs(owner_id.as_deref(), &root) {
                    let pkg = r
                        .strip_prefix("pkg:cargo/")
                        .and_then(|nv| nv.split_once('@'))
                        .and_then(|(n, v)| man.by_name_version(n, v));
                    if let Some(p) = pkg
                        && !dirs.contains(&p.manifest_dir)
                    {
                        dirs.push(p.manifest_dir.clone());
                    }
                }
            }
            for d in dirs {
                if aliases(&self.package_binds(&d), &ident).any(|a| a == last) {
                    ok = true;
                    break;
                }
            }
        }
        if !(ok && starts_token) {
            return Err(format!("expected `{ident}` in {text:?}"));
        }
        let kind = re!(r"^\[\w+\] \[([\w-]+)\]")
            .captures(ctx.tags)
            .map(|m| m[1].to_string())
            .unwrap_or_default();
        // a component is used where the asset it is part of is used
        if kind == "component"
            && let Some(m) = re!(r"; part of ([^\s;(]+)").captures(ctx.details)
        {
            let parent = &m[1];
            let here = self
                .at_pos
                .get(&(o.location.clone(), line, offset))
                .into_iter()
                .flatten()
                .any(|&j| j != oi && occs[j].component == parent);
            // a parent merged into a more specific name on the same line (Argon2 ->
            // Argon2id-19456-2-1) keeps the line, not necessarily the column
            let merged = self
                .at_line
                .get(&(o.location.clone(), line))
                .into_iter()
                .flatten()
                .any(|&j| {
                    j != oi
                        && extends(
                            &occs[j].component,
                            parent,
                            self.graph
                                .family
                                .get(&occs[j].component_ref)
                                .map(String::as_str),
                        )
                });
            if !(here || merged) {
                return Err(format!("`{parent}`, which this is part of, is not here"));
            }
        }
        // a qualifier written in the source that is not part of the symbol names the self type
        // (`Hmac::<Sha256>::new_from_slice` for `crypto_common::KeyInit::new_from_slice`). If it,
        // and every type named in the path's generic arguments, is imported from a crate of the
        // CBOM, one of those crates (or a dependency of one) must provide the asset.
        if matches!(
            kind.as_str(),
            "call" | "static" | "via-static" | "instantiation"
        ) && let Some((quals, _, generics)) = &parsed
            && let Some(q0) = quals.first()
            && !matches!(q0.as_str(), "crate" | "self" | "super" | "Self")
        {
            let sym_segs: Vec<String> = strip_generics(&o.symbol)
                .split("::")
                .map(|s| s.trim_start_matches('<').to_string())
                .collect();
            const NEUTRAL: &[&str] = &[
                "u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32", "i64", "i128",
                "isize", "f32", "f64", "bool", "char", "str", "String", "Vec", "Option", "Box",
                "Result", "as", "dyn", "impl", "mut", "const", "fn", "static", "_",
            ];
            let owner_id = owner_id.as_deref();
            if !sym_segs.iter().any(|s| s == q0)
                && let Some(mut roots) = self.origins(&src, owner_id, q0)
                && let Some(provs) = self.graph.providers.get(&o.component_ref)
            {
                let mut unknown = false;
                for g in generics.iter().filter(|g| !NEUTRAL.contains(&g.as_str())) {
                    match self.origins(&src, owner_id, g) {
                        Some(r) => roots.extend(r),
                        // a type parameter or a local type: it could carry the asset
                        None => unknown = true,
                    }
                }
                let provided = roots.iter().any(|r| {
                    let cl = self.graph.closure(r);
                    provs.iter().any(|p| cl.contains(p))
                });
                if !unknown && !provided {
                    roots.sort();
                    roots.dedup();
                    return Err(format!(
                        "`{q0}` comes from {}, which does not provide {}",
                        roots.join(", "),
                        o.component
                    ));
                }
            }
        }
        Ok(())
    }
}

/// The source from a position on, over the next 8 lines: chars and their classes.
fn rest(src: &Source, line: usize, offset: usize) -> (Vec<char>, Vec<Class>) {
    let mut s = Vec::new();
    let mut k = Vec::new();
    for (n, l) in src.lines.iter().enumerate().skip(line - 1).take(9) {
        if n + 1 != line {
            s.push('\n');
            k.push(Class::Code);
        }
        let from = if n + 1 == line { offset } else { 0 };
        for (c, ch) in l.chars().enumerate().skip(from) {
            s.push(ch);
            k.push(src.class[n].get(c).copied().unwrap_or(Class::Code));
        }
    }
    (s, k)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code_at(src: &str, needle: &str) -> bool {
        let (code, _) = lex(src);
        let line = src.lines().position(|l| l.contains(needle)).unwrap();
        let byte = src.lines().nth(line).unwrap().find(needle).unwrap();
        let col = src.lines().nth(line).unwrap()[..byte].chars().count();
        code[line][col] == Class::Code
    }

    #[test]
    fn lexer_classifies_literals_and_comments() {
        let src = "fn main() { let q = '\\''; let A = 1; let r = '\"'; let B = 2;\n let s = \"x\\\" C\"; let D = 3; let t = r#\"E\"# ; let F = 4;\n let l: &'static str = \"z\"; let G = 5; /* c /* n */ H */ let I = 6; let u = b'\\\\'; let J = 7; // K\n}";
        assert!(code_at(src, "A ="));
        assert!(code_at(src, "B ="));
        assert!(!code_at(src, "C\""));
        assert!(code_at(src, "D ="));
        assert!(!code_at(src, "E\""));
        assert!(code_at(src, "F ="));
        assert!(code_at(src, "G ="));
        assert!(!code_at(src, "H */"));
        assert!(code_at(src, "I ="));
        assert!(code_at(src, "J ="));
        assert!(!code_at(src, "K"));
    }

    fn generics_of(at: &str) -> Vec<String> {
        let s: Vec<char> = at.chars().collect();
        path_and_generics(&s, &classify(at)).unwrap().2
    }

    #[test]
    fn paths() {
        assert_eq!(
            path_at("Hmac::<Sha256>::new_from_slice(k)").unwrap().1,
            "new_from_slice"
        );
        assert_eq!(
            path_at("<Hmac<Sha256> as Mac>::new_from_slice(k)")
                .unwrap()
                .1,
            "new_from_slice"
        );
        assert_eq!(path_at("seal::<Aes256Gcm>(&k)").unwrap().1, "seal");
        assert_eq!(
            path_at("Vec::<u8>::new(); let h = Hmac::<Sha256>::new_from_slice(k)")
                .unwrap()
                .1,
            "new"
        );
        assert_eq!(
            path_at("ring::digest::SHA256.output_len()").unwrap().1,
            "SHA256"
        );
        assert_eq!(
            path_at("Foo::<[u8; 32], fn() -> u8>::bar()").unwrap().1,
            "bar"
        );
        assert_eq!(
            path_at("Hmac::<\n        Sha256,\n    >::new_from_slice(b)")
                .unwrap()
                .1,
            "new_from_slice"
        );
        assert_eq!(
            path_at("<sha2::Sha512 as Digest>\n        ::digest(b)")
                .unwrap()
                .1,
            "digest"
        );
        assert_eq!(
            path_at("hash(b);\n}\nfn x() { a::digest() }").unwrap().1,
            "hash"
        );
        assert_eq!(generics_of("Hmac::<sha2::Sha256>::new(k)"), vec!["sha2"]);
        assert_eq!(generics_of("SimpleHkdfExtract::<Kdf>::new(s)"), vec!["Kdf"]);
        assert_eq!(generics_of("Foo::<'static, [u8; 32]>::new(s)"), vec!["u8"]);
        // a crate named from the root
        assert_eq!(
            path_at("::sha2::Sha256::digest(d)").unwrap(),
            (vec!["sha2".into(), "Sha256".into()], "digest".into())
        );
    }

    #[test]
    fn raw_identifiers_are_read_without_their_prefix() {
        assert_eq!(path_at("Sha256::r#digest(b\"r\")").unwrap().1, "digest");
        assert_eq!(path_at("r#digest(b)").unwrap().1, "digest");
        assert_eq!(generics_of("Hmac::<r#Sha256>::new(k)"), vec!["Sha256"]);
        // `#digest` (a shifted position) is no path
        assert!(path_at("#digest(b)").is_none());
    }

    #[test]
    fn comments_between_path_segments_are_skipped() {
        assert_eq!(
            path_at("sha2::Sha256 // first\n        ::digest(d);")
                .unwrap()
                .1,
            "digest"
        );
        assert_eq!(
            path_at("sha2::/* the type */Sha256::digest(d)").unwrap().1,
            "digest"
        );
        // a comment in the generic arguments names no type
        assert_eq!(
            generics_of("Hmac::<Sha256 /* not Sha1 */>::new(k)"),
            vec!["Sha256"]
        );
        // a literal is not skipped: the path ends before it
        assert_eq!(
            path_at("sha2::Sha256 \"x\" ::digest(d)").unwrap().1,
            "Sha256"
        );
    }

    fn col(src: &Source, line: usize, needle: &str) -> usize {
        let l = &src.lines[line - 1];
        l[..l.find(needle).unwrap()].chars().count()
    }

    #[test]
    fn a_token_may_follow_a_single_colon_not_a_path_separator() {
        let src = Source::new(
            "let w = W { n:Sha256::digest(data).len() };\nlet h = sha2::Sha256::digest(d);\nlet g = sha2::\n    Sha256::digest(d);\nlet r = Sha256::r#digest(d);\nlet c = sha2:: /* c */ Sha256::digest(d);",
            true,
            false,
        );
        assert!(token_start(&src, 1, col(&src, 1, "Sha256")));
        assert!(token_start(&src, 2, col(&src, 2, "sha2")));
        assert!(!token_start(&src, 2, col(&src, 2, "Sha256")));
        assert!(!token_start(&src, 2, col(&src, 2, "digest")));
        assert!(!token_start(&src, 2, col(&src, 2, "ha2")));
        // after `::` on the line before, or after a comment
        assert!(!token_start(&src, 4, col(&src, 4, "Sha256")));
        assert!(!token_start(&src, 6, col(&src, 6, "Sha256")));
        // the identifier of `r#digest` is not a token of its own
        assert!(!token_start(&src, 5, col(&src, 5, "digest")));
        assert!(token_start(&src, 5, col(&src, 5, "Sha256")));
    }

    #[test]
    fn tags_are_read_from_the_head_of_the_context_only() {
        let c = split_context(
            "[reachable] [call] in p3::comment; use: digest; line: `let d = Sha256::digest(data); // see [derive Foo] and [macro bar!]`; code: `Sha256::digest`",
        );
        assert_eq!(c.tags, "[reachable] [call] ");
        assert!(!re!(r"\[macro ([\w:]+!)\]").is_match(c.tags));
        assert!(!re!(r"\[derive ([\w:]+)\]").is_match(c.tags));
        assert_eq!(c.details, "[reachable] [call] in p3::comment; use: digest");
        assert_eq!(
            c.line,
            Some("let d = Sha256::digest(data); // see [derive Foo] and [macro bar!]")
        );
        assert_eq!(c.code, Some("Sha256::digest"));
        let c = split_context(
            "[present] [call] [macro sha2::m!] in x; part of SHA-256; line: `m!(a); // ; part of MD5`",
        );
        assert_eq!(c.tags, "[present] [call] [macro sha2::m!] ");
        assert_eq!(
            &re!(r"; part of ([^\s;(]+)").captures(c.details).unwrap()[1],
            "SHA-256"
        );
        assert_eq!(c.code, None);
    }

    #[test]
    fn crlf_lines_compare_without_the_carriage_return() {
        let lock = "[[package]]\r\nname = \"sha2\"\r\nversion = \"0.10.9\"\r\n";
        let src = Source::new(lock, false, false);
        assert_eq!(src.lines[1], "name = \"sha2\"");
        let ctx = "[manifest] locked sha2 0.10.9; reached via p -> sha2";
        assert_eq!(check_lock(&src.lines, 2, 0, "sha2", ctx), Ok(()));
        assert!(check_lock(&src.lines, 2, 1, "sha2", ctx).is_err());
        assert!(check_lock(&src.lines, 3, 0, "sha2", ctx).is_err());
        assert!(check_lock(&src.lines, 2, 0, "sha2", "[manifest] locked sha2 0.11.0; x").is_err());
        assert!(check_lock(&src.lines, 2, 0, "sha2", "[manifest] something").is_err());
        let rs = Source::new(
            "use sha2::Sha256;\r\nfn f() { Sha256::digest(b) }\r\n",
            true,
            false,
        );
        assert_eq!(rs.lines[1], "fn f() { Sha256::digest(b) }");
        assert_eq!(rs.class[1].len(), rs.lines[1].chars().count());
        let toml = Source::new(
            "[package]\r\nname = \"p\"\r\n[dependencies]\r\nsha2 = \"0.10\"\r\n",
            false,
            true,
        );
        assert_eq!(
            check_toml(
                &toml.toml,
                &toml.lines[3],
                4,
                0,
                "sha2",
                "[manifest] declared by p (dependencies)"
            ),
            Ok(())
        );
    }

    const MANIFEST: &str = r#"[package]
name = "t4"
version = "0.1.0"
links = "native"

# sha1 is mentioned in this comment
[dependencies]
hashing = { package = "sha2", version = "0.10" }
md5.version = "0.7"
"sha1" = "0.10"
x = """
[dev-dependencies]
ring = 1
"""

[dependencies.hmac]
version = "0.12"

[ target . 'cfg(target_os="linux")' . dependencies ]
blake3 = "1"

[dev-dependencies]
hmac = "0.12"

[build-dependencies]
md5 = "0.7"

[workspace.dependencies]
ring = "0.17"
"#;

    fn toml_check(line: usize, col: usize, symbol: &str, ctx: &str) -> Result<(), String> {
        let src = Source::new(MANIFEST, false, true);
        check_toml(&src.toml, &src.lines[line - 1], line, col, symbol, ctx)
    }

    #[test]
    fn manifest_keys_are_read_with_their_tables() {
        let dep = "[manifest] declared by t4 (dependencies)";
        let dev = "[manifest] declared by t4 (dev-dependencies)";
        let build = "[manifest] declared by t4 (build-dependencies); default-features = false";
        // every form the generator cites
        assert_eq!(toml_check(8, 0, "hashing", dep), Ok(()));
        assert_eq!(toml_check(9, 0, "md5", dep), Ok(()));
        assert_eq!(toml_check(10, 0, "sha1", dep), Ok(()));
        assert_eq!(toml_check(16, 14, "hmac", dep), Ok(()));
        assert_eq!(toml_check(20, 0, "blake3", dep), Ok(()));
        assert_eq!(toml_check(23, 0, "hmac", dev), Ok(()));
        assert_eq!(toml_check(26, 0, "md5", build), Ok(()));
        // a quoted key at its opening quote only
        assert!(toml_check(10, 1, "sha1", dep).is_err());
        // a comment, a multi-line string, a value, keys inside a dependency's table
        assert!(toml_check(6, 2, "sha1", dep).is_err());
        assert!(toml_check(12, 0, "dev-dependencies", dep).is_err());
        assert!(toml_check(13, 0, "ring", dev).is_err());
        assert!(toml_check(8, 22, "sha2", dep).is_err());
        assert!(toml_check(8, 12, "package", dep).is_err());
        assert!(toml_check(9, 4, "version", dep).is_err());
        // positions swapped between tables
        assert!(toml_check(23, 0, "hmac", dep).is_err());
        assert!(toml_check(16, 14, "hmac", dev).is_err());
        assert!(toml_check(26, 0, "md5", dep).is_err());
        assert!(toml_check(9, 0, "md5", build).is_err());
        // [workspace.dependencies] is not where a member declares a dependency
        assert!(toml_check(29, 0, "ring", dep).is_err());
        // another package's manifest
        assert!(toml_check(8, 0, "hashing", "[manifest] declared by t5 (dependencies)").is_err());
        // links
        let links =
            "[manifest] native library `native`; code behind the FFI boundary is not analysed";
        assert_eq!(toml_check(4, 0, "links", links), Ok(()));
        assert!(toml_check(4, 0, "links", "[manifest] native library `other`; x").is_err());
        assert!(toml_check(4, 0, "links", "[manifest] unheard of").is_err());
        // a root dotted key into the table
        let root = Source::new(
            "dependencies.zeta = \"1\"\n[package]\nname = \"t4\"\n",
            false,
            true,
        );
        assert_eq!(
            check_toml(&root.toml, &root.lines[0], 1, 13, "zeta", dep),
            Ok(())
        );
    }

    #[test]
    fn merged_parents_are_strictly_more_specific_names() {
        assert!(extends("Argon2id-19456-2-1", "Argon2", Some("Argon2")));
        assert!(extends(
            "PBKDF2-SHA-256-1000-32",
            "PBKDF2-SHA-256",
            Some("PBKDF2")
        ));
        assert!(!extends("SHA-256", "SHA-256", Some("SHA-2")));
        assert!(!extends("SHA-2560", "SHA-256", Some("SHA-2")));
        assert!(!extends("Argon2id-19456-2-1", "Argon2", Some("Argon")));
        assert!(!extends("SHA-512", "SHA-256", Some("SHA-2")));
    }

    #[test]
    fn imports_of_one_name_from_several_crates() {
        let src = Source::new(
            "use sha2::Digest;\n#[cfg(feature = \"legacy\")]\nuse sha1::Sha1 as Hasher;\n#[cfg(not(feature = \"legacy\"))]\nuse sha2::Sha256 as Hasher;\nuse aes_gcm::{aead::{KeyInit, Aead as A}, Aes256Gcm, self as gcm};\nuse crate::local::Thing;\nextern crate ring as r;\nuse other::*;\nfn f<D: Digest, const N: usize>() {}\nstruct Wrapper;",
            true,
            false,
        );
        let roots =
            |n: &str| import_roots(&src.binds, n).map(|r| r.into_iter().collect::<Vec<_>>());
        assert_eq!(roots("Hasher"), Some(vec!["sha1".into(), "sha2".into()]));
        assert_eq!(roots("Aes256Gcm"), Some(vec!["aes_gcm".into()]));
        assert_eq!(roots("KeyInit"), Some(vec!["aes_gcm".into()]));
        assert_eq!(roots("A"), Some(vec!["aes_gcm".into()]));
        assert_eq!(roots("gcm"), Some(vec!["aes_gcm".into()]));
        assert_eq!(roots("r"), Some(vec!["ring".into()]));
        assert_eq!(roots("Thing"), None);
        // not imported: the crate of that name, if any
        assert_eq!(roots("sha2"), Some(vec!["sha2".into()]));
        assert_eq!(
            aliases(&src.binds, "Sha256").collect::<Vec<_>>(),
            vec!["Hasher"]
        );
        assert_eq!(aliases(&src.binds, "Aead").collect::<Vec<_>>(), vec!["A"]);
        for local in ["D", "N", "Wrapper"] {
            assert!(src.locals.contains(local), "{local}");
        }
        assert!(!src.locals.contains("Hasher"));
    }
}
