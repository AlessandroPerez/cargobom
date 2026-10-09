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

/// Library crate name -> bom-refs of the packages whose library it is (`aws_lc_rs` is
/// aws-lc-rs's), from `cargo metadata`.
type Libs = HashMap<String, Vec<String>>;

fn pkg_ref(name: &str, version: &str) -> String {
    format!("pkg:cargo/{name}@{version}")
}

fn load_externs(
    manifest_path: &Path,
    target: &str,
    features: &[String],
) -> Option<(Externs, Libs)> {
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
    let mut libs: Libs = HashMap::new();
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
                libs.entry(tn.replace('-', "_"))
                    .or_default()
                    .push(r.clone());
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
    Some((ext, libs))
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
    // the platform the CBOM was made for (its dependency tables and features)
    let target = match doc["metadata"]["properties"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|p| p["name"] == "rcbom:run:target")
        .and_then(|p| p["value"].as_str())
    {
        Some(t) => t.to_string(),
        None => rcbom_manifest::host_triple()?,
    };
    let man = rcbom_manifest::load_locked(manifest_path, &target, &features, &kb)?;
    let (externs, libs) = match load_externs(manifest_path, &target, &features) {
        Some((e, l)) => (Some(e), Some(l)),
        None => {
            eprintln!("verify: cargo metadata failed; crate names are resolved by package name");
            (None, None)
        }
    };
    let mut graph = Graph {
        packages: HashSet::new(),
        depends_on: HashMap::new(),
        providers: HashMap::new(),
        family: HashMap::new(),
    };
    // the components, and the root package (`metadata.component`)
    let root = doc["metadata"]["component"].clone();
    for c in doc["components"]
        .as_array()
        .into_iter()
        .flatten()
        .chain(std::iter::once(&root).filter(|r| r.is_object()))
    {
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
    for c in doc["components"]
        .as_array()
        .into_iter()
        .flatten()
        .chain(std::iter::once(&root).filter(|r| r.is_object()))
    {
        for o in c["evidence"]["occurrences"]
            .as_array()
            .into_iter()
            .flatten()
        {
            let (Some(line), Some(offset)) = (o["line"].as_u64(), o["offset"].as_u64()) else {
                // the generator gives every occurrence a position: one without is not evidence
                without_line += 1;
                println!(
                    "MISMATCH {} {}: an occurrence without a line and offset",
                    c["name"].as_str().unwrap_or(""),
                    o["location"].as_str().unwrap_or("")
                );
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
        kb: &kb,
        externs,
        libs,
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
    let bad = bad + without_line;
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
    /// Rust: where each `use` or `extern crate` item is, from (line, col) to (line, col)
    /// (1-based lines, 0-based char columns, end exclusive): a path there is an import, not a use
    use_spans: Vec<((usize, usize), (usize, usize))>,
    /// Rust: the items with a body (functions, statics, consts, impl blocks, traits, modules,
    /// `macro_rules!`), where a position's enclosing item is looked up
    items: Vec<Item>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ItemKind {
    Fn,
    Static,
    Impl,
    Trait,
    Mod,
    Macro,
    /// a macro's invocation (`thread_local! { .. }`): the items it makes are named by it
    MacroCall,
}

/// An item of a Rust file, from its keyword to the end of its body ((line, col), end
/// exclusive), with its name: a function's, static's or const's, a trait's, a module's, a
/// `macro_rules!`'s; for an impl block, the last segment of its self type (and `trait_name`,
/// the trait's).
#[derive(Debug)]
struct Item {
    kind: ItemKind,
    name: String,
    trait_name: Option<String>,
    start: (usize, usize),
    end: (usize, usize),
}

impl Item {
    fn contains(&self, at: (usize, usize)) -> bool {
        self.start <= at && at < self.end
    }
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
                use_spans: Vec::new(),
                items: Vec::new(),
            };
        }
        let (mut class, code_text) = lex(text);
        for (c, l) in class.iter_mut().zip(&lines) {
            c.truncate(l.chars().count());
        }
        // char index -> (line, col)
        let mut starts = vec![0usize];
        for (i, c) in code_text.chars().enumerate() {
            if c == '\n' {
                starts.push(i + 1);
            }
        }
        let at = |i: usize| {
            let l = starts.partition_point(|&s| s <= i) - 1;
            (l + 1, i - starts[l])
        };
        let char_of = |b: usize| code_text[..b].chars().count();
        let use_spans = USE_ITEM
            .find_iter(&code_text)
            .map(|m| (at(char_of(m.start())), at(char_of(m.end()))))
            .collect();
        let chars: Vec<char> = code_text.chars().collect();
        let items = items(&chars)
            .into_iter()
            .map(|(kind, name, trait_name, a, b)| Item {
                kind,
                name,
                trait_name,
                start: at(a),
                end: at(b),
            })
            .collect();
        Source {
            lines,
            class,
            binds: bindings(&code_text),
            locals: locals(&code_text),
            toml: Vec::new(),
            use_spans,
            items,
        }
    }

    /// The innermost item of one of `kinds` that contains the position.
    fn enclosing(&self, at: (usize, usize), kinds: &[ItemKind]) -> Option<&Item> {
        self.items
            .iter()
            .filter(|i| kinds.contains(&i.kind) && i.contains(at))
            .max_by_key(|i| i.start)
    }
}

/// The items of a Rust file with comments and literals blanked: (kind, name, trait, start, end)
/// in chars. A keyword counts at an item's place (not `-> impl Trait`, `*const T`, `<const N>`,
/// `const { .. }`); a function without a body (a trait's declaration) has none.
#[allow(clippy::type_complexity)]
fn items(s: &[char]) -> Vec<(ItemKind, String, Option<String>, usize, usize)> {
    let word_at = |i: usize| -> String {
        s[i..]
            .iter()
            .take_while(|c| is_ident(**c))
            .collect::<String>()
    };
    let skip_ws = |mut i: usize| {
        while i < s.len() && s[i].is_whitespace() {
            i += 1;
        }
        i
    };
    // the code before `i`: its last non-blank char, and the word ending there
    let prev = |i: usize| s[..i].iter().rev().find(|c| !c.is_whitespace()).copied();
    let prev_word = |i: usize| -> String {
        let mut j = i;
        while j > 0 && s[j - 1].is_whitespace() {
            j -= 1;
        }
        let end = j;
        while j > 0 && is_ident(s[j - 1]) {
            j -= 1;
        }
        s[j..end].iter().collect()
    };
    // an item's place: after another item, a block's start, an attribute, a visibility or a
    // qualifier
    let item_place = |i: usize| {
        matches!(prev(i), None | Some('}' | ';' | '{' | ']' | ')'))
            || matches!(
                prev_word(i).as_str(),
                "pub" | "unsafe" | "default" | "extern" | "auto"
            )
    };
    // the matching close of the bracket at `open`
    let close_of = |open: usize| -> Option<usize> {
        let (o, c) = match s[open] {
            '{' => ('{', '}'),
            '(' => ('(', ')'),
            '[' => ('[', ']'),
            _ => return None,
        };
        let mut depth = 0;
        for (j, ch) in s.iter().enumerate().skip(open) {
            if *ch == o {
                depth += 1;
            } else if *ch == c {
                depth -= 1;
                if depth == 0 {
                    return Some(j + 1);
                }
            }
        }
        None
    };
    // from `i`, the first `{` (or `;` when `semi`) outside parentheses, brackets and generic
    // arguments: a body, or the end of a declaration
    let body_or_end = |i: usize| -> Option<(usize, bool)> {
        let mut depth = 0i32;
        let mut j = i;
        while j < s.len() {
            match s[j] {
                '(' | '[' => depth += 1,
                ')' | ']' => depth -= 1,
                '<' => depth += 1,
                '>' if j > 0 && s[j - 1] != '-' && s[j - 1] != '=' => depth -= 1,
                '{' if depth <= 0 => return Some((j, true)),
                ';' if depth <= 0 => return Some((j, false)),
                _ => {}
            }
            j += 1;
        }
        None
    };
    let last_segment = |t: &str| -> String {
        // `&'a mut path::Type<A, B>` -> `Type`
        let t = strip_generics(t);
        let t = t.trim().trim_start_matches(['&', '*']).trim();
        let t = t
            .split_whitespace()
            .rfind(|w| !w.starts_with('\'') && *w != "mut" && *w != "dyn" && *w != "const")
            .unwrap_or("");
        t.rsplit("::").next().unwrap_or(t).trim().to_string()
    };
    let mut out = Vec::new();
    let mut i = 0;
    while i < s.len() {
        if !is_ident(s[i]) || (i > 0 && is_ident(s[i - 1])) {
            i += 1;
            continue;
        }
        let w = word_at(i);
        let after = skip_ws(i + w.len());
        match w.as_str() {
            "fn" if after < s.len() && is_ident(s[after]) => {
                let name = word_at(after);
                let name = name.strip_prefix("r#").unwrap_or(&name).to_string();
                if let Some((b, true)) = body_or_end(after + name.len())
                    && let Some(e) = close_of(b)
                {
                    out.push((ItemKind::Fn, name, None, i, e));
                }
            }
            "static" | "const"
                if after < s.len()
                    && is_ident(s[after])
                    && item_place(i)
                    && !matches!(
                        word_at(after).as_str(),
                        "fn" | "unsafe" | "extern" | "async"
                    ) =>
            {
                let mut n = after;
                if word_at(n) == "mut" {
                    n = skip_ws(n + 3);
                }
                let name = word_at(n);
                // `static NAME: T = ..;`: to the `;` outside all brackets
                let mut depth = 0i32;
                let mut j = n;
                while j < s.len() {
                    match s[j] {
                        '(' | '[' | '{' => depth += 1,
                        ')' | ']' | '}' => depth -= 1,
                        ';' if depth == 0 => break,
                        _ => {}
                    }
                    if depth < 0 {
                        break;
                    }
                    j += 1;
                }
                if !name.is_empty() {
                    out.push((ItemKind::Static, name, None, i, (j + 1).min(s.len())));
                }
            }
            "impl" if item_place(i) && prev(i) != Some(')') => {
                if let Some((b, true)) = body_or_end(i + 4)
                    && let Some(e) = close_of(b)
                {
                    let mut header: String = s[i + 4..b].iter().collect();
                    // the impl's own generic parameters
                    let mut params = Vec::new();
                    if header.trim_start().starts_with('<') {
                        let h = header.trim_start().to_string();
                        let hc: Vec<char> = h.chars().collect();
                        let cls = vec![Class::Code; hc.len()];
                        if let Some(end) = skip_angle(&hc, &cls, 0) {
                            let inner: String = hc[1..end.saturating_sub(1)].iter().collect();
                            params = strip_generics(&inner)
                                .split(',')
                                .filter_map(|p| {
                                    let p = p.trim().trim_start_matches("const ").trim();
                                    let n: String =
                                        p.chars().take_while(|c| is_ident(*c)).collect();
                                    (!n.is_empty() && !p.starts_with('\'')).then_some(n)
                                })
                                .collect();
                        }
                        header = strip_generics(&h).to_string();
                    }
                    // blanks collapsed: a `where` or `for` may start a line
                    let one_line = |h: &str| h.split_whitespace().collect::<Vec<_>>().join(" ");
                    let header = one_line(&header);
                    let header = header.split(" where ").next().unwrap_or("").to_string();
                    let header_full: String = one_line(&s[i + 4..b].iter().collect::<String>());
                    let header_full = header_full
                        .split(" where ")
                        .next()
                        .unwrap_or("")
                        .to_string();
                    let (tr, ty) = match header.split_once(" for ") {
                        Some((_, y)) => {
                            // the trait with its arguments (`TryFrom<&PrivateKeyDer<'_>>`),
                            // unless they are the impl's own parameters: then its name
                            let t = header_full
                                .split_once(" for ")
                                .map(|(t, _)| t.trim().to_string())
                                .unwrap_or_default();
                            let t = if t.starts_with('<') {
                                let tc: Vec<char> = t.chars().collect();
                                let cls = vec![Class::Code; tc.len()];
                                skip_angle(&tc, &cls, 0)
                                    .map(|e| tc[e..].iter().collect::<String>())
                                    .unwrap_or(t)
                            } else {
                                t
                            };
                            let generic = re!(r"\w+")
                                .find_iter(&t)
                                .any(|m| params.iter().any(|p| p == m.as_str()));
                            let t = if generic {
                                last_segment(&t)
                            } else {
                                norm_path(&t)
                            };
                            (Some(t), y.to_string())
                        }
                        None => (None, header.clone()),
                    };
                    // a blanket impl (`impl<T: Foo> Bar for T`): any type, named by its trait
                    let ty = last_segment(&ty);
                    let ty = if params.contains(&ty) {
                        String::new()
                    } else {
                        ty
                    };
                    out.push((ItemKind::Impl, ty, tr, i, e));
                }
            }
            "trait" | "mod" if after < s.len() && is_ident(s[after]) && item_place(i) => {
                let name = word_at(after);
                if let Some((b, true)) = body_or_end(after + name.len())
                    && let Some(e) = close_of(b)
                {
                    let kind = if w == "trait" {
                        ItemKind::Trait
                    } else {
                        ItemKind::Mod
                    };
                    out.push((kind, name, None, i, e));
                }
            }
            "macro_rules" if s.get(after) == Some(&'!') => {
                let n = skip_ws(after + 1);
                let name = word_at(n);
                let b = skip_ws(n + name.len());
                if b < s.len()
                    && let Some(e) = close_of(b)
                {
                    // the body: inside its brackets
                    out.push((ItemKind::Macro, name, None, b, e));
                }
            }
            // `name! (..)`, `name! [..]`, `name! { .. }`
            _ if after < s.len()
                && s[after] == '!'
                && w != "macro_rules"
                && s.get(skip_ws(after + 1))
                    .is_some_and(|c| matches!(c, '(' | '[' | '{')) =>
            {
                let b = skip_ws(after + 1);
                if let Some(e) = close_of(b) {
                    out.push((ItemKind::MacroCall, w.clone(), None, b, e));
                }
            }
            _ => {}
        }
        i += w.len().max(1);
    }
    out
}

struct Files<'a> {
    man: &'a rcbom_manifest::Manifest,
    kb: &'a Kb,
    externs: Option<Externs>,
    libs: Option<Libs>,
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

/// The (name, version) of the package a component's manifest evidence is of: a package
/// (`pkg:cargo/<name>@<version>`), or the package a candidate algorithm is declared through
/// (`crypto:candidate:<name>@<version>:<asset>`).
fn package_of(component: &str) -> Option<(&str, &str)> {
    if let Some(c) = component.strip_prefix("crypto:candidate:") {
        let (nv, _) = c.split_once(':')?;
        return nv.split_once('@');
    }
    component.strip_prefix("pkg:cargo/")?.split_once('@')
}

/// A `Cargo.lock` position: the `name = "<symbol>"` line, at column 0, whose next line is the
/// version the context names (`locked sha2 0.10.9; ..`), which is the package the occurrence
/// is evidence of: two locked versions are told apart.
fn check_lock(
    lines: &[String],
    line: usize,
    offset: usize,
    symbol: &str,
    context: &str,
    component: &str,
) -> Result<(), String> {
    let m = re!(r"^\[manifest\] locked (\S+) (\S+);")
        .captures(context)
        .ok_or("a Cargo.lock occurrence whose context names no locked package")?;
    if &m[1] != symbol {
        return Err(format!("the context names {}, the symbol {symbol}", &m[1]));
    }
    if package_of(component) != Some((&m[1], &m[2])) {
        return Err(format!(
            "the context names {} {}, but this is evidence of {component}",
            &m[1], &m[2]
        ));
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
///   `sym.version = ..`) or `[target.<platform>.K]`, in the manifest of package P, that names
///   the package the occurrence is evidence of: its name (`package = ..` if renamed), and a
///   version requirement its version meets;
/// - `native library `L``: the `links` key of `[package]`, with value L, in the manifest of the
///   package the occurrence is evidence of.
fn check_toml(
    keys: &[TomlKey],
    text: &str,
    line: usize,
    offset: usize,
    symbol: &str,
    context: &str,
    component: &str,
) -> Result<(), String> {
    let (cname, cversion) = package_of(component)
        .ok_or_else(|| format!("a manifest occurrence of {component}, not a package"))?;
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
        // the dependency this key declares: its package and version requirement
        let field = |f: &str| {
            keys.iter().find(|x| {
                x.path.len() == k.path.len() + 1
                    && x.path.starts_with(&k.path)
                    && x.path.last().is_some_and(|l| l == f)
            })
        };
        let package = field("package")
            .and_then(|x| x.value.as_deref())
            .unwrap_or(symbol);
        if package != cname {
            return Err(format!(
                "the key here declares {package}, but this is evidence of {component}"
            ));
        }
        let req = k
            .value
            .as_deref()
            .or_else(|| field("version").and_then(|x| x.value.as_deref()));
        if let Some(req) = req
            && let (Ok(req), Ok(v)) = (
                semver::VersionReq::parse(req),
                semver::Version::parse(cversion),
            )
            && !req.matches(&v)
        {
            return Err(format!(
                "the key here requires {package} {req}, but this is evidence of {component}"
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
        let name = keys
            .iter()
            .find(|k| k.path == ["package", "name"])
            .and_then(|k| k.value.as_deref());
        if name != Some(cname) {
            return Err(format!(
                "this is the manifest of {}, but this is evidence of {component}",
                name.unwrap_or("no package")
            ));
        }
        Ok(())
    } else {
        Err(format!("unrecognized manifest context {context:?}"))
    }
}

/// A `use` or `extern crate` item, in a source with comments and literals blanked.
static USE_ITEM: std::sync::LazyLock<Regex> =
    std::sync::LazyLock::new(|| Regex::new(r"(?s)\b(?:use|extern\s+crate)\s[^;]*;").unwrap());

/// Every name the `use` and `extern crate` items of a source bind (comments and literals
/// blanked: `as` renames there, not in casts).
fn bindings(code_text: &str) -> Vec<Binding> {
    USE_ITEM
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
                && re!(r"\sas\s").is_match(&t)
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
            // as the generator writes them: relative, without `.`, `..` or empty segments
            if location.starts_with('/')
                || location
                    .split('/')
                    .any(|g| g.is_empty() || g == "." || g == "..")
            {
                return Err(format!(
                    "`{location}` is not a normalised relative location"
                ));
            }
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
                "Cargo.lock" => check_lock(
                    &src.lines,
                    line,
                    offset,
                    &o.symbol,
                    &o.context,
                    &o.component_ref,
                ),
                "Cargo.toml" => check_toml(
                    &src.toml,
                    &text,
                    line,
                    offset,
                    &o.symbol,
                    &o.context,
                    &o.component_ref,
                ),
                _ => Err("a manifest occurrence outside Cargo.toml and Cargo.lock".into()),
            };
        }
        // evidence in code is one of the kinds the generator writes, after its tier
        let ctx = split_context(&o.context);
        let kind =
            re!(r"^\[(?:reachable|present)\] \[(call|static|via-static|instantiation|component)\]")
                .captures(ctx.tags)
                .map(|m| m[1].to_string())
                .ok_or("no tier and evidence kind among the tags")?;
        let starts_token = token_start(&src, line, offset);
        // code positions are in code, not in a comment or a literal
        if src.class[line - 1].get(offset) != Some(&Class::Code) {
            return Err(format!("position inside a comment or literal in {text:?}"));
        }
        // the generator records the source line and, when it is on one line outside a macro,
        // the exact text at the position, last in the context, in that order; the line may hold
        // backquotes, the text does not
        let Some(l) = ctx.line else {
            return Err("no source line recorded".into());
        };
        if text.trim() != l {
            return Err(format!("expected the line `{l}`, found {text:?}"));
        }
        if let Some(code) = ctx.code
            && !at.starts_with(code)
        {
            return Err(format!("expected `{code}` in {text:?}"));
        }
        // an import names an item, it does not use it
        if src
            .use_spans
            .iter()
            .any(|&(a, b)| a <= (line, offset) && (line, offset) < b)
        {
            return Err(format!("position inside a `use` item in {text:?}"));
        }
        // the positions the details name: where a generic instance was instantiated, where a
        // macro's code was written
        self.check_details(ctx.details, ctx.tags, &o.symbol, ctx.line)?;
        // the macro tags are among the leading tags, never in the recorded source text; a tagged
        // position is the macro's, derive's or attribute's name, not the symbol's
        let mut tagged = false;
        if let Some(m) = re!(r"\[macro ([\w:]+!)\]").captures(ctx.tags) {
            let name = &m[1];
            let ok = Regex::new(&format!(r"^(?:\w+::)*{}", regex::escape(name)))
                .unwrap()
                .is_match(&at);
            if !(ok && starts_token) {
                return Err(format!("expected `{name}` in {text:?}"));
            }
            tagged = true;
        }
        // derive: the position is the derive's name inside `#[derive(..)]` (or a `cfg_attr`'s
        // `derive(..)`)
        if !tagged && let Some(m) = re!(r"\[derive ([\w:]+)\]").captures(ctx.tags) {
            let name = m[1].rsplit("::").next().unwrap_or(&m[1]).to_string();
            let ok = Regex::new(&format!(r"^(?:\w+::)*{}\b", regex::escape(&name)))
                .unwrap()
                .is_match(&at);
            let in_derive = attribute_before(&src, line, offset).is_some_and(|a| {
                re!(r"^(?:derive|cfg_attr)\s*\(").is_match(&a) && open_in(&a, "derive")
            });
            if !(ok && starts_token && in_derive) {
                return Err(format!(
                    "expected derive `{name}` inside `#[derive(..)]` in {text:?}"
                ));
            }
            tagged = true;
        }
        // attribute macro: the position is the attribute, or its name inside a `cfg_attr`
        if !tagged && let Some(m) = re!(r"\[attribute ([\w:]+)\]").captures(ctx.tags) {
            let name = m[1].rsplit("::").next().unwrap_or(&m[1]).to_string();
            let direct = Regex::new(&format!(r"^#!?\[\s*(?:\w+::)*{}\b", regex::escape(&name)))
                .unwrap()
                .is_match(&at)
                && at.starts_with('#');
            let in_cfg_attr = Regex::new(&format!(r"^(?:\w+::)*{}\b", regex::escape(&name)))
                .unwrap()
                .is_match(&at)
                && attribute_before(&src, line, offset)
                    .is_some_and(|a| re!(r"^cfg_attr\s*\(").is_match(&a));
            if !((direct || in_cfg_attr) && starts_token) {
                return Err(format!("expected an attribute in {text:?}"));
            }
            tagged = true;
        }
        // the symbol's crate is a package of the CBOM (or the standard library): a made-up one
        // would switch the checks below off
        let sym = strip_generics(&o.symbol);
        let sym_crate = sym.split("::").next().unwrap_or("").to_string();
        // (a qualified path's, `<t14::S384 as t14::Scheme>::ALG`, is its type's)
        let first = o
            .symbol
            .trim_start_matches('<')
            .split("::")
            .next()
            .unwrap_or("");
        let known = matches!(first, "core" | "std" | "alloc")
            || self.libs.as_ref().is_some_and(|l| l.contains_key(first))
            || self
                .man
                .packages
                .iter()
                .any(|p| p.name.replace('-', "_") == first);
        if !known {
            return Err(format!("`{}`: no crate `{first}` in the build", o.symbol));
        }
        let mut parsed = None;
        let owner = man.owner_of(&path);
        let owner_id = owner.map(|p| p.id.repr.clone());
        if !tagged {
            // the enclosing item the context names (an identical statement in another
            // function, or in another type's method of that name, is another occurrence), and
            // no macro's body (a macro's code is cited where it is called)
            check_item(
                &src,
                ctx.details.strip_prefix(ctx.tags).unwrap_or(ctx.details),
                (line, offset),
            )?;
            // a definition names a new item, it does not use one (`fn seal<..>`, `pub fn digest`)
            if let Some(w) = word_before(&src, line, offset)
                && matches!(
                    w.as_str(),
                    "fn" | "struct"
                        | "enum"
                        | "union"
                        | "trait"
                        | "type"
                        | "mod"
                        | "static"
                        | "const"
                        | "let"
                        | "macro_rules"
                )
            {
                return Err(format!("position after `{w}`: a definition, in {text:?}"));
            }
            // code: the callee or static, by name or by an import alias of it
            let ident = sym
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
            parsed = path_and_generics(&rs, &rc);
            let mut ok = parsed.as_ref().is_some_and(|(_, last, _)| {
                *last == ident
                    || src.binds.iter().any(|b| {
                        b.name == *last
                            && self.alias_of(b, &ident, &sym_crate, owner_id.as_deref(), &src.binds)
                    })
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
                    let binds = self.package_binds(&d);
                    if binds.iter().any(|b| {
                        b.name == *last
                            && self.alias_of(b, &ident, &sym_crate, owner_id.as_deref(), &binds)
                    }) {
                        ok = true;
                        break;
                    }
                }
            }
            if !(ok && starts_token) {
                return Err(format!("expected `{ident}` in {text:?}"));
            }
        }
        // a component is used where the asset it is part of is used
        if kind == "component" {
            let Some(m) = re!(r"; part of ([^\s;(]+)").captures(ctx.details) else {
                return Err("a component that names no asset it is part of".into());
            };
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
        // a descriptor is evidence of the asset the knowledge base names it (`ring::digest::
        // SHA512` is SHA-512, not SHA-384): the static itself, or the one a table leads to
        let descriptor = match kind.as_str() {
            "static" => Some(sym.clone()),
            "via-static" => re!(r" -> ([\w:]+)(?:;|$)")
                .captures(ctx.details)
                .map(|m| m[1].to_string()),
            _ => None,
        };
        if let Some(d) = descriptor {
            let k = d.split("::").next().unwrap_or("");
            let names = rcbom_analysis::static_names(self.kb, k, &d);
            let family = self.graph.family.get(&o.component_ref).map(String::as_str);
            if !names.is_empty()
                && !names
                    .iter()
                    .any(|n| *n == o.component || extends(&o.component, n, family))
            {
                return Err(format!(
                    "`{d}` is {}, not {}",
                    names.join(" or "),
                    o.component
                ));
            }
        }
        // what the path names must provide the asset: the callee's crate, a self type written
        // as a qualifier (`Hmac::<Sha256>::new_from_slice` for `crypto_common::KeyInit::
        // new_from_slice`), or a type in the generic arguments (`<Hmac<Sha256> as Mac>::m`,
        // `seal::<Aes256Gcm>`). Each is a package of the CBOM the file can name it from; the
        // standard library, an interface crate and the program's own code provide nothing and
        // decide nothing. A type parameter or a local type could carry any asset: no check.
        if matches!(
            kind.as_str(),
            "call" | "static" | "via-static" | "instantiation"
        ) && let Some((quals, _, generics)) = &parsed
            && let Some(provs) = self.graph.providers.get(&o.component_ref)
        {
            let sym_segs: Vec<String> = sym
                .split("::")
                .map(|s| s.trim_start_matches('<').to_string())
                .collect();
            const NEUTRAL: &[&str] = &[
                "u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32", "i64", "i128",
                "isize", "f32", "f64", "bool", "char", "str", "String", "Vec", "Option", "Box",
                "Result", "as", "dyn", "impl", "mut", "const", "fn", "static", "_",
            ];
            let owner_id = owner_id.as_deref();
            let mut roots: Vec<String> = Vec::new();
            let mut unknown = false;
            // the callee's crate
            roots.extend(
                self.lib_refs(&sym_crate)
                    .into_iter()
                    .filter(|r| !self.neutral(r)),
            );
            // a written qualifier: a self type, unless the path is the trait's own path
            // (`aes_gcm::aead::KeyInit::new_from_slice`: the qualifiers lead to the trait)
            let trait_path = quals.last().is_some_and(|q| sym_segs.contains(q));
            if let Some(q0) = quals.first()
                && !matches!(q0.as_str(), "crate" | "self" | "super" | "Self")
                && !sym_segs.contains(q0)
                && !trait_path
            {
                match self.origins(&src, owner_id, q0) {
                    Some(r) => roots.extend(r.into_iter().filter(|r| !self.neutral(r))),
                    None => unknown = true,
                }
            }
            for g in generics.iter().filter(|g| !NEUTRAL.contains(&g.as_str())) {
                match self.origins(&src, owner_id, g) {
                    Some(r) => roots.extend(r.into_iter().filter(|r| !self.neutral(r))),
                    None => unknown = true,
                }
            }
            let provided = roots.iter().any(|r| {
                let cl = self.graph.closure(r);
                provs.iter().any(|p| cl.contains(p))
            });
            if !unknown && !roots.is_empty() && !provided {
                roots.sort();
                roots.dedup();
                return Err(format!(
                    "the path names {}, which does not provide {}",
                    roots.join(", "),
                    o.component
                ));
            }
        }
        Ok(())
    }

    /// The packages of the CBOM whose library is the crate `name` (the crate a symbol's path
    /// starts with).
    fn lib_refs(&self, name: &str) -> Vec<String> {
        let refs = match &self.libs {
            Some(l) => l.get(name).cloned().unwrap_or_default(),
            None => self.crate_refs(None, name),
        };
        refs.into_iter()
            .filter(|r| self.graph.packages.contains(r))
            .collect()
    }

    /// A package that provides no asset by being named: the program's own, or an interface
    /// crate (`digest`, `aead`, `signature`: their traits are implemented by others).
    fn neutral(&self, r: &str) -> bool {
        r.strip_prefix("pkg:cargo/")
            .and_then(|nv| nv.split_once('@'))
            .and_then(|(n, v)| self.man.by_name_version(n, v))
            .is_some_and(|p| p.local || matches!(p.role, Some(rcbom_kb::Role::Trait)))
    }

    /// Whether binding `b` (`use x::y::ident as name;`) is an alias of the item `ident` of crate
    /// `krate`: imported from that crate, from one that depends on it (a re-export), or from the
    /// program's own module when the package imports `ident` from such a crate (a local
    /// re-export); not an unrelated item that happens to share the last segment.
    fn alias_of(
        &self,
        b: &Binding,
        ident: &str,
        krate: &str,
        owner: Option<&str>,
        binds: &[Binding],
    ) -> bool {
        if b.path.last().map(String::as_str) != Some(ident) || b.name == ident {
            return false;
        }
        let target = self.lib_refs(krate);
        // the symbol's crate is not a package of the CBOM (the standard library): no check
        if target.is_empty() {
            return true;
        }
        let from = |root: &str| {
            self.crate_refs(owner, root)
                .iter()
                .any(|r| target.iter().any(|t| self.graph.closure(r).contains(t)))
        };
        match b.path.first().map(String::as_str) {
            Some("crate" | "self" | "super") => binds.iter().any(|o| {
                o.name == ident
                    && o.path.last().map(String::as_str) == Some(ident)
                    && o.path.first().is_some_and(|r| {
                        !matches!(r.as_str(), "crate" | "self" | "super") && from(r)
                    })
            }),
            Some(root) => root == krate || from(root),
            None => false,
        }
    }

    /// The positions a context's details name: `instantiated by <caller> at <file>:<line>`
    /// (where a generic instance was instantiated) and `expanded from <file>:<line>` (where a
    /// macro's code is written) must be lines of code of files that exist; a standard-library
    /// file is read from the pinned toolchain, whose commit it must name. Outside the standard
    /// library, an instantiation's line is in the caller and names what it instantiates (the
    /// occurrence's item, then each caller in turn; a closure is instantiated where it is
    /// written), and a macro's line is in the body of the `macro_rules!` of its tag.
    fn check_details(
        &mut self,
        details: &str,
        tags: &str,
        symbol: &str,
        call_line: Option<&str>,
    ) -> Result<(), String> {
        let mut callee = details
            .strip_prefix(tags)
            .unwrap_or(details)
            .strip_prefix("in ")
            .and_then(|d| d.split("; ").next())
            .map(str::to_string);
        // the names of the occurrence's item and of the callers so far
        let mut earlier: Vec<String> = callee
            .as_deref()
            .and_then(in_item)
            .map(|n| n.name)
            .into_iter()
            .collect();
        for part in details.split("; ") {
            let Some(m) =
                re!(r"^(instantiated by (.*) at|expanded from) ([^\s;]+):(\d+)$").captures(part)
            else {
                continue;
            };
            let (file, line) = (m[3].to_string(), m[4].parse::<usize>().unwrap_or(0));
            let caller = m.get(2).map(|c| c.as_str().to_string());
            let path = self.resolve(&file)?;
            let src = self
                .source(&path)
                .ok_or_else(|| format!("cannot read {file}, named in `{part}`"))?;
            let cols: Vec<usize> = src
                .class
                .get(line.wrapping_sub(1))
                .zip(src.lines.get(line.wrapping_sub(1)))
                .map(|(cls, l)| {
                    l.chars()
                        .zip(cls)
                        .enumerate()
                        .filter(|(_, (c, k))| **k == Class::Code && !c.is_whitespace())
                        .map(|(j, _)| j)
                        .collect()
                })
                .unwrap_or_default();
            if cols.is_empty() {
                return Err(format!("`{part}`: no code at line {line} of {file}"));
            }
            if file.starts_with("/rustc/") {
                if let Some(n) = caller.as_deref().and_then(in_item) {
                    earlier.push(n.name);
                }
                callee = caller;
                continue;
            }
            match &caller {
                Some(c) => {
                    let want = in_item(c).ok_or_else(|| format!("`{part}`: no item"))?;
                    let inside = cols.iter().any(|&col| {
                        src.enclosing((line, col), &[ItemKind::Fn, ItemKind::Static])
                            .is_some_and(|i| i.name == want.name)
                            || src.enclosing((line, col), &[ItemKind::MacroCall]).is_some()
                    });
                    if !inside {
                        return Err(format!("`{part}`: line {line} is not in `{}`", want.name));
                    }
                    // the line names what it instantiates, unless that is a closure: the item
                    // or a caller before it (an occurrence instantiated along two chains lists
                    // both last callers, each naming the item before them)
                    if let Some(prev) = &callee
                        && !prev.trim_end().ends_with('}')
                    {
                        let text = &src.lines[line - 1];
                        let named = earlier.iter().any(|n| {
                            Regex::new(&format!(r"\b{}\b", regex::escape(n)))
                                .unwrap()
                                .is_match(text)
                        });
                        if !named {
                            return Err(format!(
                                "`{part}`: line {line} does not name `{}`",
                                in_item(prev).map(|n| n.name).unwrap_or_default()
                            ));
                        }
                    }
                    if let Some(n) = in_item(c) {
                        earlier.push(n.name);
                    }
                    callee = Some(c.clone());
                }
                None => {
                    // a derive's or an attribute's code is the procedural macro's: only the line
                    // of its use is known
                    let Some(t) = re!(r"\[macro (?:[\w]+::)*(\w+)!\]").captures(tags) else {
                        continue;
                    };
                    let inside = src
                        .enclosing((line, cols[0]), &[ItemKind::Macro])
                        .is_some_and(|m| m.name == t[1]);
                    if !inside {
                        return Err(format!(
                            "`{part}`: line {line} is not in the body of `macro_rules! {}`",
                            &t[1]
                        ));
                    }
                    // the macro's line names the symbol, or the call passes it in
                    // (`hash_with!(SHA384)` for a body calling `digest(&$alg, ..)`)
                    let sym = strip_generics(symbol);
                    let ident = sym.rsplit("::").next().unwrap_or(&sym);
                    let word = Regex::new(&format!(r"\b{}\b", regex::escape(ident))).unwrap();
                    if !word.is_match(&src.lines[line - 1])
                        && !call_line.is_some_and(|l| word.is_match(l))
                    {
                        return Err(format!(
                            "`{part}`: line {line} of the macro does not name `{ident}`"
                        ));
                    }
                }
            }
        }
        Ok(())
    }
}

/// The item a context says an occurrence is in (`in t1::xchacha`, `in <A as T>::f::{closure#0}`,
/// `in r1::Jar::<J>::seal`): its name, and the type and trait of the impl block it is a
/// method of (`A`, `T`), when its path names them.
struct InItem {
    name: String,
    self_ty: Option<String>,
    trait_name: Option<String>,
}

fn in_item(item: &str) -> Option<InItem> {
    // the path's segments, generic arguments kept whole
    let chars: Vec<char> = item.chars().collect();
    let mut segs = Vec::new();
    let (mut depth, mut cur, mut k) = (0i32, String::new(), 0);
    while k < chars.len() {
        let c = chars[k];
        match c {
            '<' => depth += 1,
            '>' if k == 0 || chars[k - 1] != '-' => depth -= 1,
            _ => {}
        }
        if depth == 0 && c == ':' && chars.get(k + 1) == Some(&':') {
            segs.push(std::mem::take(&mut cur));
            k += 2;
            continue;
        }
        cur.push(c);
        k += 1;
    }
    segs.push(cur);
    let last_of = |t: &str| {
        let t = strip_generics(t);
        let t = t.trim().trim_start_matches(['&', '*']).trim().to_string();
        t.rsplit("::").next().unwrap_or(&t).trim().to_string()
    };
    // generic arguments (`<J>`, `<..>`) and what the compiler makes (`{closure#0}`) are not
    // items written in the source
    segs.retain(|g| {
        !g.starts_with('{')
            && !(g.starts_with('<') && !g.contains(" as ") && !g.starts_with("<impl "))
    });
    let name = segs.pop()?;
    let (mut self_ty, mut trait_name) = (None, None);
    if let Some(g) = segs.last() {
        if let Some(inner) = g.strip_prefix('<').and_then(|g| g.strip_suffix('>')) {
            if let Some(t) = inner.strip_prefix("impl ") {
                self_ty = Some(last_of(t));
            } else if let Some((t, tr)) = inner.split_once(" as ") {
                self_ty = Some(last_of(t));
                trait_name = Some(norm_path(tr));
            }
        } else if g.chars().next().is_some_and(char::is_uppercase) {
            self_ty = Some(last_of(g));
        }
    }
    Some(InItem {
        name: strip_generics(&name),
        self_ty,
        trait_name,
    })
}

/// A type or trait path as compared between a context and the source: paths cut to their last
/// segment at every level, lifetimes and blanks dropped (`core::convert::TryFrom<&rustls_pki_types::
/// PrivateKeyDer<'_>>` -> `TryFrom<&PrivateKeyDer>`).
fn norm_path(t: &str) -> String {
    let t = re!(r"\b\w+::").replace_all(t.trim(), "");
    let t = re!(r"'\w+\s*,?").replace_all(&t, "");
    let t: String = t.chars().filter(|c| !c.is_whitespace()).collect();
    t.replace("<>", "").replace(",>", ">")
}

/// Two traits are one: the same path, or the same name where either has no arguments.
fn same_trait(a: &str, b: &str) -> bool {
    let name = |t: &str| t.split('<').next().unwrap_or(t).to_string();
    a == b || (name(a) == name(b) && (!a.contains('<') || !b.contains('<')))
}

/// A code position is inside the item its context names (`in <item>; ..`): the innermost
/// function, static or const around it has the item's name, and, for a method whose path names
/// its type, the impl block (or the trait, for a default method) around that names it too. Not
/// inside a `macro_rules!` body.
fn check_item(src: &Source, details: &str, at: (usize, usize)) -> Result<(), String> {
    if let Some(m) = src.enclosing(at, &[ItemKind::Macro]) {
        return Err(format!(
            "position inside the body of `macro_rules! {}`",
            m.name
        ));
    }
    let Some(want) = details
        .strip_prefix("in ")
        .and_then(|d| d.split("; ").next())
        .and_then(in_item)
    else {
        return Err("no enclosing item in the context".into());
    };
    let Some(item) = src.enclosing(at, &[ItemKind::Fn, ItemKind::Static]) else {
        if src.enclosing(at, &[ItemKind::MacroCall]).is_some() {
            return Ok(());
        }
        return Err(format!("position outside any item, not in `{}`", want.name));
    };
    // code a macro's invocation wraps (`thread_local! { static TL: .. = digest(..) }`) is in
    // the items the macro makes, named by it
    let in_call = src.enclosing(at, &[ItemKind::MacroCall]).is_some();
    if item.name != want.name {
        if in_call {
            return Ok(());
        }
        return Err(format!(
            "position in `{}`, not in `{}`",
            item.name, want.name
        ));
    }
    // the block the function is written in (not the function itself)
    let container = src
        .items
        .iter()
        .filter(|i| {
            matches!(i.kind, ItemKind::Impl | ItemKind::Trait | ItemKind::Fn)
                && i.start < item.start
                && i.contains(item.start)
        })
        .max_by_key(|i| i.start);
    if let Some(ty) = &want.self_ty
        && let Some(block) = container
    {
        let ok = match block.kind {
            // a blanket impl's type is any type: its trait is named
            ItemKind::Impl if block.name.is_empty() => {
                matches!((&block.trait_name, &want.trait_name), (Some(a), Some(b)) if same_trait(a, b))
            }
            // its type, and the trait it implements: `impl TryFrom<&PrivateKeyDer<'_>> for
            // KeyPair` is not `impl TryFrom<&[u8]> for KeyPair`
            ItemKind::Impl => {
                block.name == *ty
                    && match (&block.trait_name, &want.trait_name) {
                        (Some(a), Some(b)) => same_trait(a, b),
                        _ => true,
                    }
            }
            ItemKind::Trait => {
                block.name == *ty
                    || want
                        .trait_name
                        .as_deref()
                        .is_some_and(|t| same_trait(&block.name, t))
            }
            // a function inside a function: no impl block of its own
            _ => true,
        };
        if !ok {
            return Err(format!(
                "position in a method of `{}`, not of `{ty}`",
                block.name
            ));
        }
    }
    Ok(())
}

/// The text of the attribute a position is in, from after its `#[` (or `#![`) to the position:
/// the code before the position, over a few lines, back to the last `#[` with its brackets still
/// open. None when the position is in no attribute.
fn attribute_before(src: &Source, line: usize, offset: usize) -> Option<String> {
    let mut code = String::new();
    for l in (line.saturating_sub(12).max(1)..=line).rev() {
        let chars: Vec<char> = src.lines[l - 1].chars().collect();
        let end = if l == line {
            offset.min(chars.len())
        } else {
            chars.len()
        };
        let part: String = chars[..end]
            .iter()
            .zip(&src.class[l - 1])
            .map(|(&c, k)| if *k == Class::Code { c } else { ' ' })
            .collect();
        code = format!("{part}\n{code}");
        if let Some(i) = code.rfind("#[").or_else(|| code.rfind("#![")) {
            let open = code[i..].find('[').unwrap() + i + 1;
            let inner = &code[open..];
            let depth: i32 = inner
                .chars()
                .map(|c| match c {
                    '[' | '(' => 1,
                    ']' | ')' => -1,
                    _ => 0,
                })
                .sum();
            return (depth >= 0 && !inner.contains(']')).then(|| inner.trim_start().to_string());
        }
    }
    None
}

/// Whether, in an attribute's text up to a position, a `name(` is still open there.
fn open_in(attr: &str, name: &str) -> bool {
    let Some(i) = attr.rfind(&format!("{name}(")).or_else(|| {
        Regex::new(&format!(r"{}\s+\(", regex::escape(name)))
            .unwrap()
            .find_iter(attr)
            .last()
            .map(|m| m.start())
    }) else {
        return false;
    };
    let mut depth = 0i32;
    for c in attr[i..].chars() {
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            _ => {}
        }
    }
    depth >= 1
}

/// The identifier just before a position (whitespace and comments skipped, over a few lines),
/// when the token before it is one: `fn` in `fn seal<..>`, `macro_rules` in `macro_rules! m`.
fn word_before(src: &Source, line: usize, offset: usize) -> Option<String> {
    let mut code = String::new();
    for l in line.saturating_sub(4).max(1)..=line {
        let chars: Vec<char> = src.lines[l - 1].chars().collect();
        let end = if l == line {
            offset.min(chars.len())
        } else {
            chars.len()
        };
        code.extend(
            chars[..end]
                .iter()
                .zip(&src.class[l - 1])
                .map(|(&c, k)| if *k == Class::Comment { ' ' } else { c }),
        );
        code.push(' ');
    }
    let code = code.trim_end();
    let code = code.strip_suffix('!').unwrap_or(code);
    let word: String = code
        .chars()
        .rev()
        .take_while(|&c| is_ident(c))
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    (!word.is_empty()).then_some(word)
}

/// The source from a position on, over the next 63 lines: chars and their classes. A path is
/// read from it with its generic arguments balanced, so the extent only bounds a path rustfmt
/// spread over many lines.
fn rest(src: &Source, line: usize, offset: usize) -> (Vec<char>, Vec<Class>) {
    let mut s = Vec::new();
    let mut k = Vec::new();
    for (n, l) in src.lines.iter().enumerate().skip(line - 1).take(64) {
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

    #[test]
    fn items_and_their_names() {
        let src = Source::new(
            "impl<T: AsRef<[u8]>> Sealer<T> {\n    fn seal(&self) -> impl Fn() -> u8 {\n        || 1\n    }\n}\nimpl TryFrom<&PrivateKeyDer<'_>> for KeyPair {\n    fn try_from(k: &PrivateKeyDer) -> Self { todo!() }\n}\nstatic S: &'static str = \"fn x() {\";\nmacro_rules! m {\n    () => { fn inner() {} };\n}\n",
            true,
            false,
        );
        let at = |l, c| {
            src.enclosing((l, c), &[ItemKind::Fn, ItemKind::Static])
                .map(|i| i.name.clone())
        };
        assert_eq!(at(3, 8).as_deref(), Some("seal"));
        assert_eq!(at(7, 45).as_deref(), Some("try_from"));
        assert_eq!(at(9, 30).as_deref(), Some("S"));
        let imp = src.enclosing((3, 8), &[ItemKind::Impl]).unwrap();
        assert_eq!(imp.name, "Sealer");
        let tf = src.enclosing((7, 45), &[ItemKind::Impl]).unwrap();
        assert_eq!(
            (tf.name.as_str(), tf.trait_name.as_deref()),
            ("KeyPair", Some("TryFrom<&PrivateKeyDer>"))
        );
        assert!(src.enclosing((11, 12), &[ItemKind::Macro]).is_some());
        // a `where` clause on its own line (hpke's `impl<D> LabeledExpand for Hkdf<D>`)
        let w = Source::new(
            "impl<D> Expand for Hkdf<D>\nwhere\n    D: BlockSizeUser,\n{\n    fn f() {}\n}\n",
            true,
            false,
        );
        let imp = w.enclosing((5, 8), &[ItemKind::Impl]).unwrap();
        assert_eq!(
            (imp.name.as_str(), imp.trait_name.as_deref()),
            ("Hkdf", Some("Expand"))
        );
        assert!(src.enclosing((9, 30), &[ItemKind::Macro]).is_none());
    }

    #[test]
    fn the_item_a_context_names() {
        let i = in_item("<rcgen::KeyPair as core::convert::TryFrom<&rustls_pki_types::PrivateKeyDer<'_>>>::try_from").unwrap();
        assert_eq!(i.name, "try_from");
        assert_eq!(i.self_ty.as_deref(), Some("KeyPair"));
        assert_eq!(i.trait_name.as_deref(), Some("TryFrom<&PrivateKeyDer>"));
        let i = in_item("r1::Jar::<J>::seal::{closure#0}").unwrap();
        assert_eq!(
            (i.name.as_str(), i.self_ty.as_deref()),
            ("seal", Some("Jar"))
        );
        let i = in_item("v4_public::<impl rusty_paseto::core::Paseto<'_, V4, Public>>::try_sign")
            .unwrap();
        assert_eq!(
            (i.name.as_str(), i.self_ty.as_deref()),
            ("try_sign", Some("Paseto"))
        );
        let i = in_item("t1::xchacha").unwrap();
        assert_eq!((i.name.as_str(), i.self_ty), ("xchacha", None));
        assert!(same_trait("TryFrom", "TryFrom<&PrivateKeyDer>"));
        assert!(!same_trait("TryFrom<&[u8]>", "TryFrom<&PrivateKeyDer>"));
    }

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
        let c = "pkg:cargo/sha2@0.10.9";
        assert_eq!(check_lock(&src.lines, 2, 0, "sha2", ctx, c), Ok(()));
        assert!(check_lock(&src.lines, 2, 1, "sha2", ctx, c).is_err());
        assert!(check_lock(&src.lines, 3, 0, "sha2", ctx, c).is_err());
        assert!(
            check_lock(
                &src.lines,
                2,
                0,
                "sha2",
                "[manifest] locked sha2 0.11.0; x",
                c
            )
            .is_err()
        );
        assert!(check_lock(&src.lines, 2, 0, "sha2", "[manifest] something", c).is_err());
        // the evidence of another version of the package, or of another package
        assert!(check_lock(&src.lines, 2, 0, "sha2", ctx, "pkg:cargo/sha2@0.11.0").is_err());
        assert!(check_lock(&src.lines, 2, 0, "sha2", ctx, "pkg:cargo/sha1@0.10.6").is_err());
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
                "[manifest] declared by p (dependencies)",
                "pkg:cargo/sha2@0.10.9"
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

    /// The package each key of MANIFEST declares, as the CBOM names it.
    fn component(symbol: &str) -> &'static str {
        match symbol {
            "hashing" => "pkg:cargo/sha2@0.10.9",
            "md5" => "pkg:cargo/md5@0.7.0",
            "sha1" => "pkg:cargo/sha1@0.10.6",
            "hmac" => "pkg:cargo/hmac@0.12.1",
            "blake3" => "pkg:cargo/blake3@1.8.5",
            "ring" => "pkg:cargo/ring@0.17.14",
            "links" => "pkg:cargo/t4@0.1.0",
            _ => "pkg:cargo/other@1.0.0",
        }
    }

    fn toml_check(line: usize, col: usize, symbol: &str, ctx: &str) -> Result<(), String> {
        toml_check_of(line, col, symbol, ctx, component(symbol))
    }

    fn toml_check_of(
        line: usize,
        col: usize,
        symbol: &str,
        ctx: &str,
        component: &str,
    ) -> Result<(), String> {
        let src = Source::new(MANIFEST, false, true);
        check_toml(
            &src.toml,
            &src.lines[line - 1],
            line,
            col,
            symbol,
            ctx,
            component,
        )
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
        assert!(toml_check_of(4, 0, "links", links, "pkg:cargo/ring@0.17.14").is_err());
        // a key declaring another package, or a version the requirement excludes
        assert!(toml_check_of(10, 0, "sha1", dep, "pkg:cargo/ring@0.17.14").is_err());
        assert!(toml_check_of(8, 0, "hashing", dep, "pkg:cargo/sha2@0.11.0").is_err());
        assert!(toml_check_of(16, 14, "hmac", dep, "pkg:cargo/hmac@0.13.0").is_err());
        assert!(toml_check_of(9, 0, "md5", dep, "pkg:cargo/md5@0.8.0").is_err());
        // a root dotted key into the table
        let root = Source::new(
            "dependencies.zeta = \"1\"\n[package]\nname = \"t4\"\n",
            false,
            true,
        );
        assert_eq!(
            check_toml(
                &root.toml,
                &root.lines[0],
                1,
                13,
                "zeta",
                dep,
                "pkg:cargo/zeta@1.2.0"
            ),
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
        let renamed = |ident: &str| {
            src.binds
                .iter()
                .filter(|b| b.path.last().is_some_and(|l| l == ident) && b.name != ident)
                .map(|b| b.name.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(renamed("Sha256"), vec!["Hasher"]);
        assert_eq!(renamed("Aead"), vec!["A"]);
        for local in ["D", "N", "Wrapper"] {
            assert!(src.locals.contains(local), "{local}");
        }
        assert!(!src.locals.contains("Hasher"));
    }
}
