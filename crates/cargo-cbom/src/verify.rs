//! `cargo cbom verify`: reopen every file a CBOM cites and check that the code at
//! `line`/`offset` names what `symbol` says was found. Independent of the driver's span
//! handling, so an off-by-one line or column fails.
//!
//! A code position must start a token, lie in code (not in a comment or a literal), and begin
//! a path whose last segment is the symbol's name or an import alias of it. Besides:
//! - the source line, and the text at the position, are those the context records
//!   (`line: `..``, `code: `..``), when it records them;
//! - one asset has one occurrence per (position, symbol), as the generator writes them;
//! - a `[component] .. part of X` occurrence is where X is;
//! - a path qualified by a type the source imports from a crate of the CBOM (`Hmac::<Sha256>::`)
//!   is evidence only of what that crate, or one it depends on, provides.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

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
    /// crate identifier (`aes_gcm`) -> package bom-ref
    crate_ref: HashMap<String, String>,
    depends_on: HashMap<String, Vec<String>>,
    /// asset bom-ref -> package bom-refs providing it
    providers: HashMap<String, HashSet<String>>,
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
    let man = rcbom_manifest::load_locked(
        manifest_path,
        &rcbom_manifest::host_triple()?,
        &features,
        &kb,
    )?;
    let mut graph = Graph {
        crate_ref: HashMap::new(),
        depends_on: HashMap::new(),
        providers: HashMap::new(),
    };
    for c in doc["components"].as_array().into_iter().flatten() {
        if matches!(
            c["type"].as_str(),
            Some("library" | "application" | "framework")
        ) && let (Some(n), Some(r)) = (c["name"].as_str(), c["bom-ref"].as_str())
        {
            graph.crate_ref.insert(n.replace('-', "_"), r.to_string());
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
        sysroot: None,
        cache: HashMap::new(),
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

struct Source {
    lines: Vec<String>,
    /// per line, per char: true when the char is code (not in a comment, string or char literal)
    code: Vec<Vec<bool>>,
    /// the file with comments and literals blanked, for finding `use` items
    code_text: String,
}

struct Files<'a> {
    man: &'a rcbom_manifest::Manifest,
    /// The pinned toolchain's sysroot, for `/rustc/<commit>/library/..` locations; read when
    /// first needed
    sysroot: Option<Option<PathBuf>>,
    cache: HashMap<PathBuf, Option<std::rc::Rc<Source>>>,
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

/// Marks which chars of a Rust source are code: not inside `//` or `/* */` comments (nested),
/// string literals (`"..."`, `b".."`, `c".."`, raw `r#".."#`), or char literals.
fn lex(text: &str) -> (Vec<Vec<bool>>, String) {
    let chars: Vec<char> = text.chars().collect();
    let mut code = vec![true; chars.len()];
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        let prev_ident = i > 0 && is_ident(chars[i - 1]);
        if c == '/' && next == Some('/') {
            while i < chars.len() && chars[i] != '\n' {
                code[i] = false;
                i += 1;
            }
        } else if c == '/' && next == Some('*') {
            let mut depth = 0;
            while i < chars.len() {
                if chars[i] == '/' && chars.get(i + 1) == Some(&'*') {
                    depth += 1;
                    code[i] = false;
                    code[i + 1] = false;
                    i += 2;
                } else if chars[i] == '*' && chars.get(i + 1) == Some(&'/') {
                    depth -= 1;
                    code[i] = false;
                    code[i + 1] = false;
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    code[i] = false;
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
            for k in code.iter_mut().take(j.min(chars.len())).skip(i) {
                *k = false;
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
            for k in code.iter_mut().take(end).skip(i) {
                *k = false;
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
                    for k in code.iter_mut().take(e).skip(i) {
                        *k = false;
                    }
                    i = e;
                }
                None => i += 1,
            }
        } else {
            i += 1;
        }
    }
    let mut per_line = vec![Vec::new()];
    let mut blank = String::with_capacity(text.len());
    for (k, &c) in chars.iter().enumerate() {
        if c == '\n' {
            per_line.push(Vec::new());
            blank.push('\n');
        } else {
            per_line.last_mut().unwrap().push(code[k]);
            blank.push(if code[k] { c } else { ' ' });
        }
    }
    (per_line, blank)
}

/// Skips a balanced `<...>` starting at `i` (which must be `<`); `->` does not close.
fn skip_angle(s: &[char], mut i: usize) -> Option<usize> {
    let mut depth = 0;
    while i < s.len() {
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
        i += 1;
    }
    None
}

fn ws(s: &[char], mut i: usize) -> usize {
    while s.get(i).is_some_and(|c| c.is_whitespace()) {
        i += 1;
    }
    i
}

/// The path at the start of `at`: `(<T as Tr>::)? (seg (::<..>)? ::)* last`, as its idents
/// (qualifiers first) and the final segment. Whitespace and line breaks between tokens are
/// allowed (rustfmt breaks long turbofishes and qualified paths). None if `at` does not start
/// with a path.
fn path_at(at: &str) -> Option<(Vec<String>, String)> {
    path_and_generics(at).map(|(q, l, _)| (q, l))
}

/// Like `path_at`, plus the first segment of every path written inside the generic arguments
/// (`Hmac::<sha2::Sha256>::new` gives `sha2`).
fn path_and_generics(at: &str) -> Option<(Vec<String>, String, Vec<String>)> {
    let s: Vec<char> = at.chars().collect();
    let mut generics: Vec<String> = Vec::new();
    let mut heads = |from: usize, to: usize| {
        let mut k = from;
        while k < to {
            if is_ident(s[k]) && !s[k].is_ascii_digit() {
                let st = k;
                while k < to && is_ident(s[k]) {
                    k += 1;
                }
                let before: String = s[from..st].iter().collect();
                if !before.trim_end().ends_with("::") && s.get(st.wrapping_sub(1)) != Some(&'\'') {
                    generics.push(s[st..k].iter().collect());
                }
            } else {
                k += 1;
            }
        }
    };
    let colons = |i: usize| s.get(i) == Some(&':') && s.get(i + 1) == Some(&':');
    let mut i = 0;
    if s.first() == Some(&'<') {
        i = ws(&s, skip_angle(&s, 0)?);
        heads(1, i - 1);
        if !colons(i) {
            return None;
        }
        i = ws(&s, i + 2);
    }
    let mut segs = Vec::new();
    loop {
        let start = i;
        while i < s.len() && is_ident(s[i]) {
            i += 1;
        }
        if i == start {
            return None;
        }
        segs.push(s[start..i].iter().collect::<String>());
        // `::<..>` turbofish
        let mut j = ws(&s, i);
        if colons(j) && s.get(ws(&s, j + 2)) == Some(&'<') {
            let open = ws(&s, j + 2);
            let close = skip_angle(&s, open)?;
            heads(open + 1, close - 1);
            j = ws(&s, close);
        }
        if colons(j) && s.get(ws(&s, j + 2)).is_some_and(|&c| is_ident(c)) {
            i = ws(&s, j + 2);
            continue;
        }
        let last = segs.pop().unwrap();
        return Some((segs, last, generics));
    }
}

impl Files<'_> {
    fn source(&mut self, path: &Path) -> Option<std::rc::Rc<Source>> {
        self.cache
            .entry(path.to_path_buf())
            .or_insert_with(|| {
                let mut t = std::fs::read_to_string(path).ok()?;
                let rust = path.extension().is_some_and(|e| e == "rs");
                // rustc drops a byte-order mark before counting columns
                if rust && t.starts_with('\u{feff}') {
                    t.remove(0);
                }
                let (code, code_text) = if rust {
                    lex(&t)
                } else {
                    (
                        t.split('\n')
                            .map(|l| vec![true; l.chars().count()])
                            .collect(),
                        t.clone(),
                    )
                };
                Some(std::rc::Rc::new(Source {
                    lines: t.split('\n').map(str::to_string).collect(),
                    code,
                    code_text,
                }))
            })
            .clone()
    }

    /// A location's file. The standard library's sources are named as rustc names them
    /// (`/rustc/<commit>/library/core/src/ops/function.rs`); they are read from the toolchain's
    /// rust-src component (`<sysroot>/lib/rustlib/src/rust/library/..`).
    fn resolve(&mut self, location: &str) -> PathBuf {
        if let Some(rest) = location.strip_prefix("/rustc/")
            && let Some((_commit, rest)) = rest.split_once('/')
        {
            let sysroot = self
                .sysroot
                .get_or_insert_with(|| crate::sysroot().ok().map(PathBuf::from));
            if let Some(s) = sysroot {
                return s.join("lib/rustlib/src/rust").join(rest);
            }
        }
        self.man.resolve(location)
    }

    fn check(&mut self, oi: usize, line: usize, offset: usize) -> Result<(), String> {
        let occs = self.occs;
        let o = &occs[oi];
        let path = self.resolve(&o.location);
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
        let prev = offset.checked_sub(1).map(|i| chars[i]);
        let starts_token = prev.is_none_or(|c| !(c.is_alphanumeric() || c == '_' || c == ':'));
        let in_code = src.code[line - 1].get(offset).copied().unwrap_or(false);
        // the path may continue on the next lines
        let rest: String = std::iter::once(at.clone())
            .chain(src.lines.iter().skip(line).take(8).cloned())
            .collect::<Vec<_>>()
            .join("\n");

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
            let ok = if o.location.ends_with("Cargo.lock") {
                let want = format!("name = \"{}\"", o.symbol);
                // the version is in the context: "locked NAME VERSION; ..."
                let version_ok = re!(r"^\[manifest\] locked \S+ (\S+);")
                    .captures(&o.context)
                    .is_none_or(|m| {
                        src.lines.get(line).map(String::as_str)
                            == Some(&format!("version = \"{}\"", &m[1]))
                    });
                at == want && version_ok
            } else {
                // `ring` is not `ring-compat`
                let bounded = |rest: &str| {
                    !rest
                        .chars()
                        .next()
                        .is_some_and(|c| c.is_alphanumeric() || c == '_' || c == '-')
                };
                at.strip_prefix(&o.symbol).is_some_and(bounded)
                    || at.starts_with(&format!("\"{}\"", o.symbol))
            };
            return if ok && starts_token {
                Ok(())
            } else {
                Err(format!("expected `{}` in {text:?}", o.symbol))
            };
        }
        // code positions are in code, not in a comment or a literal
        if !in_code {
            return Err(format!("position inside a comment or literal in {text:?}"));
        }
        // the generator recorded the source line and the exact text it found at the position,
        // last in the context, in that order; the line may hold backquotes, the text does not
        let (before_code, code) = match re!(r"; code: `([^`]*)`$").captures(&o.context) {
            Some(m) => (
                &o.context[..m.get(0).map_or(0, |g| g.start())],
                Some(m[1].to_string()),
            ),
            None => (o.context.as_str(), None),
        };
        if let Some(m) = re!(r"; line: `(.*)`$").captures(before_code)
            && text.trim() != &m[1]
        {
            return Err(format!("expected the line `{}`, found {text:?}", &m[1]));
        }
        if let Some(code) = code
            && !at.starts_with(&code)
        {
            return Err(format!("expected `{code}` in {text:?}"));
        }
        if let Some(m) = re!(r"\[macro ([\w:]+!)\]").captures(&o.context) {
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
        if let Some(m) = re!(r"\[derive ([\w:]+)\]").captures(&o.context) {
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
        if let Some(m) = re!(r"\[attribute ([\w:]+)\]").captures(&o.context) {
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
        // import aliases (`use scrypt::scrypt as scrypt_inner;`, `extern crate x as y;`): only
        // inside `use` and `extern crate` items (comments and literals blanked), where `as`
        // renames, not in casts
        let mut names = vec![ident.clone()];
        let items = re!(r"(?s)\b(?:use|extern\s+crate)\s[^;]*;");
        let alias = Regex::new(&format!(r"\b{}\s+as\s+(\w+)", regex::escape(&ident))).unwrap();
        let use_items: Vec<String> = items
            .find_iter(&src.code_text)
            .map(|m| m.as_str().to_string())
            .collect();
        for item in &use_items {
            names.extend(
                alias
                    .captures_iter(item)
                    .map(|c| c[1].to_string())
                    .filter(|n| n != "_"),
            );
        }
        // a path whose last segment is the name; generic arguments balanced, so the path cannot
        // run on into the next expression
        let ok = path_at(&rest).is_some_and(|(_, last)| names.contains(&last));
        if !(ok && starts_token) {
            return Err(format!("expected `{ident}` in {text:?}"));
        }
        let kind = re!(r"^\[\w+\] \[([\w-]+)\]")
            .captures(&o.context)
            .map(|m| m[1].to_string())
            .unwrap_or_default();
        // a component is used where the asset it is part of is used
        if kind == "component"
            && let Some(m) = re!(r"; part of ([^\s;(]+)").captures(&o.context)
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
                .any(|&j| j != oi && occs[j].component.starts_with(parent));
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
        ) && let Some((quals, _, generics)) = path_and_generics(&rest)
            && let Some(q0) = quals.first()
            && !matches!(q0.as_str(), "crate" | "self" | "super" | "Self")
        {
            let sym_segs: Vec<String> = strip_generics(&o.symbol)
                .split("::")
                .map(|s| s.trim_start_matches('<').to_string())
                .collect();
            let resolve = |n: &str| {
                import_root(&use_items, n)
                    .or_else(|| self.graph.crate_ref.contains_key(n).then(|| n.to_string()))
                    .filter(|r| self.graph.crate_ref.contains_key(r))
            };
            const NEUTRAL: &[&str] = &[
                "u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32", "i64", "i128",
                "isize", "f32", "f64", "bool", "char", "str", "String", "Vec", "Option", "Box",
                "Result", "as", "dyn", "impl", "mut", "const", "fn", "static", "_",
            ];
            if !sym_segs.iter().any(|s| s == q0)
                && let Some(root) = resolve(q0)
                && let Some(provs) = self.graph.providers.get(&o.component_ref)
            {
                let mut roots = vec![root];
                let mut unknown = false;
                for g in generics.iter().filter(|g| !NEUTRAL.contains(&g.as_str())) {
                    match resolve(g) {
                        Some(r) => roots.push(r),
                        // a type parameter or a local type: it could carry the asset
                        None => unknown = true,
                    }
                }
                let provided = roots.iter().any(|r| {
                    let cl = self.graph.closure(&self.graph.crate_ref[r]);
                    provs.iter().any(|p| cl.contains(p))
                });
                if !unknown && !provided {
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

/// The crate a `use` item imports `name` from (`use aes_gcm::{aead::KeyInit, Aes256Gcm};`
/// gives `aes_gcm` for `Aes256Gcm`). None for local paths.
fn import_root(items: &[String], name: &str) -> Option<String> {
    let leaf = Regex::new(&format!(
        r"(?:^|[\s{{,:])(?:{n}\s*(?:[,}};]|$)|\w+\s+as\s+{n}\b)",
        n = regex::escape(name)
    ))
    .unwrap();
    let head = re!(r"^(?:pub(?:\([^)]*\))?\s+)?use\s+(?:::)?(\w+)::(.*)$");
    for item in items {
        let item = item.trim();
        // only the `use` keyword onward
        let Some(start) = item.find("use") else {
            continue;
        };
        let item = item[start..]
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        let Some(m) = head.captures(&item) else {
            continue;
        };
        if leaf.is_match(&m[2]) {
            let root = m[1].to_string();
            return (!matches!(root.as_str(), "crate" | "self" | "super")).then_some(root);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code_at(src: &str, needle: &str) -> bool {
        let (code, _) = lex(src);
        let line = src.lines().position(|l| l.contains(needle)).unwrap();
        let byte = src.lines().nth(line).unwrap().find(needle).unwrap();
        let col = src.lines().nth(line).unwrap()[..byte].chars().count();
        code[line][col]
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
        assert_eq!(
            path_and_generics("Hmac::<sha2::Sha256>::new(k)").unwrap().2,
            vec!["sha2"]
        );
        assert_eq!(
            path_and_generics("SimpleHkdfExtract::<Kdf>::new(s)")
                .unwrap()
                .2,
            vec!["Kdf"]
        );
        assert_eq!(
            path_and_generics("Foo::<'static, [u8; 32]>::new(s)")
                .unwrap()
                .2,
            vec!["u8"]
        );
    }
}
