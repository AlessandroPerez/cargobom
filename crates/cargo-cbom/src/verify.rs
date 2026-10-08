//! `cargo cbom verify`: reopen every file a CBOM cites and check that the code at
//! `line`/`offset` names what `symbol` says was found. Independent of the driver's span
//! handling, so an off-by-one line or column fails.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::Result;
use rcbom_kb::Kb;
use regex::Regex;
use serde_json::Value;

struct Occ {
    component: String,
    location: String,
    line: usize,
    offset: usize,
    symbol: String,
    context: String,
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
    let man = rcbom_manifest::load(
        manifest_path,
        &rcbom_manifest::host_triple()?,
        &features,
        &kb,
    )?;
    let mut occs = Vec::new();
    let mut without_line = 0;
    for c in doc["components"].as_array().into_iter().flatten() {
        for o in c["evidence"]["occurrences"]
            .as_array()
            .into_iter()
            .flatten()
        {
            let Some(line) = o["line"].as_u64() else {
                without_line += 1;
                continue;
            };
            occs.push(Occ {
                component: c["name"].as_str().unwrap_or("").into(),
                location: o["location"].as_str().unwrap_or("").into(),
                line: line as usize,
                offset: o["offset"].as_u64().unwrap_or(0) as usize,
                symbol: o["symbol"].as_str().unwrap_or("").into(),
                context: o["additionalContext"].as_str().unwrap_or("").into(),
            });
        }
    }
    let mut files = Files {
        man: &man,
        cache: HashMap::new(),
    };
    let mut bad = 0;
    for o in &occs {
        if let Err(e) = files.check(o, o.line, o.offset) {
            bad += 1;
            println!(
                "MISMATCH {} {}:{}:{}: {e}",
                o.component, o.location, o.line, o.offset
            );
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
            let caught = occs
                .iter()
                .filter(|o| {
                    let l = (o.line as i64 + dl).max(0) as usize;
                    let c = (o.offset as i64 + dc).max(0) as usize;
                    (l, c) == (o.line, o.offset) || files.check(o, l, c).is_err()
                })
                .count();
            println!(
                "self-test {what}: {caught}/{} shifted positions rejected",
                occs.len()
            );
        }
    }
    if bad > 0 {
        anyhow::bail!("{bad} positions do not match the source");
    }
    Ok(())
}

struct Files<'a> {
    man: &'a rcbom_manifest::Manifest,
    cache: HashMap<PathBuf, Option<Vec<String>>>,
}

fn strip_generics(s: &str) -> String {
    let re = Regex::new(r"<[^<>]*>").unwrap();
    let mut s = s.to_string();
    loop {
        let n = re.replace_all(&s, "").to_string();
        if n == s {
            return s;
        }
        s = n;
    }
}

impl Files<'_> {
    fn check(&mut self, o: &Occ, line: usize, offset: usize) -> Result<(), String> {
        let path = self.man.resolve(&o.location);
        let lines = self
            .cache
            .entry(path.clone())
            .or_insert_with(|| {
                std::fs::read_to_string(&path)
                    .ok()
                    .map(|t| t.split('\n').map(str::to_string).collect())
            })
            .as_ref()
            .ok_or_else(|| format!("cannot read {}", path.display()))?;
        let text = lines.get(line.wrapping_sub(1)).ok_or("line out of range")?;
        let chars: Vec<char> = text.chars().collect();
        if offset > chars.len() {
            return Err("offset past end of line".into());
        }
        let at: String = chars[offset..].iter().collect();
        let prev = offset.checked_sub(1).map(|i| chars[i]);
        let starts_token = prev.is_none_or(|c| !(c.is_alphanumeric() || c == '_' || c == ':'));

        if o.context.starts_with("[manifest]") {
            let ok = if o.location.ends_with("Cargo.lock") {
                at.starts_with(&format!("name = \"{}\"", o.symbol))
            } else {
                at.starts_with(&o.symbol) || at.starts_with(&format!("\"{}\"", o.symbol))
            };
            return if ok && starts_token {
                Ok(())
            } else {
                Err(format!("expected `{}` in {text:?}", o.symbol))
            };
        }
        if let Some(m) = Regex::new(r"\[macro ([\w:]+!)\]")
            .unwrap()
            .captures(&o.context)
        {
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
        if let Some(m) = Regex::new(r"\[derive ([\w:]+)\]")
            .unwrap()
            .captures(&o.context)
        {
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
        if o.context.contains("[attribute ") {
            return if at.starts_with('#') {
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
        let whole = lines.join("\n");
        let mut names = vec![ident.clone()];
        let alias = Regex::new(&format!(r"\b{}\s+as\s+(\w+)", regex::escape(&ident))).unwrap();
        names.extend(alias.captures_iter(&whole).map(|c| c[1].to_string()));
        let ok = names.iter().any(|n| {
            Regex::new(&format!(
                r"^(?:<.*?>::)?(?:\w+(?:::<.*?>)?::)*{}\b",
                regex::escape(n)
            ))
            .unwrap()
            .is_match(&at)
        });
        if ok && starts_token {
            Ok(())
        } else {
            Err(format!("expected `{ident}` in {text:?}"))
        }
    }
}
