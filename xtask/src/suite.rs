//! Scores CBOMs against ground-truth labels written from source before any tool run.
//!
//! `cargo xtask suite OUT_DIR PROGRAM_DIR... [--json]`: each PROGRAM_DIR holds `labels.toml`
//! (one `[[site]]` per operation call site: file, line, callee, function, must, may, params) and
//! its CBOM is `OUT_DIR/<dirname>.cbom.json`. Program ids are `<what>-<how>`; scores are given per
//! site, per what, per how and overall.
//!
//! Per labelled site, S is the set of algorithm assets the CBOM cites with a reachable call
//! occurrence at that file and line (on a line holding two labelled calls, the occurrence whose
//! code is that callee). A site the CBOM cites only as present (not reachable) is correct when
//! the labels make it dead, and a miss when they make it live. Names compare as the registry
//! writes them: a name with numeric parameter parts (`PBKDF2-SHA-256-600000-32`,
//! `Argon2id-19456-2-1`) is the labelled name when the parts are the labelled parameters, or
//! when the label fixes none; a family name (`Argon2`, the asset's algorithmFamily) of a labelled
//! algorithm is less specific. Reporting only algorithms outside `must` while missing it, or a
//! reachable `unknown` where nothing runs or may run (a dead site; `must` and `may` empty), is
//! wrong. A correct site whose reported use differs from the labelled function is counted in
//! `function_mismatches`.
//!
//! - correct: must <= S <= must | may, no `unknown`
//! - wrong: a member outside must | may: a misclassification (any report at a dead site)
//! - less-specific: a less specific name of a labelled one (`RSA-PKCS1-1.5` for
//!   `RSA-PKCS1-1.5-SHA-384`), nothing wrong
//! - honest-unknown: `unknown` reported, nothing wrong
//! - miss: a `must` algorithm not reported, nothing wrong
//!
//! Also counted: uses the CBOM reports in the program's own files at lines with no labelled site
//! (`unlabelled`), for review; and sites where several algorithms are reported but one of them
//! is labelled as the only one (`algorithm from X ..`, not `one of N`, `possibly` or
//! `possible`): `label_mismatches`.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use regex::Regex;
use serde_json::Value;

use crate::pyjson::{Val, dumps, repr_list};

pub const VERDICTS: &[&str] = &[
    "correct",
    "wrong",
    "less-specific",
    "honest-unknown",
    "miss",
];

/// A call occurrence in the program's files.
#[derive(Clone, Debug)]
pub struct Occ {
    pub name: String,
    pub code: String,
    pub has_use: bool,
    pub reachable: bool,
    pub family_name: bool,
    pub use_: Option<String>,
    pub ctx: String,
    pub offset: Option<i64>,
}

/// A labelled site.
#[derive(Clone, Debug)]
pub struct Site {
    pub file: String,
    pub line: i64,
    pub callee: String,
    pub function: String,
    pub must: BTreeSet<String>,
    pub may: BTreeSet<String>,
    pub params: BTreeSet<String>,
}

/// The `[[site]]` tables of a labels file.
pub fn sites(labels: &toml::Value) -> Vec<Site> {
    let strs = |v: Option<&toml::Value>| -> BTreeSet<String> {
        v.and_then(toml::Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    };
    labels
        .get("site")
        .and_then(toml::Value::as_array)
        .map(|a| {
            a.iter()
                .map(|s| Site {
                    file: s.get("file").and_then(|v| v.as_str()).unwrap_or("").into(),
                    line: s.get("line").and_then(toml::Value::as_integer).unwrap_or(0),
                    callee: s
                        .get("callee")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .into(),
                    function: s
                        .get("function")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .into(),
                    must: strs(s.get("must")),
                    may: strs(s.get("may")),
                    params: s
                        .get("params")
                        .and_then(toml::Value::as_table)
                        .map(|t| t.values().map(toml_str).collect())
                        .unwrap_or_default(),
                })
                .collect()
        })
        .unwrap_or_default()
}

/// A TOML value as Python's `str` writes it.
fn toml_str(v: &toml::Value) -> String {
    match v {
        toml::Value::String(s) => s.clone(),
        toml::Value::Integer(i) => i.to_string(),
        toml::Value::Float(f) => crate::pyjson::float(*f),
        toml::Value::Boolean(b) => if *b { "True" } else { "False" }.into(),
        other => other.to_string(),
    }
}

/// (file, line) -> the call occurrences of algorithm assets in the program's files.
pub fn occurrences(cbom: &Value) -> HashMap<(String, i64), Vec<Occ>> {
    let dep = Regex::new(r"^[\w.-]+-\d+\.\d+\.\d+[^/]*/").unwrap();
    let code_re = Regex::new(r"; code: `([^`]*)`").unwrap();
    let use_re = Regex::new(r"; use: ([^;]+)").unwrap();
    let mut at: HashMap<(String, i64), Vec<Occ>> = HashMap::new();
    for c in cbom["components"].as_array().into_iter().flatten() {
        if c["type"] != "cryptographic-asset" || c["cryptoProperties"]["assetType"] != "algorithm" {
            continue;
        }
        let family = c["cryptoProperties"]["algorithmProperties"]["algorithmFamily"].as_str();
        let name = c["name"].as_str().unwrap_or("").to_string();
        for o in c["evidence"]["occurrences"]
            .as_array()
            .into_iter()
            .flatten()
        {
            let ctx = o["additionalContext"].as_str().unwrap_or("");
            let loc = o["location"].as_str().unwrap_or("");
            // dependency sources are cited under their package directory (`ring-0.17.14/..`)
            if !ctx.contains("[call]") || dep.is_match(loc) {
                continue;
            }
            let code = code_re
                .captures(ctx)
                .map(|m| m[1].to_string())
                .unwrap_or_else(|| o["symbol"].as_str().unwrap_or("").to_string());
            at.entry((loc.to_string(), o["line"].as_i64().unwrap_or(0)))
                .or_default()
                .push(Occ {
                    name: name.clone(),
                    code,
                    has_use: ctx.contains("; use: "),
                    reachable: ctx.starts_with("[reachable]"),
                    family_name: family == Some(name.as_str()),
                    use_: use_re.captures(ctx).map(|m| m[1].to_string()),
                    ctx: ctx.to_string(),
                    offset: o["offset"].as_i64(),
                });
        }
    }
    at
}

/// The verdict of site `site` given the occurrences cited at it.
pub fn verdict(site: &Site, occ: &[Occ]) -> &'static str {
    let (must, may, params) = (&site.must, &site.may, &site.params);
    // a use, or the labelled call itself: not a constructor on the same line (R1.1, setup)
    let reachable: Vec<&Occ> = occ
        .iter()
        .filter(|o| o.reachable && (o.has_use || o.code.ends_with(&site.callee)))
        .collect();
    if reachable.is_empty() {
        // cited only as present: right for a dead site, a reachability miss for a live one
        return if must.is_empty() && !occ.is_empty() {
            "correct"
        } else if !must.is_empty() {
            "miss"
        } else {
            "correct"
        };
    }
    let names: BTreeSet<&str> = reachable.iter().map(|o| o.name.as_str()).collect();
    let families: BTreeSet<&str> = reachable
        .iter()
        .filter(|o| o.family_name)
        .map(|o| o.name.as_str())
        .collect();
    let labelled: BTreeSet<&String> = must.union(may).collect();
    // the registry's full name carries parameters the labels keep apart
    // (`PBKDF2-SHA-256-600000-32` is PBKDF2-SHA-256 with 600000 iterations, 32 bytes)
    let base = |n: &str| -> String {
        for lab in &labelled {
            let Some(rest) = n.strip_prefix(&format!("{lab}-")) else {
                continue;
            };
            let parts: Vec<&str> = rest.split('-').collect();
            if parts.iter().all(|p| params.contains(*p))
                || (params.is_empty()
                    && parts
                        .iter()
                        .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit())))
            {
                return lab.to_string();
            }
        }
        n.to_string()
    };
    let known: BTreeSet<String> = names
        .iter()
        .map(|n| base(n))
        .filter(|n| n != "unknown")
        .collect();
    let outside: BTreeSet<&String> = known
        .iter()
        .filter(|n| !must.contains(*n) && !may.contains(*n))
        .collect();
    let general: BTreeSet<&String> = outside
        .iter()
        .filter(|n| {
            labelled.iter().any(|m| {
                m.starts_with(&format!("{n}-"))
                    || (families.contains(n.as_str()) && m.starts_with(n.as_str()))
            })
        })
        .copied()
        .collect();
    if outside.iter().any(|n| !general.contains(n)) {
        return "wrong";
    }
    // a reachable operation where none runs, nor may by the reference analysis (a jsonwebtoken
    // decode whose list may hold another family than the key's has the key's algorithms in
    // `may`: that the refusal happens on every way cannot be shown)
    if must.is_empty() && may.is_empty() && names.contains("unknown") {
        return "wrong";
    }
    if !general.is_empty() {
        return "less-specific";
    }
    if names.contains("unknown") {
        return "honest-unknown";
    }
    // only what may also reach it, none of what does: the report names the wrong algorithm
    if !must.is_empty() && !known.is_empty() && known.is_disjoint(must) {
        return "wrong";
    }
    if must.iter().any(|m| !known.contains(m)) {
        return "miss";
    }
    "correct"
}

/// The reachable algorithms labelled as the only one where the call may use several: several
/// algorithms reported for one instance of the call (occurrences grouped by their column and
/// `instantiated by` chain), or one beside an `unknown` (others may reach it). Only occurrences
/// with a use count (a constructor on the same line is no site). A macro invocation expanding
/// several calls at one position, each with its own value (`hash_all!(&d; SHA256, SHA384)`), is
/// no such call.
fn exact_among_several(occ: &[Occ]) -> Vec<String> {
    let chain_re = Regex::new(r"; instantiated by [^;]*").unwrap();
    let inexact = Regex::new(r"; algorithm (one of|possibly|[^;]*selector)").unwrap();
    let sentence_re = Regex::new(r"; (algorithm [^;]*)").unwrap();
    let qualified = Regex::new(r"one of|possibl|selector").unwrap();
    let mut groups: BTreeMap<(Option<i64>, Vec<String>), Vec<&Occ>> = BTreeMap::new();
    for o in occ {
        if !(o.reachable && o.has_use) {
            continue;
        }
        let chain: Vec<String> = chain_re
            .find_iter(&o.ctx)
            .map(|m| m.as_str().to_string())
            .collect();
        groups.entry((o.offset, chain)).or_default().push(o);
    }
    let mut out = BTreeSet::new();
    for group in groups.values() {
        let names: BTreeSet<&str> = group
            .iter()
            .filter(|o| o.name != "unknown")
            .map(|o| o.name.as_str())
            .collect();
        let unknown = group.iter().any(|o| o.name == "unknown");
        if names.len() < 2 && !(!names.is_empty() && unknown) {
            continue;
        }
        let exact = group
            .iter()
            .filter(|o| o.name != "unknown")
            .all(|o| !inexact.is_match(&o.ctx));
        if !unknown && exact && group.iter().all(|o| o.ctx.contains("[macro ")) {
            continue;
        }
        for o in group {
            if o.name == "unknown" {
                continue;
            }
            let sentence = sentence_re
                .captures(&o.ctx)
                .map(|m| m[1].to_string())
                .unwrap_or_default();
            if !qualified.is_match(&sentence) {
                out.insert(o.name.clone());
            }
        }
    }
    out.into_iter().collect()
}

/// A call's code without generic arguments (`decode::<C>` is `decode`).
pub fn bare(code: &str) -> String {
    let (mut out, mut depth) = (String::new(), 0usize);
    for ch in code.chars() {
        if ch == '<' {
            depth += 1;
        } else if ch == '>' && depth > 0 {
            depth -= 1;
        } else if depth == 0 {
            out.push(ch);
        }
    }
    out.replace("::::", "::").trim_end_matches(':').to_string()
}

/// Does a reported use of a reachable occurrence agree with the labelled function? The labelled
/// call reported only as set-up (`new: setup, not a use`) does not.
pub fn function_matches(site: &Site, occ: &[Occ]) -> bool {
    let uses: BTreeSet<&str> = occ
        .iter()
        .filter(|o| o.reachable)
        .filter_map(|o| o.use_.as_deref())
        .flat_map(|u| u.split(" or "))
        .collect();
    if uses.is_empty() {
        return !occ
            .iter()
            .any(|o| o.reachable && !o.has_use && bare(&o.code).ends_with(&site.callee));
    }
    uses.contains(site.function.as_str())
}

/// `cargo xtask suite OUT_DIR PROGRAM_DIR... [--json]`.
pub fn run(args: &[String]) -> Result<()> {
    let json = args.iter().any(|a| a == "--json");
    let args: Vec<&String> = args.iter().filter(|a| !a.starts_with("--")).collect();
    let (out_dir, programs) = args
        .split_first()
        .context("usage: cargo xtask suite OUT_DIR PROGRAM_DIR... [--json]")?;
    let mut programs: Vec<PathBuf> = programs
        .iter()
        .map(|p| PathBuf::from(p.trim_end_matches('/')))
        .collect();
    programs.sort();
    print!("{}", score(Path::new(out_dir.as_str()), &programs, json)?);
    Ok(())
}

/// The suite's score of the CBOMs in `out_dir`, as JSON or as the text report.
pub fn score(out_dir: &Path, programs: &[PathBuf], json: bool) -> Result<String> {
    let mut total: BTreeMap<&str, usize> = BTreeMap::new();
    let mut by_what: BTreeMap<String, BTreeMap<&str, usize>> = BTreeMap::new();
    let mut by_how: BTreeMap<String, BTreeMap<&str, usize>> = BTreeMap::new();
    let (mut details, mut unlabelled) = (Vec::new(), 0usize);
    let (mut function_mismatches, mut label_mismatches) = (Vec::new(), Vec::new());
    for prog in programs {
        let pid = prog
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();
        let (what, how) = pid.split_once('-').unwrap_or((pid.as_str(), ""));
        let labels: toml::Value = toml::from_str(
            &std::fs::read_to_string(prog.join("labels.toml"))
                .with_context(|| format!("{}/labels.toml", prog.display()))?,
        )?;
        let sites = sites(&labels);
        let cbom_path = out_dir.join(format!("{pid}.cbom.json"));
        let exists = cbom_path.exists();
        let at = if exists {
            occurrences(&serde_json::from_str(&std::fs::read_to_string(
                &cbom_path,
            )?)?)
        } else {
            HashMap::new()
        };
        let mut labelled_lines: HashMap<(String, i64), usize> = HashMap::new();
        let mut same_callee: HashMap<(String, i64, String), Vec<usize>> = HashMap::new();
        for (i, s) in sites.iter().enumerate() {
            *labelled_lines.entry((s.file.clone(), s.line)).or_default() += 1;
            same_callee
                .entry((s.file.clone(), s.line, s.callee.clone()))
                .or_default()
                .push(i);
        }
        for (si, s) in sites.iter().enumerate() {
            let mut occ: Vec<Occ> = at
                .get(&(s.file.clone(), s.line))
                .cloned()
                .unwrap_or_default();
            // the occurrences naming the labelled callee, when any does (another call on the
            // line, a constructor, an `update`, is not this site)
            let named: Vec<Occ> = occ
                .iter()
                .filter(|o| bare(&o.code).ends_with(&s.callee))
                .cloned()
                .collect();
            if !named.is_empty() || labelled_lines[&(s.file.clone(), s.line)] > 1 {
                occ = named;
            }
            // several labelled calls of one callee on one line (`digest(a, digest(b, ..))`):
            // the i-th in the labels is the i-th by column (outer first)
            let group = &same_callee[&(s.file.clone(), s.line, s.callee.clone())];
            if group.len() > 1 {
                let cols: Vec<i64> = occ
                    .iter()
                    .filter_map(|o| o.offset)
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect();
                let i = group.iter().position(|&x| x == si).unwrap_or(0);
                occ.retain(|o| i < cols.len() && o.offset == Some(cols[i]));
            }
            let v = if exists { verdict(s, &occ) } else { "miss" };
            let exact = exact_among_several(&occ);
            if !exact.is_empty() {
                label_mismatches.push(format!(
                    "{pid}:{} {}: {} labelled as the only algorithm among several",
                    s.line,
                    s.callee,
                    repr_list(&exact)
                ));
            }
            if v == "correct" && !function_matches(s, &occ) {
                let uses: Vec<String> = occ
                    .iter()
                    .filter_map(|o| o.use_.clone())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect();
                function_mismatches.push(format!(
                    "{pid}:{} {}: labelled {}, reported {}",
                    s.line,
                    s.callee,
                    s.function,
                    repr_list(&uses)
                ));
            }
            *total.entry(v).or_default() += 1;
            *by_what
                .entry(what.to_string())
                .or_default()
                .entry(v)
                .or_default() += 1;
            *by_how
                .entry(how.to_string())
                .or_default()
                .entry(v)
                .or_default() += 1;
            if v != "correct" {
                let reported: Vec<String> = occ
                    .iter()
                    .map(|o| o.name.clone())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect();
                details.push((
                    pid.clone(),
                    s.line,
                    s.callee.clone(),
                    v,
                    reported,
                    s.must.iter().cloned().collect::<Vec<_>>(),
                    s.may.iter().cloned().collect::<Vec<_>>(),
                ));
            }
        }
        for (key, occ) in &at {
            if !labelled_lines.contains_key(key) && occ.iter().any(|o| o.has_use && o.reachable) {
                unlabelled += 1;
            }
        }
    }
    let counts = |c: &BTreeMap<&str, usize>, all: bool| -> Val {
        Val::Obj(
            VERDICTS
                .iter()
                .filter(|v| all || c.get(*v).copied().unwrap_or(0) > 0)
                .map(|v| (v.to_string(), c.get(v).copied().unwrap_or(0).into()))
                .collect(),
        )
    };
    let sites_n: usize = total.values().sum();
    if json {
        let result = Val::Obj(vec![
            ("sites".into(), sites_n.into()),
            ("verdicts".into(), counts(&total, true)),
            (
                "by_what".into(),
                Val::Obj(
                    by_what
                        .iter()
                        .map(|(w, c)| (w.clone(), counts(c, false)))
                        .collect(),
                ),
            ),
            (
                "by_how".into(),
                Val::Obj(
                    by_how
                        .iter()
                        .map(|(h, c)| (h.clone(), counts(c, false)))
                        .collect(),
                ),
            ),
            ("unlabelled_uses".into(), unlabelled.into()),
            ("function_mismatches".into(), function_mismatches.into()),
            ("label_mismatches".into(), label_mismatches.into()),
            (
                "not_correct".into(),
                Val::List(
                    details
                        .iter()
                        .map(|(p, l, c, v, r, must, may)| {
                            Val::Obj(vec![
                                ("program".into(), p.as_str().into()),
                                ("line".into(), (*l).into()),
                                ("callee".into(), c.as_str().into()),
                                ("verdict".into(), (*v).into()),
                                ("reported".into(), r.clone().into()),
                                ("must".into(), must.clone().into()),
                                ("may".into(), may.clone().into()),
                            ])
                        })
                        .collect(),
                ),
            ),
        ]);
        return Ok(dumps(&result, true, Some(1)) + "\n");
    }
    let mut out = format!(
        "{sites_n} sites: {}; unlabelled uses {unlabelled}; function mismatches {}; label mismatches {}\n",
        VERDICTS
            .iter()
            .map(|v| format!("{v} {}", total.get(v).copied().unwrap_or(0)))
            .collect::<Vec<_>>()
            .join(", "),
        function_mismatches.len(),
        label_mismatches.len()
    );
    for m in &function_mismatches {
        out.push_str(&format!("  function: {m}\n"));
    }
    for m in &label_mismatches {
        out.push_str(&format!("  label: {m}\n"));
    }
    for (p, l, c, v, r, must, may) in &details {
        out.push_str(&format!(
            "  {p}:{l} {c}: {v}: reported {}, must {}, may {}\n",
            repr_list(r),
            repr_list(must),
            repr_list(may)
        ));
    }
    Ok(out)
}
