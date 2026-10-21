//! Scores the CBOMs of real projects against their ground truth
//! (`tests/fixtures/corpus/<project>.toml`).
//!
//! `cargo xtask corpus-score CBOM_DIR LABELS.toml... [--json] [--against OLD_CBOM_DIR]`:
//! `CBOM_DIR/<project>.cbom.json` is scored against `<project>.toml`:
//! - Layer 1: the labelled crypto packages (kind other than `support`) against the CBOM's
//!   library components with a crypto role (algorithm, trait, protocol, unmodelled): recall,
//!   precision, and agreement on support crates;
//! - Layer 2: each labelled operation site in the project's own source, with the suite's
//!   verdicts;
//! - with `--against OLD_CBOM_DIR` (the previous round's CBOMs): at each labelled site, the
//!   label kinds that changed (a run-time selector, a member's kind, a possible or partial set,
//!   the set's size), which the verdicts do not see.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;

use anyhow::{Context, Result};
use regex::Regex;
use serde_json::Value;

use crate::pyjson::{Val, dumps, repr_list};
use crate::suite::{self, Occ};

fn layer1(labels: &toml::Value, cbom: &Value) -> Val {
    let labelled: BTreeMap<(String, String), String> = labels
        .get("package")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .map(|p| {
            let s = |k: &str| p.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
            ((s("name"), s("version")), s("kind"))
        })
        .collect();
    let mut listed: BTreeMap<(String, String), String> = BTreeMap::new();
    for c in cbom["components"].as_array().into_iter().flatten() {
        if !["library", "application"].contains(&c["type"].as_str().unwrap_or("")) {
            continue;
        }
        let role = c["properties"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|p| p["name"] == "rcbom:crypto-role")
            .and_then(|p| p["value"].as_str());
        if let Some(role) = role {
            listed.insert(
                (
                    c["name"].as_str().unwrap_or("").to_string(),
                    c["version"].as_str().unwrap_or("").to_string(),
                ),
                role.to_string(),
            );
        }
    }
    let of =
        |m: &BTreeMap<(String, String), String>, support: bool| -> BTreeSet<(String, String)> {
            m.iter()
                .filter(|(_, v)| (*v == "support") == support)
                .map(|(k, _)| k.clone())
                .collect()
        };
    let (crypto, support) = (of(&labelled, false), of(&labelled, true));
    let (reported, reported_support) = (of(&listed, false), of(&listed, true));
    // crypto against crypto, support against support: a crypto package listed only as support
    // is not found, a support crate reported as crypto is not correct
    let names = |s: BTreeSet<&(String, String)>| -> Vec<String> {
        let mut v: Vec<String> = s.into_iter().map(|(n, v)| format!("{n} {v}")).collect();
        v.sort();
        v
    };
    Val::Obj(vec![
        ("crypto_labelled".into(), crypto.len().into()),
        (
            "crypto_found".into(),
            crypto.intersection(&reported).count().into(),
        ),
        (
            "crypto_missed".into(),
            names(crypto.difference(&reported).collect()).into(),
        ),
        ("reported".into(), reported.len().into()),
        (
            "reported_correct".into(),
            reported.intersection(&crypto).count().into(),
        ),
        (
            "reported_not_crypto".into(),
            names(reported.difference(&crypto).collect()).into(),
        ),
        ("support_labelled".into(), support.len().into()),
        ("support_listed".into(), reported_support.len().into()),
        (
            "support_agree".into(),
            support.intersection(&reported_support).count().into(),
        ),
    ])
}

fn layer2(labels: &toml::Value, cbom: &Value) -> Val {
    let at = suite::occurrences(cbom);
    let sites = suite::sites(labels);
    let mut lines: HashMap<(String, i64), usize> = HashMap::new();
    for s in &sites {
        *lines.entry((s.file.clone(), s.line)).or_default() += 1;
    }
    let mut verdicts: BTreeMap<&str, usize> = BTreeMap::new();
    let mut details = Vec::new();
    for s in &sites {
        let mut occ: Vec<Occ> = at
            .get(&(s.file.clone(), s.line))
            .cloned()
            .unwrap_or_default();
        if lines[&(s.file.clone(), s.line)] > 1 {
            occ.retain(|o| o.code.ends_with(&s.callee));
        }
        let mut v = suite::verdict(s, &occ);
        if v == "correct" && !suite::function_matches(s, &occ) {
            v = "function-mismatch";
        }
        *verdicts.entry(v).or_default() += 1;
        if v != "correct" {
            let reported: Vec<String> = occ
                .iter()
                .map(|o| o.name.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            details.push(Val::Obj(vec![
                ("line".into(), format!("{}:{}", s.file, s.line).into()),
                ("callee".into(), s.callee.as_str().into()),
                ("verdict".into(), v.into()),
                ("reported".into(), reported.into()),
                (
                    "must".into(),
                    s.must.iter().cloned().collect::<Vec<_>>().into(),
                ),
                (
                    "may".into(),
                    s.may.iter().cloned().collect::<Vec<_>>().into(),
                ),
            ]));
        }
    }
    let all = suite::VERDICTS.iter().chain(["function-mismatch"].iter());
    Val::Obj(vec![
        ("sites".into(), sites.len().into()),
        (
            "verdicts".into(),
            Val::Obj(
                all.map(|v| (v.to_string(), verdicts.get(v).copied().unwrap_or(0).into()))
                    .collect(),
            ),
        ),
        ("not_correct".into(), Val::List(details)),
    ])
}

/// The parts of a call occurrence's text that say how its algorithm reaches the call.
const LABEL_KINDS: &[&str] = &[
    r"selector: [\w-]+",
    r"member: [\w-]+",
    r"\bpossible\b",
    r"beside others not followed",
    r"hit its bound",
    r"algorithm one of \d+",
    r"algorithm unresolved",
];

/// (file, line, asset) -> the label kinds of its call occurrences, at the labelled sites.
fn label_kinds(
    cbom: &Value,
    sites: &[suite::Site],
) -> BTreeMap<(String, i64, String), BTreeSet<String>> {
    let res: Vec<Regex> = LABEL_KINDS.iter().map(|k| Regex::new(k).unwrap()).collect();
    let at = suite::occurrences(cbom);
    let mut out: BTreeMap<(String, i64, String), BTreeSet<String>> = BTreeMap::new();
    for s in sites {
        for o in at.get(&(s.file.clone(), s.line)).into_iter().flatten() {
            let kinds = res
                .iter()
                .flat_map(|r| r.find_iter(&o.ctx).map(|m| m.as_str().to_string()));
            out.entry((s.file.clone(), s.line, o.name.clone()))
                .or_default()
                .extend(kinds);
        }
    }
    out
}

fn field<'a>(v: &'a Val, k: &str) -> &'a Val {
    match v {
        Val::Obj(f) => f
            .iter()
            .find(|(n, _)| n == k)
            .map(|(_, v)| v)
            .unwrap_or(&Val::Null),
        _ => &Val::Null,
    }
}

fn int(v: &Val) -> i64 {
    match v {
        Val::Int(i) => *i,
        _ => 0,
    }
}

fn strings(v: &Val) -> Vec<String> {
    match v {
        Val::List(l) => l
            .iter()
            .filter_map(|x| match x {
                Val::Str(s) => Some(s.clone()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// `cargo xtask corpus-score CBOM_DIR LABELS.toml... [--json] [--against OLD_CBOM_DIR]`.
pub fn run(args: &[String]) -> Result<()> {
    let mut args: Vec<String> = args.to_vec();
    let json = args.iter().any(|a| a == "--json");
    let mut against = None;
    if let Some(i) = args.iter().position(|a| a == "--against") {
        against = args.get(i + 1).map(PathBuf::from);
        args.drain(i..(i + 2).min(args.len()));
    }
    let args: Vec<&String> = args.iter().filter(|a| !a.starts_with("--")).collect();
    let (cbom_dir, labels) = args.split_first().context(
        "usage: cargo xtask corpus-score CBOM_DIR LABELS.toml... [--json] [--against DIR]",
    )?;
    let cbom_dir = PathBuf::from(cbom_dir.as_str());
    let mut labels: Vec<PathBuf> = labels.iter().map(|l| PathBuf::from(l.as_str())).collect();
    labels.sort();
    let read = |p: PathBuf| -> Result<Value> {
        Ok(serde_json::from_str(
            &std::fs::read_to_string(&p).with_context(|| p.display().to_string())?,
        )?)
    };
    let mut out: Vec<(String, Val)> = Vec::new();
    for lp in labels {
        let name = lp
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string();
        let cbom = read(cbom_dir.join(format!("{name}.cbom.json")))?;
        let labels: toml::Value = toml::from_str(&std::fs::read_to_string(&lp)?)?;
        let mut r = vec![
            ("layer1".to_string(), layer1(&labels, &cbom)),
            ("layer2".to_string(), layer2(&labels, &cbom)),
        ];
        if let Some(dir) = &against {
            let old = read(dir.join(format!("{name}.cbom.json")))?;
            let sites = suite::sites(&labels);
            let (a, b) = (label_kinds(&old, &sites), label_kinds(&cbom, &sites));
            let keys: BTreeSet<&(String, i64, String)> = a.keys().chain(b.keys()).collect();
            let changes: Vec<String> = keys
                .into_iter()
                .filter(|k| a.get(*k) != b.get(*k))
                .map(|(f, l, asset)| {
                    let k = (f.clone(), *l, asset.clone());
                    let list = |m: &BTreeMap<(String, i64, String), BTreeSet<String>>| {
                        repr_list(
                            &m.get(&k)
                                .cloned()
                                .unwrap_or_default()
                                .into_iter()
                                .collect::<Vec<_>>(),
                        )
                    };
                    format!("{f}:{l} {asset}: {} -> {}", list(&a), list(&b))
                })
                .collect();
            r.push(("label_changes".to_string(), changes.into()));
        }
        out.push((name, Val::Obj(r)));
    }
    if json {
        println!("{}", dumps(&Val::Obj(out), true, Some(1)));
        return Ok(());
    }
    for (name, r) in &out {
        let (l1, l2) = (field(r, "layer1"), field(r, "layer2"));
        let n = |v: &Val, k: &str| int(field(v, k));
        let verdicts: Vec<String> = match field(l2, "verdicts") {
            Val::Obj(f) => f
                .iter()
                .filter(|(_, v)| int(v) > 0)
                .map(|(k, v)| format!("{k} {}", int(v)))
                .collect(),
            _ => Vec::new(),
        };
        println!(
            "== {name}: L1 crypto packages {}/{} found, {}/{} reported are crypto, support {} agree ({} labelled, {} listed); L2 {} sites: {}",
            n(l1, "crypto_found"),
            n(l1, "crypto_labelled"),
            n(l1, "reported_correct"),
            n(l1, "reported"),
            n(l1, "support_agree"),
            n(l1, "support_labelled"),
            n(l1, "support_listed"),
            n(l2, "sites"),
            verdicts.join(", ")
        );
        let missed = strings(field(l1, "crypto_missed"));
        if !missed.is_empty() {
            println!("   L1 missed: {}", missed.join(", "));
        }
        let extra = strings(field(l1, "reported_not_crypto"));
        if !extra.is_empty() {
            println!("   L1 reported, not labelled: {}", extra.join(", "));
        }
        if let Val::List(details) = field(l2, "not_correct") {
            for d in details {
                let must = strings(field(d, "must"));
                let shown: Vec<String> = must.iter().take(6).cloned().collect();
                println!(
                    "   L2 {} {}: {}: reported {}, must {}{}",
                    strings(&Val::List(vec![field(d, "line").clone()])).join(""),
                    strings(&Val::List(vec![field(d, "callee").clone()])).join(""),
                    strings(&Val::List(vec![field(d, "verdict").clone()])).join(""),
                    repr_list(&strings(field(d, "reported"))),
                    repr_list(&shown),
                    if must.len() > 6 { "…" } else { "" }
                );
            }
        }
        for c in strings(field(r, "label_changes")) {
            println!("   label changed: {c}");
        }
    }
    Ok(())
}
