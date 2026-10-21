//! Scores a CycloneDX CBOM against a fixture's `labels.toml` (any tool's CBOM, not only ours).
//!
//! `cargo xtask score LABELS.toml CBOM.json [--json]`. Line level, in the fixture's
//! `src/main.rs`:
//! - recall: core (asset, line) pairs the CBOM reports at the right line, by an accepted name;
//! - precision: (asset, line) pairs the CBOM reports in `src/main.rs` that match a label (core
//!   or extended, direct or component line); everything else is a false positive.
//!
//! Asset level: core assets found at any of their lines. Findings located in dependencies are
//! classified against the labelled capability set (credited) or listed as unexpected.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result};
use regex::Regex;
use serde_json::Value;

use crate::pyjson::{Val, dumps, float};

fn norm(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_whitespace() && *c != '_')
        .collect::<String>()
        .to_uppercase()
}

fn strs(v: Option<&toml::Value>) -> Vec<String> {
    v.and_then(toml::Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

fn ints(v: Option<&toml::Value>) -> Vec<i64> {
    v.and_then(toml::Value::as_array)
        .map(|a| a.iter().filter_map(toml::Value::as_integer).collect())
        .unwrap_or_default()
}

fn s<'a>(t: &'a toml::Value, k: &str) -> &'a str {
    t.get(k).and_then(|v| v.as_str()).unwrap_or("")
}

/// The score, as the JSON document the e2e compares with the fixture's committed one.
pub fn score(labels: &toml::Value, bom: &Value) -> Val {
    let assets: Vec<&toml::Value> = labels
        .get("asset")
        .and_then(toml::Value::as_array)
        .map(|a| a.iter().collect())
        .unwrap_or_default();
    let fixture = s(labels, "fixture");
    let caps: BTreeSet<String> = labels
        .get("capability")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .flat_map(|c| strs(c.get("algorithms")))
        .map(|a| norm(&a))
        .collect();
    // (name, line) the CBOM reports in src/main.rs, and everything it reports elsewhere
    let mut reported: BTreeSet<(String, i64)> = BTreeSet::new();
    let mut elsewhere: BTreeSet<String> = BTreeSet::new();
    let mut contexts: BTreeMap<(String, i64), Vec<String>> = BTreeMap::new();
    for c in bom["components"].as_array().into_iter().flatten() {
        if c["type"] != "cryptographic-asset" {
            continue;
        }
        let name = c["name"].as_str().unwrap_or("").to_string();
        for o in c["evidence"]["occurrences"]
            .as_array()
            .into_iter()
            .flatten()
        {
            let loc = o["location"].as_str().unwrap_or("");
            if loc == "src/main.rs" || (loc.ends_with("/src/main.rs") && loc.contains(fixture)) {
                if let Some(line) = o["line"].as_i64() {
                    reported.insert((name.clone(), line));
                    contexts
                        .entry((name.clone(), line))
                        .or_default()
                        .push(o["additionalContext"].as_str().unwrap_or("").to_string());
                }
            } else if !loc.ends_with("Cargo.toml") && !loc.ends_with("Cargo.lock") {
                elsewhere.insert(name.clone());
            }
        }
    }
    // exactly one of the label's names: the valid less specific registry names are listed there
    // ("PBKDF2-SHA-256" for "PBKDF2-SHA-256-1000-32"); a prefix rule would also take
    // "PBKDF2-SHA" or "SHA", which are no registry names
    let accepts = |a: &toml::Value, name: &str| {
        let n = norm(name);
        strs(a.get("accept")).iter().any(|x| n == norm(x))
    };
    let lines = |a: &toml::Value| ints(a.get("lines"));
    let component_lines = |a: &toml::Value| ints(a.get("component_lines"));
    // recall over core (asset, line) pairs
    let core_pairs: Vec<(&toml::Value, i64)> = assets
        .iter()
        .filter(|a| s(a, "tier") == "core")
        .flat_map(|a| lines(a).into_iter().map(move |l| (*a, l)))
        .collect();
    let found_at =
        |a: &toml::Value, l: i64| reported.iter().any(|(n, ln)| accepts(a, n) && *ln == l);
    let hit: Vec<(&toml::Value, i64)> = core_pairs
        .iter()
        .filter(|(a, l)| found_at(a, *l))
        .copied()
        .collect();
    let in_hit = |a: &toml::Value, l: i64| hit.iter().any(|(b, m)| std::ptr::eq(*b, a) && *m == l);
    let family_only: Vec<(&toml::Value, i64)> = core_pairs
        .iter()
        .filter(|(a, l)| {
            !in_hit(a, *l)
                && reported
                    .iter()
                    .any(|(n, ln)| ln == l && norm(n).contains(&norm(s(a, "family"))))
        })
        .copied()
        .collect();
    // precision over reported pairs in src/main.rs
    let matches_label = |n: &str, ln: i64| {
        assets
            .iter()
            .any(|a| accepts(a, n) && (lines(a).contains(&ln) || component_lines(a).contains(&ln)))
    };
    let negatives: BTreeSet<i64> = labels
        .get("negative")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .flat_map(|neg| ints(neg.get("lines")))
        .collect();
    let tp: Vec<&(String, i64)> = reported
        .iter()
        .filter(|(n, l)| matches_label(n, *l))
        .collect();
    let fp: Vec<&(String, i64)> = reported
        .iter()
        .filter(|(n, l)| !matches_label(n, *l))
        .collect();
    let mut extended_hit = Vec::new();
    for a in assets.iter().filter(|a| s(a, "tier") == "extended") {
        for l in lines(a).into_iter().chain(component_lines(a)) {
            if found_at(a, l) {
                extended_hit.push(format!("{} @ {l}", s(a, "name")));
            }
        }
    }
    let mut component_hit = Vec::new();
    for a in &assets {
        for l in component_lines(a) {
            if found_at(a, l) {
                component_hit.push(format!("{} @ {l}", s(a, "name")));
            }
        }
    }
    // specificity: the core finding carries the label's full registry name, parameters included
    let exact: Vec<(&toml::Value, i64)> = hit
        .iter()
        .filter(|(a, l)| {
            let full = strs(a.get("accept")).first().cloned().unwrap_or_default();
            reported
                .iter()
                .any(|(n, ln)| norm(n) == norm(&full) && ln == l)
        })
        .copied()
        .collect();
    let in_exact =
        |a: &toml::Value, l: i64| exact.iter().any(|(b, m)| std::ptr::eq(*b, a) && *m == l);
    let core_assets: Vec<&toml::Value> = assets
        .iter()
        .filter(|a| s(a, "tier") == "core")
        .copied()
        .collect();
    let assets_found = core_assets
        .iter()
        .filter(|a| {
            reported
                .iter()
                .any(|(n, l)| accepts(a, n) && lines(a).contains(l))
        })
        .count();
    let cap_credit: Vec<String> = elsewhere
        .iter()
        .filter(|n| caps.contains(&norm(n)))
        .cloned()
        .collect();
    let unexpected_elsewhere: Vec<String> = elsewhere
        .iter()
        .filter(|n| !caps.contains(&norm(n)) && !assets.iter().any(|a| accepts(a, n)))
        .cloned()
        .collect();
    // provenance: per labelled (asset, line, role), the set of origin kinds the CBOM states
    // (cargo-cbom writes "role: kind (..) or kind (..)" in additionalContext)
    let kinds_re =
        Regex::new(r"\b(hard-coded|environment|file|rng|parameter|derived|computed|unknown)\b")
            .unwrap();
    let parens = Regex::new(r"\([^()]*\)").unwrap();
    let (mut prov_total, mut prov_exact, mut prov_wrong) = (0usize, 0usize, Vec::new());
    for a in &core_assets {
        // (an extended asset may be omitted; its provenance is not owed)
        let Some(prov) = a.get("provenance").and_then(toml::Value::as_table) else {
            continue;
        };
        for (role, truth) in prov {
            let truth: BTreeSet<String> = strs(Some(truth)).into_iter().collect();
            for l in lines(a) {
                prov_total += 1;
                let mut said: BTreeSet<String> = BTreeSet::new();
                for ((n, ln), texts) in &contexts {
                    if *ln == l && accepts(a, n) {
                        for t in texts {
                            for part in t.split("; ") {
                                if part.starts_with(&format!("{role}: ")) {
                                    // the kinds, not the details in parentheses
                                    let bare = parens.replace_all(part, "");
                                    said.extend(
                                        kinds_re.find_iter(&bare).map(|m| m.as_str().to_string()),
                                    );
                                }
                            }
                        }
                    }
                }
                if said == truth {
                    prov_exact += 1;
                } else {
                    let said_s = if said.is_empty() {
                        "nothing".to_string()
                    } else {
                        crate::pyjson::repr_list(&said.iter().collect::<Vec<_>>())
                    };
                    prov_wrong.push(format!(
                        "{} @ {l} {role}: said {said_s}, truth {}",
                        s(a, "name"),
                        crate::pyjson::repr_list(&truth.iter().collect::<Vec<_>>())
                    ));
                }
            }
        }
    }
    let libs: BTreeSet<&str> = bom["components"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|c| {
            ["library", "application", "framework"].contains(&c["type"].as_str().unwrap_or(""))
        })
        .filter_map(|c| c["name"].as_str())
        .collect();
    let crates: Vec<&toml::Value> = labels
        .get("crate")
        .and_then(toml::Value::as_array)
        .map(|a| a.iter().collect())
        .unwrap_or_default();
    let crates_found = crates
        .iter()
        .filter(|c| libs.contains(s(c, "package")))
        .count();
    let ratio = |a: usize, b: usize| {
        if b == 0 {
            Val::Null
        } else {
            Val::Float(((a as f64 / b as f64) * 1000.0).round() / 1000.0)
        }
    };
    let named_less: Vec<String> = hit
        .iter()
        .filter(|(a, l)| !in_exact(a, *l))
        .map(|(a, l)| {
            let names: BTreeSet<&str> = reported
                .iter()
                .filter(|(n, ln)| ln == l && accepts(a, n))
                .map(|(n, _)| n.as_str())
                .collect();
            format!(
                "{} @ {l} as {}",
                s(a, "name"),
                names.into_iter().collect::<Vec<_>>().join(", ")
            )
        })
        .collect();
    let missed: Vec<String> = core_pairs
        .iter()
        .filter(|(a, l)| !in_hit(a, *l))
        .map(|(a, l)| format!("{} @ {l}", s(a, "name")))
        .collect();
    let false_positives: Vec<String> = fp
        .iter()
        .map(|(n, l)| {
            format!(
                "{n} @ {l}{}",
                if negatives.contains(l) {
                    " (negative line)"
                } else {
                    ""
                }
            )
        })
        .collect();
    Val::Obj(vec![
        ("fixture".into(), fixture.into()),
        ("core_pairs".into(), core_pairs.len().into()),
        ("core_pairs_found".into(), hit.len().into()),
        ("recall".into(), ratio(hit.len(), core_pairs.len())),
        ("reported_pairs".into(), reported.len().into()),
        ("true_positive_pairs".into(), tp.len().into()),
        ("precision".into(), ratio(tp.len(), reported.len())),
        ("fully_named".into(), exact.len().into()),
        ("core_assets".into(), core_assets.len().into()),
        ("core_assets_found".into(), assets_found.into()),
        ("named_less_specifically".into(), named_less.into()),
        ("missed".into(), missed.into()),
        (
            "family_only".into(),
            family_only
                .iter()
                .map(|(a, l)| format!("{} @ {l}", s(a, "name")))
                .collect::<Vec<_>>()
                .into(),
        ),
        ("false_positives".into(), false_positives.into()),
        ("extended_found".into(), extended_hit.into()),
        ("components_found".into(), component_hit.into()),
        ("capability_credited".into(), cap_credit.into()),
        (
            "unexpected_in_dependencies".into(),
            unexpected_elsewhere.into(),
        ),
        (
            "crates_found".into(),
            format!("{crates_found}/{}", crates.len()).into(),
        ),
        ("provenance_total".into(), prov_total.into()),
        ("provenance_exact".into(), prov_exact.into()),
        ("provenance_wrong".into(), prov_wrong.into()),
    ])
}

fn get<'a>(r: &'a Val, k: &str) -> &'a Val {
    match r {
        Val::Obj(f) => f
            .iter()
            .find(|(n, _)| n == k)
            .map(|(_, v)| v)
            .unwrap_or(&Val::Null),
        _ => &Val::Null,
    }
}

fn text(v: &Val) -> String {
    match v {
        Val::Int(i) => i.to_string(),
        Val::Float(f) => float(*f),
        Val::Str(s) => s.clone(),
        Val::List(l) => l.iter().map(text).collect::<Vec<_>>().join(", "),
        _ => String::new(),
    }
}

fn percent(v: &Val) -> String {
    match v {
        Val::Float(f) => format!(" = {:.0}%", f * 100.0),
        _ => String::new(),
    }
}

/// The score as the text report.
pub fn report(r: &Val) -> String {
    let t = |k: &str| text(get(r, k));
    let mut out = format!("== {}\n", t("fixture"));
    out.push_str(&format!(
        "  line-level recall    {}/{} core (asset, line) pairs{}\n",
        t("core_pairs_found"),
        t("core_pairs"),
        percent(get(r, "recall"))
    ));
    out.push_str(&format!(
        "  line-level precision {}/{} reported pairs in src/main.rs{}\n",
        t("true_positive_pairs"),
        t("reported_pairs"),
        percent(get(r, "precision"))
    ));
    out.push_str(&format!(
        "  core assets found    {}/{}\n",
        t("core_assets_found"),
        t("core_assets")
    ));
    out.push_str(&format!(
        "  fully named          {}/{} core findings with the full registry name\n",
        t("fully_named"),
        t("core_pairs")
    ));
    for k in [
        "missed",
        "named_less_specifically",
        "family_only",
        "false_positives",
        "extended_found",
        "components_found",
        "capability_credited",
        "unexpected_in_dependencies",
    ] {
        if matches!(get(r, k), Val::List(l) if !l.is_empty()) {
            out.push_str(&format!("  {}: {}\n", k.replace('_', " "), t(k)));
        }
    }
    if !matches!(get(r, "provenance_total"), Val::Int(0)) {
        out.push_str(&format!(
            "  provenance           {}/{} labelled (asset, line, role) origins stated exactly\n",
            t("provenance_exact"),
            t("provenance_total")
        ));
        if let Val::List(w) = get(r, "provenance_wrong") {
            for x in w {
                out.push_str(&format!("    {}\n", text(x)));
            }
        }
    }
    out.push_str(&format!("  crates in CBOM       {}\n", t("crates_found")));
    out
}

/// `cargo xtask score LABELS.toml CBOM.json [--json]`.
pub fn run(args: &[String]) -> Result<()> {
    let json = args.iter().any(|a| a == "--json");
    let args: Vec<&String> = args.iter().filter(|a| !a.starts_with("--")).collect();
    let [labels, cbom] = args.as_slice() else {
        anyhow::bail!("usage: cargo xtask score LABELS.toml CBOM.json [--json]");
    };
    let labels: toml::Value = toml::from_str(&std::fs::read_to_string(labels.as_str())?)?;
    let bom: Value = serde_json::from_str(
        &std::fs::read_to_string(cbom.as_str()).with_context(|| cbom.to_string())?,
    )?;
    let r = score(&labels, &bom);
    if json {
        println!("{}", dumps(&r, false, Some(2)));
    } else {
        print!("{}", report(&r));
    }
    Ok(())
}
