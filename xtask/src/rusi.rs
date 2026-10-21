//! Converts a rusi `cryptos` report into a minimal CycloneDX document for `cargo xtask score`.
//!
//! Every rusi crypto component becomes an occurrence of an asset named by rusi's `algorithm`,
//! at rusi's position. No filtering: cdxgen's own conversion drops algorithms it cannot map to
//! an OID, so this view is at least as generous to rusi as cdxgen's CBOM.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use serde_json::Value;

use crate::pyjson::{Val, dumps};

/// `cargo xtask rusi-to-cbom RUSI_REPORT.json > cbom.json`.
pub fn run(args: &[String]) -> Result<()> {
    let path = args
        .first()
        .context("usage: cargo xtask rusi-to-cbom RUSI_REPORT.json")?;
    let report: Value = serde_json::from_str(&std::fs::read_to_string(path)?)?;
    let mut by_name: BTreeMap<String, Vec<Val>> = BTreeMap::new();
    for c in report["crypto"]["components"]
        .as_array()
        .into_iter()
        .flatten()
    {
        let p = &c["position"];
        by_name
            .entry(c["algorithm"].as_str().unwrap_or("").to_string())
            .or_default()
            .push(Val::Obj(vec![
                ("location".into(), (&c["file_path"]).into()),
                ("line".into(), (&p["line"]).into()),
                (
                    "offset".into(),
                    (p["column"].as_i64().unwrap_or(0) - 1).max(0).into(),
                ),
                ("symbol".into(), (&c["symbol"]).into()),
                (
                    "additionalContext".into(),
                    format!(
                        "[{}] {}",
                        c["kind"].as_str().unwrap_or(""),
                        c["operation"].as_str().unwrap_or("")
                    )
                    .into(),
                ),
            ]));
    }
    let mut components: Vec<Val> = by_name
        .into_iter()
        .map(|(n, occ)| {
            Val::Obj(vec![
                ("type".into(), "cryptographic-asset".into()),
                ("name".into(), n.as_str().into()),
                ("bom-ref".into(), format!("rusi:{n}").into()),
                (
                    "cryptoProperties".into(),
                    Val::Obj(vec![("assetType".into(), "algorithm".into())]),
                ),
                (
                    "evidence".into(),
                    Val::Obj(vec![("occurrences".into(), Val::List(occ))]),
                ),
            ])
        })
        .collect();
    for l in report["crypto"]["libraries"]
        .as_array()
        .into_iter()
        .flatten()
    {
        let path = l["path"].as_str().unwrap_or("");
        components.push(Val::Obj(vec![
            ("type".into(), "library".into()),
            ("name".into(), path.replace('_', "-").into()),
            ("bom-ref".into(), format!("lib:{path}").into()),
        ]));
    }
    let doc = Val::Obj(vec![
        ("bomFormat".into(), "CycloneDX".into()),
        ("specVersion".into(), "1.7".into()),
        ("version".into(), 1i64.into()),
        (
            "metadata".into(),
            Val::Obj(vec![(
                "tools".into(),
                Val::Obj(vec![(
                    "components".into(),
                    Val::List(vec![Val::Obj(vec![
                        ("type".into(), "application".into()),
                        ("name".into(), "rusi".into()),
                        ("version".into(), (&report["tool"]["version"]).into()),
                    ])]),
                )]),
            )]),
        ),
        ("components".into(), Val::List(components)),
    ]);
    println!("{}", dumps(&doc, false, Some(2)));
    Ok(())
}
