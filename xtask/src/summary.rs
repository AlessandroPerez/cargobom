//! A CBOM as sorted text lines, for golden files (`tests/fixtures/**/expected.txt`): the
//! document's format fields, the tools, the root component and the run properties; every
//! component with its type, name, version, purl, crypto properties and rcbom properties; every
//! occurrence with its full context; and the dependency graph. Each line of a component names it
//! by bom-ref (and by name, for reading), so two components of one name (the HMAC algorithm and
//! the HMAC key material, two versions of a crate) are told apart. A field this does not know is
//! printed as JSON. Anything a reader of the CBOM sees is here, so any change shows in a diff;
//! only the serial number (a hash of the rest) is left out.

use std::collections::BTreeSet;

use serde_json::{Map, Value};

use crate::pyjson::{js, pystr};

/// The fields each kind of component line shows; any other is printed as a field line.
const ASSET: &[&str] = &[
    "type",
    "bom-ref",
    "name",
    "cryptoProperties",
    "properties",
    "evidence",
];
const PACKAGE: &[&str] = &[
    "type",
    "bom-ref",
    "name",
    "version",
    "purl",
    "properties",
    "evidence",
];
const OCCURRENCE: &[&str] = &["location", "line", "offset", "symbol", "additionalContext"];

/// A property is a name and a value; anything else it holds is shown as JSON.
fn prop(p: &Value) -> String {
    match p.as_object() {
        Some(o) if o.len() == 2 && o.contains_key("name") && o.contains_key("value") => {
            format!("{}={}", pystr(o.get("name")), pystr(o.get("value")))
        }
        _ => js(p),
    }
}

/// The keys of `o` outside `shown`, sorted.
fn others<'a>(o: &'a Map<String, Value>, shown: &[&str]) -> BTreeSet<&'a String> {
    o.keys().filter(|k| !shown.contains(&k.as_str())).collect()
}

fn list(v: Option<&Value>) -> &[Value] {
    v.and_then(Value::as_array).map_or(&[], Vec::as_slice)
}

/// The summary of CBOM document `doc`, one line per fact, sorted, with a final newline.
pub fn summary(doc: &Value) -> String {
    let empty = Map::new();
    let doc = doc.as_object().unwrap_or(&empty);
    let mut rows: Vec<String> = Vec::new();
    for (k, v) in doc {
        if !["components", "dependencies", "metadata", "serialNumber"].contains(&k.as_str()) {
            rows.push(format!("doc {k}={}", js(v)));
        }
    }
    for c in list(doc.get("components")) {
        let c = c.as_object().unwrap_or(&empty);
        let key = format!("{} | {}", pystr(c.get("name")), pystr(c.get("bom-ref")));
        let shown = if c.get("type").and_then(Value::as_str) == Some("cryptographic-asset") {
            rows.push(format!(
                "asset {key} | {}",
                js(c.get("cryptoProperties").unwrap_or(&Value::Null))
            ));
            ASSET
        } else {
            rows.push(format!(
                "component {} {} {} | {} | purl {}",
                pystr(c.get("type")),
                pystr(c.get("name")),
                c.get("version").map_or(String::new(), |v| pystr(Some(v))),
                pystr(c.get("bom-ref")),
                c.get("purl")
                    .map_or("(none)".to_string(), |v| pystr(Some(v))),
            ));
            PACKAGE
        };
        for f in others(c, shown) {
            rows.push(format!("  field {key} | {f}={}", js(&c[f])));
        }
        for p in list(c.get("properties")) {
            rows.push(format!("  prop {key} | {}", prop(p)));
        }
        let ev = c
            .get("evidence")
            .and_then(Value::as_object)
            .unwrap_or(&empty);
        for f in others(ev, &["occurrences"]) {
            rows.push(format!("  field {key} | evidence.{f}={}", js(&ev[f])));
        }
        for o in list(ev.get("occurrences")) {
            let o = o.as_object().unwrap_or(&empty);
            let extra: Map<String, Value> = o
                .iter()
                .filter(|(k, _)| !OCCURRENCE.contains(&k.as_str()))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            let mut row = format!(
                "  occ {key} | {}:{}:{} | {} | {}",
                pystr(o.get("location")),
                pystr(o.get("line")),
                pystr(o.get("offset")),
                pystr(o.get("symbol")),
                o.get("additionalContext")
                    .map_or(String::new(), |v| pystr(Some(v))),
            );
            if !extra.is_empty() {
                row.push_str(&format!(" | {}", js(&Value::Object(extra))));
            }
            rows.push(row);
        }
    }
    for d in list(doc.get("dependencies")) {
        let d = d.as_object().unwrap_or(&empty);
        let r = pystr(d.get("ref"));
        rows.push(format!("dependency {r}"));
        for t in list(d.get("dependsOn")) {
            rows.push(format!("dep {r} -> {}", pystr(Some(t))));
        }
        for t in list(d.get("provides")) {
            rows.push(format!("provides {r} -> {}", pystr(Some(t))));
        }
        for f in others(d, &["ref", "dependsOn", "provides"]) {
            rows.push(format!("depfield {r} | {f}={}", js(&d[f])));
        }
    }
    let meta = doc
        .get("metadata")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    rows.push(format!(
        "root {}",
        js(meta.get("component").unwrap_or(&Value::Null))
    ));
    rows.push(format!(
        "tools {}",
        js(meta.get("tools").unwrap_or(&Value::Null))
    ));
    for p in list(meta.get("properties")) {
        rows.push(format!("run {}", prop(p)));
    }
    for f in others(meta, &["component", "tools", "properties"]) {
        rows.push(format!("meta {f}={}", js(&meta[f])));
    }
    rows.sort();
    let mut out = rows.join("\n");
    out.push('\n');
    out
}
