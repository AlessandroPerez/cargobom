//! A Markdown review sheet for a second annotator: every label of a fixture next to the source
//! line it cites (`cargo xtask review-sheet FIXTURE_DIR... > sheet.md`).

use std::path::Path;

use anyhow::Result;

fn s<'a>(t: &'a toml::Value, k: &str) -> &'a str {
    t.get(k).and_then(|v| v.as_str()).unwrap_or("")
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

fn plain(v: &toml::Value) -> String {
    match v {
        toml::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

pub fn run(args: &[String]) -> Result<()> {
    println!("# Label review sheet\n");
    println!(
        "For each row: does the line use that asset, with that use and those parameters? Mark ✔ \
         or write the correction. `core` must be found by a tool; `extended` is credited if \
         found. Negative lines must stay empty.\n"
    );
    for d in args {
        let d = Path::new(d);
        let labels: toml::Value = toml::from_str(&std::fs::read_to_string(d.join("labels.toml"))?)?;
        let src = std::fs::read_to_string(d.join("src/main.rs"))?;
        let src: Vec<&str> = src.split('\n').collect();
        println!(
            "## {}\n\nSource: {}  \nStatus: {}\n",
            s(&labels, "fixture"),
            s(&labels, "source"),
            s(&labels, "status")
        );
        println!("| line | code | asset | tier | use | parameters | provenance | why | review |");
        println!("|---|---|---|---|---|---|---|---|---|");
        let mut rows: Vec<(i64, String, String, String, String, String, String)> = Vec::new();
        for a in labels
            .get("asset")
            .and_then(toml::Value::as_array)
            .into_iter()
            .flatten()
        {
            let mut params: Vec<String> = Vec::new();
            for k in ["params", "material"] {
                if let Some(t) = a.get(k).and_then(toml::Value::as_table) {
                    params.extend(t.iter().map(|(k, v)| format!("{k}={}", plain(v))));
                }
            }
            let prov: Vec<String> = a
                .get("provenance")
                .and_then(toml::Value::as_table)
                .into_iter()
                .flatten()
                .map(|(k, v)| format!("{k}: {}", strs(Some(v)).join(" or ")))
                .collect();
            let functions = strs(a.get("functions"));
            let use_ = if functions.is_empty() {
                "set up only".to_string()
            } else {
                functions.join(", ")
            };
            for l in ints(a.get("lines")) {
                rows.push((
                    l,
                    s(a, "name").into(),
                    s(a, "tier").into(),
                    use_.clone(),
                    params.join(", "),
                    prov.join("; "),
                    s(a, "why").into(),
                ));
            }
            for l in ints(a.get("component_lines")) {
                rows.push((
                    l,
                    s(a, "name").into(),
                    format!("{} (component)", s(a, "tier")),
                    String::new(),
                    String::new(),
                    String::new(),
                    s(a, "why").into(),
                ));
            }
        }
        for n in labels
            .get("negative")
            .and_then(toml::Value::as_array)
            .into_iter()
            .flatten()
        {
            let names = strs(n.get("names"));
            let name = if names.is_empty() {
                "— none —".to_string()
            } else {
                format!("— none — (not {})", names.join(", "))
            };
            for l in ints(n.get("lines")) {
                rows.push((
                    l,
                    name.clone(),
                    "negative".into(),
                    String::new(),
                    String::new(),
                    String::new(),
                    s(n, "why").into(),
                ));
            }
        }
        rows.sort_by(|a, b| (a.0, &a.2).cmp(&(b.0, &b.2)));
        for (l, name, tier, use_, params, prov, why) in rows {
            let code = src
                .get((l - 1) as usize)
                .map(|c| c.trim().replace('|', "\\|"))
                .unwrap_or_default();
            println!(
                "| {l} | `{code}` | {name} | {tier} | {use_} | {params} | {prov} | {} | |",
                why.replace('|', "/")
            );
        }
        for c in labels
            .get("capability")
            .and_then(toml::Value::as_array)
            .into_iter()
            .flatten()
        {
            let reachable = c
                .get("reachable")
                .and_then(toml::Value::as_bool)
                .unwrap_or(true);
            let tier = if reachable {
                "reachable"
            } else {
                "present only"
            };
            let source = s(c, "source");
            println!(
                "\nCapability via line {} ({tier}){}: {}",
                c.get("via_line")
                    .and_then(toml::Value::as_integer)
                    .unwrap_or(0),
                if source.is_empty() {
                    String::new()
                } else {
                    format!(": {source}")
                },
                strs(c.get("algorithms")).join(", ")
            );
            let suites = strs(c.get("cipher_suites"));
            if !suites.is_empty() {
                println!(
                    "\n- cipher suites: {}\n- key exchange groups: {}",
                    suites.join(", "),
                    strs(c.get("kx_groups")).join(", ")
                );
            }
        }
        let crates: Vec<String> = labels
            .get("crate")
            .and_then(toml::Value::as_array)
            .into_iter()
            .flatten()
            .map(|c| format!("{} ({})", s(c, "package"), s(c, "usage")))
            .collect();
        println!("\nCrates: {}\n", crates.join(", "));
    }
    Ok(())
}
