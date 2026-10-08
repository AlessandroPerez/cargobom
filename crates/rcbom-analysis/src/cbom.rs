//! CycloneDX 1.7 assembly.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use rcbom_facts::Tier;
use rcbom_kb::{Kb, Role};
use rcbom_manifest::{Manifest, Pkg, Scope};
use serde_json::{Value, json};

use crate::{Analysis, Asset, Kind, Occurrence, Usage};

/// What a run used, recorded in the CBOM so it can be reproduced.
pub struct RunInfo {
    pub tool_version: String,
    pub toolchain: String,
    pub target: String,
    pub features: Vec<String>,
    pub sandbox: String,
}

/// Roles whose value must not be a constant: a literal key, nonce, IV, salt or password is a
/// finding.
const SECRET_ROLES: &[&str] = &["key", "nonce", "iv", "salt", "password", "ikm"];

fn prop(name: &str, value: impl ToString) -> Value {
    json!({ "name": name, "value": value.to_string() })
}

fn pkg_ref(name: &str, version: &str) -> String {
    format!("pkg:cargo/{name}@{version}")
}

fn tier_str(t: Tier) -> &'static str {
    match t {
        Tier::Reachable => "reachable",
        Tier::Present => "present",
    }
}

/// `[tier] [kind] [macro m!] owner: use; details`. The bracketed tags come first so tools (and
/// `cargo cbom verify`) can read them back.
fn context(o: &Occurrence) -> String {
    let mut s = format!("[{}] [{}]", tier_str(o.tier), o.kind.as_str());
    match o
        .macro_name
        .as_deref()
        .map(|m| m.split_once(':').unwrap_or(("", m)))
    {
        Some(("derive", name)) => s.push_str(&format!(" [derive {name}]")),
        Some(("attr", name)) => s.push_str(&format!(" [attribute {name}]")),
        Some((_, m)) => s.push_str(&format!(" [macro {m}]")),
        None => {}
    }
    s.push_str(&format!(" in {}", o.owner));
    if let Some(f) = &o.function {
        s.push_str(&format!("; use: {f}"));
    }
    for d in &o.detail {
        s.push_str("; ");
        s.push_str(d);
    }
    s
}

fn asset_ref(name: &str) -> String {
    format!("crypto:algorithm:{name}")
}

fn asset_component(kb: &Kb, a: &Asset) -> Value {
    let observed = a.observed_functions();
    let (functions, source): (Vec<String>, &str) = if observed.is_empty() {
        (a.algo.functions.clone(), "knowledge-base")
    } else {
        (observed.into_iter().collect(), "observed")
    };
    let mut ap = serde_json::Map::new();
    ap.insert("primitive".into(), json!(a.algo.primitive));
    ap.insert("algorithmFamily".into(), json!(a.algo.family));
    if let Some(p) = &a.algo.parameter_set {
        ap.insert("parameterSetIdentifier".into(), json!(p));
    }
    if let Some(m) = &a.algo.mode {
        ap.insert("mode".into(), json!(m));
    }
    if let Some(c) = &a.algo.curve {
        ap.insert("ellipticCurve".into(), json!(c));
    }
    ap.insert("cryptoFunctions".into(), json!(functions));

    let occurrences: Vec<Value> = a
        .occurrences
        .iter()
        .map(|o| {
            json!({
                "location": o.location,
                "line": o.line,
                "offset": o.offset,
                "symbol": o.symbol,
                "additionalContext": context(o),
            })
        })
        .collect();
    let direct = a.occurrences.iter().any(|o| o.kind != Kind::Component);
    let mut props = vec![
        prop("rcbom:detection:method", "type-resolved"),
        prop("rcbom:confidence", "high"),
        prop(
            "rcbom:reachability",
            if a.reachable() {
                "reachable"
            } else {
                "present"
            },
        ),
        prop("rcbom:functions:source", source),
        prop("rcbom:kb:version", &kb.version),
    ];
    if !direct && !a.occurrences.is_empty() {
        props.push(prop("rcbom:only-as-component", "true"));
    }
    for (k, v) in &a.params {
        props.push(prop(&format!("rcbom:param:{k}"), v));
    }
    // where the key material handed to this asset's APIs comes from (intraprocedural)
    let mut by_role: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for o in &a.occurrences {
        for (role, kind) in &o.provenance {
            by_role.entry(role).or_default().insert(kind);
        }
    }
    for (role, kinds) in &by_role {
        props.push(prop(
            &format!("rcbom:provenance:{role}"),
            kinds.iter().copied().collect::<Vec<_>>().join(","),
        ));
        if kinds.contains("hard-coded") && SECRET_ROLES.contains(role) {
            props.push(prop("rcbom:finding", format!("hard-coded-{role}")));
        }
    }
    if let Some(n) = &a.algo.note {
        props.push(prop("rcbom:note", n));
    }
    props.push(prop("rcbom:occurrences", a.occurrences.len()));
    let crypto = match &a.algo.material {
        // a key with no scheme: material, linked to its family by a property
        Some(m) => {
            props.push(prop("rcbom:algorithm-family", &a.algo.family));
            let mut rp = serde_json::Map::new();
            rp.insert("type".into(), json!(m));
            if let Some(size) = a.algo.size.as_ref().and_then(|s| s.parse::<u64>().ok()) {
                rp.insert("size".into(), json!(size));
            }
            json!({ "assetType": "related-crypto-material", "relatedCryptoMaterialProperties": rp })
        }
        None => json!({ "assetType": "algorithm", "algorithmProperties": ap }),
    };
    json!({
        "type": "cryptographic-asset",
        "bom-ref": asset_ref(&a.name),
        "name": a.name,
        "cryptoProperties": crypto,
        "evidence": { "occurrences": occurrences },
        "properties": props,
    })
}

fn protocol_component(kb: &Kb, p: &crate::Protocol) -> Value {
    let occurrences: Vec<Value> = p
        .occurrences
        .iter()
        .map(|o| {
            json!({
                "location": o.location,
                "line": o.line,
                "offset": o.offset,
                "symbol": o.symbol,
                "additionalContext": context(o),
            })
        })
        .collect();
    let mut pp = serde_json::Map::new();
    pp.insert("type".into(), json!(p.kind));
    if let Some(v) = p.versions.iter().max() {
        pp.insert("version".into(), json!(v));
    }
    pp.insert(
        "cipherSuites".into(),
        json!(
            p.suites
                .iter()
                .map(|s| json!({ "name": s }))
                .collect::<Vec<_>>()
        ),
    );
    let reachable = p.occurrences.iter().any(|o| o.tier == Tier::Reachable);
    let mut props = vec![
        prop("rcbom:detection:method", "type-resolved"),
        prop(
            "rcbom:reachability",
            if reachable { "reachable" } else { "present" },
        ),
        prop("rcbom:protocol:versions", p.versions.join(",")),
        prop("rcbom:protocol:groups", p.groups.join(",")),
        prop("rcbom:kb:version", &kb.version),
    ];
    if let Some(b) = &p.backend {
        props.push(prop("rcbom:backend", b));
    }
    json!({
        "type": "cryptographic-asset",
        "bom-ref": format!("crypto:protocol:{}", p.name),
        "name": p.name,
        "cryptoProperties": { "assetType": "protocol", "protocolProperties": pp },
        "evidence": { "occurrences": occurrences },
        "properties": props,
    })
}

fn manifest_occurrences(man: &Manifest, p: &Pkg) -> Vec<Value> {
    p.evidence
        .iter()
        .map(|e| {
            json!({
                "location": man.location(&e.path),
                "line": e.line,
                "offset": e.col,
                "symbol": e.symbol,
                "additionalContext": format!("[manifest] {}", e.context),
            })
        })
        .collect()
}

fn library_component(man: &Manifest, p: &Pkg, usage: Option<Usage>) -> Value {
    let v = p.version.to_string();
    let mut props = vec![prop(
        "rcbom:scope",
        match p.scope {
            Scope::Required => "required",
            Scope::Build => "build-only",
        },
    )];
    if let Some(r) = p.role {
        props.push(prop(
            "rcbom:crypto-role",
            match r {
                Role::Algorithm => "algorithm",
                Role::Trait => "trait",
                Role::Protocol => "protocol",
            },
        ));
    }
    if p.role.is_some() && !p.kb_supported {
        props.push(prop("rcbom:kb-coverage", "unsupported-version"));
    }
    if !p.backends.is_empty() {
        props.push(prop("rcbom:backend", p.backends.join(",")));
    }
    if let Some(l) = &p.links {
        props.push(prop("rcbom:native-links", l));
        props.push(prop("rcbom:ffi-boundary", "true"));
    }
    if let (Some(u), Some(r)) = (usage, p.role) {
        if !p.kb_supported {
            // its APIs are not in the knowledge base: no use could have been seen
            props.push(prop("rcbom:usage", "unknown"));
        } else if r != Role::Trait {
            props.push(prop(
                "rcbom:usage",
                match u {
                    Usage::Reachable => "reachable",
                    Usage::Present => "present",
                    Usage::DeclaredNotUsed => "declared-not-used",
                },
            ));
        }
    }
    let mut c = json!({
        "type": if p.member { "application" } else { "library" },
        "bom-ref": pkg_ref(&p.name, &v),
        "name": p.name,
        "version": v,
        "purl": pkg_ref(&p.name, &v),
        "properties": props,
    });
    let occ = manifest_occurrences(man, p);
    if !occ.is_empty() {
        c["evidence"] = json!({ "occurrences": occ });
    }
    c
}

/// Layer 1 candidates for crypto crates Layer 2 saw no use of.
fn candidate_assets(kb: &Kb, man: &Manifest, an: &Analysis) -> Vec<Value> {
    let mut out = Vec::new();
    for p in &man.packages {
        let key = (p.name.clone(), p.version.to_string());
        if p.role != Some(Role::Algorithm)
            || an.usage.get(&key) != Some(&Usage::DeclaredNotUsed)
            || p.scope != Scope::Required
        {
            continue;
        }
        let krate = p.name.replace('-', "_");
        let template = kb
            .types
            .iter()
            .filter(|t| t.krate == krate)
            .map(|t| &t.algo)
            .chain(
                kb.statics
                    .iter()
                    .filter(|s| s.krates.contains(&krate))
                    .map(|s| &s.algo),
            )
            .chain(
                kb.fns
                    .iter()
                    .filter(|s| s.krates.contains(&krate))
                    .map(|s| &s.algo),
            )
            .next();
        for name in &p.candidates {
            if an.assets.contains_key(name) {
                continue;
            }
            let mut ap = serde_json::Map::new();
            if let Some(t) = template {
                ap.insert("primitive".into(), json!(t.primitive));
                ap.insert("algorithmFamily".into(), json!(t.family));
            }
            out.push(json!({
                "type": "cryptographic-asset",
                "bom-ref": format!("crypto:candidate:{}@{}:{}", p.name, p.version, name),
                "name": name,
                "cryptoProperties": { "assetType": "algorithm", "algorithmProperties": ap },
                "evidence": { "occurrences": manifest_occurrences(man, p) },
                "properties": [
                    prop("rcbom:detection:method", "manifest"),
                    prop("rcbom:confidence", "low"),
                    prop("rcbom:usage", "declared-not-used"),
                    prop("rcbom:kb:version", &kb.version),
                ],
            }));
        }
    }
    out
}

pub fn to_cyclonedx(kb: &Kb, man: &Manifest, an: &Analysis, run: &RunInfo) -> Value {
    // Components: workspace members, crypto crates, native libraries.
    let included: Vec<&Pkg> = man
        .packages
        .iter()
        .filter(|p| p.member || p.role.is_some() || p.links.is_some())
        .collect();
    let included_ids: HashSet<_> = included.iter().map(|p| p.id.clone()).collect();
    let mut components: Vec<Value> = included
        .iter()
        .map(|p| {
            library_component(
                man,
                p,
                an.usage
                    .get(&(p.name.clone(), p.version.to_string()))
                    .copied(),
            )
        })
        .collect();
    components.extend(an.assets.values().map(|a| asset_component(kb, a)));
    components.extend(an.protocols.values().map(|p| protocol_component(kb, p)));
    components.extend(candidate_assets(kb, man, an));

    // Dependencies: package graph reduced to the included packages, providers, composition.
    let by_id: HashMap<_, _> = man.packages.iter().map(|p| (p.id.clone(), p)).collect();
    let mut provides: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for a in an.assets.values() {
        for (n, v) in &a.providers {
            provides
                .entry(pkg_ref(n, v))
                .or_default()
                .insert(asset_ref(&a.name));
        }
    }
    let mut deps = Vec::new();
    for p in &included {
        let mut seen = HashSet::new();
        let mut stack: Vec<_> = p.deps.clone();
        let mut on = BTreeSet::new();
        while let Some(id) = stack.pop() {
            if !seen.insert(id.clone()) {
                continue;
            }
            if included_ids.contains(&id) {
                let d = by_id[&id];
                on.insert(pkg_ref(&d.name, &d.version.to_string()));
            } else if let Some(d) = by_id.get(&id) {
                stack.extend(d.deps.iter().cloned());
            }
        }
        let r = pkg_ref(&p.name, &p.version.to_string());
        let mut d = json!({ "ref": r, "dependsOn": on });
        if let Some(pr) = provides.get(&r) {
            d["provides"] = json!(pr);
        }
        deps.push(d);
    }
    for a in an.assets.values() {
        let on: BTreeSet<String> = a
            .components
            .iter()
            .filter(|c| an.assets.contains_key(*c))
            .map(|c| asset_ref(c))
            .collect();
        if !on.is_empty() {
            deps.push(json!({ "ref": asset_ref(&a.name), "dependsOn": on }));
        }
    }

    // the package `--manifest-path` names; in a virtual workspace, the first member by name
    let root = included
        .iter()
        .find(|p| p.member && man.root.as_ref() == Some(&p.id))
        .or_else(|| included.iter().find(|p| p.member));
    let mut run_props = vec![
        prop("rcbom:run:toolchain", &run.toolchain),
        prop("rcbom:run:target", &run.target),
        prop("rcbom:run:features", run.features.join(",")),
        prop("rcbom:run:sandbox", &run.sandbox),
        prop("rcbom:kb:version", &kb.version),
        prop("rcbom:run:reachable-instances", an.instances),
    ];
    for n in &an.notes {
        run_props.push(prop("rcbom:run:note", n));
    }
    let mut bom = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "version": 1,
        "metadata": {
            "tools": { "components": [ { "type": "application", "name": "cargo-cbom", "version": run.tool_version } ] },
            "properties": run_props,
        },
        "components": components,
        "dependencies": deps,
    });
    if let Some(r) = root {
        let v = r.version.to_string();
        bom["metadata"]["component"] = json!({ "type": "application", "bom-ref": format!("{}#root", pkg_ref(&r.name, &v)), "name": r.name, "version": v });
    }
    // Same inputs, same CBOM: the serial number is derived from the content.
    let digest = fnv128(serde_json::to_string(&bom).unwrap().as_bytes());
    bom["serialNumber"] = json!(format!(
        "urn:uuid:{:08x}-{:04x}-8{:03x}-{:04x}-{:012x}",
        (digest >> 96) as u32,
        (digest >> 80) as u16,
        (digest >> 64) as u16 & 0xfff,
        ((digest >> 48) as u16 & 0x3fff) | 0x8000,
        digest as u64 & 0xffff_ffff_ffff
    ));
    bom
}

fn fnv128(data: &[u8]) -> u128 {
    let mut h: u128 = 0x6c62272e07bb014262b821756295c58d;
    for b in data {
        h ^= *b as u128;
        h = h.wrapping_mul(0x0000000001000000000000000000013B);
    }
    h
}
