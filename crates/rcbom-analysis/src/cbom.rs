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
    /// The cargo profile analysed (`none` for Layer 1 only).
    pub profile: String,
    /// Packages in the build Layer 1 resolved (normal and build edges, host platform).
    pub packages: usize,
    pub sandbox: String,
    /// The walk against the linker, per binary (`cargo cbom --check-walk`).
    pub walk_check: Vec<String>,
}

/// Roles whose value must not be a constant: a literal key, nonce, IV, salt or password is a
/// finding, and so is a generator seeded with a constant (`predictable-rng`).
const SECRET_ROLES: &[&str] = &["key", "nonce", "iv", "salt", "password", "ikm", "rng"];

fn finding(role: &str) -> String {
    match role {
        "rng" => "predictable-rng".into(),
        r => format!("hard-coded-{r}"),
    }
}

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

/// `[tier] [kind] [macro m!] in owner; use: f; details; line: `..`; code: `..``. The bracketed
/// tags come first and the source text last, so tools (and `cargo cbom verify`) can read them
/// back.
/// The artifacts whose walks reach any of these occurrences.
fn artifacts_of(occurrences: &[Occurrence]) -> BTreeSet<&str> {
    occurrences
        .iter()
        .flat_map(|o| o.artifacts.iter().map(String::as_str))
        .collect()
}

/// The text after an occurrence's position: its tags (tier, kind, the artifacts reaching it
/// where the run has several, the macro), where it is, its details, and last its source line
/// and text.
fn context(o: &Occurrence, several_artifacts: bool) -> String {
    let mut s = format!("[{}] [{}]", tier_str(o.tier), o.kind.as_str());
    if several_artifacts && !o.artifacts.is_empty() {
        let a: Vec<&str> = o.artifacts.iter().map(String::as_str).collect();
        s.push_str(&format!(" [artifacts: {}]", a.join(", ")));
    }
    match &o.macro_tag {
        Some((rcbom_facts::MacroKind::Derive, name)) => s.push_str(&format!(" [derive {name}]")),
        Some((rcbom_facts::MacroKind::Attr, name)) => s.push_str(&format!(" [attribute {name}]")),
        Some((rcbom_facts::MacroKind::Bang, name)) => s.push_str(&format!(" [macro {name}!]")),
        _ => {}
    }
    s.push_str(&format!(" in {}", o.owner));
    if let Some(f) = &o.function {
        s.push_str(&format!("; use: {f}"));
    }
    for d in &o.detail {
        s.push_str("; ");
        s.push_str(d);
    }
    // last, so they can be read back: the source line, and the exact text at the position
    // (the line may hold backquotes, in a literal or a comment; the code text never does)
    if let Some(l) = &o.line_text {
        s.push_str(&format!("; line: `{l}`"));
    }
    if let Some(c) = o.code.as_ref().filter(|c| !c.contains('`')) {
        s.push_str(&format!("; code: `{c}`"));
    }
    s
}

/// bom-refs of the assets, by key: `crypto:algorithm:<name>`, `crypto:material:<type>:<name>`
/// for key material, and `:<primitive>` added when two algorithms share a name (BLAKE3 the hash
/// and BLAKE3 keyed, a MAC).
fn asset_refs(an: &Analysis) -> BTreeMap<String, String> {
    let mut by_name: BTreeMap<&str, usize> = BTreeMap::new();
    for a in an.assets.values().filter(|a| a.algo.material.is_none()) {
        *by_name.entry(&a.name).or_default() += 1;
    }
    let mut taken: BTreeMap<String, usize> = BTreeMap::new();
    an.assets
        .values()
        .map(|a| {
            let r = match &a.algo.material {
                // an unknown algorithm: by primitive and providing packages, whatever else the
                // CBOM holds
                None if a.unresolved() => {
                    let providers: Vec<&str> =
                        a.providers.iter().map(|(n, _)| n.as_str()).collect();
                    format!(
                        "crypto:algorithm:unknown:{}:{}",
                        a.algo.primitive,
                        if providers.is_empty() {
                            "none".to_string()
                        } else {
                            providers.join("+")
                        }
                    )
                }
                Some(m) => format!("crypto:material:{m}:{}", a.name),
                None if by_name[a.name.as_str()] > 1 => {
                    format!("crypto:algorithm:{}:{}", a.name, a.algo.primitive)
                }
                None => format!("crypto:algorithm:{}", a.name),
            };
            // bom-refs are unique whatever the names: a second asset of one ref is numbered
            let n = taken.entry(r.clone()).or_default();
            *n += 1;
            let r = if *n > 1 { format!("{r}:{n}") } else { r };
            (a.key.clone(), r)
        })
        .collect()
}

fn asset_component(kb: &Kb, a: &Asset, bom_ref: &str, several_artifacts: bool) -> Value {
    let observed = a.observed_functions();
    let (functions, source): (Vec<String>, &str) = if observed.is_empty() {
        (a.algo.functions.clone(), "knowledge-base")
    } else {
        (observed.into_iter().collect(), "observed")
    };
    let mut ap = serde_json::Map::new();
    ap.insert("primitive".into(), json!(a.algo.primitive));
    // a registry family the 1.7 enum lacks (`TLS-PRF`) is a property, as for key material
    if rcbom_kb::in_family_enum(&a.algo.family) {
        ap.insert("algorithmFamily".into(), json!(a.algo.family));
    }
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
                "additionalContext": context(o, several_artifacts),
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
    // the artifacts using it, where the run has several (one `rage-keygen` uses alone)
    if several_artifacts {
        for art in artifacts_of(&a.occurrences) {
            props.push(prop("rcbom:artifact", art));
        }
    }
    for (k, vs) in &a.params {
        let v: Vec<&str> = vs.iter().map(String::as_str).collect();
        props.push(prop(&format!("rcbom:param:{k}"), v.join(" | ")));
    }
    // where the key material handed to this asset's APIs comes from (intraprocedural)
    let mut by_role: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    // the hard-coded roles in reachable code, and those only in code not reachable from the
    // entry points
    let mut reachable_hc: BTreeSet<&str> = BTreeSet::new();
    let mut present_hc: BTreeSet<&str> = BTreeSet::new();
    for o in &a.occurrences {
        for (role, kind) in &o.provenance {
            by_role.entry(role).or_default().insert(kind);
            if kind == "hard-coded" && SECRET_ROLES.contains(&role.as_str()) {
                match o.tier {
                    Tier::Reachable => reachable_hc.insert(role),
                    Tier::Present => present_hc.insert(role),
                };
            }
        }
    }
    for (role, kinds) in &by_role {
        props.push(prop(
            &format!("rcbom:provenance:{role}"),
            kinds.iter().copied().collect::<Vec<_>>().join(","),
        ));
        if reachable_hc.contains(role) {
            props.push(prop("rcbom:finding", finding(role)));
        } else if present_hc.contains(role) {
            props.push(prop("rcbom:finding:present", finding(role)));
        }
    }
    if let Some(n) = &a.algo.note {
        props.push(prop("rcbom:note", n));
    }
    // the operations whose algorithm the analysis does not find: no name, no family
    if a.unresolved() {
        props.push(prop("rcbom:algorithm", "unresolved"));
    // a name the Cryptography Registry has no pattern for (a family name for a variant the
    // code does not determine, a variant the registry does not list)
    } else if a.algo.material.is_none() && !rcbom_kb::registry::valid(&a.name) {
        props.push(prop("rcbom:registry-name", "unmatched"));
    }
    props.push(prop("rcbom:occurrences", a.occurrences.len()));
    if a.algo.material.is_none()
        && !a.unresolved()
        && !a.algo.family.is_empty()
        && !rcbom_kb::in_family_enum(&a.algo.family)
    {
        props.push(prop("rcbom:algorithm-family", &a.algo.family));
    }
    let crypto = match &a.algo.material {
        // a key with no scheme: material, linked to its family by a property
        Some(m) => {
            if !a.algo.family.is_empty() {
                props.push(prop("rcbom:algorithm-family", &a.algo.family));
            }
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
        "bom-ref": bom_ref,
        "name": a.name,
        "cryptoProperties": crypto,
        "evidence": { "occurrences": occurrences },
        "properties": props,
    })
}

/// The bom-ref of a protocol's asset: `crypto:protocol:TLS`.
pub(crate) fn protocol_ref(p: &crate::Protocol) -> String {
    format!("crypto:protocol:{}", p.name)
}

/// A protocol's asset: one for the protocol the configuration offers, with every version it
/// enables (`rcbom:protocol:versions`) and all their cipher suites. CycloneDX gives a protocol
/// one `version`: it is stated only when one version is enabled, so that suites of another
/// version are never listed under it.
fn protocol_component(kb: &Kb, p: &crate::Protocol, several_artifacts: bool) -> Value {
    let occurrences: Vec<Value> = p
        .occurrences
        .iter()
        .map(|o| {
            json!({
                "location": o.location,
                "line": o.line,
                "offset": o.offset,
                "symbol": o.symbol,
                "additionalContext": context(o, several_artifacts),
            })
        })
        .collect();
    let mut pp = serde_json::Map::new();
    pp.insert("type".into(), json!(p.kind));
    if let [v] = p.versions.as_slice() {
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
    if several_artifacts {
        for art in artifacts_of(&p.occurrences) {
            props.push(prop("rcbom:artifact", art));
        }
    }
    json!({
        "type": "cryptographic-asset",
        "bom-ref": protocol_ref(p),
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

/// `provider`: the package provides an asset (an occurrence names it).
fn library_component(
    man: &Manifest,
    p: &Pkg,
    usage: Option<Usage>,
    layer2: bool,
    provider: bool,
) -> Value {
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
    // cryptographic by its metadata, not modelled by the knowledge base
    if let Some(u) = p.unmodelled {
        props.push(prop(
            "rcbom:crypto-role",
            match u {
                rcbom_kb::Unmodelled::Crypto => "unmodelled",
                rcbom_kb::Unmodelled::Support => "support",
            },
        ));
        props.push(prop("rcbom:kb-coverage", "unmodelled"));
        if let Some(u) = usage {
            let value = if !layer2 || (p.scope == Scope::Build && u == Usage::DeclaredNotUsed) {
                "unknown"
            } else {
                match u {
                    Usage::Reachable => "reachable",
                    Usage::Present => "present",
                    Usage::DeclaredNotUsed => "declared-not-used",
                }
            };
            props.push(prop("rcbom:usage", value));
        }
    }
    if !p.backends.is_empty() {
        props.push(prop("rcbom:backend", p.backends.join(",")));
    }
    if let Some(l) = &p.links {
        props.push(prop("rcbom:native-links", l));
        props.push(prop("rcbom:ffi-boundary", "true"));
    }
    // an interface package (`digest`, `crypto-common`) has no use of its own to report, unless
    // it provides an asset (rand_core 0.6's `OsRng`, drawn from)
    if let (Some(u), Some(r)) = (usage, p.role)
        && (r != Role::Trait || provider)
    {
        if !layer2 || (u == Usage::DeclaredNotUsed && (!p.kb_supported || p.scope == Scope::Build))
        {
            // without Layer 2 (`--manifest-only`) no use was looked for; its APIs are not in
            // the knowledge base (a version it does not cover): no use could have been seen,
            // only what the walk and its unknown occurrences say; only build scripts and proc
            // macros use it, and they are not analysed
            props.push(prop("rcbom:usage", "unknown"));
        } else {
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
        "type": if p.member && p.binary { "application" } else { "library" },
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
            // an algorithm of that name was found (a key of that name, the JWT HMAC secret, is
            // not the algorithm)
            if an
                .assets
                .values()
                .any(|a| a.name == *name && a.algo.material.is_none())
            {
                continue;
            }
            let mut ap = serde_json::Map::new();
            if let Some(t) = template {
                ap.insert("primitive".into(), json!(t.primitive));
                if rcbom_kb::in_family_enum(&t.family) {
                    ap.insert("algorithmFamily".into(), json!(t.family));
                }
            }
            let mut props = vec![
                prop("rcbom:detection:method", "manifest"),
                prop("rcbom:confidence", "low"),
                prop(
                    "rcbom:usage",
                    if an.layer2 && p.scope == Scope::Required {
                        "declared-not-used"
                    } else {
                        "unknown"
                    },
                ),
                prop("rcbom:kb:version", &kb.version),
            ];
            // as for the assets found: a name the registry has no pattern for is flagged
            // (`SHA-2`, the family name of the sha2 crate)
            if template.is_some() && !rcbom_kb::registry::valid(name) {
                props.push(prop("rcbom:registry-name", "unmatched"));
            }
            out.push(json!({
                "type": "cryptographic-asset",
                "rcbom-from": pkg_ref(&p.name, &p.version.to_string()),
                "bom-ref": format!("crypto:candidate:{}@{}:{}", p.name, p.version, name),
                "name": name,
                "cryptoProperties": { "assetType": "algorithm", "algorithmProperties": ap },
                "evidence": { "occurrences": manifest_occurrences(man, p) },
                "properties": props,
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
        .filter(|p| p.member || p.role.is_some() || p.unmodelled.is_some() || p.links.is_some())
        .collect();
    let included_ids: HashSet<_> = included.iter().map(|p| p.id.clone()).collect();
    let providers: HashSet<&(String, String)> =
        an.assets.values().flat_map(|a| &a.providers).collect();
    let mut components: Vec<Value> = included
        .iter()
        .map(|p| {
            let key = (p.name.clone(), p.version.to_string());
            library_component(
                man,
                p,
                an.usage.get(&key).copied(),
                an.layer2,
                providers.contains(&key),
            )
        })
        .collect();
    let refs = asset_refs(an);
    components.extend(
        an.assets
            .values()
            .map(|a| asset_component(kb, a, &refs[&a.key], an.artifacts.len() > 1)),
    );
    components.extend(
        an.protocols
            .values()
            .map(|p| protocol_component(kb, p, an.artifacts.len() > 1)),
    );
    let mut candidates = candidate_assets(kb, man, an);

    // Dependencies: package graph reduced to the included packages, providers, composition.
    let by_id: HashMap<_, _> = man.packages.iter().map(|p| (p.id.clone(), p)).collect();
    let mut provides: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for a in an.assets.values() {
        for (n, v) in &a.providers {
            provides
                .entry(pkg_ref(n, v))
                .or_default()
                .insert(refs[&a.key].clone());
        }
    }
    // the protocol crate provides the protocol; a candidate comes from its crate
    for p in an.protocols.values() {
        if let Some((n, v)) = &p.package {
            provides
                .entry(pkg_ref(n, v))
                .or_default()
                .insert(protocol_ref(p));
        }
    }
    for c in &candidates {
        if let (Some(r), Some(from)) = (c["bom-ref"].as_str(), c["rcbom-from"].as_str()) {
            provides
                .entry(from.to_string())
                .or_default()
                .insert(r.to_string());
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
            .filter_map(|c| refs.get(c).cloned())
            .collect();
        if !on.is_empty() {
            deps.push(json!({ "ref": refs[&a.key], "dependsOn": on }));
        }
    }
    for c in &mut candidates {
        if let Some(o) = c.as_object_mut() {
            o.remove("rcbom-from");
        }
    }
    components.extend(candidates);
    // every component is in the graph, those without dependencies as empty elements (CycloneDX
    // 1.7 `dependencies`)
    let listed: HashSet<String> = deps
        .iter()
        .filter_map(|d| d["ref"].as_str().map(str::to_string))
        .collect();
    for c in &components {
        if let Some(r) = c["bom-ref"].as_str()
            && !listed.contains(r)
        {
            deps.push(json!({ "ref": r, "dependsOn": [] }));
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
        prop("rcbom:run:profile", &run.profile),
        prop("rcbom:run:packages", run.packages),
        prop("rcbom:run:sandbox", &run.sandbox),
        prop("rcbom:kb:version", &kb.version),
        prop("rcbom:run:reachable-instances", an.instances),
    ];
    // the artifacts walked (each binary, a workspace library's public API)
    for a in &an.artifacts {
        run_props.push(prop("rcbom:run:artifact", a));
    }
    for n in &an.notes {
        run_props.push(prop("rcbom:run:note", n));
    }
    for w in &run.walk_check {
        run_props.push(prop("rcbom:run:walk-check", w));
    }
    if an.layer2 {
        run_props.push(prop("rcbom:run:boundary-check", an.coverage.summary()));
    }
    // the root package is the BOM's subject: `metadata.component`, the same bom-ref the
    // dependency graph starts from, and not also among the components
    let root_component = root.and_then(|r| {
        let rr = pkg_ref(&r.name, &r.version.to_string());
        let i = components
            .iter()
            .position(|c| c["bom-ref"] == rr.as_str())?;
        Some(components.remove(i))
    });
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
    if let Some(c) = root_component {
        bom["metadata"]["component"] = c;
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
