//! Layer 2 on the stable side: match the driver's facts against the knowledge base, decide
//! tiers (reachable from a workspace entry point, or only present in a compiled crate), recover
//! parameters and composition from generic arguments, classify uses by the method called, and
//! assemble a CycloneDX 1.7 CBOM together with Layer 1.

mod cbom;
mod matcher;
mod provenance;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use rcbom_facts::{CrateFacts, FACTS_VERSION, OwnerKind, Site, Target, Tier};
use rcbom_kb::{Algo, Kb, Role};
use rcbom_manifest::Manifest;

pub use cbom::{RunInfo, to_cyclonedx};
use matcher::{Match, match_constructor, match_fn, match_protocol, match_static, match_types};

/// What an occurrence is evidence of.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    /// A call into a crypto API (`Aead::encrypt`, `x25519_dalek::..::diffie_hellman`).
    Call,
    /// A crypto type chosen as a generic argument of the user's own code (`seal::<Aes256Gcm>`).
    Instantiation,
    /// A static algorithm descriptor named in code (`&ring::aead::AES_256_GCM`).
    Static,
    /// A static named in code that leads to algorithm descriptors (`DIGESTS`, a rustls suite).
    ViaStatic,
    /// The asset is part of another one used here (the SHA-256 inside `Hmac<Sha256>`).
    Component,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Call => "call",
            Kind::Instantiation => "instantiation",
            Kind::Static => "static",
            Kind::ViaStatic => "via-static",
            Kind::Component => "component",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Occurrence {
    pub location: String,
    pub line: usize,
    /// 0-based character column (CycloneDX `offset`, CBOMkit convention).
    pub offset: usize,
    pub symbol: String,
    pub kind: Kind,
    pub tier: Tier,
    pub function: Option<String>,
    /// Enclosing item.
    pub owner: String,
    /// The macro the code comes from, when it was called at this position.
    pub macro_tag: Option<(rcbom_facts::MacroKind, String)>,
    /// The source line of the position, trimmed, when the driver had it.
    pub line_text: Option<String>,
    /// The source text the position names, when the driver had it.
    pub code: Option<String>,
    pub detail: Vec<String>,
    /// Package the source file belongs to.
    pub package: (String, String),
    /// Key material arguments of the call and where they come from: (role, kind), e.g.
    /// ("nonce", "hard-coded").
    pub provenance: Vec<(String, String)>,
}

#[derive(Clone, Debug)]
pub struct Asset {
    /// Name, primitive and material together (`matcher::asset_key`).
    pub key: String,
    pub name: String,
    pub algo: Algo,
    /// Parameter values; several when occurrences disagree.
    pub params: BTreeMap<String, BTreeSet<String>>,
    pub occurrences: Vec<Occurrence>,
    /// Keys of component assets.
    pub components: BTreeSet<String>,
    /// Packages (name, version) implementing it.
    pub providers: BTreeSet<(String, String)>,
}

impl Asset {
    pub fn reachable(&self) -> bool {
        self.occurrences.iter().any(|o| o.tier == Tier::Reachable)
    }

    /// The uses the program makes of the asset: those seen at reachable occurrences when the
    /// asset is reachable (code that only exists in a dependency is not the program's use),
    /// else those seen anywhere.
    pub fn observed_functions(&self) -> BTreeSet<String> {
        let reachable = self.reachable();
        self.occurrences
            .iter()
            .filter(|o| !reachable || o.tier == Tier::Reachable)
            .filter_map(|o| o.function.as_deref())
            // `encrypt or decrypt`: the asset is used for either
            .flat_map(|f| f.split(" or ").map(str::to_string))
            .collect()
    }
}

/// How a package's crypto code is used, from Layer 2's point of view.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Usage {
    DeclaredNotUsed,
    Present,
    Reachable,
}

/// A protocol configured by the program (TLS through rustls), with what the reachable
/// configuration offers.
#[derive(Clone, Debug)]
pub struct Protocol {
    pub name: String,
    /// CycloneDX `protocolProperties.type`.
    pub kind: String,
    pub versions: Vec<String>,
    pub suites: Vec<String>,
    pub groups: Vec<String>,
    /// Backend packages, comma-separated: the providers the code names, else those of the
    /// reachable cipher suites, else what Layer 1's features select.
    pub backend: Option<String>,
    pub occurrences: Vec<Occurrence>,
    /// The protocol crate's package.
    pub package: Option<(String, String)>,
    /// Providers named by the program's reachable calls, and by any of its calls.
    named_backends: BTreeSet<String>,
    named_present: BTreeSet<String>,
    suite_backends: BTreeSet<String>,
    feature_backends: Vec<String>,
}

/// The backend package a rustls path names (`crypto::ring::default_provider`,
/// `crypto::aws_lc_rs::tls13::TLS13_AES_128_GCM_SHA256`).
fn backend_in_path(path: &str) -> Option<&'static str> {
    if path.contains("::ring::") {
        Some("ring")
    } else if path.contains("::aws_lc_rs::") {
        Some("aws-lc-rs")
    } else {
        None
    }
}

pub struct Analysis {
    pub assets: BTreeMap<String, Asset>,
    pub protocols: BTreeMap<String, Protocol>,
    pub usage: HashMap<(String, String), Usage>,
    pub notes: Vec<String>,
    pub instances: usize,
    pub truncated: bool,
    /// Layer 2 ran: without it (`--manifest-only`) nothing is known about use.
    pub layer2: bool,
}

/// The facts files in `dir`, sorted by crate, so that the result never depends on the order
/// the file system lists them in. With `units`, only the files of those cargo units (file
/// stems `<crate><unit>`): a crate compiled by an earlier build, with other dependencies or
/// features, leaves a file under another unit id that must not be read.
pub fn load_facts(
    dir: &Path,
    units: Option<&std::collections::BTreeSet<String>>,
) -> Result<Vec<CrateFacts>> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)?
        .map(|e| e.map(|e| e.path()))
        .collect::<std::io::Result<_>>()?;
    paths.sort();
    let mut out = Vec::new();
    for p in paths {
        let stem = p.file_stem().map(|s| s.to_string_lossy().to_string());
        if units.is_some_and(|u| !stem.as_ref().is_some_and(|s| u.contains(s))) {
            continue;
        }
        if p.extension().is_some_and(|x| x == "json") {
            let f: CrateFacts = serde_json::from_slice(&std::fs::read(&p)?)?;
            if f.facts_version != FACTS_VERSION {
                bail!(
                    "{}: facts version {} (expected {FACTS_VERSION}); rebuild the driver",
                    p.display(),
                    f.facts_version
                );
            }
            out.push(f);
        }
    }
    out.sort_by(|a, b| {
        (&a.krate.name, &a.krate.stable_id, &a.krate.unit).cmp(&(
            &b.krate.name,
            &b.krate.stable_id,
            &b.krate.unit,
        ))
    });
    Ok(out)
}

struct Ctx<'a> {
    kb: &'a Kb,
    /// (crate name, stable id) -> (package, version)
    crates: HashMap<(String, String), (String, String)>,
    /// Call sites by (owner, file, line, column): the site of a call an argument comes from.
    calls: HashMap<(&'a str, &'a str, usize, usize), &'a Site>,
}

impl Ctx<'_> {
    fn package_of_crate(&self, name: &str, stable_id: &str) -> Option<(String, String)> {
        self.crates
            .get(&(name.to_string(), stable_id.to_string()))
            .cloned()
    }

    /// The knowledge base covers this exact crate: known package, version in range.
    fn supported(&self, k: &rcbom_facts::CrateRef) -> bool {
        self.package_of_crate(&k.name, &k.stable_id)
            .and_then(|(n, v)| Some((n, semver::Version::parse(&v).ok()?)))
            .is_some_and(|(n, v)| self.kb.crate_by_package(&n, &v).is_some())
    }
}

pub fn analyze(kb: &Kb, man: &Manifest, facts: &[CrateFacts]) -> Analysis {
    let ctx = Ctx {
        kb,
        crates: facts
            .iter()
            .map(|f| {
                (
                    (f.krate.name.clone(), f.krate.stable_id.clone()),
                    (f.krate.package.clone(), f.krate.version.clone()),
                )
            })
            .collect(),
        calls: facts
            .iter()
            .flat_map(|f| &f.sites)
            .filter(|s| matches!(s.target, Target::Call { .. }))
            .map(|s| {
                (
                    (
                        s.owner.id.as_str(),
                        s.span.file.as_str(),
                        s.span.line,
                        s.span.col,
                    ),
                    s,
                )
            })
            .collect(),
    };
    let mut notes = Vec::new();
    let supported = |k: &rcbom_facts::CrateRef| ctx.supported(k);

    // --- statics: the graph of initializers, and what is reachable ------------------------
    let mut static_edges: HashMap<String, Vec<rcbom_facts::DefRef>> = HashMap::new();
    let mut static_defs: HashMap<String, rcbom_facts::DefRef> = HashMap::new();
    for f in facts {
        for s in &f.sites {
            if let (OwnerKind::Static, Target::Static { def } | Target::Const { def }) =
                (&s.owner.kind, &s.target)
            {
                static_edges
                    .entry(s.owner.id.clone())
                    .or_default()
                    .push(def.clone());
                static_defs.insert(def.id.clone(), def.clone());
            }
        }
        // edges only evaluation shows (a static built by a `const fn`)
        for e in &f.data_edges {
            static_edges
                .entry(e.owner.id.clone())
                .or_default()
                .push(e.target.clone());
            static_defs
                .entry(e.target.id.clone())
                .or_insert_with(|| e.target.clone());
        }
        if let Some(r) = &f.reach {
            for d in &r.statics {
                static_defs.insert(d.id.clone(), d.clone());
            }
        }
        for site in &f.sites {
            if let Target::Static { def } | Target::Const { def } = &site.target {
                static_defs
                    .entry(def.id.clone())
                    .or_insert_with(|| def.clone());
            }
        }
    }
    let closure = |start: &str| -> Vec<rcbom_facts::DefRef> {
        let mut seen = HashSet::new();
        let mut stack = vec![start.to_string()];
        let mut out = Vec::new();
        while let Some(id) = stack.pop() {
            if !seen.insert(id.clone()) {
                continue;
            }
            if let Some(d) = static_defs.get(&id) {
                out.push(d.clone());
            }
            for t in static_edges.get(&id).into_iter().flatten() {
                stack.push(t.id.clone());
            }
        }
        out
    };
    // Reachable functions, from every binary's walk; the data their bodies name (statics, and
    // consts whose values evaluation copied away) is reachable, and so is what that data names.
    let reached_fns: HashSet<&str> = facts
        .iter()
        .filter_map(|f| f.reach.as_ref())
        .flat_map(|r| r.fns.iter().map(String::as_str))
        .collect();
    let mut seeds: Vec<rcbom_facts::DefRef> = Vec::new();
    // data named by reachable functions: (crate of the function, item id)
    let mut code_refs: Vec<(String, String)> = Vec::new();
    let (mut instances, mut truncated) = (0, false);
    for f in facts {
        if let Some(r) = &f.reach {
            instances += r.instances;
            truncated |= r.truncated;
            seeds.extend(r.statics.iter().cloned());
        }
        for s in &f.sites {
            if let (OwnerKind::Fn, Target::Static { def } | Target::Const { def }) =
                (&s.owner.kind, &s.target)
                && (s.tier == Tier::Reachable || reached_fns.contains(s.owner.id.as_str()))
            {
                seeds.push(def.clone());
                code_refs.push((s.owner.krate.name.clone(), def.id.clone()));
            }
        }
    }
    let mut reachable_statics: HashSet<String> = HashSet::new();
    for d in &seeds {
        if !reachable_statics.contains(&d.id) {
            reachable_statics.extend(closure(&d.id).into_iter().map(|d| d.id));
        }
    }
    if truncated {
        notes.push(
            "reachability walk hit its instance limit; the reachable tier is incomplete".into(),
        );
    }

    // --- sites -> occurrences ---------------------------------------------------------------
    let mut assets: BTreeMap<String, Asset> = BTreeMap::new();
    let mut protocols: BTreeMap<String, Protocol> = BTreeMap::new();
    let mut usage: HashMap<(String, String), Usage> = HashMap::new();
    // outer asset -> components, from descriptor statics; applied to assets with evidence only
    let mut composition: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    for f in facts {
        let cwd = PathBuf::from(&f.krate.cwd);
        for site in &f.sites {
            let path = {
                let p = PathBuf::from(&site.span.file);
                if p.is_absolute() { p } else { cwd.join(p) }
            };
            let tier = match site.owner.kind {
                OwnerKind::Static if reachable_statics.contains(&site.owner.id) => Tier::Reachable,
                OwnerKind::Static => Tier::Present,
                OwnerKind::Fn if reached_fns.contains(site.owner.id.as_str()) => Tier::Reachable,
                OwnerKind::Fn => site.tier,
            };
            let Some(owner_pkg) = man.owner_of(&path) else {
                continue;
            }; // std, generated code
            let pkg = (owner_pkg.name.clone(), owner_pkg.version.to_string());
            // Composition between descriptor statics (ECDSA_P256_SHA256_FIXED -> SHA256) holds
            // wherever it is written, including inside the implementing crate.
            if let (OwnerKind::Static, Target::Static { def } | Target::Const { def }) =
                (&site.owner.kind, &site.target)
                && let Some(outer) = static_defs
                    .get(&site.owner.id)
                    .and_then(|d| match_static(kb, d, &supported))
                && let Some(inner) = match_static(kb, def, &supported)
                && outer.key() != inner.key()
            {
                composition
                    .entry(outer.key())
                    .or_default()
                    .insert(inner.key());
            }
            // Inside an algorithm or trait crate the code *is* the implementation: not evidence.
            if matches!(owner_pkg.role, Some(Role::Algorithm | Role::Trait)) {
                continue;
            }
            if let Target::Call { callee, .. } = &site.target
                && let Some(p) = match_protocol(kb, callee, &supported)
            {
                let pkg_of = ctx.package_of_crate(&callee.krate.name, &callee.krate.stable_id);
                let proto_pkg = pkg_of.as_ref().and_then(|(n, v)| man.by_name_version(n, v));
                let entry = protocols.entry(p.name.clone()).or_insert_with(|| Protocol {
                    name: p.name.clone(),
                    kind: p.kind.clone(),
                    versions: p
                        .versions
                        .iter()
                        .filter(|(_, feat)| {
                            feat.is_empty()
                                || proto_pkg.is_some_and(|pp| pp.features.contains(feat))
                        })
                        .map(|(v, _)| v.clone())
                        .collect(),
                    suites: Vec::new(),
                    groups: Vec::new(),
                    backend: None,
                    occurrences: Vec::new(),
                    package: pkg_of.clone(),
                    named_backends: BTreeSet::new(),
                    named_present: BTreeSet::new(),
                    suite_backends: BTreeSet::new(),
                    feature_backends: proto_pkg.map(|pp| pp.backends.clone()).unwrap_or_default(),
                });
                // a provider named by the program (`crypto::ring::default_provider`) is the
                // backend, whatever the crate's features enable; rustls naming its own providers,
                // or dead code, is not the program's choice
                if let Some(b) = backend_in_path(&callee.path)
                    && pkg_of.as_ref() != Some(&pkg)
                {
                    if tier == Tier::Reachable {
                        entry.named_backends.insert(b.to_string());
                    }
                    entry.named_present.insert(b.to_string());
                }
                let (suites, groups) = (p.suites.clone(), p.groups.clone());
                let last = |d: &rcbom_facts::DefRef| {
                    d.path.rsplit("::").next().unwrap_or(&d.path).to_string()
                };
                let is_group =
                    |d: &rcbom_facts::DefRef| d.krate.name == p.krate && groups.is_match(&last(d));
                for d in static_defs.values() {
                    if d.krate.name != p.krate || !reachable_statics.contains(&d.id) {
                        continue;
                    }
                    let n = last(d);
                    if suites.is_match(&n) && !n.ends_with("_INTERNAL") {
                        if let Some(b) = backend_in_path(&d.path) {
                            entry.suite_backends.insert(b.to_string());
                        }
                        if !entry.suites.contains(&n) {
                            entry.suites.push(n);
                        }
                    } else if groups.is_match(&n) && !entry.groups.contains(&n) {
                        // a group offered as such is listed by reachable data that is not itself
                        // a group (DEFAULT_KX_GROUPS); MLKEM768 reached only as the half of
                        // X25519MLKEM768 is a component, not an offered group
                        // or by the program's own reachable code
                        // (`kx_groups: vec![kx_group::MLKEM1024]`)
                        let offered =
                            static_edges.iter().any(|(owner, targets)| {
                                reachable_statics.contains(owner)
                                    && !static_defs.get(owner).is_some_and(is_group)
                                    && targets.iter().any(|t| t.id == d.id)
                            }) || code_refs.iter().any(|(k, id)| *k != p.krate && *id == d.id);
                        if offered {
                            entry.groups.push(n);
                        }
                    }
                }
                // the protocol crate configuring itself is not evidence of the program's use
                if pkg_of.as_ref() == Some(&pkg) {
                    continue;
                }
                entry.occurrences.push(Occurrence {
                    location: man.location(&path),
                    line: site.span.line,
                    offset: site.span.col.saturating_sub(1),
                    symbol: callee.path.clone(),
                    kind: Kind::Call,
                    tier,
                    function: None,
                    owner: short(&site.owner.name),
                    macro_tag: None,
                    line_text: site.line_text.clone(),
                    code: site.text.clone(),
                    detail: vec![],
                    package: pkg.clone(),
                    provenance: Vec::new(),
                });
            }
            // a call into a crypto crate uses it, whatever matches (rsa's OAEP through age)
            if let Target::Call { callee, .. } = &site.target
                && kb.crate_by_name(&callee.krate.name).is_some()
                && let Some(cp) = ctx.package_of_crate(&callee.krate.name, &callee.krate.stable_id)
            {
                let u = usage.entry(cp).or_insert(Usage::Present);
                if tier == Tier::Reachable {
                    *u = Usage::Reachable;
                }
            }
            let matches = site_matches(&ctx, site, &closure);
            let prov = provenance::of_call(kb, &site.target);
            for (m, kind, function, symbol, detail) in matches {
                for prov in &m.providers {
                    let u = usage.entry(prov.clone()).or_insert(Usage::Present);
                    if tier == Tier::Reachable {
                        *u = Usage::Reachable;
                    }
                }
                if owner_pkg.role.is_some() {
                    let u = usage.entry(pkg.clone()).or_insert(Usage::Present);
                    if tier == Tier::Reachable {
                        *u = Usage::Reachable;
                    }
                }
                let location = man.location(&path);
                let offset = site.span.col.saturating_sub(1);
                let mut detail = detail;
                // the key material of a call belongs to the asset called, not to its parts
                let prov: &[(String, std::collections::BTreeSet<provenance::Class>)] =
                    if kind == Kind::Component { &[] } else { &prov };
                for (role, classes) in prov {
                    let text: Vec<String> = classes
                        .iter()
                        .map(|c| {
                            if c.detail.is_empty() {
                                c.kind.clone()
                            } else {
                                format!("{} ({})", c.kind, c.detail)
                            }
                        })
                        .collect();
                    if !text.is_empty() {
                        detail.push(format!("{role}: {}", text.join(" or ")));
                    }
                }
                if let Some(e) = &site.expansion {
                    detail.push(format!(
                        "expanded from {}:{}",
                        man.location(&cwd.join(&e.def_site.file)),
                        e.def_site.line
                    ));
                }
                for v in &site.via {
                    let vp = PathBuf::from(&v.span.file);
                    let vp = if vp.is_absolute() { vp } else { cwd.join(vp) };
                    detail.push(format!(
                        "instantiated by {} at {}:{}",
                        short(&v.caller),
                        man.location(&vp),
                        v.span.line
                    ));
                }
                let occ = Occurrence {
                    location,
                    line: site.span.line,
                    offset,
                    symbol,
                    kind,
                    tier,
                    function,
                    owner: short(&site.owner.name),
                    macro_tag: site
                        .expansion
                        .as_ref()
                        .filter(|e| e.kind != rcbom_facts::MacroKind::Desugaring)
                        .map(|e| (e.kind, e.macro_name.clone())),
                    line_text: site.line_text.clone(),
                    code: site.text.clone(),
                    detail,
                    package: pkg.clone(),
                    provenance: prov
                        .iter()
                        .flat_map(|(role, cs)| {
                            cs.iter().map(move |c| (role.clone(), c.kind.clone()))
                        })
                        .collect(),
                };
                let a = assets.entry(m.key()).or_insert_with(|| Asset {
                    key: m.key(),
                    name: m.name.clone(),
                    algo: m.algo.clone(),
                    params: BTreeMap::new(),
                    occurrences: Vec::new(),
                    components: BTreeSet::new(),
                    providers: BTreeSet::new(),
                });
                // parameters that differ between occurrences are all listed
                for (k, v) in &m.params {
                    a.params.entry(k.clone()).or_default().insert(v.clone());
                }
                a.components.extend(m.components.iter().cloned());
                a.providers.extend(m.providers.iter().cloned());
                // one occurrence per (position, symbol): the per-item scan and the walk see the
                // same call, generic code is seen once per instance; the static and the call a
                // macro produces at one call site are two
                if let Some(o) = a.occurrences.iter_mut().find(|o| {
                    o.location == occ.location
                        && o.line == occ.line
                        && o.offset == occ.offset
                        && o.symbol == occ.symbol
                }) {
                    if occ.tier == Tier::Reachable {
                        o.tier = Tier::Reachable;
                    }
                    if o.function.is_none() {
                        o.function = occ.function;
                    }
                    if o.kind != occ.kind && occ.kind == Kind::Call {
                        o.kind = Kind::Call;
                    }
                    for d in occ.detail {
                        if !o.detail.contains(&d) {
                            o.detail.push(d);
                        }
                    }
                    for p in occ.provenance {
                        if !o.provenance.contains(&p) {
                            o.provenance.push(p);
                        }
                    }
                } else {
                    a.occurrences.push(occ);
                }
            }
        }
    }
    for (outer, inner) in composition {
        if let Some(a) = assets.get_mut(&outer) {
            a.components.extend(inner);
        }
    }
    merge_less_specific(&mut assets);
    protocols.retain(|_, p| !p.occurrences.is_empty());
    for p in protocols.values_mut() {
        let backends: Vec<String> = if !p.named_backends.is_empty() {
            p.named_backends.iter().cloned().collect()
        } else if !p.named_present.is_empty()
            && !p.occurrences.iter().any(|o| o.tier == Tier::Reachable)
        {
            p.named_present.iter().cloned().collect()
        } else if !p.suite_backends.is_empty() {
            p.suite_backends.iter().cloned().collect()
        } else {
            p.feature_backends.clone()
        };
        p.backend = (!backends.is_empty()).then(|| backends.join(","));
        p.suites.sort();
        p.groups.sort();
        p.occurrences
            .sort_by(|x, y| (&x.location, x.line, x.offset).cmp(&(&y.location, y.line, y.offset)));
        // the same call seen by the per-item scan and by the walk: keep the stronger tier
        p.occurrences.dedup_by(|later, kept| {
            let same = (&later.location, later.line, later.offset)
                == (&kept.location, kept.line, kept.offset);
            if same && later.tier == Tier::Reachable {
                kept.tier = Tier::Reachable;
            }
            same
        });
    }
    for a in assets.values_mut() {
        a.occurrences.sort_by(|x, y| {
            (&x.package, &x.location, x.line, x.offset).cmp(&(
                &y.package,
                &y.location,
                y.line,
                y.offset,
            ))
        });
    }
    // A crate used by a used crypto crate is used too (aes, ctr, ghash under aes-gcm), at the
    // same tier: propagate down the Layer 1 graph until nothing changes. Only edges whose code
    // ships with the user's: a build dependency runs on the build machine.
    // A protocol crate depends on every backend it can use; only the one it uses is used, at
    // the protocol's tier.
    for proto in protocols.values() {
        let tier = if proto.occurrences.iter().any(|o| o.tier == Tier::Reachable) {
            Usage::Reachable
        } else {
            Usage::Present
        };
        for b in proto.backend.iter().flat_map(|b| b.split(',')) {
            for p in man.packages.iter().filter(|p| p.name == b) {
                let e = usage
                    .entry((p.name.clone(), p.version.to_string()))
                    .or_insert(tier);
                *e = (*e).max(tier);
            }
        }
    }
    loop {
        let mut changed = false;
        for p in &man.packages {
            if p.role == Some(Role::Protocol) {
                continue;
            }
            let Some(&u) = usage.get(&(p.name.clone(), p.version.to_string())) else {
                continue;
            };
            for d in &p.runtime_deps {
                let Some(dp) = man.by_id(d) else { continue };
                if dp.role.is_none() {
                    continue;
                }
                let e = usage
                    .entry((dp.name.clone(), dp.version.to_string()))
                    .or_insert(Usage::DeclaredNotUsed);
                if *e < u {
                    *e = u;
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }
    for p in &man.packages {
        if p.role.is_some() {
            usage
                .entry((p.name.clone(), p.version.to_string()))
                .or_insert(Usage::DeclaredNotUsed);
        }
    }
    Analysis {
        assets,
        protocols,
        usage,
        notes,
        instances,
        truncated,
        layer2: true,
    }
}

type SiteMatch = (Match, Kind, Option<String>, String, Vec<String>);

/// Every asset a site is evidence of, with the kind of evidence, the use and the symbol named.
/// What the call an argument of `site` comes from matched, when it is a [[fn]] entry of
/// `family`: the one such call among the arguments, found by its position in the same function.
fn argument_constructor(ctx: &Ctx<'_>, site: &Site, family: &str) -> Option<Match> {
    let Target::Call { arg_origins, .. } = &site.target else {
        return None;
    };
    let supported = |k: &rcbom_facts::CrateRef| ctx.supported(k);
    let mut found: Vec<Match> = Vec::new();
    for o in arg_origins {
        let rcbom_facts::Origin::Call { span: Some(at), .. } = o else {
            continue;
        };
        let Some(Target::Call {
            callee,
            self_ty,
            args,
            const_args,
            arg_lens,
            ..
        }) = ctx
            .calls
            .get(&(site.owner.id.as_str(), at.file.as_str(), at.line, at.col))
            .map(|s| &s.target)
        else {
            continue;
        };
        if let Some(m) = match_fn(
            ctx.kb,
            callee,
            self_ty.as_ref(),
            args,
            const_args,
            arg_lens,
            &supported,
        ) && m.algo.family == family
            && !found.iter().any(|f| f.key() == m.key())
        {
            found.push(m);
        }
    }
    // two constructors of the family with different names: the call does not say which
    match found.len() {
        1 => found.pop(),
        _ => None,
    }
}

fn site_matches(
    ctx: &Ctx<'_>,
    site: &Site,
    closure: &dyn Fn(&str) -> Vec<rcbom_facts::DefRef>,
) -> Vec<SiteMatch> {
    let kb = ctx.kb;
    let supported = |k: &rcbom_facts::CrateRef| ctx.supported(k);
    let mut out = Vec::new();
    match &site.target {
        Target::Static { def } | Target::Const { def } => {
            let symbol = def.path.clone();
            if let Some(mut m) = match_static(kb, def, &supported) {
                m.providers
                    .extend(ctx.package_of_crate(&def.krate.name, &def.krate.stable_id));
                let outer = m.name.clone();
                // descriptors inside this one (the SHA-256 in ECDSA_P256_SHA256_FIXED) are
                // used here too
                for inner in closure(&def.id).into_iter().filter(|d| d.id != def.id) {
                    if let Some(mut c) = match_static(kb, &inner, &supported)
                        && c.name != outer
                    {
                        c.providers.extend(
                            ctx.package_of_crate(&inner.krate.name, &inner.krate.stable_id),
                        );
                        m.components.insert(c.key());
                        let d = vec![format!(
                            "part of {outer} ({} -> {})",
                            short(&def.path),
                            short(&inner.path)
                        )];
                        out.push((c, Kind::Component, None, symbol.clone(), d));
                    }
                }
                out.insert(0, (m, Kind::Static, None, symbol, vec![]));
            } else {
                // descriptors this item leads to; one reached only inside another descriptor
                // (the SHA-256 in rcgen's PKCS_ECDSA_P256_SHA256 -> ECDSA_P256_SHA256_ASN1) is
                // part of that one, not a use of its own
                let found: Vec<(rcbom_facts::DefRef, Match)> = closure(&def.id)
                    .into_iter()
                    .filter_map(|inner| {
                        let m = match_static(kb, &inner, &supported)?;
                        Some((inner, m))
                    })
                    .collect();
                for (inner, mut m) in found.iter().cloned() {
                    m.providers
                        .extend(ctx.package_of_crate(&inner.krate.name, &inner.krate.stable_id));
                    let host = found.iter().find(|(o, om)| {
                        o.id != inner.id
                            && om.key() != m.key()
                            && closure(&o.id).iter().any(|d| d.id == inner.id)
                    });
                    match host {
                        Some((o, om)) => {
                            let d = vec![format!(
                                "part of {} ({} -> {})",
                                om.name,
                                short(&o.path),
                                short(&inner.path)
                            )];
                            out.push((m, Kind::Component, None, symbol.clone(), d));
                        }
                        None => {
                            let detail =
                                vec![format!("{} -> {}", short(&def.path), short(&inner.path))];
                            out.push((m, Kind::ViaStatic, None, symbol.clone(), detail));
                        }
                    }
                }
                // the hosts record their parts
                let parts: Vec<(String, String)> = found
                    .iter()
                    .flat_map(|(o, om)| {
                        found
                            .iter()
                            .filter(|(i, im)| {
                                i.id != o.id
                                    && im.key() != om.key()
                                    && closure(&o.id).iter().any(|d| d.id == i.id)
                            })
                            .map(|(_, im)| (om.key(), im.key()))
                            .collect::<Vec<_>>()
                    })
                    .collect();
                for (host, part) in parts {
                    for (m, ..) in out.iter_mut() {
                        if m.key() == host {
                            m.components.insert(part.clone());
                        }
                    }
                }
            }
        }
        Target::Call {
            callee,
            method,
            self_ty,
            args,
            const_args,
            arg_lens,
            ..
        } => {
            let symbol = callee.path.clone();
            let fn_match = match_fn(
                kb,
                callee,
                self_ty.as_ref(),
                args,
                const_args,
                arg_lens,
                &supported,
            );
            // a fn entry with `self_type` already accounts for the self type
            let skip_self = fn_match.is_some()
                && kb
                    .fns
                    .iter()
                    .any(|e| e.self_type.is_some() && e.pattern.is_match(&callee.path));
            let fn_name = fn_match.as_ref().map(|m| m.name.clone());
            let fn_family = fn_match.as_ref().map(|m| m.algo.family.clone());
            if let Some(mut m) = fn_match {
                for k in std::mem::take(&mut m.provider_crates) {
                    m.providers
                        .extend(ctx.package_of_crate(&k.name, &k.stable_id));
                }
                // a listed use of the method, or what the entry says the call does
                // (`RsaPrivateKey::new` generates a key); else the call sets the asset up
                let f = kb
                    .use_of(method, &m.algo.primitive)
                    .or_else(|| m.algo.implied_use.clone());
                let d = if f.is_none() {
                    vec![format!("{method}: setup, not a use")]
                } else {
                    vec![]
                };
                out.push((m, Kind::Call, f, symbol.clone(), d));
            }
            // a call into a crypto crate, or a std constructor or conversion of a crypto type
            // (`StaticSecret::from(bytes)`, `SigningKey::try_from(b)`, `<Argon2 as Default>`)
            let std_callee = matches!(callee.krate.name.as_str(), "core" | "std" | "alloc");
            let into_kb = kb.crate_by_name(&callee.krate.name).is_some()
                || (std_callee
                    && matches!(self_ty, Some(rcbom_facts::TyTree::Adt { krate, .. })
                        if kb.crate_by_name(&krate.name).is_some()));
            let trees: Vec<_> = self_ty
                .iter()
                .filter(|_| !skip_self)
                .chain(args.iter())
                .cloned()
                .collect();
            let receiver = match &site.target {
                Target::Call { arg_origins, .. } => arg_origins.first(),
                _ => None,
            };
            for (mut m, outer) in match_types(kb, &trees, &supported) {
                // the fn entry already names this algorithm, with what its arguments add:
                // `Oaep::new_with_label::<Sha256, _>` is RSA-OAEP-SHA-256, not also an `Oaep`
                // that is part of it
                if fn_family.as_deref() == Some(m.algo.family.as_str()) {
                    continue;
                }
                let providers = std::mem::take(&mut m.provider_crates);
                // the receiver's constructor may say more than its type: `Argon2::default()`
                // is Argon2id-19456-2-1, `Hasher::new_keyed(k)` a keyed BLAKE3
                if outer.is_none()
                    && let Some(r) = receiver
                    && let Some(c) = match_constructor(kb, &m.algo.family, r)
                {
                    let comps = std::mem::take(&mut m.components);
                    m = c;
                    m.components = comps;
                } else if outer.is_none()
                    && let Some(c) = argument_constructor(ctx, site, &m.algo.family)
                {
                    // or a value built in an argument: `encrypt(&mut rng,
                    // Oaep::new_with_label::<Sha256, _>(label), msg)` is RSA-OAEP-SHA-256, the
                    // `Oaep` type alone RSA-OAEP
                    let comps = std::mem::take(&mut m.components);
                    m = c;
                    m.components = comps;
                }
                for k in providers {
                    m.providers
                        .extend(ctx.package_of_crate(&k.name, &k.stable_id));
                }
                // the hash of `pbkdf2_hmac::<Sha256>` is part of the PBKDF2 asset
                let outer = outer.or_else(|| fn_name.clone());
                match outer {
                    None if into_kb => {
                        let f = kb.use_of(method, &m.algo.primitive);
                        let setup = if f.is_none() {
                            vec![format!("{method}: setup, not a use")]
                        } else {
                            vec![]
                        };
                        out.push((m, Kind::Call, f, symbol.clone(), setup));
                    }
                    None => {
                        let d = vec![format!(
                            "chosen as generic argument of {}",
                            short(&callee.path)
                        )];
                        out.push((m, Kind::Instantiation, None, symbol.clone(), d));
                    }
                    Some(parent) => {
                        let d = vec![format!("part of {parent}")];
                        out.push((m, Kind::Component, None, symbol.clone(), d));
                    }
                }
            }
            // ring / aws-lc-rs: keys are untyped, the algorithm is a static passed when the key
            // was built. `k.seal_in_place_append_tag(..)` gets AES-256-GCM from the
            // `UnboundKey::new(&AES_256_GCM, ..)` in the origin of `k`.
            if out.is_empty() && into_kb {
                let has_roles = !provenance::of_call(kb, &site.target).is_empty();
                let (mut descriptors, others) = provenance::data_in_args(kb, &site.target);
                // the user's own data naming exactly one descriptor (`digest(TABLE.alg, ..)`
                // with `TABLE.alg = &SHA256`) names it; a table of several (`DIGESTS[i]`) is
                // chosen at run time
                for d in others {
                    let found: Vec<rcbom_facts::DefRef> = closure(&d.id)
                        .into_iter()
                        .filter(|x| match_static(kb, x, &supported).is_some())
                        .collect();
                    if let [one] = found.as_slice()
                        && !descriptors.contains(one)
                    {
                        descriptors.push(one.clone());
                    }
                }
                for def in descriptors {
                    if let Some(mut m) = match_static(kb, &def, &supported) {
                        let f = kb.use_of(method, &m.algo.primitive);
                        if f.is_none() && !has_roles {
                            continue;
                        }
                        m.providers
                            .extend(ctx.package_of_crate(&def.krate.name, &def.krate.stable_id));
                        let d = vec![format!(
                            "algorithm from {} in the arguments",
                            short(&def.path)
                        )];
                        out.push((m, Kind::Call, f, symbol.clone(), d));
                    }
                }
            }
            if let (Some(n), Some(first)) = (&fn_name, out.first_mut()) {
                first.0.components.extend(
                    match_types(kb, args, &supported)
                        .into_iter()
                        .filter(|(m, _)| m.name != *n)
                        .map(|(m, _)| m.key()),
                );
            }
        }
    }
    out
}

/// One use found twice on a line, once with run-time parameters unresolved (`Argon2` from
/// `hash_password`) and once resolved (`Argon2id-19456-2-1` from `Argon2::default()`): the
/// resolved name keeps the occurrence, and the use.
fn merge_less_specific(assets: &mut BTreeMap<String, Asset>) {
    let keys: Vec<String> = assets.keys().cloned().collect();
    for general in &keys {
        for specific in &keys {
            let (g, s) = (&assets[general], &assets[specific]);
            // `PBKDF2-SHA-256` -> `PBKDF2-SHA-256-1000-32`, the family name `Argon2` ->
            // `Argon2id-19456-2-1`: a prefix ending at a part boundary (not `PBKDF2-SHA-256-1000`
            // -> `PBKDF2-SHA-256-10000-32`), same family and primitive (the QUIC
            // header-protection `AES-128`, a block cipher, never merges into `AES-128-GCM`),
            // algorithms only
            let boundary = s.name.starts_with(&format!("{}-", g.name))
                || (g.name == g.algo.family && s.name.starts_with(&g.name));
            if general == specific
                || !boundary
                || g.algo.family != s.algo.family
                || g.algo.primitive != s.algo.primitive
                || g.algo.material.is_some()
                || s.algo.material.is_some()
            {
                continue;
            }
            let from_general = assets[general].occurrences.clone();
            let mut merged = Vec::new();
            {
                let s = assets.get_mut(specific).unwrap();
                for g in from_general {
                    if let Some(o) = s
                        .occurrences
                        .iter_mut()
                        .find(|o| o.location == g.location && o.line == g.line)
                    {
                        if o.function.is_none() {
                            o.function = g.function;
                        }
                        for d in g.detail {
                            if !o.detail.contains(&d) {
                                o.detail.push(d);
                            }
                        }
                        for p in g.provenance {
                            if !o.provenance.contains(&p) {
                                o.provenance.push(p);
                            }
                        }
                        merged.push((g.location, g.line));
                    }
                }
            }
            let g = assets.get_mut(general).unwrap();
            g.occurrences
                .retain(|o| !merged.contains(&(o.location.clone(), o.line)));
        }
    }
    assets.retain(|_, a| !a.occurrences.is_empty());
}

/// `micro::seal::<aes_gcm::AesGcm<aes_gcm::aes::Aes256, ..>>` -> `micro::seal::<..>`, for
/// human-readable context; the full instance stays in the facts.
fn short(name: &str) -> String {
    match name.find("::<") {
        Some(i) if name.len() > 60 => format!("{}::<..>", &name[..i]),
        _ => name.to_string(),
    }
}
