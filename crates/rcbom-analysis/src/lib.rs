//! Layer 2 on the stable side: match the driver's facts against the knowledge base, decide
//! tiers (reachable from a workspace entry point, or only present in a compiled crate), recover
//! parameters and composition from generic arguments, classify uses by the method called, and
//! assemble a CycloneDX 1.7 CBOM together with Layer 1.

mod boundary;
mod cbom;
mod links;
mod matcher;
mod pointers;
mod provenance;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use rcbom_facts::{CrateFacts, FACTS_VERSION, OwnerKind, Site, Target, Tier};
use rcbom_kb::{Algo, Kb, Role};
use rcbom_manifest::Manifest;

pub use cbom::{RunInfo, to_cyclonedx};
pub use matcher::static_names;
use matcher::{
    Match, match_constructor, match_fn, match_fn_with, match_protocol, match_static, match_types,
};

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
    /// The knowledge-base note of the entry this occurrence matched (`QUIC header protection`).
    pub note: Option<String>,
    /// Found only by the per-item scan of a generic function's body, not in an instance of it:
    /// what its type parameters choose is not known there.
    pub generic_body: bool,
    /// The calls that created the generic instance it is in, innermost first (location, line,
    /// 0-based column), as the `instantiated by` details cite them.
    pub via: Vec<(String, usize, usize)>,
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
    /// The notes of the knowledge-base entries that matched it (`None`: an entry without).
    pub entry_notes: BTreeSet<Option<String>>,
}

impl Asset {
    /// An operation's asset whose algorithm the analysis does not find (not key material of
    /// no single family: `DecodingKey::from_jwk`'s).
    pub fn unresolved(&self) -> bool {
        self.name == UNKNOWN && self.algo.family.is_empty() && self.algo.material.is_none()
    }

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
            let f: CrateFacts = serde_json::from_slice(&std::fs::read(&p)?)
                .map_err(|e| anyhow::anyhow!("{}: {e}", p.display()))?;
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
    /// The program's own packages (members, path dependencies), by (name, version): never
    /// the crates the knowledge base describes.
    local: BTreeSet<(String, String)>,
    /// Call sites by (owner, file, line, column): the site of a call an argument comes from.
    calls: HashMap<CallKey<'a>, &'a Site>,
    /// What the calls a constructor's value is passed to matched, by the constructor's call
    /// site: `Params::new(15, 8, 1, 32)` set up for `scrypt(.., &p, out)` with a 64-byte `out`
    /// is scrypt-32768-8-1-64, as the call is.
    consumers: std::cell::RefCell<HashMap<CallKey<'a>, Vec<Match>>>,
    /// Filled while sites are matched: each constructor call linked to the call its value is
    /// passed to, with what that call matched (first pass), to become `consumers` (second).
    links: std::cell::RefCell<HashMap<CallKey<'a>, Vec<Match>>>,
    /// Values across functions (`links`): fields, results, parameters, mutable statics.
    flow: links::LinkIndex,
    /// The field names of the knowledge-base crates' structs, by path (`CrateFacts::fields`).
    fields: HashMap<String, Vec<String>>,
    /// The variants of their field-less enums (name, discriminant), by path.
    variants: HashMap<String, Vec<(String, i128)>>,
    /// Crates of cryptographic packages the knowledge base does not model (Layer 1's
    /// `unmodelled`): ml-kem, p256, sha3, md-5 (`md5`), by (crate name, stable id): two
    /// packages may name their library alike.
    unmodelled: HashSet<(String, String)>,
}

type CallKey<'a> = (&'a str, &'a str, usize, usize);

fn call_key(s: &Site) -> CallKey<'_> {
    (
        s.owner.id.as_str(),
        s.span.file.as_str(),
        s.span.line,
        s.span.col,
    )
}

impl<'a> Ctx<'a> {
    /// Records that the value constructor call `at` makes is passed to a call that matched `m`.
    fn link(&self, at: &'a Site, m: &Match) {
        self.links
            .borrow_mut()
            .entry(call_key(at))
            .or_default()
            .push(m.clone());
    }

    /// A crate of a crypto package the knowledge base does not model.
    fn is_unmodelled(&self, k: &rcbom_facts::CrateRef) -> bool {
        self.unmodelled
            .contains(&(k.name.clone(), k.stable_id.clone()))
    }

    /// The `[[crate]]` entry of exactly this crate's package, any version.
    fn kb_entry(&self, k: &rcbom_facts::CrateRef) -> Option<&rcbom_kb::CrateEntry> {
        let (package, _) = self.package_of_crate(&k.name, &k.stable_id)?;
        self.kb.crates.iter().find(|c| c.package == package)
    }

    fn package_of_crate(&self, name: &str, stable_id: &str) -> Option<(String, String)> {
        self.crates
            .get(&(name.to_string(), stable_id.to_string()))
            .cloned()
    }

    /// The knowledge base covers this exact crate: known package, version in range.
    fn supported(&self, k: &rcbom_facts::CrateRef) -> bool {
        self.package_of_crate(&k.name, &k.stable_id)
            .filter(|p| !self.local.contains(p))
            .and_then(|(n, v)| Some((n, semver::Version::parse(&v).ok()?)))
            .is_some_and(|(n, v)| self.kb.crate_by_package(&n, &v).is_some())
    }
}

pub fn analyze(kb: &Kb, man: &Manifest, facts: &[CrateFacts]) -> Analysis {
    // knowledge-base lookups by crate name go through the package each crate of this build
    // comes from (the package md-5's library is named `md5`, like the package md5's)
    kb.bind_crates(
        facts
            .iter()
            .map(|f| (f.krate.name.clone(), f.krate.package.clone()))
            .collect(),
    );
    let mut flow = {
        let t = std::time::Instant::now();
        let ix = links::LinkIndex::new(facts);
        if std::env::var_os("RCBOM_DEBUG").is_some() {
            eprintln!("analysis: link index in {:.1?}", t.elapsed());
        }
        ix
    };
    // calls through function pointers, as calls of the functions they hold; the namings they
    // account for are no occurrences of their own; the program's own functions called through
    // one get the call's arguments for their parameters
    let (pointer_calls, named_for_pointers, through_pointers) = pointers::resolve(facts, &flow);
    flow.add_calls(through_pointers);
    let sites_of = |i: usize| {
        facts[i]
            .sites
            .iter()
            .chain(&pointer_calls[i])
            .filter(|s| !pointers::accounted(s, &named_for_pointers))
    };
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
        local: man
            .packages
            .iter()
            .filter(|p| p.local)
            .map(|p| (p.name.clone(), p.version.to_string()))
            .collect(),
        calls: (0..facts.len())
            .flat_map(sites_of)
            .filter(|s| matches!(s.target, Target::Call { .. }))
            .map(|s| (call_key(s), s))
            .collect(),
        consumers: Default::default(),
        links: Default::default(),
        unmodelled: {
            let pkgs: HashSet<(&str, String)> = man
                .packages
                .iter()
                .filter(|p| p.unmodelled == Some(rcbom_kb::Unmodelled::Crypto))
                .map(|p| (p.name.as_str(), p.version.to_string()))
                .collect();
            facts
                .iter()
                .filter(|f| pkgs.contains(&(f.krate.package.as_str(), f.krate.version.clone())))
                .map(|f| (f.krate.name.clone(), f.krate.stable_id.clone()))
                .collect()
        },
        flow,
        fields: facts
            .iter()
            .flat_map(|f| f.fields.iter().map(|(k, v)| (k.clone(), v.clone())))
            .collect(),
        variants: facts
            .iter()
            .flat_map(|f| f.variants.iter().map(|(k, v)| (k.clone(), v.clone())))
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
    let reached_data = |id: &str| reachable_statics.contains(id);
    // the functions reachable from an entry point, by defining path (as links name them)
    let reached_paths: HashSet<String> = facts
        .iter()
        .filter_map(|f| f.reach.as_ref())
        .flat_map(|r| r.paths.iter().cloned())
        .chain(
            facts
                .iter()
                .flat_map(|f| &f.sites)
                .filter(|s| {
                    s.owner.kind == OwnerKind::Fn
                        && (s.tier == Tier::Reachable || reached_fns.contains(s.owner.id.as_str()))
                })
                .map(|s| s.owner.path.clone()),
        )
        .collect();
    let reached_path = |p: &str| reached_paths.contains(p);
    if truncated {
        notes.push(
            "reachability walk hit its instance limit; the reachable tier is incomplete".into(),
        );
    }

    // A first pass over the calls links each constructor to the calls its value is passed to
    // (`Params::new` to the `scrypt` it configures); the second names the constructor's own
    // occurrence after them.
    {
        let t = std::time::Instant::now();
        let mut keys: Vec<_> = ctx.calls.keys().copied().collect();
        keys.sort();
        for k in keys {
            let _ = site_matches(&ctx, ctx.calls[&k], &closure, &reached_data, &reached_path);
        }
        let links = ctx.links.take();
        *ctx.consumers.borrow_mut() = links;
        if std::env::var_os("RCBOM_DEBUG").is_some() {
            eprintln!("analysis: first pass in {:.1?}", t.elapsed());
        }
    }
    let main_pass = std::time::Instant::now();

    // --- sites -> occurrences ---------------------------------------------------------------
    let mut assets: BTreeMap<String, Asset> = BTreeMap::new();
    let mut protocols: BTreeMap<String, Protocol> = BTreeMap::new();
    let mut usage: HashMap<(String, String), Usage> = HashMap::new();
    // outer asset -> components, from descriptor statics; applied to assets with evidence only
    let mut composition: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    for (fi, f) in facts.iter().enumerate() {
        let cwd = PathBuf::from(&f.krate.cwd);
        for site in sites_of(fi) {
            let path = {
                let p = PathBuf::from(&site.span.file);
                if p.is_absolute() { p } else { cwd.join(p) }
            };
            let tier = match site.owner.kind {
                OwnerKind::Static if reachable_statics.contains(&site.owner.id) => Tier::Reachable,
                OwnerKind::Static => Tier::Present,
                OwnerKind::Fn if reached_fns.contains(site.owner.id.as_str()) => Tier::Reachable,
                // a closure or `async` body is reached with the function that writes it: in a
                // library's generic public function, which no instance walks, the per-item
                // scan sees it alone (`serialize_der_with_signer::{closure#1}`)
                OwnerKind::Fn if enclosing_fn(&site.owner.path).is_some_and(&reached_path) => {
                    Tier::Reachable
                }
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
            // nor is a crate the knowledge base does not model calling itself (hpke's own
            // generic functions, instantiated with a hash)
            if let Target::Call { callee, .. } = &site.target
                && ctx.is_unmodelled(&callee.krate)
                && callee.krate == site.owner.krate
            {
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
                        // the registry's (IANA's) name: rustls's `TLS13_AES_128_GCM_SHA256` is
                        // `TLS_AES_128_GCM_SHA256` (RFC 8446 B.4); TLS 1.2 names already are
                        let n = match n.strip_prefix("TLS13_") {
                            Some(rest) => format!("TLS_{rest}"),
                            None => n,
                        };
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
                    note: None,
                    generic_body: false,
                    via: Vec::new(),
                });
            }
            // a call into a crypto crate uses it, whatever matches (rsa's OAEP through age); so
            // does a call on a value of one of its types through an interface crate's trait
            // (`Aes128::new(key)` is `crypto_common::KeyInit::new`), and a call an algorithm
            // crate's type instantiates, whose code runs it (`generate_nonce(&mut OsRng)` draws
            // from rand_core's `OsRng`)
            if let Target::Call {
                callee,
                self_ty,
                args,
                ..
            } = &site.target
            {
                let self_krate = match self_ty {
                    Some(rcbom_facts::TyTree::Adt { krate, .. }) => Some(krate),
                    _ => None,
                };
                let mut in_args = Vec::new();
                for a in args {
                    adt_crates(a, &mut in_args);
                }
                let in_args = in_args.into_iter().filter(|k| {
                    kb.crate_by_name(&k.name)
                        .is_some_and(|c| c.role == Role::Algorithm)
                });
                for k in std::iter::once(&callee.krate)
                    .chain(self_krate)
                    .chain(in_args)
                {
                    if kb.crate_by_name(&k.name).is_some()
                        && let Some(cp) = ctx.package_of_crate(&k.name, &k.stable_id)
                    {
                        let u = usage.entry(cp).or_insert(Usage::Present);
                        if tier == Tier::Reachable {
                            *u = Usage::Reachable;
                        }
                    }
                }
            }
            let matches = site_matches(&ctx, site, &closure, &reached_data, &reached_path);
            let protocol = kb
                .crate_by_name(&site.owner.krate.name)
                .is_some_and(|c| c.role == Role::Protocol);
            let prov = provenance::of_call(kb, &ctx.flow, &site.target, protocol);
            for (m, kind, function, symbol, detail, unreached) in matches {
                let tier = if unreached { Tier::Present } else { tier };
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
                // a call through a function pointer: the operation is at the call, the function
                // was named elsewhere (`let h = digest;`)
                if let Target::Call {
                    through: Some(t),
                    callee,
                    ..
                } = &site.target
                {
                    let tp = PathBuf::from(&t.file);
                    let tp = if tp.is_absolute() { tp } else { cwd.join(tp) };
                    detail.push(format!(
                        "called through a function pointer to `{}` named at {}:{}:{}",
                        short(&callee.path),
                        man.location(&tp),
                        t.line,
                        t.col.saturating_sub(1)
                    ));
                }
                for v in &site.via {
                    // a call without a position (in the standard library's optimized MIR)
                    if v.span.line == 0 {
                        detail.push(format!("instantiated by {}", short(&v.caller)));
                        continue;
                    }
                    let vp = PathBuf::from(&v.span.file);
                    let vp = if vp.is_absolute() { vp } else { cwd.join(vp) };
                    // with the call's text where it has one: a neighbouring call that
                    // instantiates the function with other type arguments is told apart
                    // (`aes_ctr::<Aes128Ctr>` above `aes_ctr::<Aes192Ctr>`)
                    let text = v
                        .text
                        .as_ref()
                        .filter(|t| !t.contains('`') && !t.contains(';'))
                        .map(|t| format!(" as `{t}`"))
                        .unwrap_or_default();
                    detail.push(format!(
                        "instantiated by {} at {}:{}:{}{text}",
                        short(&v.caller),
                        man.location(&vp),
                        v.span.line,
                        v.span.col.saturating_sub(1)
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
                    note: m.algo.note.clone(),
                    generic_body: site.owner.kind == OwnerKind::Fn && is_def_hash(&site.owner.id),
                    via: site
                        .via
                        .iter()
                        .filter(|v| v.span.line != 0)
                        .map(|v| {
                            let vp = PathBuf::from(&v.span.file);
                            let vp = if vp.is_absolute() { vp } else { cwd.join(vp) };
                            (man.location(&vp), v.span.line, v.span.col.saturating_sub(1))
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
                    entry_notes: BTreeSet::new(),
                });
                // Several entries can name one asset: a verification and a signing descriptor of
                // one algorithm (`ECDSA_P256_SHA256_ASN1`, `.._SIGNING`), aws-lc-rs's
                // `cipher::AES_256` and its QUIC header-protection `AES_256`. What the asset can do
                // is what they say together; as for observed uses, those reached from an entry
                // point count alone if there are any. Their notes are kept per occurrence when
                // they differ (below).
                a.entry_notes.insert(m.algo.note.clone());
                let reached = a.occurrences.iter().any(|o| o.tier == Tier::Reachable);
                if tier == Tier::Reachable && !reached {
                    a.algo.functions = m.algo.functions.clone();
                } else if tier == Tier::Reachable || !reached {
                    let known = a.algo.functions.len();
                    for f in &m.algo.functions {
                        if !a.algo.functions.contains(f) {
                            a.algo.functions.push(f.clone());
                        }
                    }
                    if a.algo.functions.len() > known {
                        a.algo.functions.sort();
                    }
                }
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
                    o.generic_body &= occ.generic_body;
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
    // the packages implementing an algorithm under the matched one provide it too
    for a in assets.values_mut() {
        let mut more = Vec::new();
        for (n, v) in &a.providers {
            let Some(p) = man.by_name_version(n, v) else {
                continue;
            };
            for d in p.runtime_deps.iter().filter_map(|d| man.by_id(d)) {
                if a.algo.implemented_by.contains(&d.name) {
                    more.push((d.name.clone(), d.version.to_string()));
                }
            }
        }
        a.providers.extend(more);
    }
    // the per-item scan of a generic function cannot resolve what its type parameters choose
    // (`digest(T::A, x)` in `h<T: Pick>`): an instance of it that does at the same position
    // (`h::<P>`, SHA-1) says what the call uses. An instance that does not stays unknown.
    let resolved: HashSet<(String, usize, usize, String)> = assets
        .values()
        .filter(|a| !a.unresolved())
        .flat_map(|a| &a.occurrences)
        .filter(|o| o.kind == Kind::Call)
        .map(|o| (o.location.clone(), o.line, o.offset, o.symbol.clone()))
        .collect();
    for a in assets.values_mut().filter(|a| a.unresolved()) {
        a.occurrences.retain(|o| {
            !(o.generic_body
                && resolved.contains(&(o.location.clone(), o.line, o.offset, o.symbol.clone())))
        });
    }
    // an unknown operation inside a crypto library's generic code that an operation of a known
    // algorithm instantiated is part of that operation (`NonZeroScalar::random` in ecdsa's
    // `SigningKey::random`, which `main` calls): the call that runs it says what runs. So is a
    // draw from the generator the operation was handed (`rng.fill_bytes(..)` in p384's
    // `Scalar::random` under `EphemeralSecret::random(&mut OsRng)`). An unknown operation says
    // no more than what it instantiates, which is kept.
    let operations: HashSet<(String, usize, usize)> = assets
        .values()
        .filter(|a| !a.unresolved())
        .flat_map(|a| &a.occurrences)
        .filter(|o| o.kind == Kind::Call && o.function.is_some())
        .map(|o| (o.location.clone(), o.line, o.offset))
        .collect();
    let inner = |a: &Asset| a.unresolved() || a.algo.primitive == "drbg";
    for a in assets.values_mut().filter(|a| inner(a)) {
        a.occurrences
            .retain(|o| !o.via.iter().any(|v| operations.contains(v)));
    }
    assets.retain(|_, a| !(inner(a) && a.occurrences.is_empty()));
    // entries with different notes behind one asset: each note goes with its occurrences
    for a in assets.values_mut() {
        if a.entry_notes.len() > 1 {
            a.algo.note = None;
            for o in &mut a.occurrences {
                if let Some(n) = &o.note {
                    let d = format!("note: {n}");
                    if !o.detail.contains(&d) {
                        o.detail.push(d);
                    }
                }
            }
        }
    }
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
    // A package whose code the walk reached runs: the walk follows the algorithm crates' code
    // for this only (block-buffer under sha2's `Digest` impl, not ecdsa under p256 used for
    // ECDH only). Not reached: a crypto package the knowledge base does not model is present
    // when it was compiled into the build.
    let walks: Vec<&rcbom_facts::Reach> = facts.iter().filter_map(|f| f.reach.as_ref()).collect();
    let ran: HashSet<(String, String)> = walks
        .iter()
        .flat_map(|r| &r.crates)
        .filter_map(|k| ctx.package_of_crate(&k.name, &k.stable_id))
        .collect();
    let compiled: HashSet<(&str, &str)> = facts
        .iter()
        .map(|f| (f.krate.package.as_str(), f.krate.version.as_str()))
        .collect();
    for p in man
        .packages
        .iter()
        .filter(|p| p.role.is_some() || p.unmodelled.is_some())
    {
        let key = (p.name.clone(), p.version.to_string());
        let u = if ran.contains(&key) {
            Usage::Reachable
        } else if p.unmodelled.is_some() && compiled.contains(&(key.0.as_str(), key.1.as_str())) {
            Usage::Present
        } else {
            continue;
        };
        // at least what its occurrences gave it (a provider of a reachable occurrence)
        let e = usage.entry(key).or_insert(u);
        *e = (*e).max(u);
    }
    // An algorithm crate's dependencies are present with it (compiled in with the code that
    // uses them); what runs is what the walk reached, and only without a complete walk (none,
    // or one cut at its limit) is that taken from the dependencies too. An interface crate
    // passes nothing on: its traits are implemented by the algorithm crates, so aes-gcm using
    // `aead`, or the program calling `KeyInit::new_from_slice`, does not run `aead`'s
    // `getrandom` (through crypto-common and rand_core).
    let complete = !walks.is_empty() && walks.iter().all(|r| r.crates_complete);
    let mut changed = true;
    while changed {
        changed = false;
        for p in &man.packages {
            // only modelled algorithm crates run their dependencies' code for sure: a package
            // the knowledge base does not model (age) may use a dependency for anything
            if p.role != Some(Role::Algorithm) {
                continue;
            }
            let key = (p.name.clone(), p.version.to_string());
            let Some(&u) = usage.get(&key) else {
                continue;
            };
            let u = if complete { u.min(Usage::Present) } else { u };
            for d in &p.runtime_deps {
                let Some(dp) = man.by_id(d) else { continue };
                // into crypto crates, modelled or not (salsa20 under scrypt)
                if dp.role.is_none() && dp.unmodelled.is_none() {
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
    }
    for p in &man.packages {
        if p.role.is_some() {
            usage
                .entry((p.name.clone(), p.version.to_string()))
                .or_insert(Usage::DeclaredNotUsed);
        }
    }
    if std::env::var_os("RCBOM_DEBUG").is_some() {
        eprintln!("analysis: sites in {:.1?}", main_pass.elapsed());
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

/// (match, kind, use, symbol, details, reached only from data no entry point reaches)
type SiteMatch = (Match, Kind, Option<String>, String, Vec<String>, bool);

/// The detail of a call whose parameters are not its receiver's (`verify_password`): it is
/// not merged into the receiver's constructor on the same line.
const OWN_PARAMS: &str = ": its own parameters, not its receiver's";

/// `None` (`Option::None` passed for an optional argument).
/// The variant a value names by a unit variant of the family's enum (`Some(Algorithm::Argon2d
/// .ident())`): `d`, its name after the family's.
fn named_variant(o: &rcbom_facts::Origin, family: &str) -> Option<String> {
    use rcbom_facts::Origin;
    match o {
        Origin::Unit { path, .. } => {
            let last = path.rsplit("::").next()?;
            last.strip_prefix(family)
                .filter(|v| !v.is_empty())
                .map(str::to_lowercase)
        }
        Origin::Call { args, .. } => args.iter().find_map(|a| named_variant(a, family)),
        Origin::Any(v) => {
            let found: Vec<String> = v.iter().filter_map(|a| named_variant(a, family)).collect();
            match found.as_slice() {
                [one] => Some(one.clone()),
                _ => None,
            }
        }
        _ => None,
    }
}

fn is_none_origin(o: &rcbom_facts::Origin) -> bool {
    matches!(o, rcbom_facts::Origin::Unit { path, .. } if path.ends_with("Option::None"))
}

/// What the call an argument of `site` comes from matched, when it is a [[fn]] entry of
/// `family`: the one such call among the arguments, found by its position in the same function.
/// It must build a type the call names in its generic arguments, or one of `own` crate (the
/// `Params` of `scrypt::scrypt`, whose parameter types the facts do not list). `overrides` are
/// parameters the site itself fixes.
fn argument_constructor<'a>(
    ctx: &Ctx<'a>,
    site: &Site,
    family: &str,
    own: Option<&str>,
    overrides: &BTreeMap<String, String>,
    skip_receiver: bool,
) -> Option<(Match, &'a Site)> {
    let Target::Call {
        arg_origins,
        self_ty: site_self,
        args: site_args,
        ..
    } = &site.target
    else {
        return None;
    };
    // the ADTs the call names in its types (`RsaPublicKey::encrypt::<R, Oaep>`): a
    // constructor counts only if it builds one of them
    let mut adts: Vec<&str> = Vec::new();
    fn collect<'t>(t: &'t rcbom_facts::TyTree, out: &mut Vec<&'t str>) {
        match t {
            rcbom_facts::TyTree::Adt { path, args, .. } => {
                out.push(path);
                args.iter().for_each(|a| collect(a, out));
            }
            rcbom_facts::TyTree::Ref(x)
            | rcbom_facts::TyTree::Slice(x)
            | rcbom_facts::TyTree::Array(x, _) => collect(x, out),
            rcbom_facts::TyTree::Tuple(xs) => xs.iter().for_each(|x| collect(x, out)),
            _ => {}
        }
    }
    site_self
        .iter()
        .chain(site_args.iter())
        .for_each(|t| collect(t, &mut adts));
    let mut found: Vec<(Match, &Site)> = Vec::new();
    for o in arg_origins.iter().skip(usize::from(skip_receiver)) {
        // the constructor itself, or through plumbing (`Params::new(..).ok()?`, `.unwrap()`)
        let mut o = o;
        for _ in 0..8 {
            let rcbom_facts::Origin::Call {
                krate,
                args: inner,
                span,
                ..
            } = o
            else {
                break;
            };
            let at = span.as_ref().and_then(|at| {
                ctx.calls
                    .get(&(site.owner.id.as_str(), at.file.as_str(), at.line, at.col))
            });
            if let Some(&c) = at
                && let Some(m) = constructed(ctx, c, &adts, own, overrides)
            {
                if m.algo.family == family && !found.iter().any(|(f, _)| f.key() == m.key()) {
                    found.push((m, c));
                }
                break;
            }
            match inner.first() {
                Some(a) if matches!(krate.as_str(), "core" | "std" | "alloc") => o = a,
                _ => break,
            }
        }
    }
    // two constructors of the family with different names: the call does not say which
    match found.len() {
        1 => found.pop(),
        _ => None,
    }
}

/// What the call at `site` matched as a constructor of one of `adts` or of a type of `own`
/// crate: a [[fn]] entry whose call builds such a value (`Oaep::new_with_label` builds an
/// `Oaep`; `blake3::derive_key` builds no `Hasher`).
fn constructed(
    ctx: &Ctx<'_>,
    site: &Site,
    adts: &[&str],
    own: Option<&str>,
    overrides: &BTreeMap<String, String>,
) -> Option<Match> {
    let Target::Call {
        callee,
        self_ty,
        args,
        const_args,
        arg_lens,
        ..
    } = &site.target
    else {
        return None;
    };
    let Some(rcbom_facts::TyTree::Adt { path: built, .. }) = self_ty else {
        return None;
    };
    if !adts.contains(&built.as_str()) && !own.is_some_and(|k| built.starts_with(&format!("{k}::")))
    {
        return None;
    }
    let supported = |k: &rcbom_facts::CrateRef| ctx.supported(k);
    match_fn_with(
        ctx.kb,
        callee,
        self_ty.as_ref(),
        args,
        const_args,
        arg_lens,
        &supported,
        overrides,
    )
}

/// The [[fn]] entry a call matches, named by the constructor of a value of its family passed
/// to it (`scrypt(pw, salt, &Params::recommended(), out)` is scrypt-131072-8-1-32), with what
/// the call fixes itself (the length of `out`) standing over the constructor's; and that
/// constructor's call.
fn fn_site_match<'a>(ctx: &Ctx<'a>, site: &Site) -> Option<(Match, Option<&'a Site>)> {
    let Target::Call {
        callee,
        self_ty,
        args,
        const_args,
        arg_lens,
        ..
    } = &site.target
    else {
        return None;
    };
    let supported = |k: &rcbom_facts::CrateRef| ctx.supported(k);
    let m = match_fn(
        ctx.kb,
        callee,
        self_ty.as_ref(),
        args,
        const_args,
        arg_lens,
        &supported,
    )?;
    let own = Some(callee.krate.name.as_str());
    Some(
        match argument_constructor(ctx, site, &m.algo.family, own, &m.values, false) {
            Some((c, at)) => (adopt(c, m), Some(at)),
            None => (m, None),
        },
    )
}

/// `named`'s asset and parameters, with what `entry` says the call does (its functions, use and
/// note).
fn adopt(named: Match, entry: Match) -> Match {
    Match {
        algo: Algo {
            functions: entry.algo.functions,
            implied_use: entry.algo.implied_use,
            note: entry.algo.note,
            ..named.algo
        },
        provider_crates: entry.provider_crates,
        ..named
    }
}

fn site_matches(
    ctx: &Ctx<'_>,
    site: &Site,
    closure: &dyn Fn(&str) -> Vec<rcbom_facts::DefRef>,
    reachable: &dyn Fn(&str) -> bool,
    reached_path: &dyn Fn(&str) -> bool,
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
                        out.push((c, Kind::Component, None, symbol.clone(), d, false));
                    }
                }
                // a descriptor named is not used here: the calls it reaches say how
                out.insert(0, (m, Kind::Static, None, symbol, vec![], false));
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
                            out.push((m, Kind::Component, None, symbol.clone(), d, false));
                        }
                        None => {
                            let detail =
                                vec![format!("{} -> {}", short(&def.path), short(&inner.path))];
                            out.push((m, Kind::ViaStatic, None, symbol.clone(), detail, false));
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
        // a protocol crate's API modelled at its boundary
        Target::Call { .. }
            if let Some(found) = boundary::site_matches(ctx, site, reachable, reached_path) =>
        {
            out = found;
        }
        Target::Call {
            callee,
            method,
            self_ty,
            args,
            ..
        } => {
            let symbol = callee.path.clone();
            let fn_match = fn_site_match(ctx, site).map(|(m, at)| {
                if let Some(c) = at {
                    ctx.link(c, &m);
                }
                // a constructor set up for calls that all compute one asset is part of it
                match ctx
                    .consumers
                    .borrow()
                    .get(&call_key(site))
                    .map(Vec::as_slice)
                {
                    Some([u, rest @ ..]) if rest.iter().all(|r| r.key() == u.key()) => {
                        adopt(u.clone(), m)
                    }
                    _ => m,
                }
            });
            // a fn entry with `self_type` already accounts for the self type
            let skip_self = fn_match.is_some()
                && kb
                    .fns
                    .iter()
                    .any(|e| e.self_type.is_some() && e.pattern.is_match(&callee.path));
            let fn_name = fn_match.as_ref().map(|m| m.name.clone());
            // the entry makes key material (`SigningKey::<Sha256>::random(rng, 2048)` an RSA-2048
            // key): the scheme its type names is what the key is made for, not a part of it
            let fn_material = fn_match.as_ref().is_some_and(|m| m.algo.material.is_some());
            let fn_family = fn_match.as_ref().map(|m| m.algo.family.clone());
            if let Some(mut m) = fn_match {
                for k in std::mem::take(&mut m.provider_crates) {
                    m.providers
                        .extend(ctx.package_of_crate(&k.name, &k.stable_id));
                }
                // what the entry says the call does (`RsaPrivateKey::new` generates a key,
                // ring's `rand::generate` draws), or a listed use of the method; else the call
                // sets the asset up
                let f = m
                    .algo
                    .implied_use
                    .clone()
                    .or_else(|| kb.use_of(method, &m.algo.primitive));
                let d = if f.is_none() {
                    vec![format!("{method}: setup, not a use")]
                } else {
                    vec![]
                };
                out.push((m, Kind::Call, f, symbol.clone(), d, false));
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
            // a type's asset the constructor of the value renamed (`SigningKey::<Sha1>::
            // new_unprefixed` is `RSA-PKCS1-1.5`): its components are parts of the new name
            let mut renamed: HashMap<String, String> = HashMap::new();
            // a random generator is used where the code draws from it (`rng.fill_bytes(..)`):
            // one among the call's type arguments (`SaltString::generate(&mut OsRng)`,
            // `StaticSecret::new(OsRng)`) is handed to the call, which draws from it
            let receiver_types: Vec<String> = self_ty
                .iter()
                .filter(|_| !skip_self)
                .flat_map(|t| match_types(kb, std::slice::from_ref(t), &supported))
                .map(|(m, _)| m.key())
                .collect();
            for (mut m, outer) in match_types(kb, &trees, &supported) {
                // ..except by rand's own APIs, which draw from the generator they are given
                // (`Alphanumeric.sample_string(&mut OsRng, 16)`, `v.shuffle(&mut rng)`)
                let drawn_by_rand = callee.krate.name == "rand";
                let handed = m.algo.primitive == "drbg" && !receiver_types.contains(&m.key());
                if handed && !drawn_by_rand {
                    continue;
                }
                let outer = outer.map(|p| renamed.get(&p).cloned().unwrap_or(p));
                // the fn entry already names this algorithm, with what its arguments add:
                // `Oaep::new_with_label::<Sha256, _>` is RSA-OAEP-SHA-256, not also an `Oaep`
                // that is part of it
                if fn_family.as_deref() == Some(m.algo.family.as_str()) {
                    if let Some(f) = &fn_name {
                        renamed.insert(m.name.clone(), f.clone());
                    }
                    continue;
                }
                let providers = std::mem::take(&mut m.provider_crates);
                // the receiver's constructor may say more than its type: `Argon2::default()`
                // is Argon2id-19456-2-1, `Hasher::new_keyed(k)` a keyed BLAKE3
                // ..unless the method takes its parameters from elsewhere: `verify_password`
                // from the stored hash, `hash_password_customized` from its arguments (a
                // `Params` built there; the variant its algorithm argument names, the crate's
                // default when that is `None`)
                let own_params = m.algo.own_params.iter().any(|x| x == method);
                let family = m.algo.family.clone();
                let from_receiver = |r| match_constructor(kb, &family, r);
                let overrides = match &site.target {
                    Target::Call { arg_origins, .. } if own_params => match arg_origins.get(2) {
                        Some(o) if is_none_origin(o) => m.algo.own_defaults.clone(),
                        Some(o) => named_variant(o, &family)
                            .map(|v| BTreeMap::from([("variant".to_string(), v)]))
                            .unwrap_or_default(),
                        None => BTreeMap::new(),
                    },
                    _ => BTreeMap::new(),
                };
                let own_crate = providers.first().map(|k| k.name.clone());
                if outer.is_none()
                    && !own_params
                    && let Some(r) = receiver
                    && let Some((c, at)) = from_receiver(r)
                {
                    // the constructor's asset, unless the type names more of what the
                    // constructor's name leaves open: the `Hkdf<Sha256, SimpleHmac<Sha256>>`
                    // that `SharedSecret::extract::<Sha256>` builds is HKDF-SHA-256 (`HKDF-{hash}`,
                    // the constructor's origin has no type arguments); a constructor naming its
                    // asset whole stays (`SigningKey::<Sha1>::new_unprefixed`: RSA-PKCS1-1.5)
                    let finer = !c.algo.open.is_empty()
                        && m.name.len() > c.name.len()
                        && m.name.starts_with(&c.name);
                    if !finer {
                        let comps = std::mem::take(&mut m.components);
                        renamed.insert(m.name.clone(), c.name.clone());
                        m = c;
                        m.components = comps;
                    }
                    if let Some(at) = at
                        && let Some(c) = ctx.calls.get(&(
                            site.owner.id.as_str(),
                            at.file.as_str(),
                            at.line,
                            at.col,
                        ))
                    {
                        ctx.link(c, &m);
                    }
                } else if outer.is_none()
                    && let Some((c, at)) = argument_constructor(
                        ctx,
                        site,
                        &m.algo.family,
                        own_crate.as_deref().filter(|_| own_params),
                        &overrides,
                        own_params,
                    )
                {
                    ctx.link(at, &c);
                    // or a value built in an argument: `encrypt(&mut rng,
                    // Oaep::new_with_label::<Sha256, _>(label), msg)` is RSA-OAEP-SHA-256, the
                    // `Oaep` type alone RSA-OAEP
                    let comps = std::mem::take(&mut m.components);
                    renamed.insert(m.name.clone(), c.name.clone());
                    m = c;
                    m.components = comps;
                }
                // the receiver of such a method is set up for what the method computes, unless
                // the call fixes what the receiver's constructor chose (the variant of
                // `hash_password_customized(pw, None, ..)` is the crate's default)
                if outer.is_none()
                    && own_params
                    && overrides.is_empty()
                    && let Some((_, Some(at))) = receiver.and_then(from_receiver)
                    && let Some(c) =
                        ctx.calls
                            .get(&(site.owner.id.as_str(), at.file.as_str(), at.line, at.col))
                {
                    ctx.link(c, &m);
                }
                for k in providers {
                    m.providers
                        .extend(ctx.package_of_crate(&k.name, &k.stable_id));
                }
                // the hash of `pbkdf2_hmac::<Sha256>` is part of the PBKDF2 asset
                let outer = outer.or_else(|| {
                    fn_name
                        .clone()
                        .filter(|_| !(fn_material && m.algo.material.is_none()))
                });
                match outer {
                    None if into_kb => {
                        let f = if handed {
                            Some("generate".to_string())
                        } else {
                            kb.use_of(method, &m.algo.primitive)
                        };
                        let mut setup = if f.is_none() {
                            vec![format!("{method}: setup, not a use")]
                        } else {
                            vec![]
                        };
                        if own_params {
                            setup.push(format!("{method}{OWN_PARAMS}"));
                        }
                        out.push((m, Kind::Call, f, symbol.clone(), setup, false));
                    }
                    None => {
                        let d = vec![format!(
                            "chosen as generic argument of {}",
                            short(&callee.path)
                        )];
                        out.push((m, Kind::Instantiation, None, symbol.clone(), d, false));
                    }
                    Some(parent) => {
                        let d = vec![format!("part of {parent}")];
                        out.push((m, Kind::Component, None, symbol.clone(), d, false));
                    }
                }
            }
            // ring / aws-lc-rs: keys are untyped, the algorithm is a static passed when the key
            // was built. `k.seal_in_place_append_tag(..)` gets AES-256-GCM from the
            // `UnboundKey::new(&AES_256_GCM, ..)` in the origin of `k`.
            let has_roles = || !provenance::of_call(kb, &ctx.flow, &site.target, false).is_empty();
            // a call that can give an occurrence: the method is a use, or it has key-material
            // roles (most calls into a protocol crate's own code are neither)
            let can_occur = || {
                kb.uses
                    .iter()
                    .any(|u| u.methods.iter().any(|m| m == method))
            };
            // a protocol crate's own function (rustls's `KeySchedule::derive`, jsonwebtoken's
            // `crypto::ecdsa::sign`), also a standard trait's method on its type (`<rustls::
            // Writer as io::Write>::write`, plaintext into the connection), is not a crypto API:
            // its crypto is at the algorithm crate's calls inside it, which are looked up there
            let implementer = match self_ty {
                Some(rcbom_facts::TyTree::Adt { krate, .. }) if std_callee => &krate.name,
                _ => &callee.krate.name,
            };
            let protocol_callee = kb
                .crate_by_name(implementer)
                .is_some_and(|c| c.role == Role::Protocol);
            if out.is_empty() && into_kb && !protocol_callee && (can_occur() || has_roles()) {
                let has_roles = has_roles();
                // the call's own arguments; if what they name is not used here, its receiver's;
                // if nothing in this function names the algorithm, what reaches the key or
                // algorithm from other functions (a field, a parameter, a function's result),
                // looked up only then
                let local = provenance::data_in_args(kb, None, &site.target);
                // what an argument names here is not all that reaches it when its other
                // alternatives come from elsewhere (`if c { &SHA256 } else { pick() }`): then
                // the values from other functions are looked up too, those named here kept as
                // named here
                // a field read of a static that stores values in fields (`TABLE[i].h`, a table of
                // structs) is what its initializer stores in that field: looked up with the links
                let static_field = local
                    .iter()
                    .any(|(_, others)| others.iter().any(|d| ctx.flow.static_fields(&d.id)));
                let incomplete = provenance::incomplete(kb, &site.target) || static_field;
                let named_here: HashSet<String> = if incomplete {
                    local
                        .iter()
                        .flat_map(|(d, _)| d.iter().map(|x| x.id.clone()))
                        .collect()
                } else {
                    HashSet::new()
                };
                let local = if incomplete {
                    Default::default()
                } else {
                    local
                };
                let named = std::cell::RefCell::new(HashMap::new());
                let named_via = std::cell::RefCell::new(HashMap::new());
                let linked = std::iter::once_with(|| {
                    ctx.flow.take_named();
                    ctx.flow.take_named_via();
                    let r = provenance::data_in_args(
                        kb,
                        Some((&ctx.flow, site.owner.path.as_str())),
                        &site.target,
                    );
                    *named.borrow_mut() = ctx.flow.take_named();
                    *named_via.borrow_mut() = ctx.flow.take_named_via();
                    r
                })
                .flatten();
                let places = local
                    .into_iter()
                    .map(|p| (p, false))
                    .chain(linked.map(|p| (p, true)));
                for ((mut descriptors, others), from_elsewhere) in places {
                    // the user's own data naming exactly one descriptor (`digest(TABLE.alg, ..)`
                    // with `TABLE.alg = &SHA256`) names it; a table of several (`DIGESTS[i]`):
                    // any of them, the element read by an index (or a field) not followed
                    let mut tables: HashMap<String, (String, usize)> = HashMap::new();
                    for d in others {
                        // a static that changes at run time holds what the program puts there
                        // (looked up with the values from elsewhere), not its initializer's
                        if ctx.flow.mutable_static(&d.id).is_some() {
                            continue;
                        }
                        let mut found: Vec<rcbom_facts::DefRef> = closure(&d.id)
                            .into_iter()
                            .filter(|x| match_static(kb, x, &supported).is_some())
                            .collect();
                        // a descriptor another one is made of (`HMAC_SHA256`'s `SHA256`) is part
                        // of it, not a second one
                        let parts: Vec<String> = found
                            .iter()
                            .flat_map(|y| {
                                closure(&y.id)
                                    .into_iter()
                                    .filter(|x| x.id != y.id)
                                    .map(|x| x.id)
                            })
                            .collect();
                        found.retain(|x| !parts.contains(&x.id));
                        if let [one] = found.as_slice() {
                            if !descriptors.contains(one) {
                                descriptors.push(one.clone());
                            }
                        } else {
                            let k = found.len();
                            for x in found {
                                if !descriptors.contains(&x) {
                                    tables.insert(x.id.clone(), (d.path.clone(), k));
                                    descriptors.push(x);
                                }
                            }
                        }
                    }
                    // a value named only by code or data no entry point reaches (a caller never
                    // called, ALL_KX_GROUPS's MLKEM1024, a static only a test uses: rustls's own
                    // `HMAC_SHA512`) does not reach this call at run time
                    let unreached_by = |def: &rcbom_facts::DefRef| {
                        from_elsewhere && !named_here.contains(&def.id) && {
                            let owners = named.borrow().get(&def.id).cloned().unwrap_or_default();
                            !owners.iter().any(|w| {
                                if w.is_empty() {
                                    reachable(&def.id)
                                } else if let Some((_, id)) = rcbom_facts::owner_static(w) {
                                    reachable(id)
                                } else {
                                    reached_path(w)
                                }
                            }) && !(owners.is_empty() && reachable(&def.id))
                        }
                    };
                    // the members counted are those that reach the call
                    let n = descriptors.iter().filter(|d| !unreached_by(d)).count();
                    // all of them read from one static's initializer (`TABLE[i].h`)
                    let all_in_static = {
                        let vias = named_via.borrow();
                        let owners: HashSet<Option<&String>> = descriptors
                            .iter()
                            .filter(|d| !unreached_by(d))
                            .map(|d| match vias.get(&d.id) {
                                Some(crate::links::Via::Table(w)) => Some(w),
                                _ => None,
                            })
                            .collect();
                        owners.len() == 1 && !owners.contains(&None)
                    };
                    for def in descriptors {
                        if let Some(mut m) =
                            matcher::match_static_called(kb, &def, Some(method), &supported)
                        {
                            let f = kb.use_of(method, &m.algo.primitive);
                            if f.is_none() && !has_roles {
                                continue;
                            }
                            m.providers.extend(
                                ctx.package_of_crate(&def.krate.name, &def.krate.stable_id),
                            );
                            // several algorithms reach it (rustls's record keys, one per cipher
                            // suite): which one is chosen at run time
                            let here = named_here.contains(&def.id);
                            let from_elsewhere = from_elsewhere && !here;
                            let unreached = unreached_by(&def);
                            let table = tables.get(&def.id);
                            // read from a static's initializer (`TABLE[i].h`): from there
                            let in_static = match named_via.borrow().get(&def.id) {
                                Some(crate::links::Via::Table(w)) => Some(boundary::short_fn(w)),
                                _ => None,
                            };
                            let mut d = vec![match (from_elsewhere, n) {
                                (true, 1) if !unreached && in_static.is_some() => format!(
                                    "algorithm from {}, stored in `{}`",
                                    short(&def.path),
                                    in_static.clone().unwrap_or_default()
                                ),
                                (true, n) if !unreached && all_in_static => format!(
                                    "algorithm one of the {n} in `{}` that may reach the call: \
                                     {}",
                                    in_static.clone().unwrap_or_default(),
                                    short(&def.path)
                                ),
                                _ if !unreached && table.is_some() => {
                                    let (t, k) = table.cloned().unwrap_or_default();
                                    format!(
                                        "algorithm one of the {k} in `{}`, the element read by \
                                         an index or a field the analysis does not follow: {}",
                                        short(&t),
                                        short(&def.path)
                                    )
                                }
                                (true, _) if unreached => format!(
                                    "algorithm {} only through code or data no entry point \
                                     reaches{}",
                                    short(&def.path),
                                    static_witness(&named.borrow(), &def.id)
                                ),
                                (false, n) if n > 1 => format!(
                                    "algorithm one of {n} that may reach the call: {} in the arguments",
                                    short(&def.path)
                                ),
                                (false, _) => {
                                    format!("algorithm from {} in the arguments", short(&def.path))
                                }
                                // the only value found, but one that may not reach the call
                                // (a store into the field anywhere, a trait object's type)
                                (true, 1)
                                    if named_via
                                        .borrow()
                                        .get(&def.id)
                                        .is_some_and(|v| v.rank() > 1) =>
                                {
                                    format!(
                                        "algorithm possibly from {}, the only one found reaching \
                                         the call from another function",
                                        short(&def.path)
                                    )
                                }
                                (true, 1) => format!(
                                    "algorithm from {}, reaching the call from another function",
                                    short(&def.path)
                                ),
                                (true, n) => format!(
                                    "algorithm one of {n} that may reach the call from other functions: {}",
                                    short(&def.path)
                                ),
                            }];
                            // a call that is no use sets the asset up, as for a typed call
                            // (`UnboundKey::new(&AES_256_GCM, k)`, `hmac::Key::new(..)`)
                            if f.is_none() {
                                d.insert(0, format!("{method}: setup, not a use"));
                            }
                            // an element of a container the call reads, named here: one of
                            // the values it holds
                            if !from_elsewhere
                                && n > 1
                                && provenance::container_member(&site.target, &def.id)
                            {
                                let at = d
                                    .iter()
                                    .position(|x| x.starts_with("algorithm"))
                                    .map_or(d.len(), |i| i + 1);
                                d.insert(
                                    at,
                                    "member: container, possible (an element of the container \
                                     the call reads)"
                                        .to_string(),
                                );
                            }
                            // how the member reaches the call (its set label and witness)
                            if from_elsewhere
                                && !unreached
                                && let Some(via) = named_via.borrow().get(&def.id)
                            {
                                let at = d
                                    .iter()
                                    .position(|x| x.starts_with("algorithm"))
                                    .map_or(d.len(), |i| i + 1);
                                d.insert(at, boundary::member_label(via));
                            }
                            out.push((m, Kind::Call, f, symbol.clone(), d, unreached));
                        }
                    }
                    if !out.is_empty() {
                        break;
                    }
                }
            }
            // an operation is never dropped: when no algorithm reaches it, it is reported with
            // an unknown one, and why; so is the rest of the algorithms when the search for them
            // hit its bound (what was found is not all)
            let unresolved = if out.is_empty() {
                unresolved_operation(ctx, site)
            } else if let Some(reason) = algorithm_cut(ctx, site) {
                unresolved_operation(ctx, site).map(|(p, f, _, pr)| (p, f, reason, pr))
            } else {
                None
            };
            if let Some((primitive, function, reason, provider)) = unresolved {
                // a set-up call (`Md5::new()`): the algorithm is there, not used yet
                let setup = function.is_empty();
                let mut m = Match {
                    name: UNKNOWN.to_string(),
                    algo: Algo {
                        asset: UNKNOWN.to_string(),
                        primitive,
                        functions: function
                            .split(" or ")
                            .filter(|f| !f.is_empty())
                            .map(str::to_string)
                            .collect(),
                        ..Algo::default()
                    },
                    params: BTreeMap::new(),
                    values: BTreeMap::new(),
                    components: BTreeSet::new(),
                    providers: BTreeSet::new(),
                    provider_crates: Vec::new(),
                };
                m.providers.extend(provider);
                let mut d = vec![format!("algorithm unresolved: {reason}")];
                if setup {
                    d.insert(0, format!("{method}: setup, not a use"));
                }
                let function = (!setup).then_some(function);
                out.push((m, Kind::Call, function, symbol.clone(), d, false));
            }
            // a random generator is reported where the code draws from it (`rng.fill_bytes(..)`):
            // not where it is built (`SystemRandom::new()`, `StdRng::seed_from_u64(n)`; `OsRng`
            // needs no constructor), nor where it is handed to another operation
            // (`RsaPrivateKey::new(&mut rng, 2048)` draws from it, and the key's provenance says
            // so: `rng: csprng`)
            out.retain(|(m, k, f, ..)| {
                m.algo.primitive != "drbg" || (*k == Kind::Call && f.is_some())
            });
            if out
                .iter()
                .any(|(m, k, ..)| *k == Kind::Call && m.algo.primitive != "drbg")
            {
                out.retain(|(m, k, ..)| !(*k == Kind::Call && m.algo.primitive == "drbg"));
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
        // a pointer call whose function is not followed: nothing says it is cryptography
        Target::Pointer { .. } => {}
    }
    out
}

/// The function a closure or `async` body is written in (`f` for `f::{closure#1}::{closure#0}`),
/// or `None` for a function.
fn enclosing_fn(path: &str) -> Option<&str> {
    let i = path.find("::{")?;
    Some(&path[..i])
}

/// An owner id that is a def-path hash (32 hex digits), as the driver gives a generic function
/// it scans without an instance; an instance's id is its mangled name.
fn is_def_hash(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit())
}

/// (primitive, use, reason, providing packages) of an operation whose algorithm is not named.
type Unresolved = (String, String, String, Vec<(String, String)>);

/// A call that performs an operation whose algorithm the knowledge base cannot name. Three
/// kinds:
/// - an `[[operation]]` whose algorithm is a run-time value no algorithm reaches;
/// - an `[[operation]]` of a RustCrypto trait whose Self type is of a crypto package the
///   knowledge base does not model, or of a version it does not cover (`Sha3_256::digest`);
/// - a call from another crate into a crypto package the knowledge base does not model, with a
///   method that is a use (`p256::ecdh::diffie_hellman`).
fn unresolved_operation(ctx: &Ctx<'_>, site: &Site) -> Option<Unresolved> {
    let Target::Call {
        callee,
        method,
        self_ty,
        args,
        arg_origins,
        value,
        ..
    } = &site.target
    else {
        return None;
    };
    let in_crate = callee
        .path
        .strip_prefix(&format!("{}::", callee.krate.name))
        .unwrap_or(&callee.path);
    // any version of the crate: a trait crate of an unsupported version (digest 0.11 under sha2
    // 0.11) still names the operation
    let op = ctx.kb.crate_by_name(&callee.krate.name).and_then(|_| {
        ctx.kb
            .operation(&callee.krate.name, &matcher::strip_generics(in_crate))
    });
    match op {
        Some(op) if op.self_type => {
            let t = self_ty.as_ref()?;
            // a trait object (`Box<dyn DynDigest>`): the type is chosen at run time
            let (reason, provider) = match dyn_trait(t) {
                Some(d) => (
                    // by the trait's name: one trait reached by two paths
                    // (`digest::DynDigest`, `sha2::digest::DynDigest`) gives one reason
                    format!(
                        "a trait object (`dyn {}`): its type is chosen at run time",
                        d.rsplit("::").next().unwrap_or(d)
                    ),
                    ctx.package_of_crate(&callee.krate.name, &callee.krate.stable_id)
                        .into_iter()
                        .collect(),
                ),
                None => unmodelled_type(ctx, site, t)?,
            };
            let function = if op.setup {
                String::new()
            } else {
                op.function.clone()
            };
            // a keystream of a mode over a block cipher (`ctr::Ctr64BE<Blowfish>`) is the block
            // cipher's operation, as the knowledge base names AES-CTR
            let primitive = match t {
                rcbom_facts::TyTree::Adt { krate, .. }
                    if op.primitive == "stream-cipher"
                        && matches!(krate.name.as_str(), "ctr" | "cfb_mode" | "cfb8" | "ofb") =>
                {
                    "block-cipher".to_string()
                }
                _ => op.primitive.clone(),
            };
            Some((primitive, function, reason, provider))
        }
        Some(op) => {
            // a function named as a value whose calls no pointer call accounts for (handed to
            // code that is not followed): the algorithm is in the calls' arguments
            let reason = if *value {
                "named as a function value; the calls through it are not followed".to_string()
            } else {
                let o = arg_origins.get(op.algorithm)?;
                let r = unresolved_reason(o);
                if !r.contains("hit its bound") && linked_cut(ctx, site, o) {
                    // a parameter whose callers the search followed until its bound: what
                    // their arguments name is not known, not that they name none
                    if matches!(links::peel(o), rcbom_facts::Origin::Param { .. }) {
                        "a parameter: the search for the value through its callers hit its bound"
                            .to_string()
                    } else {
                        format!("{r}; the search for the value hit its bound")
                    }
                } else {
                    r
                }
            };
            let provider = ctx.package_of_crate(&callee.krate.name, &callee.krate.stable_id);
            Some((
                op.primitive.clone(),
                op.function.clone(),
                reason,
                provider.into_iter().collect(),
            ))
        }
        // an API the knowledge base names, of a version it does not cover (`getrandom::fill`
        // of getrandom 0.5): the call is the operation the entry says, of an unknown algorithm
        None if ctx.kb_entry(&callee.krate).is_some() && !ctx.supported(&callee.krate) => {
            let bare = matcher::strip_generics(in_crate);
            let e = ctx.kb.fns.iter().find(|e| {
                e.self_type.is_none()
                    && e.krates.contains(&callee.krate.name)
                    && (e.pattern.is_match(in_crate) || e.pattern.is_match(&bare))
            })?;
            let function = e
                .algo
                .implied_use
                .clone()
                .or_else(|| ctx.kb.use_of(method, &e.algo.primitive))?;
            let provider = ctx.package_of_crate(&callee.krate.name, &callee.krate.stable_id);
            let reason = match &provider {
                Some((n, v)) => format!(
                    "`{}` of {n} {v}, a version the knowledge base does not cover",
                    short(&callee.path)
                ),
                None => format!("`{}` is not covered", short(&callee.path)),
            };
            Some((
                e.algo.primitive.clone(),
                function,
                reason,
                provider.into_iter().collect(),
            ))
        }
        None => {
            // a crypto package the knowledge base does not model, or an API of an algorithm
            // crate it models that it does not name (`p256::SecretKey::random`), called from
            // another crate
            let unnamed_api = ctx
                .kb_entry(&callee.krate)
                .is_some_and(|e| e.role == Role::Algorithm)
                && ctx.supported(&callee.krate);
            if !(ctx.is_unmodelled(&callee.krate) || unnamed_api)
                || site.owner.krate == callee.krate
                || GENERIC_METHODS.contains(&method.as_str())
            {
                return None;
            }
            let mut uses: Vec<&str> = ctx
                .kb
                .uses
                .iter()
                .filter(|u| u.methods.iter().any(|m| m == method))
                .map(|u| u.function.as_str())
                .collect();
            uses.sort();
            uses.dedup();
            if uses.is_empty() {
                return None;
            }
            let provider = ctx.package_of_crate(&callee.krate.name, &callee.krate.stable_id);
            let reason = match &provider {
                Some((n, v)) if unnamed_api => format!(
                    "`{}` of {n} {v}, an API the knowledge base does not name",
                    short(&callee.path)
                ),
                Some((n, v)) => format!(
                    "`{}` of {n} {v}, a crypto package the knowledge base does not model",
                    short(&callee.path)
                ),
                None => format!("`{}` is not modelled", short(&callee.path)),
            };
            // the algorithm's packages are those of the types the call is made on or for
            // (`kem::Encapsulate::encapsulate` on an ml-kem key, `diffie_hellman::<NistP256>`),
            // the called crate's when it names none
            let typed: Vec<(String, String)> = self_ty
                .iter()
                .chain(args.iter())
                .flat_map(|t| crypto_packages(ctx, t))
                .collect();
            // with the called crate, which the call's path names (`kem::Encapsulate`)
            let mut provider: Vec<(String, String)> = typed.into_iter().chain(provider).collect();
            provider.sort();
            provider.dedup();
            Some(("unknown".into(), uses.join(" or "), reason, provider))
        }
    }
}

/// Does the driver's search for the value `o` stop at its bound somewhere (`Truncated`)?
fn cut(o: &rcbom_facts::Origin) -> bool {
    use rcbom_facts::Origin;
    match o {
        Origin::Truncated => true,
        Origin::Any(v) | Origin::All(v) => v.iter().any(cut),
        Origin::Call { args, .. } | Origin::Written { args, .. } => args.iter().any(cut),
        Origin::Field { base, .. } => cut(base),
        Origin::Set { value, .. } => cut(value),
        _ => false,
    }
}

/// Why the algorithms found for a value-selected operation are not all: the search was cut at
/// its bound (a choice among more alternatives than the driver keeps), or a value it met is
/// not followed.
fn algorithm_cut(ctx: &Ctx<'_>, site: &Site) -> Option<String> {
    let Target::Call {
        callee,
        arg_origins,
        ..
    } = &site.target
    else {
        return None;
    };
    let in_crate = callee
        .path
        .strip_prefix(&format!("{}::", callee.krate.name))
        .unwrap_or(&callee.path);
    ctx.kb
        .operation(&callee.krate.name, &matcher::strip_generics(in_crate))
        .filter(|op| !op.self_type)
        .and_then(|op| arg_origins.get(op.algorithm))
        .and_then(|o| {
            // the cut among the values that reach the call, once followed (a cut inside a value
            // a later write replaced is no part of them); the origin's own when none are
            let cut_here = match ctx.flow.values(o, &site.owner.path) {
                Some(vs) => vs
                    .iter()
                    .any(|(v, _)| matches!(v, rcbom_facts::Origin::Truncated)),
                None => cut(o),
            };
            if cut_here {
                Some(
                    "the search for the value hit its bound: other algorithms than these may \
                     reach the call"
                        .to_string(),
                )
            } else {
                unfollowed(ctx, site, o).map(|r| {
                    format!("other algorithms than these may reach the call: {r} is not followed")
                })
            }
        })
}

/// An alternative of the algorithm argument `o` (read at `site`), once the values from
/// elsewhere are followed, that is neither an algorithm nor followed to one: a value of unknown
/// origin, a parameter or field no value reaches, a call whose result is not followed (a
/// closure's that writes the variable, a function writing through an `Option<&mut>`, a trait
/// method on a type whose implementation records nothing). What it is, if any: the algorithms
/// found beside it are not all.
fn unfollowed(ctx: &Ctx<'_>, site: &Site, o: &rcbom_facts::Origin) -> Option<String> {
    use rcbom_facts::Origin;
    type Seen = HashSet<(Origin, String)>;
    fn leaf(
        ctx: &Ctx<'_>,
        o: &Origin,
        owner: &str,
        depth: usize,
        seen: &mut Seen,
    ) -> Option<String> {
        if depth > 10 {
            return None;
        }
        let o = links::peel(o);
        match o {
            Origin::Data { .. }
            | Origin::Unit { .. }
            | Origin::Const { .. }
            | Origin::Truncated => None,
            Origin::Any(v) | Origin::All(v) => {
                v.iter().find_map(|a| leaf(ctx, a, owner, depth + 1, seen))
            }
            Origin::Set { value, .. } => leaf(ctx, value, owner, depth + 1, seen),
            // the error a `?` returns: no value
            Origin::Call { callee, .. } if callee.ends_with("FromResidual::from_residual") => None,
            Origin::Call { callee, args, .. } if callee == "<closure>" => args
                .iter()
                .find_map(|a| leaf(ctx, a, owner, depth + 1, seen)),
            // a crypto crate's getter for the algorithm a value was made with is followed to
            // the value (`ctx.algorithm()`); another of its calls returning an algorithm
            // (`algorithm().digest_algorithm()`) is not
            Origin::Call { krate, callee, .. } if ctx.kb.crate_by_name(krate).is_some() => {
                let bare = matcher::strip_generics(callee);
                (bare.ends_with("_algorithm") && !bare.ends_with("::algorithm"))
                    .then(|| unresolved_kind(o))
            }
            // a call of a closure runs the closure's code, not followed
            Origin::Call { callee, krate, .. }
                if matches!(krate.as_str(), "core" | "std" | "alloc")
                    && ["Fn::call", "FnMut::call_mut", "FnOnce::call_once"]
                        .iter()
                        .any(|f| callee.ends_with(f)) =>
            {
                Some(unresolved_kind(o))
            }
            // a standard-library call passes its arguments' values on (an iterator, an
            // `Option`'s fallback): a container read its container's (not the index or key), a
            // map's store its value (not the key); a trait object's method is no such call
            Origin::Call {
                callee,
                krate,
                args,
                self_ty,
                ..
            } if matches!(krate.as_str(), "core" | "std" | "alloc")
                && !self_ty.as_deref().is_some_and(|t| t.starts_with("dyn ")) =>
            {
                let bare = matcher::strip_generics(callee);
                let read = [
                    "Index::index",
                    "IndexMut::index_mut",
                    "::get",
                    "::get_mut",
                    "::get_unchecked",
                    "::nth",
                    "::remove",
                    "::swap_remove",
                ]
                .iter()
                .any(|m| bare.ends_with(m));
                let map_store = bare.ends_with("Map::insert");
                args.iter()
                    .enumerate()
                    .filter(|(i, _)| {
                        if read {
                            *i == 0
                        } else {
                            !(map_store && *i == 1)
                        }
                    })
                    .find_map(|(_, a)| leaf(ctx, a, owner, depth + 1, seen))
            }
            // an iterator advanced by `next` (`for a in DIGESTS.iter()`): its elements are the
            // container's, followed beside it
            Origin::Through { callee } if callee.ends_with("Iterator::next") => None,
            Origin::Unknown | Origin::Loop | Origin::Through { .. } => Some(unresolved_kind(o)),
            // a value from elsewhere: what reaches it, followed; the value itself among them is
            // one the links could not follow (a trait object's type whose method records
            // nothing, a caller passing a value not known)
            _ => {
                if !seen.insert((o.clone(), owner.to_string())) {
                    return None;
                }
                match ctx.flow.values(o, owner) {
                    Some(vs) => {
                        if vs.iter().any(|(v, w)| v == o && w == owner) {
                            return Some(unresolved_kind(o));
                        }
                        vs.iter()
                            .find_map(|(v, w)| leaf(ctx, v, w, depth + 1, seen))
                    }
                    None => Some(unresolved_kind(o)),
                }
            }
        }
    }
    leaf(ctx, o, &site.owner.path, 0, &mut HashSet::new())
}

/// Do the values that reach `o` from elsewhere (read at `site`) include a cut (`Truncated`: in
/// a function's summary, or where the lookup stopped at its bound)?
fn linked_cut(ctx: &Ctx<'_>, site: &Site, o: &rcbom_facts::Origin) -> bool {
    ctx.flow.values(o, &site.owner.path).is_some_and(|vs| {
        vs.iter()
            .any(|(v, _)| matches!(v, rcbom_facts::Origin::Truncated))
    })
}

/// `: stored by static `X``, when the descriptor `id` was found stored by statics only.
fn static_witness(named: &HashMap<String, std::collections::BTreeSet<String>>, id: &str) -> String {
    let statics: Vec<&str> = named
        .get(id)
        .into_iter()
        .flatten()
        .filter_map(|w| rcbom_facts::owner_static(w).map(|(p, _)| p))
        .collect();
    if statics.is_empty() {
        String::new()
    } else {
        format!(
            " (stored by static {})",
            statics
                .iter()
                .map(|p| format!("`{}`", short(p)))
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

/// Method names that say nothing about cryptography without a modelled type to scope them: a
/// `write` is a hash update on a `Sha256` but plain output on age's `ArmoredWriter`.
const GENERIC_METHODS: &[&str] = &[
    "write",
    "write_all",
    "copy",
    "update",
    "chain_update",
    "finish",
    "finalize",
    "hash",
    "consume",
    "compute",
    "fill",
    "new_with_prefix",
];

/// The principal trait of a trait object type (`dyn digest::DynDigest`), behind references.
fn dyn_trait(t: &rcbom_facts::TyTree) -> Option<&str> {
    use rcbom_facts::TyTree;
    match t {
        TyTree::Dyn(traits) => traits.first().map(String::as_str),
        TyTree::Ref(t) => dyn_trait(t),
        TyTree::Adt { path, args, .. } if path.ends_with("::Box") => {
            args.first().and_then(dyn_trait)
        }
        _ => None,
    }
}

/// The packages of the algorithm crates a type names (modelled or not), outside the program.
fn crypto_packages(ctx: &Ctx<'_>, t: &rcbom_facts::TyTree) -> Vec<(String, String)> {
    use rcbom_facts::TyTree;
    let mut out = Vec::new();
    let mut stack = vec![t];
    while let Some(t) = stack.pop() {
        match t {
            TyTree::Adt { krate, args, .. } => {
                if let Some(p) = ctx.package_of_crate(&krate.name, &krate.stable_id)
                    && !ctx.local.contains(&p)
                    && (ctx.is_unmodelled(krate)
                        || ctx
                            .kb_entry(krate)
                            .is_some_and(|e| e.role == Role::Algorithm))
                {
                    out.push(p);
                }
                stack.extend(args.iter());
            }
            TyTree::Ref(t) | TyTree::Slice(t) | TyTree::Array(t, _) => stack.push(t),
            TyTree::Tuple(ts) => stack.extend(ts.iter()),
            _ => {}
        }
    }
    out
}

/// The type in a call's Self type that names its algorithm and is not modelled: the innermost
/// type of a crypto package the knowledge base does not model (`sha3::Sha3_256Core` in
/// `CoreWrapper<..>`), or of a version it does not cover; with the reason and its package. A
/// type of the program's own crates is its own code (out of scope), and a type of the crate
/// making the call is that crate's implementation: neither gives an occurrence.
fn unmodelled_type(
    ctx: &Ctx<'_>,
    site: &Site,
    t: &rcbom_facts::TyTree,
) -> Option<(String, Vec<(String, String)>)> {
    use rcbom_facts::TyTree;
    let mut found: Option<(&rcbom_facts::CrateRef, &str, bool)> = None;
    // else the outermost type of a modelled algorithm crate the knowledge base names no entry
    // for (sha3's `Keccak256Core`, elliptic-curve's `SecretKey`)
    let mut unnamed: Option<(&rcbom_facts::CrateRef, &str)> = None;
    // the algorithm crates in the type provide the algorithm together: the unmodelled cipher
    // and the modelled mode crate of `cbc::Encryptor<blowfish::Blowfish>`
    let mut providers: Vec<(String, String)> = Vec::new();
    let mut stack = vec![t];
    while let Some(t) = stack.pop() {
        match t {
            TyTree::Adt { krate, path, args } => {
                let package = ctx.package_of_crate(&krate.name, &krate.stable_id);
                let local = package.as_ref().is_some_and(|p| ctx.local.contains(p));
                let kb_entry = ctx.kb_entry(krate);
                let unsupported = kb_entry.is_some() && !ctx.supported(krate);
                if !local && (unsupported || ctx.is_unmodelled(krate)) {
                    found = Some((krate, path, unsupported));
                }
                let name = path.rsplit("::").next().unwrap_or(path);
                // no cryptography at all (rand's `SmallRng`)
                if ctx.kb.not_crypto.iter().any(|n| n == name) && kb_entry.is_some() {
                    return None;
                }
                if !local
                    && unnamed.is_none()
                    && kb_entry.is_some_and(|e| e.role == Role::Algorithm)
                    && !unsupported
                    && !ctx
                        .kb
                        .types
                        .iter()
                        .any(|e| e.krate == krate.name && e.name == name)
                {
                    unnamed = Some((krate, path));
                }
                if let Some(p) = package
                    && !local
                    && (ctx.is_unmodelled(krate)
                        || kb_entry.is_some_and(|e| e.role == Role::Algorithm))
                    && !providers.contains(&p)
                {
                    providers.push(p);
                }
                stack.extend(args.iter());
            }
            TyTree::Ref(t) | TyTree::Slice(t) | TyTree::Array(t, _) => stack.push(t),
            TyTree::Tuple(ts) => stack.extend(ts.iter()),
            _ => {}
        }
    }
    let (krate, path, unsupported, named) = match (found, unnamed) {
        (Some((k, p, u)), _) => (k, p, u, true),
        (None, Some((k, p))) => (k, p, false, false),
        (None, None) => return None,
    };
    if krate.name == site.owner.krate.name {
        return None;
    }
    let of = ctx
        .package_of_crate(&krate.name, &krate.stable_id)
        .as_ref()
        .map(|(n, v)| format!(" of {n} {v}"))
        .unwrap_or_default();
    let reason = if !named {
        format!(
            "the type `{}`{of}, which the knowledge base does not name",
            short(path)
        )
    } else if unsupported {
        format!(
            "the type `{}`{of}, a version the knowledge base does not cover",
            short(path)
        )
    } else {
        format!(
            "the type `{}`{of}, a crypto package the knowledge base does not model",
            short(path)
        )
    };
    providers.sort();
    Some((reason, providers))
}

/// The name of the asset of operations whose algorithm the analysis does not find; its family
/// is empty.
pub const UNKNOWN: &str = "unknown";

/// Why no algorithm reaches an operation, from where the value of its algorithm argument
/// comes (`the result of `Scheme::alg``).
fn unresolved_reason(o: &rcbom_facts::Origin) -> String {
    use rcbom_facts::Origin;
    // the value itself was cut, not the arguments of a call whose result is not followed: a
    // field of a value whose search stopped at its bound (a chain of writes through `&mut
    // self` longer than the driver follows)
    fn value_cut(o: &Origin) -> bool {
        match o {
            Origin::Truncated => true,
            Origin::Any(v) | Origin::All(v) => v.iter().any(value_cut),
            Origin::Written { args, .. } => args.iter().any(value_cut),
            Origin::Field { base, .. } => value_cut(base),
            Origin::Set { value, .. } => value_cut(value),
            _ => false,
        }
    }
    let peeled = links::peel(o);
    let reason = unresolved_kind(peeled);
    if !matches!(peeled, Origin::Truncated) && value_cut(peeled) {
        format!("{reason}; the search for the value hit its bound")
    } else {
        reason
    }
}

fn unresolved_kind(o: &rcbom_facts::Origin) -> String {
    use rcbom_facts::Origin;
    match o {
        Origin::Param { .. } => {
            "a parameter, whose arguments (where a recorded call passes one) name no algorithm"
                .into()
        }
        Origin::Call { callee, .. } => format!("the result of `{}`", short(callee)),
        Origin::Field { adt, .. } => format!("a field of `{}`", short(adt)),
        Origin::Written { callee, .. } => format!("what `{}` writes", short(callee)),
        Origin::Through { callee } => format!("a value written through `{}`", short(callee)),
        Origin::Data { def, .. } => {
            format!("`{}`, which leads to no single algorithm", short(&def.path))
        }
        Origin::Any(_) => "one of several values, none naming an algorithm".into(),
        Origin::Truncated => "the search for the value hit its bound".into(),
        Origin::Set { value, .. } => unresolved_kind(links::peel(value)),
        Origin::Loop | Origin::All(_) | Origin::Const { .. } | Origin::Unit { .. } => {
            "a value the analysis does not follow".into()
        }
        Origin::Unknown => "a value of unknown origin".into(),
    }
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
                    if g.detail.iter().any(|d| d.ends_with(OWN_PARAMS)) {
                        continue;
                    }
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
                        merged.push((g.location, g.line, g.offset, g.symbol));
                    }
                }
            }
            // only the occurrences merged: another on the line (`Argon2::from(Params::default())
            // .verify_password(..)`, a call naming its own parameters) stays
            let g = assets.get_mut(general).unwrap();
            g.occurrences.retain(|o| {
                !merged.contains(&(o.location.clone(), o.line, o.offset, o.symbol.clone()))
            });
        }
    }
    assets.retain(|_, a| !a.occurrences.is_empty());
}

/// `micro::seal::<aes_gcm::AesGcm<aes_gcm::aes::Aes256, ..>>` -> `micro::seal::<..>`, for
/// human-readable context; the full instance stays in the facts. Only a path's generic
/// arguments are elided, the item's name is kept (`ConnectorBuilder::<WantsTlsConfig>::
/// with_native_roots` -> `ConnectorBuilder::<..>::with_native_roots`), and so are the types of
/// a qualified segment (`<impl Paseto<'_, V4, Public>>::try_sign`).
fn short(name: &str) -> String {
    if name.len() <= 60 {
        return name.to_string();
    }
    let mut out = String::new();
    // nesting inside elided arguments
    let mut skip = 0usize;
    let mut prev = None;
    for (i, c) in name.char_indices() {
        if skip > 0 {
            match c {
                '<' => skip += 1,
                // not the arrow of a function type (`fn(&[u8]) -> Vec<u8>`)
                '>' if prev != Some('-') => skip -= 1,
                _ => {}
            }
            if skip == 0 {
                out.push_str("..>");
            }
        } else {
            out.push(c);
            // the generic arguments of a path (`seal::<..>`, `ConnectorBuilder::<..>`); a type's
            // in a qualified segment (`<KeyPair as TryFrom<&PrivateKeyDer<'_>>>`, `<impl
            // Paseto<'_, V4, Public>>`) tell impls apart, and stay
            if c == '<' && prev == Some(':') && !name[i + 1..].starts_with("impl ") {
                skip = 1;
            }
        }
        prev = Some(c);
    }
    out
}

/// The crates of the ADTs a type tree names (`OsRng` in `generate_nonce::<OsRng>`).
fn adt_crates<'a>(t: &'a rcbom_facts::TyTree, out: &mut Vec<&'a rcbom_facts::CrateRef>) {
    use rcbom_facts::TyTree;
    match t {
        TyTree::Adt { krate, args, .. } => {
            out.push(krate);
            args.iter().for_each(|a| adt_crates(a, out));
        }
        TyTree::Ref(t) | TyTree::Slice(t) | TyTree::Array(t, _) => adt_crates(t, out),
        TyTree::Tuple(ts) => ts.iter().for_each(|a| adt_crates(a, out)),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::short;

    #[test]
    fn short_names_keep_the_item() {
        assert_eq!(
            short("micro::seal::<aes_gcm::AesGcm<aes_gcm::aes::Aes256, typenum::U12>>"),
            "micro::seal::<..>"
        );
        assert_eq!(
            short(
                "rusty_paseto::core::paseto_impl::v4_public::<impl rusty_paseto::core::Paseto<'_, V4, Public>>::try_sign"
            ),
            "rusty_paseto::core::paseto_impl::v4_public::<impl rusty_paseto::core::Paseto<'_, V4, Public>>::try_sign"
        );
        assert_eq!(
            short(
                "<rcgen::KeyPair as core::convert::TryFrom<&rustls_pki_types::PrivateKeyDer<'_>>>::try_from"
            ),
            "<rcgen::KeyPair as core::convert::TryFrom<&rustls_pki_types::PrivateKeyDer<'_>>>::try_from"
        );
        assert_eq!(
            short(
                "<rcgen::key_pair::KeyPair as rcgen::key_pair::SigningKey>::sign_with_a_long_name"
            ),
            "<rcgen::key_pair::KeyPair as rcgen::key_pair::SigningKey>::sign_with_a_long_name"
        );
        assert_eq!(
            short(
                "hyper_rustls::connector::builder::ConnectorBuilder::<WantsTlsConfig>::with_native_roots"
            ),
            "hyper_rustls::connector::builder::ConnectorBuilder::<..>::with_native_roots"
        );
        assert_eq!(
            short("a_crate::module::apply::<fn(&[u8]) -> std::vec::Vec<u8>, u8>::run_it"),
            "a_crate::module::apply::<..>::run_it"
        );
        assert_eq!(short("a::b::<c>"), "a::b::<c>");
    }
}
