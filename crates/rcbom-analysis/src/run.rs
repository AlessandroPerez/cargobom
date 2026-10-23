//! The analysis of a build's facts, from the sites to the assets (`analyze`).

use super::*;

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
        pta: {
            let mut m: HashMap<_, Vec<&rcbom_facts::PtaCall>> = HashMap::new();
            for f in facts {
                let cwd = PathBuf::from(&f.krate.cwd);
                for c in f
                    .reach
                    .iter()
                    .flat_map(|r| &r.points_to)
                    .flat_map(|p| &p.calls)
                {
                    let file = PathBuf::from(&c.at.file);
                    let file = if file.is_absolute() {
                        file
                    } else {
                        cwd.join(file)
                    };
                    m.entry((file, c.at.line, c.at.col)).or_default().push(c);
                }
            }
            m
        },
        descriptor_types: facts
            .iter()
            .flat_map(|f| &f.reach)
            .flat_map(|r| &r.points_to)
            .flat_map(|p| &p.static_types)
            .filter(|(d, _)| match_static(kb, d, &|_| true).is_some())
            .map(|(_, t)| t.clone())
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
    // the statics and constants an initializer names directly
    let edges = |id: &str| -> Vec<rcbom_facts::DefRef> {
        static_edges.get(id).cloned().unwrap_or_default()
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
    // the data reachable from these seeds: what they name in turn, and the internals of the
    // `thread_local!`s among them
    let data_reached = |seeds: &[rcbom_facts::DefRef]| -> HashSet<String> {
        let mut reachable_statics: HashSet<String> = HashSet::new();
        for d in seeds {
            if !reachable_statics.contains(&d.id) {
                reachable_statics.extend(closure(&d.id).into_iter().map(|d| d.id));
            }
        }
        // a `thread_local!`'s own items (its initializer `__RUST_STD_INTERNAL_INIT`, its storage
        // `{constant#0}::{closure#0}::__RUST_STD_INTERNAL_VAL`) are reached when its key is: the
        // key's `with` runs them through a pointer the walk does not follow
        let key_of = |path: &str| -> Option<String> {
            let i = path
                .find("::__RUST_STD_INTERNAL")
                .or_else(|| path.find("::__rust_std_internal"))?;
            let head = &path[..i];
            Some(head.find("::{").map_or(head, |j| &head[..j]).to_string())
        };
        let keys: HashSet<String> = reachable_statics
            .iter()
            .filter_map(|id| static_defs.get(id))
            .map(|d| d.path.clone())
            .collect();
        let internals: Vec<String> = static_defs
            .values()
            .map(|d| (d.id.clone(), d.path.clone()))
            .chain(
                facts
                    .iter()
                    .flat_map(|f| &f.sites)
                    .filter(|s| s.owner.kind == OwnerKind::Static)
                    .map(|s| (s.owner.id.clone(), s.owner.path.clone())),
            )
            .filter(|(id, path)| {
                !reachable_statics.contains(id) && key_of(path).is_some_and(|k| keys.contains(&k))
            })
            .map(|(id, _)| id)
            .collect();
        for id in internals {
            reachable_statics.insert(id.clone());
            reachable_statics.extend(closure(&id).into_iter().map(|d| d.id));
        }
        reachable_statics
    };
    let reachable_statics = data_reached(&seeds);
    let reached_data = |id: &str| reachable_statics.contains(id);
    // each artifact's walk: the functions it reaches and the data they name, the artifacts an
    // occurrence is tagged with (`rcbom:artifact`); together they are what is reachable
    let walks: Vec<ArtifactWalk> = facts
        .iter()
        .filter_map(|f| f.reach.as_ref())
        .map(|r| {
            let fns: HashSet<&str> = r.fns.iter().map(String::as_str).collect();
            let mut seeds = r.statics.clone();
            for s in facts.iter().flat_map(|f| &f.sites) {
                if let (OwnerKind::Fn, Target::Static { def } | Target::Const { def }) =
                    (&s.owner.kind, &s.target)
                    && fns.contains(s.owner.id.as_str())
                {
                    seeds.push(def.clone());
                }
            }
            ArtifactWalk {
                name: r.artifact.clone(),
                statics: data_reached(&seeds),
                paths: r.paths.iter().map(String::as_str).collect(),
                fns,
            }
        })
        .collect();
    let mut artifacts: Vec<String> = walks.iter().map(|w| w.name.clone()).collect();
    artifacts.sort();
    artifacts.dedup();
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
    ctx.flow.set_reached(reached_paths.clone());
    let reached_path = |p: &str| reached_paths.contains(p);
    // the functions the walk itself went through (an instance of each; not a library's generic
    // function no instance walks)
    let walked_paths: HashSet<&str> = facts
        .iter()
        .filter_map(|f| f.reach.as_ref())
        .flat_map(|r| {
            r.paths
                .iter()
                .filter(|p| r.generic.binary_search(p).is_err())
                .map(String::as_str)
        })
        .collect();
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
            let _ = site_matches(
                &ctx,
                ctx.calls[&k],
                None,
                &closure,
                &edges,
                &reached_data,
                &reached_path,
            );
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

    // the calls the walk found in instances (`pick::<Fast>`'s `t.alg()`): the per-item scan's
    // site at the same position, in the generic item's body, stands for no other instance of
    // this build, and its arguments are not resolved for the types it runs with
    let abs = |f: &CrateFacts, file: &str| {
        let p = PathBuf::from(file);
        if p.is_absolute() {
            p
        } else {
            PathBuf::from(&f.krate.cwd).join(p)
        }
    };
    let walked: HashSet<(PathBuf, usize, usize, String)> = facts
        .iter()
        .enumerate()
        .flat_map(|(fi, f)| {
            sites_of(fi).filter_map(move |s| match &s.target {
                Target::Call { callee, .. } if s.tier == Tier::Reachable => Some((
                    abs(f, &s.span.file),
                    s.span.line,
                    s.span.col,
                    callee.path.clone(),
                )),
                _ => None,
            })
        })
        .collect();
    for (fi, f) in facts.iter().enumerate() {
        let cwd = PathBuf::from(&f.krate.cwd);
        for site in sites_of(fi) {
            let path = {
                let p = PathBuf::from(&site.span.file);
                if p.is_absolute() { p } else { cwd.join(p) }
            };
            if let Target::Call { callee, .. } = &site.target
                && site.tier == Tier::Present
                && is_def_hash(&site.owner.id)
                // (a closure's or `async` body's per-item site: its own arguments, as precise
                // as an instance's, under the closure's name; not when its types are a library's
                // generic parameters, which the instance's are as the caller chose them)
                && (!site.owner.path.contains("{closure") || names_param(&site.target))
                && walked.contains(&(
                    path.clone(),
                    site.span.line,
                    site.span.col,
                    callee.path.clone(),
                ))
            {
                continue;
            }
            let tier = match site.owner.kind {
                OwnerKind::Static if reachable_statics.contains(&site.owner.id) => Tier::Reachable,
                OwnerKind::Static => Tier::Present,
                OwnerKind::Fn if reached_fns.contains(site.owner.id.as_str()) => Tier::Reachable,
                // a closure or `async` body is reached with the function that writes it: in a
                // library's generic public function, which no instance walks, the per-item
                // scan sees it alone (`serialize_der_with_signer::{closure#1}`); in a function
                // the walk went through, as the walk says (a closure only made a trait object
                // no code calls is not reached), unless the walk hit its bound
                OwnerKind::Fn
                    if enclosing_fn(&site.owner.path).is_some_and(|e| {
                        reached_path(e) && (truncated || !walked_paths.contains(e))
                    }) =>
                {
                    Tier::Reachable
                }
                OwnerKind::Fn => site.tier,
            };
            // the artifacts whose walk reaches the site: of a function, those reaching its
            // instance, else (a closure reached with its function) those reaching that function
            let artifacts: BTreeSet<String> = if tier == Tier::Reachable {
                let mut a: BTreeSet<String> = walks
                    .iter()
                    .filter(|w| match site.owner.kind {
                        OwnerKind::Static => w.statics.contains(&site.owner.id),
                        OwnerKind::Fn => w.fns.contains(site.owner.id.as_str()),
                    })
                    .map(|w| w.name.clone())
                    .collect();
                if a.is_empty()
                    && let Some(e) = enclosing_fn(&site.owner.path)
                {
                    a = walks
                        .iter()
                        .filter(|w| w.paths.contains(e))
                        .map(|w| w.name.clone())
                        .collect();
                }
                // (never untagged: reachable is what some walk reaches)
                if a.is_empty() {
                    a = artifacts.iter().cloned().collect();
                }
                a
            } else {
                BTreeSet::new()
            };
            // code a build script generated (`OUT_DIR`, inside the target directory wherever
            // that is), and any file outside every package's directory, belongs to the package
            // of the crate that includes it; the standard library's has none
            let by_path = if path.starts_with(&man.target_directory) {
                None
            } else {
                man.owner_of(&path)
            };
            let Some(owner_pkg) = by_path.or_else(|| {
                ctx.package_of_crate(&site.owner.krate.name, &site.owner.krate.stable_id)
                    .and_then(|(n, v)| man.by_name_version(&n, &v))
            }) else {
                continue;
            };
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
                let kb_backends = kb
                    .crate_by_name(&callee.krate.name)
                    .map(|c| c.backends.clone())
                    .unwrap_or_default();
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
                if let Some(b) = backend_in_path(&callee.path, &kb_backends)
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
                        if let Some(b) = backend_in_path(&d.path, &kb_backends) {
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
                    // a `[[protocol]]` call configures the stack; it makes no connection
                    detail: vec![format!(
                        "{}: configuration, not a connection",
                        callee.path.rsplit("::").next().unwrap_or(&callee.path)
                    )],
                    package: pkg.clone(),
                    provenance: Vec::new(),
                    note: None,
                    generic_body: false,
                    via: Vec::new(),
                    artifacts: artifacts.clone(),
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
            let mut matches = site_matches(
                &ctx,
                site,
                Some(&path),
                &closure,
                &edges,
                &reached_data,
                &reached_path,
            );
            // what an asset computes inside itself (`[[part]]`: Argon2's BLAKE2b), where it is
            // used; its provider is the package under the asset's that implements it
            let mut parts: Vec<SiteMatch> = Vec::new();
            for (m, kind, function, symbol, _, unreached) in matches.iter_mut() {
                if *kind != Kind::Call || function.is_none() {
                    continue;
                }
                for mut p in matcher::parts_of(kb, m) {
                    if p.key() == m.key() {
                        continue;
                    }
                    m.components.insert(p.key());
                    if parts.iter().any(|q| q.0.key() == p.key()) {
                        continue;
                    }
                    for (n, v) in &m.providers {
                        let deps = man
                            .by_name_version(n, v)
                            .into_iter()
                            .flat_map(|o| &o.runtime_deps)
                            .filter_map(|d| man.by_id(d));
                        for d in deps.filter(|d| p.algo.implemented_by.contains(&d.name)) {
                            p.providers.insert((d.name.clone(), d.version.to_string()));
                        }
                    }
                    let d = vec![format!("part of {}", m.name)];
                    parts.push((p, Kind::Component, None, symbol.clone(), d, *unreached));
                }
            }
            matches.extend(parts);
            let protocol = kb
                .crate_by_name(&site.owner.krate.name)
                .is_some_and(|c| c.role == Role::Protocol);
            let prov = provenance::of_call(kb, &ctx.flow, &site.target, protocol);
            for (m, kind, function, symbol, detail, unreached) in matches {
                let tier = if unreached { Tier::Present } else { tier };
                let artifacts = if unreached {
                    BTreeSet::new()
                } else {
                    artifacts.clone()
                };
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
                    artifacts,
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
                for (k, v) in m.params.iter().chain(&m.algo.fixed) {
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
                    o.artifacts.extend(occ.artifacts);
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
            if same {
                kept.artifacts.append(&mut later.artifacts);
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
        artifacts,
        layer2: true,
    }
}

/// One artifact's walk: the functions it reaches (owner ids, defining paths) and the data they
/// name, for the artifacts an occurrence is tagged with.
struct ArtifactWalk<'f> {
    name: String,
    fns: HashSet<&'f str>,
    paths: HashSet<&'f str>,
    statics: HashSet<String>,
}
