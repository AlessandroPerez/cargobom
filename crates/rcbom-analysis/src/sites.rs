//! A site's occurrences: its call matched, its values searched, its members labelled.

use super::*;

pub(super) fn call_key(s: &Site) -> CallKey<'_> {
    (
        s.owner.id.as_str(),
        s.span.file.as_str(),
        s.span.line,
        s.span.col,
    )
}
impl<'a> Ctx<'a> {
    /// Records that the value constructor call `at` makes is passed to a call that matched `m`.
    pub(super) fn link(&self, at: &'a Site, m: &Match) {
        self.links
            .borrow_mut()
            .entry(call_key(at))
            .or_default()
            .push(m.clone());
    }

    /// A crate of a crypto package the knowledge base does not model.
    pub(super) fn is_unmodelled(&self, k: &rcbom_facts::CrateRef) -> bool {
        self.unmodelled
            .contains(&(k.name.clone(), k.stable_id.clone()))
    }

    /// The `[[crate]]` entry of exactly this crate's package, any version.
    pub(super) fn kb_entry(&self, k: &rcbom_facts::CrateRef) -> Option<&rcbom_kb::CrateEntry> {
        let (package, _) = self.package_of_crate(&k.name, &k.stable_id)?;
        self.kb.crates.iter().find(|c| c.package == package)
    }

    pub(super) fn package_of_crate(&self, name: &str, stable_id: &str) -> Option<(String, String)> {
        self.crates
            .get(&(name.to_string(), stable_id.to_string()))
            .cloned()
    }

    /// The knowledge base covers this exact crate: known package, version in range.
    pub(super) fn supported(&self, k: &rcbom_facts::CrateRef) -> bool {
        self.package_of_crate(&k.name, &k.stable_id)
            .filter(|p| !self.local.contains(p))
            .and_then(|(n, v)| Some((n, semver::Version::parse(&v).ok()?)))
            .is_some_and(|(n, v)| self.kb.crate_by_package(&n, &v).is_some())
    }
}
/// The variant a value names by a unit variant of the family's enum (`Some(Algorithm::Argon2d
/// .ident())`): `d`, its name after the family's.
pub(super) fn named_variant(o: &rcbom_facts::Origin, family: &str) -> Option<String> {
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
/// `None` (`Option::None` passed for an optional argument).
pub(super) fn is_none_origin(o: &rcbom_facts::Origin) -> bool {
    matches!(o, rcbom_facts::Origin::Unit { path, .. } if path.ends_with("Option::None"))
}
/// What the call an argument of `site` comes from matched, when it is a [[fn]] entry of
/// `family`: the one such call among the arguments, found by its position in the same function.
/// It must build a type the call names in its generic arguments, or one of `own` crate (the
/// `Params` of `scrypt::scrypt`, whose parameter types the facts do not list). `overrides` are
/// parameters the site itself fixes.
pub(super) fn argument_constructor<'a>(
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
pub(super) fn constructed(
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
pub(super) fn fn_site_match<'a>(ctx: &Ctx<'a>, site: &Site) -> Option<(Match, Option<&'a Site>)> {
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
/// Parameters a method fixes itself (`call_params`), over those of the constructor that built
/// its receiver: one the call does not resolve is unknown, not the constructor's.
pub(super) fn fix_call_params(
    m: &mut Match,
    fixes: &BTreeMap<String, rcbom_kb::Param>,
    site: &Site,
) {
    let Target::Call {
        const_args,
        arg_lens,
        ..
    } = &site.target
    else {
        return;
    };
    for (k, p) in fixes {
        match matcher::call_value(p, const_args, arg_lens) {
            Some(v) => {
                m.values.insert(k.clone(), v.clone());
                m.params.insert(k.clone(), v);
            }
            None => {
                m.values.remove(k);
                m.params.remove(k);
            }
        }
    }
}
/// `named`'s asset and parameters, with what `entry` says the call does (its functions, use and
/// note).
pub(super) fn adopt(named: Match, entry: Match) -> Match {
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
#[allow(clippy::too_many_arguments)]
pub(super) fn site_matches(
    ctx: &Ctx<'_>,
    site: &Site,
    at: Option<&std::path::Path>,
    closure: &dyn Fn(&str) -> Vec<rcbom_facts::DefRef>,
    edges: &dyn Fn(&str) -> Vec<rcbom_facts::DefRef>,
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
                // ..except by the APIs drawing from the generator they are given (rand's
                // `Alphanumeric.sample_string(&mut OsRng, 16)`, `v.shuffle(&mut rng)`)
                let draws = Kb::lists(&kb.draws, &callee.krate.name);
                let handed = m.algo.primitive == "drbg" && !receiver_types.contains(&m.key());
                if handed && !draws {
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
                // what the method fixes itself, whatever built its receiver
                let fixes = m.algo.call_params.get(method).cloned().unwrap_or_default();
                fix_call_params(&mut m, &fixes, site);
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
                        fix_call_params(&mut m, &fixes, site);
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
                    fix_call_params(&mut m, &fixes, site);
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
            let has_roles = || {
                !provenance::of_call(kb, &ctx.flow, &site.owner.path, &site.target, false)
                    .is_empty()
            };
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
            // why the algorithms found are not all that may reach the call (the gaps of the
            // value search, of the place used), and a table of several algorithms read where
            // which one is not followed
            let mut gaps: Vec<search::Gap> = Vec::new();
            let mut table_gap: Option<String> = None;
            if out.is_empty() && into_kb && !protocol_callee && (can_occur() || has_roles()) {
                let has_roles = has_roles();
                let live = |v: &links::Via| boundary::reached(v, reachable, reached_path);
                // the argument that carries the algorithm of an operation
                let algorithm = operation_algorithm(ctx, site);
                // the call's own arguments; if what they name is not used here, its receiver's;
                // if nothing in this function names the algorithm, what reaches the key or
                // algorithm from other functions (a field, a parameter, a function's result),
                // looked up only then
                // a static or constant that is no descriptor leads to one (a table)
                let leads = |d: &rcbom_facts::DefRef| {
                    closure(&d.id)
                        .iter()
                        .any(|x| x.id != d.id && match_static(kb, x, &supported).is_some())
                };
                let local = {
                    let mut s = search::Search::new(kb, &ctx.flow, false, &live).with_leads(&leads);
                    search::data_in_args(&mut s, &site.owner.path, &site.target, algorithm)
                };
                // what an argument names here is not all that reaches it when its other
                // alternatives come from elsewhere (`if c { &SHA256 } else { pick() }`, a field
                // read of a table of structs, a static that changes at run time): then the
                // values from other functions are looked up too, those named here kept as
                // named here
                let incomplete = local
                    .iter()
                    .any(|p| p.gaps.iter().any(|g| g.kind == search::GapKind::Elsewhere));
                let named_here: HashSet<String> = if incomplete {
                    local
                        .iter()
                        .flat_map(|p| p.defs.iter())
                        .filter(|d| provenance::is_descriptor(kb, d))
                        .map(|x| x.id.clone())
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
                    let mut s = search::Search::new(kb, &ctx.flow, true, &live).with_leads(&leads);
                    let r = search::data_in_args(
                        &mut s,
                        site.owner.path.as_str(),
                        &site.target,
                        algorithm,
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
                for (place, from_elsewhere) in places {
                    let (mut descriptors, others): (Vec<_>, Vec<_>) = place
                        .defs
                        .iter()
                        .cloned()
                        .partition(|d| provenance::is_descriptor(kb, d));
                    // the user's own data naming exactly one descriptor (`digest(TABLE.alg, ..)`
                    // with `TABLE.alg = &SHA256`) names it; a list of several (`DIGESTS[i]`): any
                    // of them, the element read by an index not followed (R4.3)
                    let mut tables: HashMap<String, (String, usize)> = HashMap::new();
                    let mut place_table_gap: Option<String> = None;
                    for d in others {
                        // a static that changes at run time holds what the program puts there
                        // (looked up with the values from elsewhere), not its initializer's
                        if ctx.flow.mutable_static(&d.id).is_some() {
                            continue;
                        }
                        let read_field = matches!(&site.target, Target::Call { arg_origins, .. }
                        if arg_origins.iter().any(|o| provenance::reads_static_field(
                            o,
                            &|id| id == d.id,
                            0,
                        )));
                        match table_members(
                            kb,
                            &d,
                            read_field,
                            closure,
                            edges,
                            &|id| ctx.flow.static_fields(id),
                            &supported,
                        ) {
                            Ok(found) => {
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
                            Err(why) => {
                                place_table_gap.get_or_insert(why);
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
                    // a table read where which of its algorithms is not followed says so
                    if table_gap.is_none() {
                        table_gap = place_table_gap;
                    }
                    // the place that names the algorithm is the answer, with its gaps
                    if !out.is_empty() {
                        gaps = place.gaps;
                        break;
                    }
                }
            }
            // an operation is never dropped: when no algorithm reaches it, it is reported with
            // an unknown one, and why; so is the rest of the algorithms when the search for them
            // met a value it does not follow or hit its bound (what was found is not all)
            let gap_reason = gaps_reason(&gaps);
            let unresolved = if let Some(t) = &table_gap {
                unresolved_operation(ctx, site).map(|(p, f, _, pr)| {
                    let reason = format!(
                        "{}{t}",
                        if out.is_empty() {
                            ""
                        } else {
                            "other algorithms than these may reach the call: "
                        },
                    );
                    (p, f, reason, pr)
                })
            } else if out.is_empty() {
                unresolved_operation(ctx, site)
            } else if let Some(reason) = &gap_reason {
                unresolved_operation(ctx, site).map(|(p, f, _, pr)| (p, f, reason.clone(), pr))
            } else {
                None
            };
            // the points-to analysis (`RCBOM_PTA`), where it ran and the call is given a descriptor
            // by reference, only removes doubt: a complete answer within the search's members
            // drops those it shows cannot reach the call and closes the call's gaps; one beyond
            // a search answer that claims completeness gives the unknown (`pta_members`);
            // anything else leaves the search's answer as it is
            let mut gap_reason = gap_reason;
            let mut unresolved = unresolved;
            if let Some(v) = at.and_then(|at| pta_verdict(ctx, site, at)) {
                let search_gap =
                    unresolved.is_some() || gap_reason.is_some() || table_gap.is_some();
                match pta_members(ctx, site, &v, search_gap, &mut out) {
                    Settled::Closed => {
                        unresolved = None;
                        gap_reason = None;
                        table_gap = None;
                    }
                    Settled::Beyond => {
                        unresolved = unresolved_operation(ctx, site)
                            .map(|(p, f, _, pr)| (p, f, BEYOND.to_string(), pr));
                        gap_reason = Some(BEYOND.to_string());
                    }
                    Settled::No => {}
                }
            }
            // a call that is no operation (a key set up with the algorithm) gives no unknown
            // occurrence: its members say they are not all
            if unresolved.is_none() && (gap_reason.is_some() || table_gap.is_some()) {
                let n = out.iter().filter(|o| !o.5).count();
                for o in out.iter_mut().filter(|o| !o.5) {
                    if let Some(s) = o.4.iter_mut().find(|s| s.starts_with("algorithm ")) {
                        *s = beside_unknown(s, n);
                    }
                }
            }
            if let Some((primitive, function, reason, provider)) = unresolved {
                // the members found beside it are not all that may reach the call: none is
                // the only one
                let n = out.iter().filter(|o| !o.5).count();
                for o in out.iter_mut().filter(|o| !o.5) {
                    if let Some(s) = o.4.iter_mut().find(|s| s.starts_with("algorithm ")) {
                        *s = beside_unknown(s, n);
                    }
                }
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
pub(super) fn enclosing_fn(path: &str) -> Option<&str> {
    let i = path.find("::{")?;
    Some(&path[..i])
}
/// An owner id that is a def-path hash (32 hex digits), as the driver gives a generic function
/// it scans without an instance; an instance's id is its mangled name.
pub(super) fn is_def_hash(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit())
}
/// The argument of an operation (`[[operation]]`, of a value-selected algorithm) that carries
/// its algorithm.
pub(super) fn operation_algorithm(ctx: &Ctx<'_>, site: &Site) -> Option<usize> {
    let Target::Call { callee, .. } = &site.target else {
        return None;
    };
    let in_crate = callee
        .path
        .strip_prefix(&format!("{}::", callee.krate.name))
        .unwrap_or(&callee.path);
    ctx.kb
        .operation(&callee.krate.name, &matcher::strip_generics(in_crate))
        .filter(|op| !op.self_type)
        .map(|op| op.algorithm)
}
/// The descriptors a value read from static (or constant) `d` can be, when its data says: the
/// one descriptor it leads to, or each element of a list of descriptors (`static DIGESTS:
/// [&Algorithm; 2] = [&SHA256, &SHA384]`, read at any index: R4.3). Otherwise (a field read,
/// `TABLE[i].h`; a table of structs or of other statics, `[&BASE, &FIX]`), which of its several
/// algorithms is read is not followed: the reason.
pub(super) fn table_members(
    kb: &Kb,
    d: &rcbom_facts::DefRef,
    read_field: bool,
    closure: &dyn Fn(&str) -> Vec<rcbom_facts::DefRef>,
    edges: &dyn Fn(&str) -> Vec<rcbom_facts::DefRef>,
    stores_fields: &dyn Fn(&str) -> bool,
    supported: &dyn Fn(&rcbom_facts::CrateRef) -> bool,
) -> std::result::Result<Vec<rcbom_facts::DefRef>, String> {
    let mut found: Vec<rcbom_facts::DefRef> = closure(&d.id)
        .into_iter()
        .filter(|x| match_static(kb, x, supported).is_some())
        .collect();
    // a descriptor another one is made of (`HMAC_SHA256`'s `SHA256`) is part of it, not a
    // second one
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
    if found.len() <= 1 {
        return Ok(found);
    }
    // a field read of it (`AREF[i].h`, `OPT.unwrap().h`) where nothing says what the field
    // holds: not every descriptor of the data (another field's among them), the unknown
    if read_field {
        return Err(format!(
            "a field of `{}` the analysis does not follow (the data holds several algorithms)",
            boundary::short_fn(&d.path)
        ));
    }
    // a list of the descriptors themselves, or of such lists (`[&DIGESTS]`): any element
    // (R4.3); a static or constant holding structs or tuples (its initializer stores fields:
    // `stores_fields`) is no list
    fn list(
        kb: &Kb,
        id: &str,
        edges: &dyn Fn(&str) -> Vec<rcbom_facts::DefRef>,
        stores_fields: &dyn Fn(&str) -> bool,
        supported: &dyn Fn(&rcbom_facts::CrateRef) -> bool,
        depth: usize,
    ) -> bool {
        let items = edges(id);
        depth < 4
            && !stores_fields(id)
            && !items.is_empty()
            && items.iter().all(|x| {
                match_static(kb, x, supported).is_some()
                    || list(kb, &x.id, edges, stores_fields, supported, depth + 1)
            })
    }
    if list(kb, &d.id, edges, stores_fields, supported, 0) {
        return Ok(found);
    }
    Err(format!(
        "a value read from `{}` the analysis does not follow (the data holds several \
         algorithms, not as a list of them)",
        boundary::short_fn(&d.path)
    ))
}
/// A member's algorithm sentence when the set found has an unknown beside it (others may reach
/// the call): never "the only one" (`from X`), always one of those found.
pub(super) fn beside_unknown(s: &str, n: usize) -> String {
    const BESIDE: &str = ", beside others not followed";
    if s.contains(BESIDE) {
        return s.to_string();
    }
    let local = s.ends_with(" in the arguments");
    if let Some(rest) = s.strip_prefix("algorithm one of ")
        && let Some((head, member)) = rest.split_once(": ")
        && !head.starts_with("the ")
    {
        return format!("algorithm one of {head}{BESIDE}: {member}");
    }
    let member = s
        .strip_prefix("algorithm from ")
        .or_else(|| s.strip_prefix("algorithm possibly from "))
        .map(|r| {
            r.trim_end_matches(" in the arguments")
                .split(", ")
                .next()
                .unwrap_or(r)
        });
    match member {
        Some(m) if local => {
            format!("algorithm one of {n} that may reach the call{BESIDE}: {m} in the arguments")
        }
        Some(m) => format!(
            "algorithm one of {n} that may reach the call from other functions{BESIDE}: {m}"
        ),
        None => s.to_string(),
    }
}
/// Do the values that reach `o` from elsewhere (read at `site`) include a cut (`Truncated`: in
/// a function's summary, or where the lookup stopped at its bound)?
pub(super) fn linked_cut(ctx: &Ctx<'_>, site: &Site, o: &rcbom_facts::Origin) -> bool {
    ctx.flow.values(o, &site.owner.path).is_some_and(|vs| {
        vs.iter()
            .any(|(v, _)| matches!(v, rcbom_facts::Origin::Truncated))
    })
}
/// `: stored by static `X``, when the descriptor `id` was found stored by statics only.
pub(super) fn static_witness(
    named: &HashMap<String, std::collections::BTreeSet<String>>,
    id: &str,
) -> String {
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
/// The principal trait of a trait object type (`dyn digest::DynDigest`), behind references.
pub(super) fn dyn_trait(t: &rcbom_facts::TyTree) -> Option<&str> {
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
