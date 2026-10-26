//! Operations whose algorithm is not found, with why, and crypto packages and types not modelled.

use super::*;

/// A call that performs an operation whose algorithm the knowledge base cannot name. Three
/// kinds:
/// - an `[[operation]]` whose algorithm is a run-time value no algorithm reaches;
/// - an `[[operation]]` of a RustCrypto trait whose Self type is of a crypto package the
///   knowledge base does not model, or of a version it does not cover (`Sha3_256::digest`);
/// - a call from another crate into a crypto package the knowledge base does not model, with a
///   method that is a use (`p256::ecdh::diffie_hellman`).
pub(super) fn unresolved_operation(ctx: &Ctx<'_>, site: &Site) -> Option<Unresolved> {
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
    // an API the knowledge base names, of a version it does not cover (`getrandom::fill` of
    // getrandom 0.5)
    let uncovered_entry =
        (op.is_none() && ctx.kb_entry(&callee.krate).is_some() && !ctx.supported(&callee.krate))
            .then(|| {
                let bare = matcher::strip_generics(in_crate);
                ctx.kb.fns.iter().find(|e| {
                    e.self_type.is_none()
                        && e.krates.contains(&callee.krate.name)
                        && (e.pattern.is_match(in_crate) || e.pattern.is_match(&bare))
                })
            })
            .flatten();
    match (op, uncovered_entry) {
        (Some(op), _) if op.self_type => {
            let t = self_ty.as_ref()?;
            // a trait object (`Box<dyn DynDigest>`): the type is chosen at run time; a type
            // parameter of a library's generic function (`<A as Aead>::encrypt`): by its callers
            let (reason, provider) = match (dyn_trait(t), type_param(t)) {
                (Some(d), _) => (
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
                (None, Some(p)) => (
                    format!(
                        "a type parameter (`{p}`) of the library's generic API: its callers \
                         choose the type"
                    ),
                    ctx.package_of_crate(&callee.krate.name, &callee.krate.stable_id)
                        .into_iter()
                        .collect(),
                ),
                (None, None) => unmodelled_type(ctx, site, t)?,
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
                        && Kb::lists(&ctx.kb.block_modes, &krate.name) =>
                {
                    "block-cipher".to_string()
                }
                _ => op.primitive.clone(),
            };
            // (a trait hashes and MACs both implement, on a type it cannot name: either)
            if op.shared && !op.setup {
                return Some(("unknown".into(), "digest or tag".into(), reason, provider));
            }
            Some((primitive, function, reason, provider))
        }
        (Some(op), _) => {
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
        // the call is the operation the entry says, of an unknown algorithm
        (None, Some(e)) => {
            // (at a version not covered, a call whose name is no use is cited too: what it
            // does there is not known)
            let function = e
                .algo
                .implied_use
                .clone()
                .or_else(|| ctx.kb.use_of(method, &e.algo.primitive))
                .unwrap_or_else(|| "unknown".to_string());
            let provider = ctx.package_of_crate(&callee.krate.name, &callee.krate.stable_id);
            let reason = match &provider {
                Some((n, v)) => format!(
                    "`{}` of {n} {v}, a version the knowledge base does not cover",
                    short(&callee.path)
                ),
                None => format!("`{}` is not covered", short(&callee.path)),
            };
            let reason = if function == "unknown" {
                format!("{reason}: what the call does is not known")
            } else {
                reason
            };
            Some((
                e.algo.primitive.clone(),
                function,
                reason,
                provider.into_iter().collect(),
            ))
        }
        (None, None) => {
            // a method of a standard-library trait run by a type of another crate is a call
            // into that crate (`<orion::aead::SecretKey as Default>::default()` draws a key), on
            // a value or a reference to one (`&point * &scalar`)
            let mut own = self_ty.as_ref();
            while let Some(rcbom_facts::TyTree::Ref(t)) = own {
                own = Some(t);
            }
            let runs_in = match own {
                Some(rcbom_facts::TyTree::Adt { krate, .. })
                    if matches!(callee.krate.name.as_str(), "core" | "std" | "alloc") =>
                {
                    krate
                }
                _ => &callee.krate,
            };
            // a crypto package the knowledge base does not model, an API of an algorithm crate
            // it models that it does not name (`p256::SecretKey::random`), or an algorithm or
            // trait crate it models at a version it does not cover (md5 0.8's
            // `Context::finalize`, ed25519-dalek 3's `SigningKey::verify`, password-hash 0.6's
            // `verify_password`), called from another crate
            // (not what the knowledge base says is no operation, `[[aside]]`: a view, a copy, a
            // wipe, an accessor; by the trait a method is of, or its path in its crate)
            let bare = matcher::strip_generics(&callee.path);
            let trait_path = bare.rsplit_once("::").map(|(t, _)| t);
            let in_runs = bare
                .strip_prefix(&format!("{}::", runs_in.name))
                .unwrap_or("");
            if ctx.kb.aside(&runs_in.name, in_runs, trait_path).is_some() {
                return None;
            }
            let entry = ctx.kb_entry(runs_in);
            let supported = ctx.supported(runs_in);
            let unnamed_api = entry.is_some_and(|e| e.role == Role::Algorithm) && supported;
            // (a dependency: the program's own package named like one is no such crate)
            let dependency = ctx
                .package_of_crate(&runs_in.name, &runs_in.stable_id)
                .is_some_and(|p| !ctx.local.contains(&p));
            let uncovered = entry.is_some_and(|e| matches!(e.role, Role::Algorithm | Role::Trait))
                && dependency
                && !supported;
            // (a generic method name says nothing without a modelled type to scope it; a crate
            // the knowledge base models scopes it, md5's `finalize` being MD5's, rand's `fill` a
            // draw, though a streaming step of it is still no operation)
            let generic = ctx.kb.generic_method(method);
            let step = ctx.kb.step(method) || ctx.kb.step_trait(trait_path);
            // a crypto package without entries: every call into it from another crate is
            // reported (openssl's `sha256`, orion's `SecretKey::default()`, curve25519-dalek's
            // `mul_clamped`), what it does not known but for a use its name has, other than a
            // step of a stream, whose operation is the call that ends it, and a call into a
            // relay (tokio-rustls, rustls-pki-types: `[unmodelled]`)
            // (from outside the crypto layer: another crypto package's calls into it, openssl's
            // into openssl-sys, are the internals of what the program asked of that one)
            // (or code running on its behalf on every way: a generic function another crate
            // instantiates with its types, subtle's `CtOption::map` on p384's field elements)
            let crypto_caller = ((ctx.is_unmodelled(&site.owner.krate)
                || ctx.kb_entry(&site.owner.krate).is_some())
                && ctx
                    .package_of_crate(&site.owner.krate.name, &site.owner.krate.stable_id)
                    .is_some_and(|p| !ctx.local.contains(&p)))
                || ctx
                    .behalf
                    .get(&(site.span.file.clone(), site.span.line, site.span.col))
                    == Some(&true);
            let unmodelled = ctx.is_unmodelled(runs_in) && !ctx.kb.relay(&runs_in.name);
            let open = unmodelled && !unnamed_api && !uncovered && !crypto_caller;
            if !(open || unnamed_api || uncovered || unmodelled)
                || site.owner.krate == *runs_in
                || step
                || (!open && !unnamed_api && generic && !uncovered)
            {
                return None;
            }
            // a type the call is made on or for that is a parameter of a library's generic
            // function (`v.shuffle::<R>(rng)`): its callers choose it
            let param = self_ty.iter().chain(args.iter()).find_map(type_param);
            // what an uncovered crate computes, as its entries say (md5's: a hash), scopes the
            // use; so it does for a type the callers choose (rand's: a generator)
            let primitives: BTreeSet<&str> = if uncovered || param.is_some() {
                let k = runs_in.name.as_str();
                ctx.kb
                    .types
                    .iter()
                    .filter(|t| t.krate == k)
                    .map(|t| &t.algo)
                    .chain(
                        ctx.kb
                            .fns
                            .iter()
                            .chain(&ctx.kb.statics)
                            .filter(|e| e.krates.iter().any(|x| x == k))
                            .map(|e| &e.algo),
                    )
                    .map(|a| a.primitive.as_str())
                    .collect()
            } else {
                BTreeSet::new()
            };
            let scoped: Vec<String> = primitives
                .iter()
                .filter_map(|p| ctx.kb.use_of(method, p))
                .collect();
            // (of a package without entries, a generic name names no use: age's `finish` ends
            // an encryption)
            let mut uses: Vec<&str> = if !scoped.is_empty() {
                scoped.iter().map(String::as_str).collect()
            } else if open && generic {
                Vec::new()
            } else {
                ctx.kb
                    .uses
                    .iter()
                    .filter(|u| u.methods.iter().any(|m| m == method))
                    .map(|u| u.function.as_str())
                    .collect()
            };
            uses.sort();
            uses.dedup();
            if uses.is_empty() {
                // (an API of a modelled crate at a version it covers that it does not name
                // counts where its name is a use: any other is a gap the boundary check
                // reports; at a version it does not cover, every call counts, as for a package
                // without entries)
                if !open && !uncovered {
                    return None;
                }
                uses.push("unknown");
            }
            // a draw from a generator that computes no cryptography (`v.shuffle(&mut small_rng)`)
            // is no operation; a key made with one still is
            if uses.iter().all(|u| *u == "generate")
                && self_ty
                    .iter()
                    .chain(args.iter())
                    .any(|t| names_not_crypto(ctx, t))
            {
                return None;
            }
            let primitive = match (scoped.is_empty(), primitives.len()) {
                (false, 1) => primitives.first().copied().unwrap_or("unknown"),
                _ => "unknown",
            };
            let provider = ctx.package_of_crate(&runs_in.name, &runs_in.stable_id);
            let reason = match (&provider, param) {
                (Some((n, v)), Some(p)) => format!(
                    "`{}` of {n} {v} on a type parameter (`{p}`) of the library's generic API: \
                     its callers choose the type",
                    short(&callee.path)
                ),
                (Some((n, v)), None) if uncovered => format!(
                    "`{}` of {n} {v}, a version the knowledge base does not cover",
                    short(&callee.path)
                ),
                (Some((n, v)), None) if unnamed_api => format!(
                    "`{}` of {n} {v}, an API the knowledge base does not name",
                    short(&callee.path)
                ),
                (Some((n, v)), None) => format!(
                    "`{}` of {n} {v}, a crypto package the knowledge base does not model",
                    short(&callee.path)
                ),
                (None, _) => format!("`{}` is not modelled", short(&callee.path)),
            };
            let reason = if uses == ["unknown"] {
                format!("{reason}: what the call does is not known")
            } else {
                reason
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
            Some((primitive.into(), uses.join(" or "), reason, provider))
        }
    }
}
/// Why the algorithms found are not all that may reach the call, from the gaps of the value
/// search that reach it (not those met only through code no entry point reaches): its bound
/// first, then the first value it does not follow.
pub(super) fn gaps_reason(gaps: &[search::Gap]) -> Option<String> {
    let live: Vec<&search::Gap> = gaps
        .iter()
        .filter(|g| !g.dead && g.kind != search::GapKind::Elsewhere)
        .collect();
    if live.iter().any(|g| g.kind == search::GapKind::Cut) {
        return Some(
            "the search for the value hit its bound: other algorithms than these may reach the \
             call"
                .to_string(),
        );
    }
    live.first().map(|g| {
        format!(
            "other algorithms than these may reach the call: {} is not followed",
            g.reason
        )
    })
}
/// The type parameter a call's type is, directly or behind a reference (`&mut R`).
fn type_param(t: &rcbom_facts::TyTree) -> Option<&str> {
    match t {
        rcbom_facts::TyTree::Param(p) => Some(p),
        rcbom_facts::TyTree::Ref(t) => type_param(t),
        _ => None,
    }
}
/// Whether a call's types name a type parameter (a site of a library's generic function).
pub(super) fn names_param(target: &Target) -> bool {
    fn deep(t: &rcbom_facts::TyTree) -> bool {
        use rcbom_facts::TyTree;
        match t {
            TyTree::Param(_) => true,
            TyTree::Adt { args, .. } => args.iter().any(deep),
            TyTree::Ref(t) | TyTree::Slice(t) | TyTree::Array(t, _) => deep(t),
            TyTree::Tuple(ts) => ts.iter().any(deep),
            _ => false,
        }
    }
    match target {
        Target::Call { self_ty, args, .. } => self_ty.iter().chain(args.iter()).any(deep),
        _ => false,
    }
}
/// Whether a type names a type of a modelled crate that computes no cryptography (rand's
/// `SmallRng`, at any version).
fn names_not_crypto(ctx: &Ctx<'_>, t: &rcbom_facts::TyTree) -> bool {
    use rcbom_facts::TyTree;
    match t {
        TyTree::Adt { krate, path, args } => {
            let name = path.rsplit("::").next().unwrap_or(path);
            (ctx.kb.not_crypto.iter().any(|n| n == name) && ctx.kb_entry(krate).is_some())
                || args.iter().any(|a| names_not_crypto(ctx, a))
        }
        TyTree::Ref(t) | TyTree::Slice(t) | TyTree::Array(t, _) => names_not_crypto(ctx, t),
        TyTree::Tuple(ts) => ts.iter().any(|t| names_not_crypto(ctx, t)),
        _ => false,
    }
}
/// The packages of the algorithm crates a type names (modelled or not), outside the program.
pub(super) fn crypto_packages(ctx: &Ctx<'_>, t: &rcbom_facts::TyTree) -> Vec<(String, String)> {
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
pub(super) fn unmodelled_type(
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
/// Why no algorithm reaches an operation, from where the value of its algorithm argument
/// comes (`the result of `Scheme::alg``).
pub(super) fn unresolved_reason(o: &rcbom_facts::Origin) -> String {
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
    let reason = search::unresolved_kind(peeled);
    if !matches!(peeled, Origin::Truncated) && value_cut(peeled) {
        format!("{reason}; the search for the value hit its bound")
    } else {
        reason
    }
}
