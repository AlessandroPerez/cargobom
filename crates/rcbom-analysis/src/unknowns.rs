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
