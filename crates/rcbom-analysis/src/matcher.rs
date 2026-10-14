//! Knowledge-base matching on structured facts.

use std::collections::{BTreeMap, BTreeSet};

use rcbom_facts::{CrateRef, DefRef, Origin, TyTree};
use rcbom_kb::{Algo, Kb, Param, ProtocolEntry, TypeEntry};

#[derive(Clone, Debug)]
pub struct Match {
    pub name: String,
    pub algo: Algo,
    pub params: BTreeMap<String, String>,
    /// Every parameter value resolved, those the name shows included: what a constructor hands
    /// on to the calls its value is passed to (the variant of `Argon2::new(..)` to `Params`).
    pub values: BTreeMap<String, String>,
    /// Keys of the assets found inside this one's generic arguments.
    pub components: BTreeSet<String>,
    pub providers: BTreeSet<(String, String)>,
    /// Crates of the providers, to be resolved to packages.
    pub provider_crates: Vec<CrateRef>,
}

fn last(path: &str) -> &str {
    path.rsplit("::").next().unwrap_or(path)
}

/// Fills `{name}` placeholders from `vals`, following the registry's notation, where trailing
/// parts are optional:
/// - a placeholder left unresolved drops its `-{..}` segment when what follows is literal
///   (`AES-{key}-GCM` -> `AES-GCM`), and ends the name when another placeholder follows, since
///   later parts are positional (`PBKDF2-{hash}-{iterations}-{dk_len}` with the iterations
///   unknown is `PBKDF2-SHA-256`, not `PBKDF2-SHA-256-32`, which would read as 32 iterations);
/// - `[..]` is an optional part, written only when all its placeholders are resolved and one of
///   them differs from its default (`AES-{key}-GCM[-{tag_bits}-{nonce_bits}]` is `AES-256-GCM`
///   with the standard 16-byte tag and 12-byte nonce, `AES-256-GCM-128-128` with a 16-byte
///   nonce). A default can be another parameter (`RSA-OAEP-{hash}[-MGF1-{mgf_hash}]` with
///   `mgf_hash = "{hash}"` is `RSA-OAEP-SHA-256` when MGF1 hashes with SHA-256 too).
pub(crate) fn fill(
    template: &str,
    vals: &BTreeMap<String, String>,
    defaults: &BTreeMap<String, String>,
) -> String {
    // optional parts first
    let mut t = String::new();
    let mut rest = template;
    while let Some(i) = rest.find('[') {
        let Some(j) = rest[i..].find(']').map(|j| i + j) else {
            break;
        };
        t.push_str(&rest[..i]);
        let part = &rest[i + 1..j];
        let keys = placeholders(part);
        let resolved = keys.iter().all(|k| vals.contains_key(k));
        let differs = keys
            .iter()
            .any(|k| default_of(defaults, vals, k).is_none_or(|d| vals.get(k) != Some(d)));
        if resolved && differs {
            t.push_str(part);
        }
        rest = &rest[j + 1..];
    }
    t.push_str(rest);
    // then the placeholders
    let mut out = String::new();
    let mut rest = t.as_str();
    while let Some(i) = rest.find('{') {
        let Some(j) = rest[i..].find('}').map(|j| i + j) else {
            break;
        };
        let key = &rest[i + 1..j];
        match vals.get(key) {
            Some(v) => {
                out.push_str(&rest[..i]);
                out.push_str(v);
            }
            None => {
                let before = &rest[..i];
                out.push_str(before.strip_suffix('-').unwrap_or(before));
                if rest[j + 1..].contains('{') {
                    return out; // positional parts follow: stop here
                }
            }
        }
        rest = &rest[j + 1..];
    }
    out.push_str(rest);
    out
}

/// A parameter's default value; a default can be another parameter's value (`mgf_hash =
/// "{hash}"`: MGF1 with the OAEP hash).
fn default_of<'a>(
    defaults: &'a BTreeMap<String, String>,
    vals: &'a BTreeMap<String, String>,
    key: &str,
) -> Option<&'a String> {
    let d = defaults.get(key)?;
    match d.strip_prefix('{').and_then(|x| x.strip_suffix('}')) {
        Some(other) => vals.get(other),
        None => Some(d),
    }
}

fn placeholders(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = s;
    while let Some(i) = rest.find('{') {
        let Some(j) = rest[i..].find('}').map(|j| i + j) else {
            break;
        };
        out.push(rest[i + 1..j].to_string());
        rest = &rest[j + 1..];
    }
    out
}

/// The parameters the filled name `name` actually spells out: a template placeholder can be
/// left out (`PBKDF2-SHA-256-{iterations}-{dk_len}` with the iterations unknown ends after the
/// hash), and then its value must stay a property.
fn in_name(algo: &Algo, vals: &BTreeMap<String, String>, name: &str) -> BTreeSet<String> {
    vals.keys()
        .filter(|k| algo.asset.contains(&format!("{{{k}}}")))
        .filter(|k| {
            // an optional part left out at its default value is implied by the name
            algo.defaults.contains_key(*k) || {
                let mut without = vals.clone();
                without.remove(*k);
                fill(&algo.asset, &without, &algo.defaults) != name
            }
        })
        .cloned()
        .collect()
}

fn filled_algo(algo: &Algo, vals: &BTreeMap<String, String>) -> Algo {
    let mut a = algo.clone();
    let none = BTreeMap::new();
    let fill = |t: &str, v: &BTreeMap<String, String>| fill(t, v, &none);
    a.asset = self::fill(&algo.asset, vals, &algo.defaults);
    let mut required = String::new();
    let mut optional = 0usize;
    for ch in algo.asset.chars() {
        match ch {
            '[' => optional += 1,
            ']' => optional = optional.saturating_sub(1),
            _ if optional == 0 => required.push(ch),
            _ => {}
        }
    }
    a.open = required
        .split('{')
        .skip(1)
        .filter_map(|s| s.split_once('}'))
        .map(|(p, _)| p.to_string())
        .filter(|p| !vals.contains_key(p))
        .collect();
    a.parameter_set = algo
        .parameter_set
        .as_ref()
        .map(|p| fill(p, vals))
        .filter(|p| !p.is_empty());
    a.curve = algo.curve.as_ref().map(|c| fill(c, vals));
    a.size = algo
        .size
        .as_ref()
        .map(|c| fill(c, vals))
        .filter(|s| !s.is_empty());
    a
}

/// Whether the knowledge base covers this exact crate (its version is in range).
pub type Supported<'a> = &'a dyn Fn(&CrateRef) -> bool;

pub fn match_static(kb: &Kb, def: &DefRef, supported: Supported) -> Option<Match> {
    match_static_called(kb, def, None, supported)
}

/// A descriptor named by a call to `method`, which may say more than the descriptor alone
/// (`asset_by_method`): aws-lc-rs's `key_wrap::AES_256` is AES-256-KWP for
/// `wrap_with_padding`.
pub fn match_static_called(
    kb: &Kb,
    def: &DefRef,
    method: Option<&str>,
    supported: Supported,
) -> Option<Match> {
    if !supported(&def.krate) {
        return None;
    }
    let name = last(&def.path);
    let within = def
        .path
        .strip_prefix(&format!("{}::", def.krate.name))
        .unwrap_or(&def.path);
    for e in kb.statics.iter().filter(|e| {
        e.krates.contains(&def.krate.name) && e.module.as_ref().is_none_or(|m| m.is_match(within))
    }) {
        if let Some(c) = e.pattern.captures(name) {
            let vals: BTreeMap<String, String> = (1..c.len())
                .filter_map(|i| c.get(i).map(|m| (i.to_string(), m.as_str().to_string())))
                .collect();
            let mut algo = e.algo.clone();
            if let Some(t) = method.and_then(|m| e.asset_by_method.get(m)) {
                algo.asset = t.clone();
            }
            let algo = filled_algo(&algo, &vals);
            return Some(Match {
                name: algo.asset.clone(),
                params: BTreeMap::new(),
                values: BTreeMap::new(),
                algo,
                components: BTreeSet::new(),
                providers: BTreeSet::new(),
                provider_crates: Vec::new(),
            });
        }
    }
    None
}

/// Every name a descriptor static or const can be an asset of: its entry's, and those the
/// methods called with it select (`asset_by_method`). Empty when no `[[static]]` entry matches.
/// For `cargo cbom verify`, which checks that a descriptor cited as evidence is of its asset.
pub fn static_names(kb: &Kb, krate: &str, path: &str) -> Vec<String> {
    let def = DefRef {
        krate: CrateRef {
            name: krate.to_string(),
            stable_id: String::new(),
        },
        path: path.to_string(),
        id: String::new(),
    };
    let all = |_: &CrateRef| true;
    let methods: BTreeSet<&str> = kb
        .statics
        .iter()
        .filter(|e| e.krates.iter().any(|k| k == krate))
        .flat_map(|e| e.asset_by_method.keys().map(String::as_str))
        .collect();
    let mut out: Vec<String> = std::iter::once(None)
        .chain(methods.into_iter().map(Some))
        .filter_map(|m| match_static_called(kb, &def, m, &all).map(|m| m.name))
        .collect();
    out.sort();
    out.dedup();
    out
}

/// A call matched by a `[[fn]]` entry: a free function or method of a KB crate
/// (`pbkdf2::pbkdf2_hmac::<Sha256>`), or a trait method implemented by a KB type
/// (`<Argon2 as Default>::default`, entry with `self_type`). Parameters come from the call's
/// generic arguments and integer constant arguments.
pub fn match_fn(
    kb: &Kb,
    callee: &DefRef,
    self_ty: Option<&TyTree>,
    args: &[TyTree],
    const_args: &[Option<i128>],
    arg_lens: &[Option<u64>],
    supported: Supported,
) -> Option<Match> {
    let none = BTreeMap::new();
    match_fn_with(
        kb, callee, self_ty, args, const_args, arg_lens, supported, &none,
    )
}

/// [`match_fn`], with parameter values known from elsewhere standing over the call's own:
/// the constructor of a value passed to a call, with what the call itself says
/// (`scrypt(.., &Params::new(15, 8, 1, 32), out)` derives `out.len()` bytes).
#[allow(clippy::too_many_arguments)]
pub fn match_fn_with(
    kb: &Kb,
    callee: &DefRef,
    self_ty: Option<&TyTree>,
    args: &[TyTree],
    const_args: &[Option<i128>],
    arg_lens: &[Option<u64>],
    supported: Supported,
    overrides: &BTreeMap<String, String>,
) -> Option<Match> {
    let prefix = format!("{}::", callee.krate.name);
    let path = callee.path.strip_prefix(&prefix).unwrap_or(&callee.path);
    // with and without the impl's generic arguments (`argon2::Argon2::<'key>::new`)
    let bare = strip_generics(path);
    let full_bare = strip_generics(&callee.path);
    let mut provider = None;
    // an entry for the methods of a type: its parameters may be the type's own arguments
    // (`parent_arg`: the curve of `SigningKey<NistP256>`)
    let mut parent = None;
    let e = kb.fns.iter().find(|e| match &e.self_type {
        Some(st) => match self_ty {
            Some(TyTree::Adt {
                krate,
                path: tp,
                args: targs,
            }) if e.krates.contains(&krate.name) && last(tp) == st && supported(krate) => {
                let ok = e.pattern.is_match(&callee.path) || e.pattern.is_match(&full_bare);
                if ok {
                    provider = Some(krate.clone());
                    parent = Some(targs.as_slice());
                }
                ok
            }
            _ => false,
        },
        None => {
            let ok = e.krates.contains(&callee.krate.name)
                && supported(&callee.krate)
                && (e.pattern.is_match(path) || e.pattern.is_match(&bare));
            if ok {
                provider = Some(callee.krate.clone());
            }
            ok
        }
    })?;
    Some(fn_entry_match_in(
        kb, e, args, parent, const_args, arg_lens, provider, supported, overrides,
    ))
}

/// A parameter declared without a source: the call the value is passed to gives it.
fn sourceless(p: &Param) -> bool {
    p.arg.is_none()
        && p.parent_arg.is_none()
        && p.const_arg.is_none()
        && p.arg_len.is_none()
        && p.value.is_none()
}

/// The asset of a `[[fn]]` entry, with its parameters from the call and `overrides`.
#[allow(clippy::too_many_arguments)]
fn fn_entry_match(
    kb: &Kb,
    e: &rcbom_kb::PatternEntry,
    args: &[TyTree],
    const_args: &[Option<i128>],
    arg_lens: &[Option<u64>],
    provider: Option<CrateRef>,
    supported: Supported,
    overrides: &BTreeMap<String, String>,
) -> Match {
    fn_entry_match_in(
        kb, e, args, None, const_args, arg_lens, provider, supported, overrides,
    )
}

/// [`fn_entry_match`] for a method of a type whose arguments are `parent`.
#[allow(clippy::too_many_arguments)]
fn fn_entry_match_in(
    kb: &Kb,
    e: &rcbom_kb::PatternEntry,
    args: &[TyTree],
    parent: Option<&[TyTree]>,
    const_args: &[Option<i128>],
    arg_lens: &[Option<u64>],
    provider: Option<CrateRef>,
    supported: Supported,
    overrides: &BTreeMap<String, String>,
) -> Match {
    let mut params = BTreeMap::new();
    for (k, p) in &e.params {
        let v = match (p.const_arg, p.arg_len) {
            (Some(i), _) => const_args
                .get(i)
                .copied()
                .flatten()
                .map(|v| (v * p.scale.unwrap_or(1) as i128).to_string())
                .and_then(|v| mapped(p, v)),
            (None, Some(i)) => arg_lens.get(i).copied().flatten().map(|v| v.to_string()),
            _ => p
                .value
                .clone()
                .or_else(|| eval_param(kb, p, args, parent, supported)),
        };
        if let Some(v) = v {
            params.insert(k.clone(), v);
        }
    }
    // what the entry leaves to the call its value is passed to (declared without a source:
    // the output length of `scrypt(.., &params, out)`, the Argon2 variant of the `Argon2` value
    // `Params` are used with)
    for (k, v) in overrides {
        if e.params.get(k).is_some_and(sourceless) && !params.contains_key(k) {
            params.insert(k.clone(), v.clone());
        }
    }
    let algo = filled_algo(&e.algo, &params);
    let values = params.clone();
    // placeholders of the name left without a value (`{missing}` in `unresolved`); a parameter
    // declared without a source is the call's to give (`dk_len` of `scrypt::Params::new`, which
    // `scrypt(.., &params, out)` derives as `out.len()`), not one this call failed to resolve
    let from_call = |k: &String| e.params.get(k).is_some_and(sourceless);
    let missing: Vec<String> = placeholders(&e.algo.asset)
        .into_iter()
        .filter(|k| !params.contains_key(k) && !from_call(k))
        .collect();
    let shown = in_name(&e.algo, &params, &algo.asset);
    params.retain(|k, _| !shown.contains(k));
    if let Some(u) = &e.algo.unresolved {
        // `{missing}`: only what is unknown at this call, and nothing when all is known
        if !u.contains("{missing}") {
            params.insert("unresolved".to_string(), u.clone());
        } else if !missing.is_empty() {
            params.insert(
                "unresolved".to_string(),
                u.replace("{missing}", &missing.join(", ")),
            );
        }
    }
    Match {
        name: algo.asset.clone(),
        algo,
        params,
        values,
        components: BTreeSet::new(),
        providers: BTreeSet::new(),
        provider_crates: provider.into_iter().collect(),
    }
}

/// The asset a constructor call in an origin tree makes, its parameters from its constant
/// arguments.
fn constructed_by(
    kb: &Kb,
    e: &rcbom_kb::PatternEntry,
    args: &[Origin],
    overrides: &BTreeMap<String, String>,
) -> Match {
    let consts: Vec<Option<i128>> = args
        .iter()
        .map(|a| match a {
            Origin::Const { value, .. }
            | Origin::Data { value, .. }
            | Origin::Unit { value, .. } => *value,
            _ => None,
        })
        .collect();
    fn_entry_match(kb, e, &[], &consts, &[], None, &|_| true, overrides)
}

/// The `[[fn]]` entry of `family` an argument's origin is a call of, through standard-library
/// plumbing (`Params::new(..).unwrap()`, `?`), with that call's arguments.
fn argument_entry<'k, 'o>(
    kb: &'k Kb,
    family: &str,
    mut o: &'o Origin,
) -> Option<(&'k rcbom_kb::PatternEntry, &'o [Origin])> {
    for _ in 0..8 {
        let Origin::Call {
            callee,
            krate,
            self_ty,
            args,
            ..
        } = o
        else {
            return None;
        };
        let path = strip_generics(callee);
        let within = path.strip_prefix(&format!("{krate}::")).unwrap_or(&path);
        // a constructor of a parameter value of that crate (`argon2::Params`), not data computed
        // with the family (`blake3::derive_key(..)` as the key of `Hasher::new_keyed`)
        let builds = self_ty
            .as_deref()
            .is_some_and(|t| t.starts_with(&format!("{krate}::")));
        if builds
            && let Some(e) = kb.fns.iter().find(|e| {
                e.algo.family == family
                    && e.self_type.is_none()
                    && e.krates.contains(krate)
                    && e.pattern.is_match(within)
            })
        {
            return Some((e, args));
        }
        // a std constructor of such a value (`Params::default()`): an entry with that self type
        if let Some(t) = self_ty.as_deref()
            && let Some(e) = kb.fns.iter().find(|e| {
                e.algo.family == family
                    && e.self_type.as_deref() == Some(last(t))
                    && e.krates.iter().any(|k| t.starts_with(&format!("{k}::")))
                    && e.pattern.is_match(&path)
            })
        {
            return Some((e, args));
        }
        if !matches!(krate.as_str(), "core" | "std" | "alloc") {
            return None;
        }
        o = args.first()?;
    }
    None
}

/// The constructor a receiver was built by, when a `[[fn]]` entry of the same family names
/// it: `argon2.hash_password(..)` with `argon2` from `Argon2::default()` is Argon2id-19456-2-1,
/// a `blake3::Hasher` from `Hasher::new_keyed(key)` a keyed hash. Follows the receiver chain
/// (`&mut x`, `x.unwrap()`).
pub fn match_constructor<'o>(
    kb: &Kb,
    family: &str,
    receiver: &'o Origin,
) -> Option<(Match, Option<&'o rcbom_facts::Loc>)> {
    let mut cur = receiver;
    for _ in 0..8 {
        let Origin::Call {
            callee,
            krate,
            self_ty,
            args,
            span,
        } = cur
        else {
            return None;
        };
        let path = strip_generics(callee);
        let entry = kb.fns.iter().find(|e| {
            e.algo.family == family
                && match &e.self_type {
                    Some(st) => self_ty.as_deref().is_some_and(|t| {
                        last(t) == st
                            && e.krates.iter().any(|k| t.starts_with(&format!("{k}::")))
                            && e.pattern.is_match(&path)
                    }),
                    None => {
                        e.krates.contains(krate)
                            && e.pattern
                                .is_match(path.strip_prefix(&format!("{krate}::")).unwrap_or(&path))
                    }
                }
        });
        if let Some(e) = entry {
            let none = BTreeMap::new();
            let m = constructed_by(kb, e, args, &none);
            // a value of the family built in its arguments says more (`Argon2::new(alg, ver,
            // Params::new(m, t, p, None)?)`): that one, with what this constructor fixes
            for a in args {
                if let Some(inner) = argument_entry(kb, family, a) {
                    let (f, inner_args) = inner;
                    return Some((constructed_by(kb, f, inner_args, &m.values), span.as_ref()));
                }
            }
            return Some((m, span.as_ref()));
        }
        // only plumbing hands its receiver on (`unwrap`, `as_ref`, a crypto crate's
        // conversion); what the program's own function returns is not its argument
        if !matches!(krate.as_str(), "core" | "std" | "alloc") && kb.crate_by_name(krate).is_none()
        {
            return None;
        }
        cur = args.first()?;
    }
    None
}

pub(crate) fn strip_generics(path: &str) -> String {
    let mut out = String::new();
    let mut depth = 0usize;
    for ch in path.chars() {
        match ch {
            '<' => depth += 1,
            '>' => depth = depth.saturating_sub(1),
            _ if depth == 0 => out.push(ch),
            _ => {}
        }
    }
    out.replace("::::", "::")
}

/// A call into a protocol crate that configures the protocol (`ClientConfig::builder`).
pub fn match_protocol<'k>(
    kb: &'k Kb,
    callee: &DefRef,
    supported: Supported,
) -> Option<&'k ProtocolEntry> {
    let prefix = format!("{}::", callee.krate.name);
    let path = callee.path.strip_prefix(&prefix).unwrap_or(&callee.path);
    kb.protocols.iter().find(|p| {
        p.krate == callee.krate.name && supported(&callee.krate) && p.pattern.is_match(path)
    })
}

/// Every KB type inside the generic arguments, outermost first. The second element names the
/// enclosing match for components (`Some("HMAC-SHA-256")` for the SHA-256 inside it).
pub fn match_types(kb: &Kb, args: &[TyTree], supported: Supported) -> Vec<(Match, Option<String>)> {
    let mut out = Vec::new();
    for a in args {
        walk(kb, a, None, None, supported, &mut out);
    }
    out
}

fn walk(
    kb: &Kb,
    t: &TyTree,
    parent: Option<&[TyTree]>,
    outer: Option<&str>,
    supported: Supported,
    out: &mut Vec<(Match, Option<String>)>,
) {
    match t {
        TyTree::Adt { krate, path, args } => {
            let within = path
                .strip_prefix(&format!("{}::", krate.name))
                .unwrap_or(path);
            // an entry whose required parameter does not resolve does not match (`cbc::Encryptor`
            // is AES-CBC for an AES cipher only)
            let entry = kb
                .types
                .iter()
                .filter(|e| {
                    e.krate == krate.name
                        && e.name == last(path)
                        && e.module
                            .as_deref()
                            .is_none_or(|m| regex::Regex::new(m).is_ok_and(|r| r.is_match(within)))
                        && supported(krate)
                })
                .find_map(|e| Some((e, type_match(kb, e, args, parent, supported)?)));
            if let Some((e, mut m)) = entry {
                m.provider_crates = vec![krate.clone()];
                // an argument read as a parameter (the `Aes256` of `AesGcm<Aes256, ..>`, a
                // nonce size) is part of this asset's name, not a component of its own
                let consumed: Vec<usize> = e
                    .params
                    .values()
                    .filter(|p| !p.asset && p.parent_arg.is_none())
                    .filter_map(|p| p.arg)
                    .collect();
                // ... and the crate of the type a `map` parameter reads provides the asset too
                // (the `aes` of `cbc::Encryptor<aes::Aes128>`; the `chacha20` of the
                // `ChaChaCore` inside cipher's `StreamCipherCoreWrapper`, not cipher)
                for p in e.params.values().filter(|p| !p.map.is_empty() && !p.asset) {
                    let Some(mut node) = p.arg.and_then(|i| args.get(i)) else {
                        continue;
                    };
                    for &j in &p.path {
                        match node {
                            TyTree::Adt { args: inner, .. } if inner.len() > j => node = &inner[j],
                            _ => break,
                        }
                    }
                    if let TyTree::Adt { krate: k, .. } = node
                        && kb.crate_by_name(&k.name).is_some()
                        && !m.provider_crates.contains(k)
                    {
                        m.provider_crates.push(k.clone());
                    }
                }
                let name = m.name.clone();
                let idx = out.len();
                out.push((m, outer.map(str::to_string)));
                let before = out.len();
                for (i, a) in args.iter().enumerate() {
                    if consumed.contains(&i) {
                        continue;
                    }
                    walk(
                        kb,
                        a,
                        Some(args),
                        Some(outer.unwrap_or(&name)),
                        supported,
                        out,
                    );
                }
                let inner: Vec<String> = out[before..].iter().map(|(m, _)| m.key()).collect();
                out[idx].0.components.extend(inner);
            } else {
                for a in args {
                    walk(kb, a, Some(args), outer, supported, out);
                }
            }
        }
        TyTree::Ref(x) | TyTree::Slice(x) | TyTree::Array(x, _) => {
            walk(kb, x, parent, outer, supported, out)
        }
        TyTree::Tuple(xs) => xs
            .iter()
            .for_each(|x| walk(kb, x, parent, outer, supported, out)),
        _ => {}
    }
}

fn type_match(
    kb: &Kb,
    e: &TypeEntry,
    args: &[TyTree],
    parent: Option<&[TyTree]>,
    supported: Supported,
) -> Option<Match> {
    let mut params = BTreeMap::new();
    for (k, p) in &e.params {
        match eval_param(kb, p, args, parent, supported) {
            Some(v) => {
                params.insert(k.clone(), v);
            }
            None if p.required => return None,
            None => {}
        }
    }
    let algo = filled_algo(&e.algo, &params);
    let shown = in_name(&e.algo, &params, &algo.asset);
    // parameters already spelled out in the name or the parameter set are not repeated
    params.retain(|k, _| {
        !shown.contains(k)
            && !e
                .algo
                .parameter_set
                .as_deref()
                .unwrap_or("")
                .contains(&format!("{{{k}}}"))
    });
    Some(Match {
        name: algo.asset.clone(),
        algo,
        values: params.clone(),
        params,
        components: BTreeSet::new(),
        providers: BTreeSet::new(),
        provider_crates: Vec::new(),
    })
}

fn eval_param(
    kb: &Kb,
    p: &Param,
    args: &[TyTree],
    parent: Option<&[TyTree]>,
    supported: Supported,
) -> Option<String> {
    let mut t = match (p.arg, p.parent_arg) {
        (Some(i), _) => args.get(i)?,
        (None, Some(i)) => parent?.get(i)?,
        _ => return None,
    };
    for &i in &p.path {
        t = match t {
            TyTree::Adt { args, .. } => args.get(i)?,
            _ => return None,
        };
    }
    if p.typenum {
        return typenum(t)
            .map(|n| (n * p.scale.unwrap_or(1)).to_string())
            .and_then(|v| mapped(p, v));
    }
    if !p.map.is_empty() {
        return match t {
            TyTree::Adt { path, .. } => p.map.get(last(path)).cloned(),
            _ => None,
        };
    }
    if p.asset {
        return match_types(kb, std::slice::from_ref(t), supported)
            .into_iter()
            .next()
            .map(|(m, _)| m.name);
    }
    None
}

/// A value through the parameter's map, if it has one (`28` -> `512/224`); unmapped values of
/// a mapped parameter are unknown.
fn mapped(p: &Param, v: String) -> Option<String> {
    if p.map.is_empty() {
        Some(v)
    } else {
        p.map.get(&v).cloned()
    }
}

/// `UInt<UInt<UTerm, B1>, B0>` = 2; a const generic argument as is.
impl Match {
    /// What tells assets apart: the name, the primitive, and whether this is key material.
    /// BLAKE3 keyed (a MAC) is not BLAKE3 the hash; the HMAC secret of
    /// `EncodingKey::from_secret` (key material) is not the HMAC algorithm.
    pub fn key(&self) -> String {
        // an unknown algorithm is one per primitive and providing package: ML-KEM's and P-256's
        // unknown operations are two assets
        if self.name == crate::UNKNOWN
            && self.algo.family.is_empty()
            && self.algo.material.is_none()
        {
            let providers: Vec<&str> = self.providers.iter().map(|(n, _)| n.as_str()).collect();
            return format!(
                "{}|{}",
                asset_key(&self.name, &self.algo),
                providers.join(",")
            );
        }
        asset_key(&self.name, &self.algo)
    }
}

pub fn asset_key(name: &str, algo: &Algo) -> String {
    // key material is what it is whatever it is used for: rsa's `RsaPrivateKey::new` (for
    // encryption) and ring's `RsaKeyPair::from_pkcs8` (for signatures) hold one kind of key
    match &algo.material {
        Some(m) => format!("{name}||{m}"),
        None => format!("{name}|{}|", algo.primitive),
    }
}

pub fn typenum(t: &TyTree) -> Option<u64> {
    match t {
        TyTree::Const(n) => *n,
        TyTree::Adt { path, args, .. } => match last(path) {
            "UTerm" | "B0" => Some(0),
            "B1" => Some(1),
            "UInt" if args.len() == 2 => Some(2 * typenum(&args[0])? + typenum(&args[1])?),
            _ => None,
        },
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adt(krate: &str, path: &str, args: Vec<TyTree>) -> TyTree {
        TyTree::Adt {
            krate: CrateRef {
                name: krate.into(),
                stable_id: "0".into(),
            },
            path: path.into(),
            args,
        }
    }

    fn all(_: &CrateRef) -> bool {
        true
    }

    fn num(n: u64) -> TyTree {
        if n == 0 {
            return adt("typenum", "typenum::UTerm", vec![]);
        }
        let bit = adt(
            "typenum",
            if n % 2 == 1 {
                "typenum::B1"
            } else {
                "typenum::B0"
            },
            vec![],
        );
        adt("typenum", "typenum::UInt", vec![num(n / 2), bit])
    }

    #[test]
    fn typenum_decodes() {
        assert_eq!(typenum(&num(12)), Some(12));
        assert_eq!(typenum(&num(32)), Some(32));
    }

    #[test]
    fn aes_gcm_parameters_come_from_generic_arguments() {
        let kb = Kb::seed().unwrap();
        let t = adt(
            "aes_gcm",
            "aes_gcm::AesGcm",
            vec![adt("aes", "aes::Aes256", vec![]), num(12), num(16)],
        );
        let m = match_types(&kb, &[t], &all);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].0.name, "AES-256-GCM");
        assert_eq!(m[0].0.params["nonce_bytes"], "12");
        assert_eq!(m[0].0.algo.parameter_set.as_deref(), Some("256"));
    }

    #[test]
    fn hmac_composes_with_its_hash() {
        let kb = Kb::seed().unwrap();
        let core = adt("sha2", "sha2::core_api::Sha256VarCore", vec![]);
        let sha = adt(
            "digest",
            "digest::core_api::CoreWrapper",
            vec![adt(
                "digest",
                "digest::core_api::CtVariableCoreWrapper",
                vec![core, num(32), adt("sha2", "sha2::OidSha256", vec![])],
            )],
        );
        let hmac = adt(
            "digest",
            "digest::core_api::CoreWrapper",
            vec![adt("hmac", "hmac::HmacCore", vec![sha])],
        );
        let m = match_types(&kb, &[hmac], &all);
        let names: Vec<_> = m
            .iter()
            .map(|(m, o)| (m.name.as_str(), o.as_deref()))
            .collect();
        assert_eq!(
            names,
            vec![("HMAC-SHA-256", None), ("SHA-256", Some("HMAC-SHA-256"))]
        );
        assert!(m[0].0.components.contains("SHA-256|hash|"));
    }

    #[test]
    fn a_mode_entry_holds_for_its_cipher_only() {
        let kb = Kb::seed().unwrap();
        let cbc = |cipher: TyTree| adt("cbc", "cbc::encrypt::Encryptor", vec![cipher]);
        let aes = cbc(adt("aes", "aes::autodetect::Aes128Enc", vec![]));
        let m = match_types(&kb, &[aes], &all);
        assert_eq!(m[0].0.name, "AES-128-CBC");
        // `Encryptor<Blowfish>` is not AES-CBC: the required key size does not resolve
        let blowfish = cbc(adt("blowfish", "blowfish::Blowfish", vec![]));
        assert!(match_types(&kb, &[blowfish], &all).is_empty());
    }

    #[test]
    fn a_descriptor_named_by_a_method_takes_its_name() {
        let kb = Kb::seed().unwrap();
        let def = DefRef {
            krate: CrateRef {
                name: "aws_lc_rs".into(),
                stable_id: "0".into(),
            },
            path: "aws_lc_rs::key_wrap::AES_256".into(),
            id: "0".into(),
        };
        let named = |m| match_static_called(&kb, &def, m, &all).unwrap().name;
        assert_eq!(named(None), "AES-256");
        assert_eq!(named(Some("wrap")), "AES-256-KW");
        assert_eq!(named(Some("wrap_with_padding")), "AES-256-KWP");
    }

    #[test]
    fn fn_parameters_the_name_cannot_show_are_kept() {
        let kb = Kb::seed().unwrap();
        let e = kb
            .fns
            .iter()
            .find(|e| e.pattern.as_str() == "Params::new$")
            .unwrap();
        // `Params::new(log_n, 8, 1, 32)` with log_n computed at run time
        let m = fn_entry_match(
            &kb,
            e,
            &[],
            &[None, Some(8), Some(1), Some(32)],
            &[],
            None,
            &all,
            &BTreeMap::new(),
        );
        assert_eq!(m.name, "scrypt");
        assert_eq!(m.params["r"], "8");
        assert_eq!(m.params["p"], "1");
        // the `Params` length is not the derived key's: dk_len is the call's to give
        assert!(!m.params.contains_key("dk_len"));
        assert_eq!(
            m.params["unresolved"],
            "N: not a constant where scrypt::Params is built"
        );
        // all constants: the name says everything, nothing is unresolved
        let m = fn_entry_match(
            &kb,
            e,
            &[],
            &[Some(15), Some(8), Some(1), Some(32)],
            &[],
            None,
            &all,
            &BTreeMap::new(),
        );
        assert_eq!(m.name, "scrypt-32768-8-1");
        assert!(m.params.is_empty());
        // passed to `scrypt(.., out)` with a 64-byte `out`: the call derives 64 bytes
        let call: BTreeMap<String, String> = [("dk_len", "64"), ("unresolved", "x")]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let m = fn_entry_match(
            &kb,
            e,
            &[],
            &[Some(15), Some(8), Some(1), Some(32)],
            &[],
            None,
            &all,
            &call,
        );
        assert_eq!(m.name, "scrypt-32768-8-1-64");
        assert!(m.params.is_empty());
        // `Params::recommended()`: the crate's defaults, the output length the call's
        let e = kb
            .fns
            .iter()
            .find(|e| e.pattern.as_str() == "Params::recommended$")
            .unwrap();
        let m = fn_entry_match(&kb, e, &[], &[], &[], None, &all, &BTreeMap::new());
        assert_eq!(m.name, "scrypt-131072-8-1");
        let m = fn_entry_match(&kb, e, &[], &[], &[], None, &all, &call);
        assert_eq!(m.name, "scrypt-131072-8-1-64");
    }

    #[test]
    fn unresolved_placeholders_drop_their_segment() {
        let v = BTreeMap::new();
        let d = BTreeMap::new();
        assert_eq!(fill("HMAC-{hash}", &v, &d), "HMAC");
        assert_eq!(fill("AES-{key}-GCM", &v, &d), "AES-GCM");
    }

    #[test]
    fn positional_parts_after_an_unknown_one_are_cut() {
        let v: BTreeMap<String, String> = [("hash", "SHA-256"), ("dk_len", "32")]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let d = BTreeMap::new();
        // not PBKDF2-SHA-256-32, which would read as 32 iterations
        assert_eq!(
            fill("PBKDF2-{hash}-{iterations}-{dk_len}", &v, &d),
            "PBKDF2-SHA-256"
        );
    }

    #[test]
    fn optional_parts_only_when_not_default() {
        let d: BTreeMap<String, String> = [("tag_bits", "128"), ("nonce_bits", "96")]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let mut v: BTreeMap<String, String> = [("key", "256"), ("tag_bits", "128")]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let t = "AES-{key}-GCM[-{tag_bits}-{nonce_bits}]";
        v.insert("nonce_bits".into(), "96".into());
        assert_eq!(fill(t, &v, &d), "AES-256-GCM");
        v.insert("nonce_bits".into(), "128".into());
        assert_eq!(fill(t, &v, &d), "AES-256-GCM-128-128");
    }

    #[test]
    fn a_default_can_be_another_parameter() {
        let map = |kv: &[(&str, &str)]| -> BTreeMap<String, String> {
            kv.iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        };
        let d = map(&[("mgf_hash", "{hash}")]);
        let t = "RSA-OAEP-{hash}[-MGF1-{mgf_hash}]";
        let same = map(&[("hash", "SHA-256"), ("mgf_hash", "SHA-256")]);
        assert_eq!(fill(t, &same, &d), "RSA-OAEP-SHA-256");
        let other = map(&[("hash", "SHA-256"), ("mgf_hash", "SHA-1")]);
        assert_eq!(fill(t, &other, &d), "RSA-OAEP-SHA-256-MGF1-SHA-1");
        assert!(rcbom_kb::registry::valid(
            "RSA-OAEP-SHA-256-MGF1-SHA-1",
            "RSAES-OAEP"
        ));
    }
}

#[cfg(test)]
mod version_tests {
    use super::*;

    #[test]
    fn types_of_an_unsupported_crate_version_do_not_match() {
        let kb = Kb::seed().unwrap();
        let t = TyTree::Adt {
            krate: CrateRef {
                name: "sha2".into(),
                stable_id: "new".into(),
            },
            path: "sha2::block_api::Sha256VarCore".into(),
            args: vec![],
        };
        let none = |_: &CrateRef| false;
        assert!(match_types(&kb, &[t], &none).is_empty());
    }
}
