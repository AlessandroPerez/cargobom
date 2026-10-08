//! Knowledge-base matching on structured facts.

use std::collections::{BTreeMap, BTreeSet};

use rcbom_facts::{CrateRef, DefRef, Origin, TyTree};
use rcbom_kb::{Algo, Kb, Param, ProtocolEntry, TypeEntry};

#[derive(Clone, Debug)]
pub struct Match {
    pub name: String,
    pub algo: Algo,
    pub params: BTreeMap<String, String>,
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
///   nonce).
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
            .any(|k| defaults.get(k).is_none_or(|d| vals.get(k) != Some(d)));
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

fn filled_algo(algo: &Algo, vals: &BTreeMap<String, String>) -> Algo {
    let mut a = algo.clone();
    let none = BTreeMap::new();
    let fill = |t: &str, v: &BTreeMap<String, String>| fill(t, v, &none);
    a.asset = self::fill(&algo.asset, vals, &algo.defaults);
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
            let algo = filled_algo(&e.algo, &vals);
            return Some(Match {
                name: algo.asset.clone(),
                params: BTreeMap::new(),
                algo,
                components: BTreeSet::new(),
                providers: BTreeSet::new(),
                provider_crates: Vec::new(),
            });
        }
    }
    None
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
    let prefix = format!("{}::", callee.krate.name);
    let path = callee.path.strip_prefix(&prefix).unwrap_or(&callee.path);
    let mut provider = None;
    let e = kb.fns.iter().find(|e| match &e.self_type {
        Some(st) => match self_ty {
            Some(TyTree::Adt {
                krate, path: tp, ..
            }) if e.krates.contains(&krate.name) && last(tp) == st && supported(krate) => {
                let ok = e.pattern.is_match(&callee.path);
                if ok {
                    provider = Some(krate.clone());
                }
                ok
            }
            _ => false,
        },
        None => {
            let ok = e.krates.contains(&callee.krate.name)
                && supported(&callee.krate)
                && e.pattern.is_match(path);
            if ok {
                provider = Some(callee.krate.clone());
            }
            ok
        }
    })?;
    Some(fn_entry_match(
        kb, e, args, const_args, arg_lens, provider, supported,
    ))
}

/// The asset of a `[[fn]]` entry, with its parameters from the call.
fn fn_entry_match(
    kb: &Kb,
    e: &rcbom_kb::PatternEntry,
    args: &[TyTree],
    const_args: &[Option<i128>],
    arg_lens: &[Option<u64>],
    provider: Option<CrateRef>,
    supported: Supported,
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
            _ => eval_param(kb, p, args, None, supported),
        };
        if let Some(v) = v {
            params.insert(k.clone(), v);
        }
    }
    let algo = filled_algo(&e.algo, &params);
    params.retain(|k, _| !e.algo.asset.contains(&format!("{{{k}}}")));
    if let Some(u) = &e.algo.unresolved {
        params.insert("unresolved".to_string(), u.clone());
    }
    Match {
        name: algo.asset.clone(),
        algo,
        params,
        components: BTreeSet::new(),
        providers: BTreeSet::new(),
        provider_crates: provider.into_iter().collect(),
    }
}

/// The constructor a receiver was built by, when a `[[fn]]` entry of the same family names
/// it: `argon2.hash_password(..)` with `argon2` from `Argon2::default()` is Argon2id-19456-2-1,
/// a `blake3::Hasher` from `Hasher::new_keyed(key)` a keyed hash. Follows the receiver chain
/// (`&mut x`, `x.unwrap()`).
pub fn match_constructor(kb: &Kb, family: &str, receiver: &Origin) -> Option<Match> {
    let mut cur = receiver;
    for _ in 0..8 {
        let Origin::Call {
            callee,
            krate,
            self_ty,
            args,
            ..
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
            let consts: Vec<Option<i128>> = args
                .iter()
                .map(|a| match a {
                    Origin::Const { value, .. } => *value,
                    _ => None,
                })
                .collect();
            return Some(fn_entry_match(kb, e, &[], &consts, &[], None, &|_| true));
        }
        cur = args.first()?;
    }
    None
}

fn strip_generics(path: &str) -> String {
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
            let entry = kb.types.iter().find(|e| {
                e.krate == krate.name
                    && e.name == last(path)
                    && e.module
                        .as_deref()
                        .is_none_or(|m| regex::Regex::new(m).is_ok_and(|r| r.is_match(within)))
                    && supported(krate)
            });
            if let Some(e) = entry {
                let mut m = type_match(kb, e, args, parent, supported);
                m.provider_crates = vec![krate.clone()];
                let name = m.name.clone();
                let idx = out.len();
                out.push((m, outer.map(str::to_string)));
                let before = out.len();
                // an argument read as a parameter (the `Aes256` of `AesGcm<Aes256, ..>`, a
                // nonce size) is part of this asset's name, not a component of its own
                let consumed: Vec<usize> = e
                    .params
                    .values()
                    .filter(|p| !p.asset && p.parent_arg.is_none())
                    .filter_map(|p| p.arg)
                    .collect();
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
) -> Match {
    let mut params = BTreeMap::new();
    for (k, p) in &e.params {
        if let Some(v) = eval_param(kb, p, args, parent, supported) {
            params.insert(k.clone(), v);
        }
    }
    let algo = filled_algo(&e.algo, &params);
    // parameters already spelled out in the name or the parameter set are not repeated
    params.retain(|k, _| {
        !e.algo.asset.contains(&format!("{{{k}}}"))
            && !e
                .algo
                .parameter_set
                .as_deref()
                .unwrap_or("")
                .contains(&format!("{{{k}}}"))
    });
    Match {
        name: algo.asset.clone(),
        algo,
        params,
        components: BTreeSet::new(),
        providers: BTreeSet::new(),
        provider_crates: Vec::new(),
    }
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
        asset_key(&self.name, &self.algo)
    }
}

pub fn asset_key(name: &str, algo: &Algo) -> String {
    format!(
        "{name}|{}|{}",
        algo.primitive,
        algo.material.as_deref().unwrap_or("")
    )
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
