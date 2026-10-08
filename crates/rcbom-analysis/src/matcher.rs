//! Knowledge-base matching on structured facts.

use std::collections::{BTreeMap, BTreeSet};

use rcbom_facts::{CrateRef, DefRef, TyTree};
use rcbom_kb::{Algo, Kb, Param, ProtocolEntry, TypeEntry};

#[derive(Clone, Debug)]
pub struct Match {
    pub name: String,
    pub algo: Algo,
    pub params: BTreeMap<String, String>,
    /// Assets found inside this one's generic arguments.
    pub components: BTreeSet<String>,
    pub providers: BTreeSet<(String, String)>,
    /// Crates of the providers, to be resolved to packages.
    pub provider_crates: Vec<CrateRef>,
}

fn last(path: &str) -> &str {
    path.rsplit("::").next().unwrap_or(path)
}

/// `{name}` placeholders from `vals`; a placeholder left unresolved drops its `-{..}` segment,
/// which the registry patterns treat as optional (`HMAC-{hash}` -> `HMAC`).
fn fill(template: &str, vals: &BTreeMap<String, String>) -> String {
    let mut s = template.to_string();
    for (k, v) in vals {
        s = s.replace(&format!("{{{k}}}"), v);
    }
    while let (Some(i), Some(j)) = (s.find('{'), s.find('}')) {
        if j < i {
            break;
        }
        let start = if s[..i].ends_with('-') { i - 1 } else { i };
        s.replace_range(start..=j, "");
    }
    s
}

fn filled_algo(algo: &Algo, vals: &BTreeMap<String, String>) -> Algo {
    let mut a = algo.clone();
    a.asset = fill(&algo.asset, vals);
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
    for e in kb
        .statics
        .iter()
        .filter(|e| e.krates.contains(&def.krate.name))
    {
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
    let mut params = BTreeMap::new();
    for (k, p) in &e.params {
        let v = match (p.const_arg, p.arg_len) {
            (Some(i), _) => const_args.get(i).copied().flatten().map(|v| v.to_string()),
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
    Some(Match {
        name: algo.asset.clone(),
        algo,
        params,
        components: BTreeSet::new(),
        providers: BTreeSet::new(),
        provider_crates: provider.into_iter().collect(),
    })
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
            let entry = kb
                .types
                .iter()
                .find(|e| e.krate == krate.name && e.name == last(path) && supported(krate));
            if let Some(e) = entry {
                let mut m = type_match(kb, e, args, parent, supported);
                m.provider_crates = vec![krate.clone()];
                let name = m.name.clone();
                let idx = out.len();
                out.push((m, outer.map(str::to_string)));
                let before = out.len();
                for a in args {
                    walk(
                        kb,
                        a,
                        Some(args),
                        Some(outer.unwrap_or(&name)),
                        supported,
                        out,
                    );
                }
                let inner: Vec<String> =
                    out[before..].iter().map(|(m, _)| m.name.clone()).collect();
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
    let t = match (p.arg, p.parent_arg) {
        (Some(i), _) => args.get(i)?,
        (None, Some(i)) => parent?.get(i)?,
        _ => return None,
    };
    if !p.map.is_empty() {
        return match t {
            TyTree::Adt { path, .. } => p.map.get(last(path)).cloned(),
            _ => None,
        };
    }
    if p.typenum {
        return typenum(t).map(|n| (n * p.scale.unwrap_or(1)).to_string());
    }
    if p.asset {
        return match_types(kb, std::slice::from_ref(t), supported)
            .into_iter()
            .next()
            .map(|(m, _)| m.name);
    }
    None
}

/// `UInt<UInt<UTerm, B1>, B0>` = 2; a const generic argument as is.
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
        assert!(m[0].0.components.contains("SHA-256"));
    }

    #[test]
    fn unresolved_placeholders_drop_their_segment() {
        let v = BTreeMap::new();
        assert_eq!(fill("HMAC-{hash}", &v), "HMAC");
        assert_eq!(fill("AES-{key}-GCM", &v), "AES-GCM");
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
