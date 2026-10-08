//! Provenance of key material: the knowledge base's roles say which argument of an API is a
//! key, nonce, salt...; the driver's origin tree says where that argument came from inside
//! the enclosing function; the knowledge base's sources classify it.

use std::collections::BTreeSet;

use rcbom_facts::{DefRef, Origin, Target, TyTree};
use rcbom_kb::Kb;

/// What a value was found to come from, with a short human-readable trace.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Class {
    /// `hard-coded`, `parameter`, `environment`, `file`, `rng`, `derived`, `computed`, `unknown`
    pub kind: String,
    pub detail: String,
}

/// The paths a call is known by, for matching roles: its defining path, without generic
/// arguments, and `<Self type>::<method>` (`x25519_dalek::x25519::StaticSecret::from` for
/// `<StaticSecret as From<[u8; 32]>>::from`).
pub fn call_paths(target: &Target) -> Vec<String> {
    let Target::Call {
        callee,
        method,
        self_ty,
        ..
    } = target
    else {
        return Vec::new();
    };
    let mut out = vec![strip_generics(&callee.path), callee.path.clone()];
    if let Some(TyTree::Adt { path, .. }) = self_ty {
        out.push(format!("{}::{method}", strip_generics(path)));
    }
    out
}

/// Key material arguments of a call, with the classes of their origins: (role, classes).
pub fn of_call(kb: &Kb, target: &Target) -> Vec<(String, BTreeSet<Class>)> {
    let Target::Call {
        arg_origins,
        arg_lens,
        ..
    } = target
    else {
        return Vec::new();
    };
    let paths = call_paths(target);
    let mut out = Vec::new();
    for r in kb
        .roles
        .iter()
        .filter(|r| paths.iter().any(|p| r.pattern.is_match(p)))
    {
        for (i, role) in &r.args {
            if let Some(o) = arg_origins.get(*i) {
                let mut classes = BTreeSet::new();
                classify(kb, o, 0, &mut classes);
                // a constant array or static passed directly, whose length the type gives
                if let Some(Some(n)) = arg_lens.get(*i)
                    && is_direct_data(o)
                {
                    classes = classes
                        .into_iter()
                        .map(|mut c| {
                            if c.kind == "hard-coded" && !c.detail.contains("bytes") {
                                c.detail = format!(
                                    "{n} bytes{}",
                                    if c.detail.is_empty() {
                                        String::new()
                                    } else {
                                        format!(", {}", c.detail)
                                    }
                                );
                            }
                            c
                        })
                        .collect();
                }
                out.push((role.clone(), classes));
            }
        }
    }
    out
}

/// The origin is the data itself (a constant or a static, possibly one of several), not
/// something computed from it.
fn is_direct_data(o: &Origin) -> bool {
    match o {
        Origin::Const { .. } | Origin::Data { .. } => true,
        Origin::Any(alts) => alts.iter().any(is_direct_data),
        _ => false,
    }
}

/// A static or const the knowledge base names as an algorithm (`[[static]]`), in any version
/// of its crate.
pub fn is_descriptor(kb: &Kb, def: &DefRef) -> bool {
    let name = last(&def.path);
    kb.statics
        .iter()
        .any(|e| e.krates.contains(&def.krate.name) && e.pattern.is_match(name))
}

fn matches(pattern: &regex::Regex, callee: &str, self_ty: Option<&str>) -> bool {
    let stripped = strip_generics(callee);
    pattern.is_match(&stripped)
        || pattern.is_match(callee)
        || self_ty.is_some_and(|t| pattern.is_match(&format!("{t}::{}", last(&stripped))))
}

fn classify(kb: &Kb, o: &Origin, depth: usize, out: &mut BTreeSet<Class>) {
    let class = |kind: &str, detail: String| Class {
        kind: kind.to_string(),
        detail,
    };
    if depth > 12 {
        out.insert(class("unknown", "too deep".into()));
        return;
    }
    match o {
        Origin::Const { len, span, .. } => {
            let mut d = Vec::new();
            if let Some(n) = len {
                d.push(format!("{n} bytes"));
            }
            if let Some(s) = span
                && s.line > 0
            {
                d.push(format!("literal at line {}", s.line));
            }
            out.insert(class("hard-coded", d.join(", ")));
        }
        // an algorithm descriptor (`&AES_256_GCM`, `HKDF_SHA256`) says which algorithm, not
        // what the key material is; any other static or const is data compiled in
        Origin::Data { def } if is_descriptor(kb, def) => {}
        Origin::Data { def } => {
            out.insert(class("hard-coded", format!("static {}", short(&def.path))));
        }
        Origin::Param { index } => {
            out.insert(class(
                "parameter",
                format!("argument {index} of the enclosing function"),
            ));
        }
        // a value of a field-less type: its type may be a source (`OsRng`)
        Origin::Unit { path, .. } => {
            if let Some(s) = kb.sources.iter().find(|s| s.pattern.is_match(path)) {
                out.insert(class(&s.kind, short(path)));
            }
        }
        Origin::Call {
            callee,
            krate,
            self_ty,
            args,
            ..
        } => {
            let path = strip_generics(callee);
            let self_ty = self_ty.as_deref();
            // a closure of this function, followed by the driver: its argument is what the
            // closure returns
            if callee == "<closure>" {
                for a in args {
                    classify(kb, a, depth + 1, out);
                }
                return;
            }
            if let Some(s) = kb
                .sources
                .iter()
                .find(|s| matches(&s.pattern, callee, self_ty))
            {
                // a generator built from a seed is as predictable as the seed
                if s.kind == "rng"
                    && let Some(seed) = args.first().and_then(|r| seeded(kb, r, 0))
                {
                    let mut inner = BTreeSet::new();
                    classify(kb, seed, depth + 1, &mut inner);
                    for c in inner {
                        out.insert(class(
                            &c.kind,
                            format!("seed of {}: {}", short(&path), c.detail),
                        ));
                    }
                    return;
                }
                out.insert(class(&s.kind, short(&path)));
            } else if kb.fns.iter().any(|f| {
                f.algo.primitive == "kdf"
                    && f.krates.contains(krate)
                    && f.pattern.is_match(last(&path))
            }) {
                out.insert(class("derived", short(&path)));
            } else if let Some(p) = kb
                .passthroughs
                .iter()
                .find(|p| matches(&p.pattern, callee, self_ty))
            {
                // the data arguments only: the value of `Engine::decode(&STANDARD, input)` is
                // `input`, of `result.context("message")` the result
                for i in &p.args {
                    if let Some(a) = args.get(*i) {
                        classify(kb, a, depth + 1, out);
                    }
                }
            } else if path.ends_with("::default::Default::default") && args.is_empty() {
                // `[u8; 32]::default()`, `GenericArray::default()`: a fixed value
                out.insert(class("hard-coded", "default value".into()));
            } else if args.is_empty() {
                // returned by code that takes nothing from here: an interprocedural question
                out.insert(class("computed", short(&path)));
            } else if matches!(krate.as_str(), "core" | "std" | "alloc") {
                // standard-library plumbing (`as_bytes`, `unwrap`, `into`): the value comes from
                // the receiver (`expect(msg)`, `ok_or(err)`, `map_err(f)`), except for the
                // fallbacks that can supply it from another argument instead
                // (`unwrap_or_else(|_| "literal")`): either one, so all of them count
                let receiver_only = !FALLBACKS.iter().any(|m| path.ends_with(m))
                    || INDEXING.iter().any(|m| path.ends_with(m));
                for a in args.iter().take(if receiver_only { 1 } else { args.len() }) {
                    classify(kb, a, depth + 1, out);
                }
            } else if kb.crate_by_name(krate).is_some() {
                // a crypto crate's constructor or computation (`Nonce::assume_unique_for_key`,
                // `UnboundKey::new(&AES_256_GCM, key)`, `SaltString::encode_b64`): a function of
                // its arguments only (generators are sources, matched above). Indexing takes its
                // data from the receiver (`&key[..32]`: the range is not key material).
                if INDEXING.iter().any(|m| path.ends_with(m)) {
                    classify(kb, &args[0], depth + 1, out);
                } else {
                    of_inputs(kb, args, depth, out);
                }
            } else {
                // any other function (the program's own `hkdf(key, LABEL, &[])`, a dependency
                // outside the knowledge base): what it returns is an interprocedural question
                out.insert(class("computed", short(&path)));
            }
        }
        Origin::Any(alts) => alts.iter().for_each(|a| classify(kb, a, depth + 1, out)),
        Origin::Truncated => {
            out.insert(class("unknown", "origin search bound reached".into()));
        }
        Origin::Unknown => {}
    }
}

/// The value of a function of several inputs: hard-coded only when every input can be (a
/// value computed from a parameter and a constant label varies with the parameter), and
/// otherwise whatever its varying inputs are. Inputs that carry no data (an algorithm
/// descriptor, a value of a field-less type that is no source) are left out; an input whose
/// origin is unknown keeps the value from being hard-coded.
fn of_inputs(kb: &Kb, args: &[Origin], depth: usize, out: &mut BTreeSet<Class>) {
    let mut constant = true;
    let mut hard_coded = BTreeSet::new();
    let mut varying = BTreeSet::new();
    let mut any = false;
    for a in args {
        let mut classes = BTreeSet::new();
        classify(kb, a, depth + 1, &mut classes);
        if classes.is_empty() {
            let no_data = matches!(a, Origin::Unit { .. })
                || matches!(a, Origin::Data { def } if is_descriptor(kb, def));
            constant &= no_data;
            continue;
        }
        any = true;
        constant &= classes.iter().any(|c| c.kind == "hard-coded");
        for c in classes {
            if c.kind == "hard-coded" {
                hard_coded.insert(c);
            } else {
                varying.insert(c);
            }
        }
    }
    if any && constant {
        out.extend(hard_coded);
    }
    out.extend(varying);
}

/// The seed of a generator built from one (`StdRng::seed_from_u64(42)`), looking through the
/// receiver chain (`&mut rng`).
fn seeded<'a>(kb: &Kb, o: &'a Origin, depth: usize) -> Option<&'a Origin> {
    if depth > 8 {
        return None;
    }
    match o {
        Origin::Call {
            callee,
            self_ty,
            args,
            ..
        } => {
            if kb
                .seeded
                .iter()
                .any(|s| matches(&s.pattern, callee, self_ty.as_deref()))
            {
                return args.first();
            }
            args.first().and_then(|a| seeded(kb, a, depth + 1))
        }
        Origin::Any(alts) => alts.iter().find_map(|a| seeded(kb, a, depth + 1)),
        _ => None,
    }
}

/// Algorithm descriptors a call names: its own arguments (`digest(&SHA256, msg)`,
/// `UnboundKey::new(&AES_256_GCM, key)`), and those its receiver was built from
/// (`key.seal_in_place_append_tag(..)` with `key` from `LessSafeKey::new(UnboundKey::new(
/// &AES_256_GCM, ..))`). Other arguments are data, not the algorithm: a buffer filled by
/// `digest(&SHA256, ..)` passed to `seal_in_place_append_tag` does not make the seal SHA-256.
/// Also returns, second, the other statics and consts in those places (the user's
/// `TABLE.alg`), whose descriptors the caller can look up.
pub fn data_in_args(kb: &Kb, target: &Target) -> (Vec<DefRef>, Vec<DefRef>) {
    let Target::Call { arg_origins, .. } = target else {
        return (Vec::new(), Vec::new());
    };
    let mut out = Vec::new();
    for o in arg_origins {
        direct_data(o, &mut out);
    }
    if let Some(r) = arg_origins.first() {
        receiver_data(r, 0, &mut out);
    }
    out.into_iter().partition(|d| is_descriptor(kb, d))
}

fn direct_data(o: &Origin, out: &mut Vec<DefRef>) {
    match o {
        Origin::Data { def } if !out.contains(def) => out.push(def.clone()),
        Origin::Any(alts) => alts.iter().for_each(|a| direct_data(a, out)),
        _ => {}
    }
}

/// Descriptors along the chain of calls that built a receiver: each call's own descriptor
/// arguments, then its own receiver.
fn receiver_data(o: &Origin, depth: usize, out: &mut Vec<DefRef>) {
    if depth > 8 {
        return;
    }
    match o {
        Origin::Call { args, .. } => {
            for a in args {
                direct_data(a, out);
            }
            if let Some(r) = args.first() {
                receiver_data(r, depth + 1, out);
            }
        }
        Origin::Any(alts) => alts.iter().for_each(|a| receiver_data(a, depth + 1, out)),
        _ => {}
    }
}

/// Standard-library calls whose result may come from an argument other than the receiver.
const FALLBACKS: &[&str] = &[
    "::unwrap_or",
    "::unwrap_or_else",
    "::or",
    "::or_else",
    "::map_or",
    "::map_or_else",
    "::get_or_insert",
    "::get_or_insert_with",
];

/// Calls whose result is part of their receiver.
const INDEXING: &[&str] = &[
    "Index::index",
    "IndexMut::index_mut",
    "::get",
    "::get_mut",
    "::split_at",
    "::first_chunk",
    "::chunks",
];

fn strip_generics(path: &str) -> String {
    let mut s = path.to_string();
    loop {
        let mut out = String::new();
        let mut depth = 0;
        let mut changed = false;
        for ch in s.chars() {
            match ch {
                '<' => {
                    depth += 1;
                    changed = true;
                }
                '>' if depth > 0 => depth -= 1,
                _ if depth == 0 => out.push(ch),
                _ => {}
            }
        }
        if !changed {
            return out.replace("::::", "::");
        }
        s = out.replace("::::", "::");
    }
}

fn last(path: &str) -> &str {
    path.rsplit("::").next().unwrap_or(path)
}

fn short(path: &str) -> String {
    let parts: Vec<&str> = path.split("::").collect();
    if parts.len() > 3 {
        parts[parts.len() - 3..].join("::")
    } else {
        path.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generics_are_stripped_from_paths() {
        assert_eq!(strip_generics("hkdf::Hkdf::<H, I>::new"), "hkdf::Hkdf::new");
        assert_eq!(strip_generics("<A as B<C>>::f"), "::f");
    }

    fn data(krate: &str, path: &str) -> Origin {
        Origin::Data {
            def: rcbom_facts::DefRef {
                krate: rcbom_facts::CrateRef {
                    name: krate.into(),
                    stable_id: "0".into(),
                },
                path: path.into(),
                id: "0".into(),
            },
        }
    }

    #[test]
    fn descriptors_are_not_key_material() {
        let kb = Kb::seed().unwrap();
        // `UnboundKey::new(&AES_256_GCM, key)` wrapped into a key object: the descriptor names
        // the algorithm, the key comes from the parameter
        let key = Origin::Call {
            callee: "ring::aead::UnboundKey::new".into(),
            krate: "ring".into(),
            self_ty: None,
            args: vec![
                data("ring", "ring::aead::AES_256_GCM"),
                Origin::Param { index: 0 },
            ],
            span: None,
        };
        let mut out = BTreeSet::new();
        classify(&kb, &key, 0, &mut out);
        let kinds: Vec<_> = out.iter().map(|c| c.kind.as_str()).collect();
        assert_eq!(kinds, ["parameter"]);
        // a static that is not a descriptor is data compiled in
        let mut out = BTreeSet::new();
        classify(&kb, &data("app", "app::MASTER_KEY"), 0, &mut out);
        let kinds: Vec<_> = out.iter().map(|c| c.kind.as_str()).collect();
        assert_eq!(kinds, ["hard-coded"]);
    }

    fn call(callee: &str, krate: &str, args: Vec<Origin>) -> Origin {
        Origin::Call {
            callee: callee.into(),
            krate: krate.into(),
            self_ty: None,
            args,
            span: None,
        }
    }

    fn lit() -> Origin {
        Origin::Const {
            value: None,
            len: Some(0),
            span: None,
        }
    }

    fn kinds(kb: &Kb, o: &Origin) -> Vec<String> {
        let mut out = BTreeSet::new();
        classify(kb, o, 0, &mut out);
        out.into_iter().map(|c| c.kind).collect()
    }

    #[test]
    fn computations_are_hard_coded_only_from_constants() {
        let kb = Kb::seed().unwrap();
        // a knowledge-base function of a parameter and a constant varies with the parameter
        let mixed = call(
            "ring::hkdf::Salt::new",
            "ring",
            vec![Origin::Param { index: 0 }, lit()],
        );
        assert_eq!(kinds(&kb, &mixed), ["parameter"]);
        // of constants only, it is a constant
        let constant = call(
            "ring::aead::Nonce::assume_unique_for_key",
            "ring",
            vec![lit()],
        );
        assert_eq!(kinds(&kb, &constant), ["hard-coded"]);
        // an input of unknown origin keeps it from being hard-coded
        let unknown = call(
            "ring::hkdf::Salt::new",
            "ring",
            vec![Origin::Unknown, lit()],
        );
        assert!(kinds(&kb, &unknown).is_empty());
        // age's own `hkdf(ssh_key, LABEL, &[])`: outside the knowledge base, computed
        let own = call(
            "age::primitives::hkdf",
            "age",
            vec![Origin::Param { index: 0 }, data("age", "age::LABEL"), lit()],
        );
        assert_eq!(kinds(&kb, &own), ["computed"]);
        // a closure of this function is looked through
        let closure = call("<closure>", "", vec![lit()]);
        assert_eq!(kinds(&kb, &closure), ["hard-coded"]);
        // standard-library fallbacks are alternatives: either supplies the value
        let fallback = call(
            "core::result::Result::<T, E>::unwrap_or",
            "core",
            vec![Origin::Param { index: 0 }, lit()],
        );
        assert_eq!(kinds(&kb, &fallback), ["hard-coded", "parameter"]);
    }
}
