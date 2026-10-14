//! Provenance of key material: the knowledge base's roles say which argument of an API is a
//! key, nonce, salt...; the driver's origin tree says where that argument came from inside
//! the enclosing function; the knowledge base's sources classify it.

use std::collections::{BTreeSet, HashSet};

use rcbom_facts::{DefRef, Origin, Target, TyTree};
use rcbom_kb::Kb;

use crate::links::LinkIndex;

/// What a value was found to come from, with a short human-readable trace.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Class {
    /// `hard-coded`, `parameter`, `environment`, `file`, `rng`, `derived`, `computed`, `unknown`,
    /// `absent` (no material: empty, or a protocol's all-zero salt or input key)
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
/// The role of an argument that only gives an output length: neither key material nor the
/// algorithm.
const LENGTH: &str = "length";

/// The arguments of a call (by its callee's paths) that only give a length.
fn length_args(kb: &Kb, paths: &[String]) -> HashSet<usize> {
    kb.roles
        .iter()
        .filter(|r| paths.iter().any(|p| r.pattern.is_match(p)))
        .flat_map(|r| {
            r.args
                .iter()
                .filter(|(_, role)| *role == LENGTH)
                .map(|(i, _)| *i)
        })
        .collect()
}

///
/// `protocol`: the call is a protocol crate's (rustls's key schedule), where an all-zero salt
/// or input key is the protocol's own "none".
pub fn of_call(
    kb: &Kb,
    links: &LinkIndex,
    target: &Target,
    protocol: bool,
) -> Vec<(String, BTreeSet<Class>)> {
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
            // an output length (`Prk::expand`'s `len`) is not key material
            if role == LENGTH {
                continue;
            }
            if let Some(o) = arg_origins.get(*i) {
                let mut classes = BTreeSet::new();
                classify(kb, links, o, 0, &mut classes);
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
                // an all-zero salt or input key is what a protocol puts where it has none (TLS 1.3's
                // key schedule: HKDF-Extract of zeros, RFC 8446 7.1; HKDF's default salt, RFC
                // 5869): no material, not a hard-coded secret. An all-zero key is a hard-coded one,
                // and so is the program's own all-zero input (a derived key that depends on
                // nothing secret)
                if protocol && matches!(role.as_str(), "salt" | "ikm") {
                    classes = classes
                        .into_iter()
                        .map(|c| {
                            if c.kind == "hard-coded" && c.detail.starts_with("all zero") {
                                Class {
                                    kind: "absent".into(),
                                    detail: c.detail,
                                }
                            } else {
                                c
                            }
                        })
                        .collect();
                }
                out.push((role.clone(), classes));
            }
        }
    }
    // a value of the program's type the library asks for data (`SealingKey::new(key, seq)`:
    // each nonce is what the program's `NonceSequence::advance` returns)
    let Target::Call { self_ty, args, .. } = target else {
        return out;
    };
    for p in kb
        .produces
        .iter()
        .filter(|p| paths.iter().any(|x| p.pattern.is_match(x)))
    {
        let mut tys = Vec::new();
        for t in self_ty.iter().chain(args) {
            adt_paths(t, &mut tys);
        }
        let mut classes = BTreeSet::new();
        for ty in tys {
            for v in links.impl_returns(&p.method, &ty) {
                classify(kb, links, &v, 0, &mut classes);
            }
        }
        if classes.is_empty() {
            continue;
        }
        match out.iter_mut().find(|(r, _)| *r == p.role) {
            Some((_, c)) => c.extend(classes),
            None => out.push((p.role.clone(), classes)),
        }
    }
    out
}

/// The paths of the types a type tree names (`SealingKey<Fixed>`: both).
fn adt_paths(t: &TyTree, out: &mut Vec<String>) {
    match t {
        TyTree::Adt { path, args, .. } => {
            out.push(strip_generics(path));
            args.iter().for_each(|a| adt_paths(a, out));
        }
        TyTree::Ref(t) | TyTree::Slice(t) | TyTree::Array(t, _) => adt_paths(t, out),
        TyTree::Tuple(ts) => ts.iter().for_each(|a| adt_paths(a, out)),
        _ => {}
    }
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

fn classify(kb: &Kb, links: &LinkIndex, o: &Origin, depth: usize, out: &mut BTreeSet<Class>) {
    let class = |kind: &str, detail: String| Class {
        kind: kind.to_string(),
        detail,
    };
    if depth > 12 {
        out.insert(class("unknown", "too deep".into()));
        return;
    }
    match o {
        // no data at all (`""`, `&[]`): nothing is hard-coded
        Origin::Const { len: Some(0), .. } => {
            out.insert(class("absent", "empty".into()));
        }
        Origin::Const {
            len, span, zero, ..
        } => {
            let mut d = Vec::new();
            if *zero {
                d.push("all zero".to_string());
            }
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
        Origin::Data { def, .. } if is_descriptor(kb, def) => {}
        // a static whose contents change at run time (`LazyLock`, `OnceLock`, `static mut`, a
        // lock, an atomic): what its initializer or the writes to it put there
        Origin::Data { def, .. } if let Some(values) = links.mutable_static(&def.id) => {
            if values.is_empty() {
                out.insert(class(
                    "computed",
                    format!("run-time contents of static {}", short(&def.path)),
                ));
            }
            for v in values {
                classify(kb, links, v, depth + 1, out);
            }
        }
        Origin::Data { def, zero, .. } => {
            out.insert(class(
                "hard-coded",
                format!(
                    "{}static {}",
                    if *zero { "all zero, " } else { "" },
                    short(&def.path)
                ),
            ));
        }
        // a field of a value a method wrote or fields were written into: what is in that field
        // (`self.key` after a method replaced it, not the counter beside it); of any other
        // value, as for that value (a parameter's field is the parameter's)
        Origin::Field {
            adt, field, base, ..
        } => match links.field_parts(crate::links::peel(base), adt, *field) {
            Some(parts) => parts
                .iter()
                .for_each(|p| classify(kb, links, p, depth + 1, out)),
            None => classify(kb, links, base, depth + 1, out),
        },
        Origin::Param { index, owner } => {
            out.insert(class(
                "parameter",
                match owner {
                    Some(f) => format!("argument {index} of {}", short(f)),
                    None => format!("argument {index} of the enclosing function"),
                },
            ));
        }
        // a value of a field-less type: its type may be a source (`OsRng`)
        Origin::Unit { path, .. } => {
            if let Some(s) = kb.sources.iter().find(|s| s.pattern.is_match(path)) {
                out.insert(class(&s.kind, short(path)));
            }
        }
        // `opt.unwrap_or_default()`: the value, or the type's default, which the driver gives as a
        // constant when it is data (zeros), not when it is empty
        Origin::Call {
            callee,
            krate,
            args,
            ..
        } if matches!(krate.as_str(), "core" | "std" | "alloc")
            && callee.ends_with("::unwrap_or_default") =>
        {
            args.iter()
                .for_each(|a| classify(kb, links, a, depth + 1, out));
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
                    classify(kb, links, a, depth + 1, out);
                }
                return;
            }
            // a generator's method on the program's own type (its own `RngCore` impl) is that
            // type's code, not a known source
            let own_type = self_ty.is_some_and(|t| {
                let k = t.split("::").next().unwrap_or("");
                !matches!(k, "core" | "std" | "alloc") && kb.crate_by_name(k).is_none()
            });
            if own_type
                && kb
                    .sources
                    .iter()
                    .any(|s| matches(&s.pattern, callee, self_ty))
            {
                out.insert(class(
                    "computed",
                    format!("{}::{}", short(self_ty.unwrap_or("")), last(&path)),
                ));
                return;
            }
            if let Some(s) = kb
                .sources
                .iter()
                .filter(|_| !own_type)
                .find(|s| matches(&s.pattern, callee, self_ty))
            {
                // a generator built from a seed is as predictable as the seed
                if s.kind == "rng"
                    && let Some(seed) = args.first().and_then(|r| seeded(kb, r, 0))
                {
                    let mut inner = BTreeSet::new();
                    classify(kb, links, seed, depth + 1, &mut inner);
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
                // as `[[fn]]` entries match: the path inside the crate (`Hasher::new_derive_key`)
                let within = path.strip_prefix(&format!("{krate}::")).unwrap_or(&path);
                f.algo.primitive == "kdf"
                    && f.krates.contains(krate)
                    && (f.pattern.is_match(within) || f.pattern.is_match(last(&path)))
            }) {
                out.insert(class("derived", short(&path)));
            } else if let Some(p) = kb
                .passthroughs
                .iter()
                .find(|p| matches(&p.pattern, callee, self_ty))
            {
                // the data arguments only: the value of `Engine::decode(&STANDARD, input)` is
                // `input`, of `result.context("message")` the result; of `key.push_str(s)`
                // both, together (hard-coded only if both are)
                let data: Vec<Origin> = p
                    .args
                    .iter()
                    .filter_map(|i| args.get(*i).cloned())
                    .collect();
                if data.len() > 1 {
                    of_inputs(kb, links, &data, depth, out);
                } else {
                    data.iter()
                        .for_each(|a| classify(kb, links, a, depth + 1, out));
                }
            } else if path.ends_with("::default::Default::default") && args.is_empty() {
                // `[u8; 32]::default()`, `GenericArray::default()`, a crypto type's default: a
                // fixed value; the program's own type (or another crate's) may compute it
                // (`Config::default()` reading the environment): an interprocedural question
                let ty_crate = self_ty.and_then(|t| t.split("::").next());
                let fixed = ty_crate.is_none_or(|k| {
                    matches!(k, "core" | "std" | "alloc" | "generic_array")
                        || kb.crate_by_name(k).is_some()
                });
                if fixed {
                    out.insert(class("hard-coded", "default value".into()));
                } else {
                    out.insert(class(
                        "computed",
                        format!("{}::default", short(self_ty.unwrap_or(&path))),
                    ));
                }
            } else if args.is_empty() && kb.crate_by_name(krate).is_some() && last(&path) == "new" {
                // a crypto type's fresh state (`Sha256::new()`, `blake3::Hasher::new()`): fixed,
                // so what is fed into it decides (`Sha256::new().chain_update(secret)` is the
                // secret's)
                out.insert(class(
                    "hard-coded",
                    format!("initial state, {}", short(self_ty.unwrap_or(&path))),
                ));
            } else if empty_container(o) {
                // an empty `String` or `Vec` (`String::new()` before `push_str`): no data
            } else if args.is_empty() {
                // returned by code that takes nothing from here: an interprocedural question
                out.insert(class("computed", short(&path)));
            } else if matches!(krate.as_str(), "core" | "std" | "alloc") && GUARDED.is_match(&path)
            {
                // what a lock or a cell holds now: whatever was written through its guards
                // since (`*key.lock().unwrap()` filled by `fill_bytes`), not followed
                out.insert(class("computed", format!("contents of {}", short(&path))));
            } else if matches!(krate.as_str(), "core" | "std" | "alloc") {
                if INDEXING.iter().any(|m| path.ends_with(m)) {
                    // part of the receiver: `&key[..32]` (the range is not key material), of a
                    // length of its own (`&zeroes[..32]` is not the 64 bytes of `zeroes`); all
                    // of it with `[..]`
                    let mut inner = BTreeSet::new();
                    classify(kb, links, &args[0], depth + 1, &mut inner);
                    if whole_range(args.get(1)) {
                        out.extend(inner);
                    } else {
                        out.extend(inner.into_iter().map(without_length));
                    }
                } else if REPEATING.iter().any(|m| path.ends_with(m)) {
                    // copies of the element: `vec![0; n]` (the length is not data, nor is the
                    // element's own)
                    let mut inner = BTreeSet::new();
                    classify(kb, links, &args[0], depth + 1, &mut inner);
                    out.extend(inner.into_iter().map(without_length));
                } else if ERROR_ARGS.iter().any(|m| path.ends_with(m)) {
                    // the value is the receiver: `expect(msg)`, `ok_or(err)`, `map_err(f)` (the
                    // other argument is what an error carries)
                    classify(kb, links, &args[0], depth + 1, out);
                } else if FALLBACKS.iter().any(|m| path.ends_with(m)) {
                    // the receiver, or what the fallback supplies instead
                    // (`unwrap_or_else(|_| "literal")`): either one
                    for a in args {
                        classify(kb, links, a, depth + 1, out);
                    }
                } else {
                    // anything else computes its result from all its inputs
                    // (`b"..".iter().chain(secret.iter())`, `1_000u64.wrapping_add(seq)`,
                    // `u64::from_str_radix(s, 16)`): hard-coded only if all of them are
                    of_inputs(kb, links, args, depth, out);
                }
            } else if kb.crate_by_name(krate).is_some() {
                // a crypto crate's constructor or computation (`Nonce::assume_unique_for_key`,
                // `UnboundKey::new(&AES_256_GCM, key)`, `SaltString::encode_b64`): a function of
                // its arguments only (generators are sources, matched above). Indexing takes its
                // data from the receiver (`&key[..32]`: the range is not key material).
                if INDEXING.iter().any(|m| path.ends_with(m)) {
                    let mut inner = BTreeSet::new();
                    classify(kb, links, &args[0], depth + 1, &mut inner);
                    if whole_range(args.get(1)) {
                        out.extend(inner);
                    } else {
                        out.extend(inner.into_iter().map(without_length));
                    }
                } else {
                    of_inputs(kb, links, args, depth, out);
                }
            } else {
                // any other function (the program's own `hkdf(key, LABEL, &[])`, a dependency
                // outside the knowledge base): what it returns is an interprocedural question
                out.insert(class("computed", short(&path)));
            }
        }
        // what a function of the program writes through a parameter (`set_key(&mut c.key)`):
        // the values it writes, with the call's arguments for its parameters
        Origin::Written { callee, .. } => match links.values(o, "") {
            Some(vs) if !vs.is_empty() => vs
                .iter()
                .for_each(|(v, _)| classify(kb, links, v, depth + 1, out)),
            _ => {
                out.insert(class(
                    "computed",
                    format!("written by {}", short(&strip_generics(callee))),
                ));
            }
        },
        // written through a borrow the call returned (`key.chunks_mut(16)`, `split_at_mut`):
        // what was written is not followed
        Origin::Through { callee } => {
            out.insert(class(
                "computed",
                format!("written through {}", short(&strip_generics(callee))),
            ));
        }
        // a value updated from its own earlier value (`ctr += 1`): a counter, whose constant
        // alternatives are only where it starts
        Origin::Any(alts) if alts.iter().any(recurs) => {
            let mut inner = BTreeSet::new();
            alts.iter()
                .for_each(|a| classify(kb, links, a, depth + 1, &mut inner));
            out.extend(inner.into_iter().filter(|c| c.kind != "hard-coded"));
            out.insert(class(
                "computed",
                "changes with each iteration of a loop".into(),
            ));
        }
        Origin::Any(alts) => alts
            .iter()
            .for_each(|a| classify(kb, links, a, depth + 1, out)),
        Origin::Loop => {
            out.insert(class(
                "computed",
                "changes with each iteration of a loop".into(),
            ));
        }
        // built from all of these parts (`[user, b"pepper"].concat()`, `key[31] = 1` after the
        // key was read from the environment): a constant only if every part is
        Origin::All(parts) => of_inputs(kb, links, parts, depth, out),
        // a field written into the value: what was written
        Origin::Set { value, .. } => classify(kb, links, value, depth, out),
        Origin::Truncated => {
            out.insert(class("unknown", "origin search bound reached".into()));
        }
        Origin::Unknown => {}
    }
}

/// The index `..`: all of the value.
fn whole_range(o: Option<&Origin>) -> bool {
    matches!(o, Some(Origin::Unit { path, .. }) if path.ends_with("RangeFull"))
}

/// A class of a part of the value: the whole's byte count (`hard-coded (64 bytes, literal at
/// line 263)`) is not the part's.
fn without_length(c: Class) -> Class {
    let detail = c
        .detail
        .split(", ")
        .filter(|d| !d.ends_with(" bytes"))
        .collect::<Vec<_>>()
        .join(", ");
    Class { detail, ..c }
}

/// A new, empty `String` or `Vec` (`String::new()`, `Vec::with_capacity(32)`): it holds no data
/// until something is put in it.
fn empty_container(o: &Origin) -> bool {
    matches!(o, Origin::Call { callee, krate, .. }
        if matches!(krate.as_str(), "core" | "std" | "alloc")
            && [
                "String::new",
                "String::with_capacity",
                "Vec::new",
                "Vec::with_capacity",
                "VecDeque::new",
                "VecDeque::with_capacity",
                "HashMap::new",
                "HashMap::with_capacity",
                "BTreeMap::new",
                "HashSet::new",
                "HashSet::with_capacity",
                "BTreeSet::new",
            ]
            .iter()
            .any(|m| strip_generics(callee).ends_with(m)))
}

/// Does the value depend on its own earlier value (a loop's `Origin::Loop` inside it)?
fn recurs(o: &Origin) -> bool {
    match o {
        Origin::Loop => true,
        Origin::Any(v) | Origin::All(v) => v.iter().any(recurs),
        Origin::Set { value, .. } => recurs(value),
        Origin::Call { args, .. } => args.iter().any(recurs),
        Origin::Field { base, .. } => recurs(base),
        _ => false,
    }
}

/// The value of a function of several inputs: hard-coded only when every input can be (a
/// value computed from a parameter and a constant label varies with the parameter), and
/// otherwise whatever its varying inputs are. Inputs that carry no data (an algorithm
/// descriptor, a value of a field-less type that is no source) are left out; an input whose
/// origin is unknown keeps the value from being hard-coded.
fn of_inputs(kb: &Kb, links: &LinkIndex, args: &[Origin], depth: usize, out: &mut BTreeSet<Class>) {
    let mut constant = true;
    let mut hard_coded = BTreeSet::new();
    let mut varying = BTreeSet::new();
    let mut any = false;
    for a in args {
        let mut classes = BTreeSet::new();
        classify(kb, links, a, depth + 1, &mut classes);
        if classes.is_empty() {
            let no_data = matches!(a, Origin::Unit { .. })
                || matches!(a, Origin::Data { def, .. } if is_descriptor(kb, def))
                || empty_container(a);
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
        Origin::Any(alts) | Origin::All(alts) => alts.iter().find_map(|a| seeded(kb, a, depth + 1)),
        Origin::Set { value, .. } => seeded(kb, value, depth + 1),
        _ => None,
    }
}

/// Algorithm descriptors a call names, in two places to try in turn: its own arguments
/// (`digest(&SHA256, msg)`, `UnboundKey::new(&AES_256_GCM, key)`), then those its receiver was
/// built from (`key.seal_in_place_append_tag(..)` with `key` from `LessSafeKey::new(
/// UnboundKey::new(&AES_256_GCM, ..))`). The receiver's are for a call whose own say nothing
/// of it: `prk.expand(&[info], &AES_256_GCM)` is an HKDF use, of the `HKDF_SHA256` `prk` was
/// built with. Other arguments are data, not the algorithm: a buffer filled by
/// `digest(&SHA256, ..)` passed to `seal_in_place_append_tag` does not make the seal SHA-256.
/// Each place also gives, second, the other statics and consts in it (the user's
/// `TABLE.alg`), whose descriptors the caller can look up.
///
/// With `links` (the index and the defining path of the function the call is in), values from
/// other functions are followed too: a field the key or algorithm is read from holds what the
/// crate stores there, a parameter what callers pass, a call of the program's own function what
/// it returns (`self.inner.sign(..)`, rustls's record keys).
pub fn data_in_args(
    kb: &Kb,
    links: Option<(&LinkIndex, &str)>,
    target: &Target,
) -> [(Vec<DefRef>, Vec<DefRef>); 2] {
    let Target::Call { arg_origins, .. } = target else {
        return Default::default();
    };
    let mut seen = HashSet::new();
    let mut own = Vec::new();
    // an argument that only gives a length names no algorithm (`prk.expand(info,
    // hkdf::HKDF_SHA256)` expands with the PRK's algorithm; the descriptor is its output length)
    let lengths = length_args(kb, &call_paths(target));
    for (i, o) in arg_origins.iter().enumerate() {
        if !lengths.contains(&i) {
            direct_data(kb, links, o, 0, &mut own, &mut seen);
        }
    }
    let mut chain = Vec::new();
    let hkdf_use =
        !lengths.is_empty() || matches!(target, Target::Call { method, .. } if method == "fill");
    if let Some(r) = arg_origins.first() {
        receiver_data(kb, links, r, 0, &mut chain, &mut seen, hkdf_use);
    }
    chain.retain(|d| !own.contains(d));
    [own, chain].map(|v| v.into_iter().partition(|d| is_descriptor(kb, d)))
}

/// Is what the call's own arguments name an incomplete answer: an argument (or the receiver
/// chain) where a descriptor is named in the function has other alternatives that come from
/// elsewhere (`if n > 1 { &SHA256 } else { pick() }`, a parameter, a field, what a function of
/// the program writes through `&mut`)? Then the values from other functions are looked up too.
pub fn incomplete(kb: &Kb, target: &Target) -> bool {
    let Target::Call { arg_origins, .. } = target else {
        return false;
    };
    let lengths = length_args(kb, &call_paths(target));
    let named = |o: &Origin| {
        let mut here = Vec::new();
        direct_data(kb, None, o, 0, &mut here, &mut HashSet::new());
        here.iter().any(|d| is_descriptor(kb, d))
    };
    let own = arg_origins
        .iter()
        .enumerate()
        .filter(|(i, _)| !lengths.contains(i))
        .any(|(_, o)| named(o) && elsewhere_direct(kb, o, 0));
    own || arg_origins.first().is_some_and(|r| {
        let mut chain = Vec::new();
        receiver_data(kb, None, r, 0, &mut chain, &mut HashSet::new(), false);
        chain.iter().any(|d| is_descriptor(kb, d)) && elsewhere_receiver(kb, r, 0)
    })
}

/// Does `direct_data`'s local search of `o` pass a value from elsewhere it cannot follow?
fn elsewhere_direct(kb: &Kb, o: &Origin, depth: usize) -> bool {
    if depth > 6 {
        return false;
    }
    let o = crate::links::peel(o);
    match o {
        Origin::Data { .. } => false,
        Origin::Call { callee, args, .. } if callee == "<closure>" => {
            args.iter().any(|a| elsewhere_direct(kb, a, depth + 1))
        }
        Origin::Any(alts) | Origin::All(alts) => {
            alts.iter().any(|a| elsewhere_direct(kb, a, depth + 1))
        }
        Origin::Set { value, .. } => elsewhere_direct(kb, value, depth + 1),
        Origin::Field { .. } if static_root(o).is_some() => false,
        _ => from_elsewhere(kb, None, o),
    }
}

/// Does `receiver_data`'s local search of `o` pass a value from elsewhere it cannot follow?
fn elsewhere_receiver(kb: &Kb, o: &Origin, depth: usize) -> bool {
    if depth > 8 {
        return false;
    }
    if from_elsewhere(kb, None, o) {
        return true;
    }
    match o {
        Origin::Call { args, .. } => args
            .iter()
            .any(|a| elsewhere_direct(kb, a, 0) || elsewhere_receiver(kb, a, depth + 1)),
        Origin::Any(alts) | Origin::All(alts) => {
            alts.iter().any(|a| elsewhere_receiver(kb, a, depth + 1))
        }
        Origin::Set { value, .. } => elsewhere_receiver(kb, value, depth + 1),
        _ => false,
    }
}

/// A value that comes from outside the function: a field read, a parameter, or a call of a
/// function whose code is analysed (not the standard library's, nor an algorithm or trait
/// crate's: a protocol crate's, rustls's, is).
fn from_elsewhere(kb: &Kb, ix: Option<&LinkIndex>, o: &Origin) -> bool {
    match crate::links::peel_ix(ix, o) {
        Origin::Field { .. } | Origin::Param { .. } | Origin::Written { .. } => true,
        c @ Origin::Call { .. } if ix.is_some_and(|ix| ix.own_impl(c)) => true,
        Origin::Call { krate, .. } => {
            !matches!(krate.as_str(), "core" | "std" | "alloc")
                && kb
                    .crate_by_name(krate)
                    .is_none_or(|c| c.role == rcbom_kb::Role::Protocol)
        }
        _ => false,
    }
}

/// The lookups made for one question, by search (`direct_data` or `receiver_data`): a value
/// is followed once in each.
type Seen = HashSet<(bool, Origin, String)>;

/// The values from elsewhere `o`, read in `owner`, can be, once per question and search
/// (`seen`, `receiver`): each read in its own function, whose fields and parameters it names.
fn elsewhere(
    ix: &LinkIndex,
    o: &Origin,
    owner: &str,
    receiver: bool,
    seen: &mut Seen,
) -> Vec<(Origin, String, crate::links::Via)> {
    if !seen.insert((receiver, o.clone(), owner.to_string())) {
        return Vec::new();
    }
    ix.values_via(o, owner).unwrap_or_default()
}

fn direct_data(
    kb: &Kb,
    links: Option<(&LinkIndex, &str)>,
    o: &Origin,
    depth: usize,
    out: &mut Vec<DefRef>,
    seen: &mut Seen,
) {
    if depth > 6 {
        return;
    }
    // a static that changes at run time, also behind std wrappers (`*LAZY`,
    // `ONCE.get().unwrap()`): what the program puts there (`ONCE.set(&SHA512)`, `ALG2 =
    // &SHA1`, its initial value), looked up with the values from elsewhere
    if let Origin::Data { def, .. } = crate::links::peel_ix(links.map(|(ix, _)| ix), o)
        && let Some((ix, _)) = links
        && let Some(values) = ix.mutable_static(&def.id)
    {
        let values = values.to_vec();
        let key = Origin::Data {
            def: def.clone(),
            value: None,
            zero: false,
        };
        if seen.insert((false, key, String::new())) {
            for v in &values {
                direct_data(kb, Some((ix, "")), v, depth + 1, out, seen);
            }
        }
        return;
    }
    // (through std wrappers: `RwLock::new(&SHA256)`)
    let o = crate::links::peel_ix(links.map(|(ix, _)| ix), o);
    match o {
        Origin::Data { def, .. } => {
            if let Some((ix, owner)) = links {
                ix.note(&def.id, owner);
            }
            if !out.contains(def) {
                out.push(def.clone());
            }
        }
        // what a `LazyLock`'s closure returns
        Origin::Call { callee, args, .. } if callee == "<closure>" => args
            .iter()
            .for_each(|a| direct_data(kb, links, a, depth + 1, out, seen)),
        Origin::Any(alts) | Origin::All(alts) => alts
            .iter()
            .for_each(|a| direct_data(kb, links, a, depth + 1, out, seen)),
        Origin::Set { value, .. } => direct_data(kb, links, value, depth + 1, out, seen),
        // a field of a static (`TABLE.alg`): the static, whose own data says which descriptor
        // (`TABLE.alg = &SHA256`), not what every value of its type holds there
        Origin::Field { .. } if let Some(def) = static_root(o) => {
            if let Some((ix, _)) = links {
                ix.note(&def.id, "");
            }
            if !out.contains(def) {
                out.push(def.clone());
            }
        }
        _ if from_elsewhere(kb, links.map(|(ix, _)| ix), o) => {
            if let Some((ix, owner)) = links {
                // a value from elsewhere, read in its own function: what it names there is
                // followed too (a key pair stored by `start`, built from `self.alg`)
                for (v, w, by) in elsewhere(ix, o, owner, false, seen) {
                    ix.with_via(ix.current_via().then(by), || {
                        direct_data(kb, Some((ix, &w)), &v, depth + 1, out, seen)
                    });
                }
            }
        }
        _ => {}
    }
}

/// A standard-library call that stores a value in a container (`Vec::push`, `HashMap::insert`).
pub(crate) fn container_store(callee: &str) -> bool {
    const STORES: &[&str] = &[
        "Vec::push",
        "Vec::insert",
        "VecDeque::push_back",
        "VecDeque::push_front",
        "VecDeque::insert",
        "HashMap::insert",
        "BTreeMap::insert",
        "HashSet::insert",
        "BTreeSet::insert",
        "Extend::extend",
    ];
    let bare = strip_generics(callee);
    (bare.starts_with("alloc::") || bare.starts_with("std::") || bare.starts_with("core::"))
        && STORES.iter().any(|s| bare.ends_with(s))
}

/// The static a field read reads from (`TABLE.inner.alg`).
fn static_root(o: &Origin) -> Option<&DefRef> {
    match crate::links::peel(o) {
        Origin::Field { base, .. } => static_root(base),
        Origin::Data { def, .. } => Some(def),
        _ => None,
    }
}

/// Descriptors along the chain of calls that built a receiver: each call's own descriptor
/// arguments, then its own receiver, down to the first call that names a descriptor. That one
/// says what the value is (`prk.expand(&[info], &AES_256_GCM)` makes an AES-256-GCM key);
/// what built its own receiver (`Salt::new(HKDF_SHA256, ..)`) is another algorithm's.
/// `lengths`: the descriptors only given as an output length along the chain (`expand(info,
/// HKDF_SHA256)`) are skipped, for an operation of the HKDF itself (`Okm::fill`); a key made
/// from the output (`UnboundKey::from(okm)`) is of that length's algorithm.
fn receiver_data(
    kb: &Kb,
    links: Option<(&LinkIndex, &str)>,
    o: &Origin,
    depth: usize,
    out: &mut Vec<DefRef>,
    seen: &mut Seen,
    lengths: bool,
) {
    if depth > 8 {
        return;
    }
    // a key kept in a static that changes at run time (`KEY.get().unwrap().seal_in_place(..)`):
    // the chains of the values put there
    if let Origin::Data { def, .. } = crate::links::peel_ix(links.map(|(ix, _)| ix), o)
        && let Some((ix, _)) = links
        && let Some(values) = ix.mutable_static(&def.id)
    {
        let values = values.to_vec();
        let key = Origin::Data {
            def: def.clone(),
            value: None,
            zero: false,
        };
        if seen.insert((true, key, String::new())) {
            for v in &values {
                receiver_data(kb, Some((ix, "")), v, depth + 1, out, seen, lengths);
            }
        }
        return;
    }
    // a receiver from another function (a field, a parameter, the program's own constructor):
    // the chains of the values that reach it
    if from_elsewhere(kb, links.map(|(ix, _)| ix), o)
        && let Some((ix, owner)) = links
    {
        for (v, w, by) in elsewhere(ix, o, owner, true, seen) {
            if !from_elsewhere(kb, Some(ix), &v) {
                ix.with_via(ix.current_via().then(by), || {
                    receiver_data(kb, Some((ix, &w)), &v, depth + 1, out, seen, lengths)
                });
            }
        }
        return;
    }
    match o {
        // a container built by stores (`v.push(&SHA256); v.push(&SHA512)`, `m.insert(k, key)`):
        // a read of it is any value stored (flow-insensitive), so every stored value's chain
        // and the container's earlier stores are followed
        Origin::Call { args, callee, .. } if container_store(callee) => {
            for a in args.iter().skip(1) {
                // a descriptor stored itself (`v.push(&SHA256)`), or a value built from one
                let mut here = Vec::new();
                direct_data(kb, links, a, 0, &mut here, seen);
                for d in here {
                    if !out.contains(&d) {
                        out.push(d);
                    }
                }
                receiver_data(kb, links, a, depth + 1, out, seen, lengths);
            }
            if let Some(c) = args.first() {
                receiver_data(kb, links, c, depth + 1, out, seen, lengths);
            }
        }
        Origin::Call { args, callee, .. } => {
            let mut here = Vec::new();
            let skip = if lengths {
                length_args(kb, &[strip_generics(callee), callee.clone()])
            } else {
                HashSet::new()
            };
            for (i, a) in args.iter().enumerate() {
                if !skip.contains(&i) {
                    direct_data(kb, links, a, 0, &mut here, seen);
                }
            }
            let named = here.iter().any(|d| is_descriptor(kb, d));
            for d in here {
                if !out.contains(&d) {
                    out.push(d);
                }
            }
            if !named && let Some(r) = args.first() {
                receiver_data(kb, links, r, depth + 1, out, seen, lengths);
            }
        }
        Origin::Any(alts) | Origin::All(alts) => alts
            .iter()
            .for_each(|a| receiver_data(kb, links, a, depth + 1, out, seen, lengths)),
        Origin::Set { value, .. } => receiver_data(kb, links, value, depth + 1, out, seen, lengths),
        _ => {}
    }
}

/// Access to what a lock, a cell or an atomic holds (`Mutex::lock`, `RefCell::borrow_mut`,
/// `Cell::get`, `AtomicU64::fetch_add`): a value that may have been written through a guard or
/// a shared reference elsewhere (`c.set(fresh)`), or a counter.
static GUARDED: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(
        r"::(Mutex|RwLock|RefCell|ReentrantLock)::(lock|try_lock|read|try_read|write|try_write|borrow|borrow_mut|try_borrow|try_borrow_mut|take|replace|replace_with)$|::(Cell|OnceCell)::(get|take|replace|into_inner)$|::Atomic\w*::(load|swap|fetch_\w+|compare_exchange\w*|into_inner)$",
    )
    .unwrap()
});

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

/// Standard-library calls whose other arguments are what an error carries, not the value.
const ERROR_ARGS: &[&str] = &[
    "::ok_or",
    "::ok_or_else",
    "::map_err",
    "::expect",
    "::expect_err",
    "::inspect",
    "::inspect_err",
];

/// Calls whose result is part of their receiver.
const INDEXING: &[&str] = &[
    "Index::index",
    "IndexMut::index_mut",
    "::get",
    "::get_mut",
    "::split_at",
    "::split_at_mut",
    "::split_first",
    "::split_first_mut",
    "::split_last",
    "::split_last_mut",
    "::first_chunk",
    "::first_chunk_mut",
    "::chunks",
    "::chunks_mut",
    "::chunks_exact",
    "::chunks_exact_mut",
];

/// Calls whose result is copies of their first argument: `vec![0u8; n]` is zeros whatever
/// `n` is, `[0u8; 4].repeat(n)` its element.
const REPEATING: &[&str] = &["vec::from_elem", "::repeat"];

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
            value: None,
            zero: false,
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
                Origin::Param {
                    index: 0,
                    owner: None,
                },
            ],
            span: None,
        };
        let mut out = BTreeSet::new();
        classify(&kb, &LinkIndex::default(), &key, 0, &mut out);
        let kinds: Vec<_> = out.iter().map(|c| c.kind.as_str()).collect();
        assert_eq!(kinds, ["parameter"]);
        // a static that is not a descriptor is data compiled in
        let mut out = BTreeSet::new();
        classify(
            &kb,
            &LinkIndex::default(),
            &data("app", "app::MASTER_KEY"),
            0,
            &mut out,
        );
        let kinds: Vec<_> = out.iter().map(|c| c.kind.as_str()).collect();
        assert_eq!(kinds, ["hard-coded"]);
    }

    #[test]
    fn no_data_and_a_protocols_zeros_are_absent() {
        let kb = Kb::seed().unwrap();
        let empty = Origin::Const {
            value: None,
            len: Some(0),
            span: None,
            zero: false,
        };
        assert_eq!(kinds(&kb, &empty), ["absent"]);
        let zeros = Origin::Const {
            value: None,
            len: Some(32),
            span: None,
            zero: true,
        };
        assert_eq!(kinds(&kb, &zeros), ["hard-coded"]);
        // as HKDF's salt or input key: what TLS 1.3 puts where it has none
        let call = |role_arg: usize| Target::Call {
            callee: rcbom_facts::DefRef {
                id: String::new(),
                krate: rcbom_facts::CrateRef {
                    name: "ring".into(),
                    stable_id: String::new(),
                },
                path: "ring::hkdf::Salt::new".into(),
            },
            method: "new".into(),
            self_ty: None,
            args: vec![],
            const_args: vec![None, None],
            arg_origins: (0..2)
                .map(|i| {
                    if i == role_arg {
                        zeros.clone()
                    } else {
                        Origin::Unknown
                    }
                })
                .collect(),
            arg_lens: vec![None, None],
            through: None,
            value: false,
        };
        let salt = |protocol: bool| -> Vec<String> {
            of_call(&kb, &LinkIndex::default(), &call(1), protocol)
                .iter()
                .filter(|(r, _)| r == "salt")
                .flat_map(|(_, c)| c.iter().map(|c| c.kind.clone()))
                .collect()
        };
        // inside a protocol crate (TLS 1.3's key schedule) the all-zero salt is its "none"; the
        // program's own all-zero input is hard-coded
        assert_eq!(salt(true), ["absent"]);
        assert_eq!(salt(false), ["hard-coded"]);
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
            len: Some(4),
            span: None,
            zero: false,
        }
    }

    fn kinds(kb: &Kb, o: &Origin) -> Vec<String> {
        let mut out = BTreeSet::new();
        classify(kb, &LinkIndex::default(), o, 0, &mut out);
        out.into_iter().map(|c| c.kind).collect()
    }

    #[test]
    fn computations_are_hard_coded_only_from_constants() {
        let kb = Kb::seed().unwrap();
        // a knowledge-base function of a parameter and a constant varies with the parameter
        let mixed = call(
            "ring::hkdf::Salt::new",
            "ring",
            vec![
                Origin::Param {
                    index: 0,
                    owner: None,
                },
                lit(),
            ],
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
            vec![
                Origin::Param {
                    index: 0,
                    owner: None,
                },
                data("age", "age::LABEL"),
                lit(),
            ],
        );
        assert_eq!(kinds(&kb, &own), ["computed"]);
        // a closure of this function is looked through
        let closure = call("<closure>", "", vec![lit()]);
        assert_eq!(kinds(&kb, &closure), ["hard-coded"]);
        // standard-library fallbacks are alternatives: either supplies the value
        let fallback = call(
            "core::result::Result::<T, E>::unwrap_or",
            "core",
            vec![
                Origin::Param {
                    index: 0,
                    owner: None,
                },
                lit(),
            ],
        );
        assert_eq!(kinds(&kb, &fallback), ["hard-coded", "parameter"]);
    }
}
