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

/// The role of an argument that only gives an output length: neither key material nor the
/// algorithm.
const LENGTH: &str = "length";

/// The arguments of a call (by its callee's paths) that only give a length.
pub(crate) fn length_args(kb: &Kb, paths: &[String]) -> HashSet<usize> {
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

/// Key material arguments of a call, with the classes of their origins: (role, classes).
/// `protocol`: the call is a protocol crate's (rustls's key schedule), where an all-zero salt
/// or input key is the protocol's own "none".
pub fn of_call(
    kb: &Kb,
    links: &LinkIndex,
    owner: &str,
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
                classify(kb, links, owner, o, 0, &mut classes);
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
                classify(kb, links, "", &v, 0, &mut classes);
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

fn classify(
    kb: &Kb,
    links: &LinkIndex,
    owner: &str,
    o: &Origin,
    depth: usize,
    out: &mut BTreeSet<Class>,
) {
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
            // (written by other functions: their parameters are not this one's)
            for v in values {
                classify(kb, links, "", v, depth + 1, out);
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
                .for_each(|p| classify(kb, links, "", p, depth + 1, out)),
            None => classify(kb, links, owner, base, depth + 1, out),
        },
        Origin::Param { index, owner: of } => {
            out.insert(class(
                "parameter",
                match of {
                    Some(f) => format!("argument {index} of {}", short(f)),
                    None => format!("argument {index} of the enclosing function"),
                },
            ));
            // and what the program's callers pass there (`seal(&[1u8; 32], msg)`: hard-coded),
            // each in its caller; the parameter stays, for callers outside the program or
            // through pointers
            let func = of.as_deref().unwrap_or(owner);
            if !func.is_empty() {
                for (caller, args) in links.callers_of(func) {
                    if let Some(a) = args.get(*index) {
                        classify(kb, links, caller, a, depth + 1, out);
                    }
                }
            }
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
                .for_each(|a| classify(kb, links, owner, a, depth + 1, out));
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
                    classify(kb, links, owner, a, depth + 1, out);
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
                    classify(kb, links, owner, seed, depth + 1, &mut inner);
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
                    of_inputs(kb, links, owner, &data, depth, out);
                } else {
                    data.iter()
                        .for_each(|a| classify(kb, links, owner, a, depth + 1, out));
                }
            } else if path.ends_with("::default::Default::default") && args.is_empty() {
                // `[u8; 32]::default()`, `GenericArray::default()`, a crypto type's default: a
                // fixed value; the program's own type (or another crate's) may compute it
                // (`Config::default()` reading the environment): an interprocedural question
                let ty_crate = self_ty.and_then(|t| t.split("::").next());
                let fixed = ty_crate.is_none_or(|k| {
                    matches!(k, "core" | "std" | "alloc")
                        || Kb::lists(&kb.fixed_defaults, k)
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
                    classify(kb, links, owner, &args[0], depth + 1, &mut inner);
                    if whole_range(args.get(1)) {
                        out.extend(inner);
                    } else {
                        out.extend(inner.into_iter().map(without_length));
                    }
                } else if REPEATING.iter().any(|m| path.ends_with(m)) {
                    // copies of the element: `vec![0; n]` (the length is not data, nor is the
                    // element's own)
                    let mut inner = BTreeSet::new();
                    classify(kb, links, owner, &args[0], depth + 1, &mut inner);
                    out.extend(inner.into_iter().map(without_length));
                } else if LOOKUPS.iter().any(|m| path.ends_with(m)) {
                    // a lookup in a container (`map.get(&kid)`, `iter.find(..)`): one of the
                    // values it holds, not the key looked up
                    classify(kb, links, owner, &args[0], depth + 1, out);
                } else if ERROR_ARGS.iter().any(|m| path.ends_with(m)) {
                    // the value is the receiver: `expect(msg)`, `ok_or(err)`, `map_err(f)` (the
                    // other argument is what an error carries)
                    classify(kb, links, owner, &args[0], depth + 1, out);
                } else if FALLBACKS.iter().any(|m| path.ends_with(m)) {
                    // the receiver, or what the fallback supplies instead
                    // (`unwrap_or_else(|_| "literal")`): either one
                    for a in args {
                        classify(kb, links, owner, a, depth + 1, out);
                    }
                } else {
                    // anything else computes its result from all its inputs
                    // (`b"..".iter().chain(secret.iter())`, `1_000u64.wrapping_add(seq)`,
                    // `u64::from_str_radix(s, 16)`): hard-coded only if all of them are
                    of_inputs(kb, links, owner, args, depth, out);
                }
            } else if kb.crate_by_name(krate).is_some() {
                // a crypto crate's constructor or computation (`Nonce::assume_unique_for_key`,
                // `UnboundKey::new(&AES_256_GCM, key)`, `SaltString::encode_b64`): a function of
                // its arguments only (generators are sources, matched above). Indexing takes its
                // data from the receiver (`&key[..32]`: the range is not key material).
                if INDEXING.iter().any(|m| path.ends_with(m)) {
                    let mut inner = BTreeSet::new();
                    classify(kb, links, owner, &args[0], depth + 1, &mut inner);
                    if whole_range(args.get(1)) {
                        out.extend(inner);
                    } else {
                        out.extend(inner.into_iter().map(without_length));
                    }
                } else if LOOKUPS.iter().any(|m| path.ends_with(m)) && !args.is_empty() {
                    // a lookup (`jwks.find(&kid)`): what it finds is held by the receiver; the
                    // key it looks up with is not key material
                    classify(kb, links, owner, &args[0], depth + 1, out);
                } else {
                    // (a protocol crate's that combines data from two arguments or more,
                    // rustls's `Nonce::new(&self.iv, seq)` being `iv ^ seq`: computed, from them,
                    // unless all are constants; an algorithm crate's call is the operation, its
                    // output a function of its input, `OutputReader::fill(&mut key)` derived)
                    let protocol = kb
                        .crate_by_name(krate)
                        .is_some_and(|c| c.role == rcbom_kb::Role::Protocol);
                    let carrying = args
                        .iter()
                        .filter(|a| {
                            let mut c = BTreeSet::new();
                            classify(kb, links, owner, a, depth + 1, &mut c);
                            !c.is_empty()
                        })
                        .count();
                    let mut inner = BTreeSet::new();
                    of_inputs(kb, links, owner, args, depth, &mut inner);
                    if protocol && carrying > 1 && inner.iter().any(|c| c.kind != "hard-coded") {
                        out.insert(class("computed", short(&path)));
                    } else {
                        out.extend(inner);
                    }
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
                .for_each(|(v, w)| classify(kb, links, w, v, depth + 1, out)),
            _ => {
                out.insert(class(
                    "computed",
                    format!("written by {}", fn_display(callee)),
                ));
            }
        },
        // a value the links do not follow (`links::marker`): no class, as an unknown origin
        Origin::Through { .. } if crate::links::not_followed(o).is_some() => {}
        // written through a borrow the call returned (`key.chunks_mut(16)`, `split_at_mut`):
        // what was written is not followed
        Origin::Through { callee } => {
            let how = match rcbom_facts::element_writer(callee) {
                Some("") => "written into an element".to_string(),
                Some(w) => format!("written into an element by {}", fn_display(w)),
                None => format!("written through {}", fn_display(callee)),
            };
            out.insert(class("computed", how));
        }
        // a value updated from its own earlier value (`ctr += 1`): a counter, whose constant
        // alternatives are only where it starts
        Origin::Any(alts) if alts.iter().any(recurs) => {
            let mut inner = BTreeSet::new();
            alts.iter()
                .for_each(|a| classify(kb, links, owner, a, depth + 1, &mut inner));
            out.extend(inner.into_iter().filter(|c| c.kind != "hard-coded"));
            out.insert(class(
                "computed",
                "changes with each iteration of a loop".into(),
            ));
        }
        Origin::Any(alts) => alts
            .iter()
            .for_each(|a| classify(kb, links, owner, a, depth + 1, out)),
        Origin::Loop => {
            out.insert(class(
                "computed",
                "changes with each iteration of a loop".into(),
            ));
        }
        // built from all of these parts (`[user, b"pepper"].concat()`, `key[31] = 1` after the
        // key was read from the environment): a constant only if every part is
        Origin::All(parts) => of_inputs(kb, links, owner, parts, depth, out),
        // a field written into the value: what was written
        Origin::Set { value, .. } => classify(kb, links, owner, value, depth, out),
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
fn of_inputs(
    kb: &Kb,
    links: &LinkIndex,
    owner: &str,
    args: &[Origin],
    depth: usize,
    out: &mut BTreeSet<Class>,
) {
    let mut constant = true;
    let mut hard_coded = BTreeSet::new();
    let mut varying = BTreeSet::new();
    let mut any = false;
    for a in args {
        let mut classes = BTreeSet::new();
        classify(kb, links, owner, a, depth + 1, &mut classes);
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

/// Is descriptor `id`, named in the call's own arguments, an element of a container the call
/// reads (`v[0]` of `vec![&SHA256, &SHA384]`, `m["a"]` after two `insert`s): one of the values
/// it holds, not the one read?
pub fn container_member(target: &Target, id: &str) -> bool {
    fn walk(o: &Origin, id: &str, read: bool, depth: usize) -> Option<bool> {
        if depth > 12 {
            return None;
        }
        match crate::links::peel(o) {
            Origin::Data { def, .. } if def.id == id => Some(false),
            Origin::All(alts) => alts
                .iter()
                .find_map(|a| walk(a, id, read, depth + 1).map(|c| c || (read && alts.len() > 1))),
            Origin::Any(alts) => alts.iter().find_map(|a| walk(a, id, read, depth + 1)),
            Origin::Set { value, .. } => walk(value, id, read, depth + 1),
            Origin::Call { callee, args, .. } if callee == "<closure>" || std_choice(callee) => {
                args.iter().find_map(|a| walk(a, id, read, depth + 1))
            }
            Origin::Call { callee, args, .. } if container_store(callee) => args
                .iter()
                .find_map(|a| walk(a, id, true, depth + 1).map(|_| true)),
            Origin::Call { krate, args, .. }
                if matches!(krate.as_str(), "core" | "std" | "alloc") =>
            {
                args.iter().find_map(|a| walk(a, id, true, depth + 1))
            }
            _ => None,
        }
    }
    let Target::Call { arg_origins, .. } = target else {
        return false;
    };
    arg_origins
        .iter()
        .any(|o| walk(o, id, false, 0).unwrap_or(false))
}

/// A standard-library call choosing between a value and another (`unwrap_or`, `or_else`,
/// `get_or_init`): its value is either (`search::Std::Choice`).
pub(crate) fn std_choice(callee: &str) -> bool {
    matches!(
        crate::search::std_semantics(callee),
        Some(crate::search::Std::Choice)
    )
}

/// What a combinator makes of its receiver's value with the functions it is given (`map(f)`,
/// `map_or(d, f)`, an iterator's `map(f)`, a thread-local key's `with(f)`): each function's
/// result, the one the combinator passes the receiver's value (`fed_argument`) given it: a
/// function item called with it, a closure's own parameter bound to it (`Call::fed`); another
/// argument (`map_or`'s default) as it is.
pub(crate) fn mapped_values(callee: &str, args: &[Origin]) -> Vec<Origin> {
    let Some(receiver) = args.first() else {
        return Vec::new();
    };
    let fed = fed_argument(callee);
    let err = error_of(callee, receiver);
    args.iter()
        .enumerate()
        .skip(1)
        .flat_map(|(i, a)| {
            let input = match &err {
                Some((n, e)) if *n == i => Some(e),
                _ => (fed == Some(i)).then_some(receiver),
            };
            fn_values(a, input)
        })
        .collect()
}

/// The callee of an origin the analysis makes for the error side of a `Result` (its argument),
/// given to the function a combinator calls with it: what `search` reads as the error.
pub(crate) const ERROR_OF: &str = "<error of>";

/// The argument of a `Result`'s combinator that is a function given the receiver's error
/// (`unwrap_or_else(|e| e)`, `or_else(f)`, `map_or_else(d, f)`'s `d`), with that error as an
/// origin.
fn error_of(callee: &str, receiver: &Origin) -> Option<(usize, Origin)> {
    let bare = strip_generics(callee);
    [
        "result::Result::unwrap_or_else",
        "result::Result::or_else",
        "result::Result::map_or_else",
    ]
    .iter()
    .any(|m| bare.ends_with(m))
    .then(|| {
        (
            1,
            Origin::Call {
                callee: ERROR_OF.to_string(),
                krate: String::new(),
                self_ty: None,
                args: vec![receiver.clone()],
                span: None,
                runs: None,
                pointer: None,
                fed: None,
            },
        )
    })
}

/// The argument of a combinator that is a function given the receiver's value: an `Option`'s
/// or a `Result`'s value (`map(f)`, `and_then(f)`, `map_or(d, f)`, `map_or_else(d, f)`, whose
/// default `d` is given nothing, or a `Result`'s error), an iterator's elements (`map(f)`,
/// `filter_map(f)`, `find_map(f)`, `flat_map(f)`). Not a thread-local key's `with(f)`: its
/// value is a static with interior mutability, whose fields are read with a gap (writes through
/// its borrows are not attributed to it), where the field of a value not followed is what the
/// program stores in that field anywhere (`with(|c| c.borrow().h)`), a complete answer.
fn fed_argument(callee: &str) -> Option<usize> {
    let bare = strip_generics(callee);
    let ends = |m: &str| bare.ends_with(m);
    if ends("option::Option::map")
        || ends("option::Option::and_then")
        || ends("result::Result::map")
        || ends("result::Result::and_then")
        || ends("iterator::Iterator::map")
        || ends("iterator::Iterator::filter_map")
        || ends("iterator::Iterator::find_map")
        || ends("iterator::Iterator::flat_map")
    {
        Some(1)
    } else if ends("option::Option::map_or")
        || ends("option::Option::map_or_else")
        || ends("result::Result::map_or")
        || ends("result::Result::map_or_else")
    {
        Some(2)
    } else {
        None
    }
}

/// `o` with a followed closure's own parameters (`Param { owner: Some(CLOSURE_INPUT) }`) given
/// the value `input` (the first) or `Unknown` (any other).
fn bind_input(o: &Origin, input: &Origin) -> Origin {
    let go = |x: &Origin| bind_input(x, input);
    match o {
        Origin::Param {
            index,
            owner: Some(w),
        } if w == rcbom_facts::CLOSURE_INPUT => {
            if *index == 0 {
                input.clone()
            } else {
                Origin::Unknown
            }
        }
        Origin::Call {
            callee,
            krate,
            self_ty,
            args,
            span,
            runs,
            pointer,
            fed,
        } => Origin::Call {
            callee: callee.clone(),
            krate: krate.clone(),
            self_ty: self_ty.clone(),
            args: args.iter().map(go).collect(),
            span: span.clone(),
            runs: runs.clone(),
            pointer: pointer.as_ref().map(|p| Box::new(go(p))),
            fed: fed.clone(),
        },
        Origin::Field {
            adt,
            field,
            base,
            args,
        } => Origin::Field {
            adt: adt.clone(),
            field: *field,
            base: Box::new(go(base)),
            args: args.clone(),
        },
        Origin::Written {
            callee,
            index,
            args,
            self_ty,
            place_ty,
            path,
        } => Origin::Written {
            callee: callee.clone(),
            index: *index,
            args: args.iter().map(go).collect(),
            self_ty: self_ty.clone(),
            place_ty: place_ty.clone(),
            path: path.clone(),
        },
        Origin::Any(v) => Origin::Any(v.iter().map(go).collect()),
        Origin::All(v) => Origin::All(v.iter().map(go).collect()),
        Origin::Set {
            path,
            value,
            strong,
        } => Origin::Set {
            path: path.clone(),
            value: Box::new(go(value)),
            strong: *strong,
        },
        other => other.clone(),
    }
}

/// What an argument given as a function makes (`map(keep)`, `unwrap_or_else(fallback)`): a
/// function item called (with `input`, the value it is given, where it takes one), each of
/// several a pointer may be (`let g = if c { keep } else { fixed }`); `identity`, `Some`, `Ok`:
/// the input itself; any other argument: itself.
pub(crate) fn fn_values(a: &Origin, input: Option<&Origin>) -> Vec<Origin> {
    match a {
        Origin::Unit {
            path,
            krate,
            value,
            runs,
            ..
        } => {
            let std = matches!(krate.as_str(), "core" | "std" | "alloc");
            let bare = strip_generics(path);
            // (a standard-library function whose value is its argument's: `identity`, `Some`,
            // `Clone::clone` of a reference)
            if std
                && (bare.ends_with("convert::identity")
                    || bare.ends_with("::Some")
                    || bare.ends_with("::Ok")
                    || bare.ends_with("::Err")
                    || matches!(
                        crate::search::std_semantics(path),
                        Some(crate::search::Std::Arg(0))
                    ))
            {
                vec![input.cloned().unwrap_or(Origin::Unknown)]
            } else if std || value.is_some() {
                vec![Origin::Unknown]
            } else {
                // the body it runs, as the driver resolved it (`map(Pick::alg)` on a `Fast`)
                vec![Origin::Call {
                    callee: path.clone(),
                    krate: krate.clone(),
                    self_ty: None,
                    args: input.cloned().into_iter().collect(),
                    span: None,
                    runs: runs.clone(),
                    pointer: None,
                    fed: None,
                }]
            }
        }
        Origin::Any(alts) if alts.iter().all(|x| matches!(x, Origin::Unit { .. })) => {
            alts.iter().flat_map(|x| fn_values(x, input)).collect()
        }
        // a closure given the value (`o.map(|x| x)`, `get(i).map(|e| e.h)`): what it returns,
        // its parameter that value
        Origin::Call {
            callee,
            fed: Some(f),
            ..
        } if callee == "<closure>"
            && let Some(i) = input =>
        {
            let mut c = a.clone();
            if let Origin::Call { args, fed, .. } = &mut c {
                *args = vec![bind_input(f, i)];
                *fed = None;
            }
            vec![c]
        }
        // a function another call returns (`unwrap_or_else(get_fb())`): a call through that
        // pointer, run with the value, followed to the functions it may be (or a gap)
        Origin::Call { callee, .. } if callee != "<closure>" && callee != "<indirect>" => {
            vec![Origin::Call {
                callee: "<indirect>".into(),
                krate: String::new(),
                self_ty: None,
                args: input.cloned().into_iter().collect(),
                span: None,
                runs: None,
                pointer: Some(Box::new(a.clone())),
                fed: None,
            }]
        }
        _ => vec![a.clone()],
    }
}

/// The values a choice between an `Option`'s or a `Result`'s value and a fallback is made of
/// (`std_choice`): its arguments, a fallback function called (`unwrap_or_else(fallback)`).
pub(crate) fn choice_values(callee: &str, args: &[Origin]) -> Vec<Origin> {
    let err = args.first().and_then(|r| error_of(callee, r));
    // (a fallback value, `unwrap_or(Algorithm::HS384)`, is no function: only the `_else` and
    // `_with` choices, and `get_or_init`, are given one)
    let bare = strip_generics(callee);
    let given_fn = bare.ends_with("_else") || bare.ends_with("_with") || bare.ends_with("_init");
    args.iter()
        .enumerate()
        .flat_map(|(i, a)| {
            if i == 0 || !given_fn {
                vec![a.clone()]
            } else {
                // (a `Result`'s fallback function is given its error: `unwrap_or_else(|e| e)`)
                let input = err.as_ref().filter(|(n, _)| *n == i).map(|(_, e)| e);
                fn_values(a, input)
            }
        })
        .collect()
}

/// A crypto crate's getter for the algorithm a value was made with (`ctx.algorithm()`,
/// `key.algorithm()`): the descriptor its receiver was built from.
pub(crate) fn algorithm_getter(kb: &Kb, krate: &str, callee: &str) -> bool {
    kb.crate_by_name(krate).is_some() && strip_generics(callee).ends_with("::algorithm")
}

/// A standard-library call that stores a value in a container (`Vec::push`, `HashMap::insert`,
/// `extend`): `search::Std::Store`.
pub(crate) fn container_store(callee: &str) -> bool {
    matches!(
        crate::search::std_semantics(callee),
        Some(crate::search::Std::Store(_))
    )
}

/// Does `o` read a field of a static (`MADE.h`, `LAZY.h`, `TABLE[i].h`) for which `pred` holds?
pub(crate) fn reads_static_field(o: &Origin, pred: &dyn Fn(&str) -> bool, depth: usize) -> bool {
    if depth > 8 {
        return false;
    }
    match o {
        Origin::Field { .. } => crate::search::static_root(o).is_some_and(|d| pred(&d.id)),
        Origin::Any(v) | Origin::All(v) => v.iter().any(|x| reads_static_field(x, pred, depth + 1)),
        Origin::Call { args, .. } => args.iter().any(|x| reads_static_field(x, pred, depth + 1)),
        Origin::Set { value, .. } => reads_static_field(value, pred, depth + 1),
        _ => false,
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

/// Lookups: the value found is the receiver's (`JwkSet::find(&kid)`, `HashMap::get(&k)`).
const LOOKUPS: &[&str] = &["::find", "::get", "::get_mut", "::get_key_value"];

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

/// A function's path for reading: its last segments, without generic arguments, an
/// implementation's item named by its self type (`<a::X<T> as b::Tr>::f` -> `a::X::f`).
fn fn_display(path: &str) -> String {
    // (an instance's turbofish with its `::`: `app::fill::<app::X>` is `app::fill`)
    let path = &path.replace("::<", "<");
    if let Some(inner) = path.strip_prefix('<') {
        let mut depth = 1usize;
        for (i, c) in inner.char_indices() {
            match c {
                '<' => depth += 1,
                '>' => {
                    depth -= 1;
                    if depth == 0 {
                        let qself = &inner[..i];
                        let ty = strip_generics(qself);
                        let ty = ty.split(" as ").next().unwrap_or(&ty);
                        return short(&format!("{ty}{}", strip_generics(&inner[i + 1..])));
                    }
                }
                _ => {}
            }
        }
    }
    short(&strip_generics(path))
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

    #[test]
    fn writers_are_named_by_their_self_type() {
        assert_eq!(
            fn_display(
                "<rustls::crypto::tls12::GcmMessageDecrypter as rustls::crypto::cipher::MessageDecrypter>::decrypt"
            ),
            "tls12::GcmMessageDecrypter::decrypt"
        );
        assert_eq!(
            fn_display("<app::W<app::A> as app::Gen<u8>>::set"),
            "app::W::set"
        );
        assert_eq!(fn_display("app::fill::<app::X>"), "app::fill");
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
            runs: None,
            pointer: None,
            fed: None,
        };
        let mut out = BTreeSet::new();
        classify(&kb, &LinkIndex::default(), "", &key, 0, &mut out);
        let kinds: Vec<_> = out.iter().map(|c| c.kind.as_str()).collect();
        assert_eq!(kinds, ["parameter"]);
        // a static that is not a descriptor is data compiled in
        let mut out = BTreeSet::new();
        classify(
            &kb,
            &LinkIndex::default(),
            "",
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
            of_call(&kb, &LinkIndex::default(), "", &call(1), protocol)
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
            runs: None,
            pointer: None,
            fed: None,
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
        classify(kb, &LinkIndex::default(), "", o, 0, &mut out);
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
        // a protocol crate's combining two values is computed from them (rustls's
        // `Nonce::new(&self.iv, seq)`, `iv ^ seq`), not the parameters themselves
        let combined = call(
            "rustls::crypto::cipher::Nonce::new",
            "rustls",
            vec![
                Origin::Param {
                    index: 0,
                    owner: None,
                },
                Origin::Param {
                    index: 2,
                    owner: None,
                },
            ],
        );
        assert_eq!(kinds(&kb, &combined), ["computed"]);
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
