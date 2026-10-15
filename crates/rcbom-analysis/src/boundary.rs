//! Boundary models (`[[boundary]]`): a protocol crate's API whose algorithm is a value the
//! program chooses (jsonwebtoken's `encode(&header, ..)` signs with `header.alg`). The call is
//! reported with the variants of the algorithm enum (`[[enum]]`) that reach the argument, or
//! the field of the struct behind it, followed across functions (`links`); several are a
//! candidate set chosen at run time (`selector: configuration`). A member the analysis cannot
//! follow makes the call an unknown algorithm too, unless the variants found are already all
//! of the enum's. A key's family enum (`key`) narrows the variants: jsonwebtoken refuses an
//! algorithm whose family is not the key's.

use std::collections::{BTreeMap, BTreeSet};

use rcbom_facts::{Origin, Site, Target};
use rcbom_kb::{Algo, FieldRef};

use crate::links::Via;
use crate::matcher::{Match, strip_generics};
use crate::{Ctx, Kind, SiteMatch, UNKNOWN, unresolved_reason};

/// What reaches an argument: the variants found, each with how it reaches the call, and why
/// some members were not followed.
#[derive(Default)]
struct Found {
    names: BTreeMap<String, Via>,
    /// Every way each variant was found.
    ways: BTreeMap<String, BTreeSet<Via>>,
    /// What was not followed, and the way it was met (a value no entry point reaches is
    /// none of the call's).
    unresolved: Vec<(String, Via)>,
}

impl Found {
    /// A variant found; found several ways, it keeps the most specific.
    fn add(&mut self, name: String, via: &Via) {
        self.ways
            .entry(name.clone())
            .or_default()
            .insert(via.clone());
        let e = self.names.entry(name).or_insert_with(|| via.clone());
        if *via < *e {
            *e = via.clone();
        }
    }
}

/// Does a member found this way reach the call at run time: not only through a function no
/// entry point reaches, or a static no reachable code or data names?
pub(crate) fn reached(
    via: &Via,
    reachable: &dyn Fn(&str) -> bool,
    reached_path: &dyn Fn(&str) -> bool,
) -> bool {
    // what a function returns into the call's own value is on its way (reached with it); a
    // caller, or a store into the field anywhere, may be code no entry point reaches
    match via {
        Via::Caller(w) | Via::Join(w) | Via::Table(w) | Via::Static(w) => {
            let w = w.strip_prefix('=').unwrap_or(w);
            match rcbom_facts::owner_static(w) {
                Some((_, id)) => reachable(id),
                None => w.is_empty() || w.contains(" for ") || reached_path(w),
            }
        }
        // put in a static at run time: by a function an entry point reaches, into a static
        // reachable code names
        Via::Store { writer, statik } => {
            reached_path(writer)
                && rcbom_facts::owner_static(statik).is_none_or(|(_, id)| reachable(id))
        }
        _ => true,
    }
}

/// The occurrences of a call a boundary model describes; `None` when none does.
pub(crate) fn site_matches(
    ctx: &Ctx<'_>,
    site: &Site,
    reachable: &dyn Fn(&str) -> bool,
    reached_path: &dyn Fn(&str) -> bool,
) -> Option<Vec<SiteMatch>> {
    let Target::Call {
        callee,
        arg_origins,
        ..
    } = &site.target
    else {
        return None;
    };
    // the crate's own calls are its implementation, which the walk follows
    if site.owner.krate == callee.krate || !ctx.supported(&callee.krate) {
        return None;
    }
    let in_crate = callee
        .path
        .strip_prefix(&format!("{}::", callee.krate.name))
        .unwrap_or(&callee.path);
    let b = ctx
        .kb
        .boundary(&callee.krate.name, &strip_generics(in_crate))?;
    let e = ctx
        .kb
        .enums
        .iter()
        .find(|e| e.krate == b.krate && e.name == b.enumeration)?;
    let all: BTreeSet<&str> = e.variants.keys().map(String::as_str).collect();
    // the variants the call can use: those the key's family allows
    let mut possible = all.len();
    let mut found = members(ctx, site, &b.krate, &b.algorithm, &all, arg_origins);
    // a value not followed met only through code no entry point reaches (a caller never
    // called, a static only it names) is none of the call's
    found
        .unresolved
        .retain(|(_, v)| reached(v, reachable, reached_path));
    let what = described(&b.algorithm);
    let mut detail = Vec::new();
    // the key's family allows some of them
    if let Some(k) = &b.key {
        let families: BTreeSet<&str> = e
            .variants
            .values()
            .filter_map(|v| v.key.as_deref())
            .collect();
        let mut key = members(ctx, site, &b.krate, k, &families, arg_origins);
        key.unresolved
            .retain(|(_, v)| reached(v, reachable, reached_path));
        if key.unresolved.is_empty() && !key.names.is_empty() {
            let allowed = |n: &str| {
                e.variants[n]
                    .key
                    .as_ref()
                    .is_none_or(|f| key.names.contains_key(f))
            };
            let before = found.names.len();
            // a variant of another family than the key's that may be in a list the call uses
            // all of (put there beside the others: `v.algorithms.push(HS256)`, `vec![RS256,
            // HS256]`, `fill`, an element write in a helper; or instead of them):
            // jsonwebtoken refuses the call when it is there, so which of the others it
            // verifies with, if any, is not known; in a single value (`Header.alg`) it is an
            // alternative, the call failing when it is chosen; a value only stored in the field
            // somewhere (a type-join) is not shown to be in this list
            // (a value the program's own code puts there: a write into the list, by a function
            // of the program or a container call; not one only stored in the field somewhere,
            // nor what another crate's code returns, which reaches it as `Validation::new`'s
            // argument: the list's one value)
            let list = b.algorithm.list;
            let program_fn = |f: &str| {
                let krate = f.trim_start_matches('<').split("::").next().unwrap_or("");
                ctx.crates
                    .iter()
                    .any(|((name, _), pkg)| name == krate && ctx.local.contains(pkg))
            };
            // (a variant named in the function is put in the list by a container call
            // (`push`, `fill`): named alone it is the list's value, an alternative (`if c {
            // vec![RS384] } else { vec![HS256] }`); a value not followed there, a closure's
            // write, is a write)
            let in_list = |v: &Via, fixed: bool| match v {
                Via::Container(_) => true,
                _ if !list => false,
                Via::Join(_) => false,
                Via::Fixed => fixed,
                Via::Object(f) | Via::Caller(f) => program_fn(f),
                _ => true,
            };
            let refused: Vec<String> = found
                .names
                .keys()
                .filter(|n| {
                    !allowed(n)
                        && found.ways.get(*n).is_some_and(|w| {
                            w.iter()
                                .any(|v| in_list(v, false) && reached(v, reachable, reached_path))
                        })
                })
                .cloned()
                .collect();
            found.names.retain(|n, _| allowed(n));
            possible = all.iter().filter(|n| allowed(n)).count();
            // values in the list the analysis does not follow (a write through `get_mut`, a
            // closure, `splice`): any of them may be of another family, then refused; the
            // members are not known to be verified with
            if list
                && found.unresolved.iter().any(|(_, v)| in_list(v, true))
                && possible < all.len()
                && !found.names.is_empty()
            {
                let note = format!(
                    "; jsonwebtoken refuses the token when one is of another family than the \
                     key's ({}), else it verifies with one of {} or a value not followed",
                    key.names.keys().cloned().collect::<Vec<_>>().join(", "),
                    found.names.keys().cloned().collect::<Vec<_>>().join(", ")
                );
                for (r, _) in found.unresolved.iter_mut() {
                    r.push_str(&note);
                }
                found.names.clear();
            }
            // none the key allows (`Validation::new(HS256)` with an RSA key): jsonwebtoken
            // refuses the token before any verification
            if before > 0 && found.names.is_empty() && found.unresolved.is_empty() {
                return Some(Vec::new());
            }
            if !refused.is_empty() && !found.names.is_empty() {
                found.unresolved.push((
                    format!(
                        "{what} may list {}, of another family than the key's ({}): jsonwebtoken \
                     then refuses the token before any verification, else it verifies with one \
                     of {}",
                        refused.join(", "),
                        key.names.keys().cloned().collect::<Vec<_>>().join(", "),
                        found.names.keys().cloned().collect::<Vec<_>>().join(", ")
                    ),
                    Via::Fixed,
                ));
                found.names.clear();
            }
            detail.push(format!(
                "the key's family ({}) allows these",
                key.names.keys().cloned().collect::<Vec<_>>().join(", ")
            ));
        }
    }
    let provider = ctx.package_of_crate(&callee.krate.name, &callee.krate.stable_id);
    let symbol = callee.path.clone();
    // a member found only through code or data no entry point reaches (a header a function
    // never called builds, a static nothing uses) does not reach the call: shown, not counted
    let ways = std::mem::take(&mut found.ways);
    let live = |name: &str| {
        ways.get(name)
            .is_none_or(|w| w.iter().any(|v| reached(v, reachable, reached_path)))
    };
    // the witness shown: one that reaches the call, the most specific, and of those one of the
    // program's functions before the modelled crate's own (`translate_algorithm`, the choice
    // the program makes, not `Validation::new`, which passes it on)
    let own = format!("{}::", b.krate);
    let modelled = |v: &Via| match v {
        Via::Caller(f) | Via::Object(f) | Via::Join(f) => f.starts_with(&own),
        _ => false,
    };
    for (name, via) in found.names.iter_mut() {
        if let Some(best) = ways.get(name).and_then(|w| {
            w.iter()
                .filter(|v| reached(v, reachable, reached_path))
                .min_by_key(|v| (v.rank(), modelled(v), (*v).clone()))
        }) {
            *via = best.clone();
        }
    }
    let n = found.names.keys().filter(|n| live(n)).count();
    // an unknown beside the members (values not followed): none of them is the only one
    let beside = !found.unresolved.is_empty() && n < possible;
    // a function of the program called here with constants only (`alg_for(0)`): the program
    // fixes its choice, no input selects it
    let fixed_by_program = constant_calls(arg_origins);
    let mut out = Vec::new();
    for (name, via) in &found.names {
        if !live(name) {
            let algo = e.variants[name].algo.clone();
            let function = ctx
                .kb
                .use_of(&b.function, &algo.primitive)
                .unwrap_or_else(|| b.function.clone());
            let d = vec![format!(
                "algorithm from {what} only through code or data no entry point reaches{}",
                witness_unreached(via)
            )];
            out.push((
                matched(algo, provider.clone()),
                Kind::Call,
                Some(function),
                symbol.clone(),
                d,
                true,
            ));
            continue;
        }
        let algo = e.variants[name].algo.clone();
        let function = ctx
            .kb
            .use_of(&b.function, &algo.primitive)
            .unwrap_or_else(|| b.function.clone());
        // how the variant reaches the call: a choice the program makes at run time, or one of
        // the values it stores in the field anywhere (possible, not shown to reach this call)
        let one_of = if n > 1 {
            format!("one of {n} ")
        } else {
            String::new()
        };
        let mut d = vec![match (via, n > 1) {
            (Via::Join(w), _) => format!(
                "algorithm {one_of}from {what}: possible (type-join: a value `{}` stores in the \
                 field)",
                short_fn(w)
            ),
            // a call through a trait object of which several types are made: each type's
            // value may reach it
            (
                Via::Dyn { only: false, .. } | Via::Impl(_) | Via::Static(_) | Via::Store { .. },
                _,
            ) => {
                format!("algorithm {one_of}from {what}: possible{}", witness(via))
            }
            // one of the values a container holds, read from it
            (Via::Container(f), _) if f.starts_with('+') => format!(
                "algorithm {one_of}from {what}: possible (container: in the list `{}` adds to)",
                short_fn(&f[1..])
            ),
            (Via::Container(f), _) => format!(
                "algorithm {one_of}from {what}: possible (container: a value `{}` puts in it)",
                short_fn(f)
            ),
            // several that a function of the program returns (`translate_algorithm(&cli.alg)`):
            // it chooses at run time; not the modelled crate's own constructor, which only
            // passes its argument on (`Header::new(alg)`)
            (Via::Object(f), true)
                if !f.starts_with(&format!("{}::", b.krate)) && !fixed_by_program.contains(f) =>
            {
                format!(
                    "algorithm one of {n} chosen at run time (selector: configuration) from {what}{}",
                    witness(via)
                )
            }
            // several the program passes or names itself (callers, a loop over them): each
            // may reach the call
            (_, true) => format!(
                "algorithm one of {n} that may reach the call from {what}{}",
                witness(via)
            ),
            (_, false) if beside => format!(
                "algorithm one of 1 that may reach the call from {what}, beside others not \
                 followed{}",
                witness(via)
            ),
            (_, false) => format!("algorithm from {what}{}", witness(via)),
        }];
        d.extend(detail.iter().cloned());
        out.push((
            matched(algo, provider.clone()),
            Kind::Call,
            Some(function),
            symbol.clone(),
            d,
            false,
        ));
    }
    // members not followed: an unknown algorithm, unless every variant the call can use is
    // already there
    if found.names.is_empty() || (!found.unresolved.is_empty() && n < possible) {
        let reasons: BTreeSet<String> = found.unresolved.into_iter().map(|(r, _)| r).collect();
        let reason = if reasons.is_empty() {
            format!("no `{}` reaches {what}", e.name)
        } else {
            format!(
                "{what} takes values the analysis does not follow ({})",
                reasons.into_iter().collect::<Vec<_>>().join("; ")
            )
        };
        let algo = Algo {
            asset: UNKNOWN.to_string(),
            primitive: "unknown".to_string(),
            functions: vec![b.function.clone()],
            ..Algo::default()
        };
        out.push((
            matched(algo, provider),
            Kind::Call,
            Some(b.function.clone()),
            symbol,
            vec![format!("algorithm unresolved: {reason}")],
            false,
        ));
    }
    Some(out)
}

/// The functions of the program a value tree calls with constant arguments only, at every
/// call of them in it (`Header::new(alg_for(0))`).
fn constant_calls(origins: &[Origin]) -> BTreeSet<String> {
    // the iteration of a loop (`for i in 0..2u8`, `for i in [0u8, 1]`): each value in turn,
    // not a choice
    fn looped(o: &Origin) -> bool {
        match o {
            Origin::Loop => true,
            Origin::Through { callee } => callee.ends_with("Iterator::next"),
            Origin::Call { callee, krate, .. } => {
                matches!(krate.as_str(), "core" | "std" | "alloc")
                    && strip_generics(callee).ends_with("Iterator::next")
            }
            _ => false,
        }
    }
    // several different values a branch picks between (`if arg(1).is_empty() { 0 } else
    // { 1 }`), not a loop's: chosen at run time
    fn branch(v: &[Origin]) -> bool {
        v.iter().skip(1).any(|x| x != &v[0]) && !v.iter().any(looped)
    }
    fn constant(o: &Origin) -> bool {
        match o {
            Origin::Const { .. } | Origin::Unit { .. } | Origin::Data { .. } => true,
            Origin::All(v) => v.iter().all(constant),
            Origin::Any(v) => v.iter().all(constant) && !branch(v),
            // an element of a literal the program iterates (`for i in [0u8, 1]`)
            Origin::Call {
                callee,
                krate,
                args,
                ..
            } if matches!(krate.as_str(), "core" | "std" | "alloc")
                && [
                    "Iterator::next",
                    "::into_iter",
                    "::iter",
                    "::copied",
                    "::cloned",
                ]
                .iter()
                .any(|m| strip_generics(callee).ends_with(m)) =>
            {
                !args.is_empty() && args.iter().all(constant)
            }
            // (the iterator advanced by the loop)
            Origin::Through { callee } => callee.ends_with("Iterator::next"),
            Origin::Loop => true,
            _ => false,
        }
    }
    // `chosen`: under a branch between different values (`if c { alg_for(0) } else {
    // alg_for(1) }`): a call there is one the run picks
    fn walk(o: &Origin, all: &mut BTreeMap<String, bool>, chosen: bool, depth: usize) {
        if depth > 16 {
            return;
        }
        match o {
            Origin::Call { callee, args, .. } => {
                let c = !chosen && !args.is_empty() && args.iter().all(constant);
                all.entry(callee.clone())
                    .and_modify(|v| *v &= c)
                    .or_insert(c);
                args.iter().for_each(|a| walk(a, all, chosen, depth + 1));
            }
            Origin::Any(v) => {
                let chosen = chosen || branch(v);
                v.iter().for_each(|a| walk(a, all, chosen, depth + 1))
            }
            Origin::All(v) => v.iter().for_each(|a| walk(a, all, chosen, depth + 1)),
            Origin::Set { value, .. } => walk(value, all, chosen, depth + 1),
            Origin::Field { base, .. } => walk(base, all, chosen, depth + 1),
            Origin::Written { args, .. } => {
                args.iter().for_each(|a| walk(a, all, chosen, depth + 1))
            }
            _ => {}
        }
    }
    let mut all = BTreeMap::new();
    origins.iter().for_each(|o| walk(o, &mut all, false, 0));
    all.into_iter()
        .filter(|(_, c)| *c)
        .map(|(f, _)| f)
        .collect()
}

/// `member: ..`: how a member of a set found across functions reaches the call, with its
/// witness (the set label): fixed, caller, object, type-join (possible), through a trait
/// object, a container or a type parameter's implementations (possible).
pub(crate) fn member_label(via: &Via) -> String {
    match via {
        Via::Fixed => "member: fixed".to_string(),
        Via::Caller(c) => format!("member: caller, passed by `{}`", short_fn(c)),
        Via::Object(f) => format!("member: object, from `{}`", short_fn(f)),
        Via::Join(w) => format!(
            "member: type-join, possible (a value `{}` stores in the field)",
            short_fn(w)
        ),
        // (a value already in a list a call adds to: `+` and the call)
        Via::Container(f) if f.starts_with('+') => format!(
            "member: container, possible (in the list `{}` adds to)",
            short_fn(&f[1..])
        ),
        Via::Container(f) => format!(
            "member: container, possible (a value `{}` puts in it)",
            short_fn(f)
        ),
        Via::Dyn { only, .. } => format!(
            "member: dyn{}{}",
            if *only { "" } else { ", possible" },
            witness(via)
        ),
        Via::Impl(f) => format!("member: impl, possible (what `{}` writes)", short_fn(f)),
        Via::Table(w) => format!("member: table, stored by `{}`", short_fn(w)),
        // (a static no function puts a value in, a `LazyLock`: the value it holds)
        Via::Static(w) => match w.strip_prefix('=') {
            Some(w) => format!(
                "member: static, possible (the value `{}` holds)",
                short_fn(w)
            ),
            None => format!(
                "member: static, possible (the value `{}` starts with, which the program may \
                 replace)",
                short_fn(w)
            ),
        },
        Via::Store { writer, statik } => format!(
            "member: static, possible (a value `{}` puts in `{}`)",
            short_fn(writer),
            short_fn(statik)
        ),
    }
}

/// ` (stored by static `X`)`, ` (stored by `f`)`: the code or data no entry point reaches that
/// a member comes through.
fn witness_unreached(via: &Via) -> String {
    match via {
        Via::Caller(w) => format!(" (passed by `{}`)", short_fn(w)),
        Via::Join(w) | Via::Table(w) => format!(" (stored by `{}`)", short_fn(w)),
        Via::Static(w) => format!(
            " (stored by `{}`)",
            short_fn(w.strip_prefix('=').unwrap_or(w))
        ),
        Via::Store { writer, .. } => format!(" (stored by `{}`)", short_fn(writer)),
        _ => String::new(),
    }
}

/// `, passed by `caller``, `, from `f``: where a member reaches the call from.
fn witness(via: &Via) -> String {
    match via {
        Via::Caller(c) => format!(" (caller: passed by `{}`)", short_fn(c)),
        Via::Object(f) => format!(" (object: from `{}`)", short_fn(f)),
        Via::Dyn {
            trait_path,
            ty,
            at,
            in_static,
            only,
        } => {
            let place = if *in_static { " in a static" } else { "" };
            let at = at
                .as_ref()
                .map(|l| format!("{place} at {}:{}", l.file, l.line))
                .unwrap_or_else(|| {
                    if *in_static {
                        " in a static".to_string()
                    } else {
                        " in a constant".to_string()
                    }
                });
            if *only {
                format!(
                    " (dyn: `{ty}`, the only type coerced to `dyn {}`{at})",
                    strip_generics(trait_path)
                )
            } else {
                format!(
                    " (dyn: `{ty}` is coerced to `dyn {}`{at})",
                    strip_generics(trait_path)
                )
            }
        }
        Via::Impl(f) => format!(" (impl: what `{}` writes)", short_fn(f)),
        Via::Table(w) => format!(" (table: stored by `{}`)", short_fn(w)),
        Via::Static(w) => match w.strip_prefix('=') {
            Some(w) => format!(" (static: the value `{}` holds)", short_fn(w)),
            None => format!(" (static: the value `{}` starts with)", short_fn(w)),
        },
        Via::Store { writer, statik } => format!(
            " (static: a value `{}` puts in `{}`)",
            short_fn(writer),
            short_fn(statik)
        ),
        Via::Fixed | Via::Join(_) | Via::Container(_) => String::new(),
    }
}

/// A function's path without its generic arguments (`app::pick` for an instance
/// `app::pick::<app::Fast>`), a trait's implementation with its type and trait (`<app::A as
/// app::Up>::up`), or `static X` for a static's initializer.
pub(crate) fn short_fn(f: &str) -> String {
    match rcbom_facts::owner_static(f) {
        Some((path, _)) if f.starts_with("const ") => format!("const {path}"),
        Some((path, _)) => format!("static {path}"),
        None if f.is_empty() => "a constant expression".to_string(),
        None => fn_name(f),
    }
}

/// `f` without the generic arguments of its path, the qualified self type of an
/// implementation's item kept whole (`<app::W<app::A> as app::Gen>::alg`).
fn fn_name(f: &str) -> String {
    // (an instance's turbofish with its `::`: `app::pick::<app::Fast>` is `app::pick`)
    let f = &f.replace("::<", "<");
    if f.starts_with('<') {
        let mut depth = 0usize;
        for (i, c) in f.char_indices() {
            match c {
                '<' => depth += 1,
                '>' => {
                    depth -= 1;
                    if depth == 0 {
                        return format!("{}{}", &f[..=i], strip_generics(&f[i + 1..]));
                    }
                }
                _ => {}
            }
        }
    }
    strip_generics(f)
}

fn matched(algo: Algo, provider: Option<(String, String)>) -> Match {
    Match {
        name: algo.asset.clone(),
        algo,
        params: Default::default(),
        values: Default::default(),
        components: Default::default(),
        providers: provider.into_iter().collect(),
        provider_crates: Vec::new(),
    }
}

/// `Header.alg`, or the argument.
fn described(f: &FieldRef) -> String {
    match (&f.adt, &f.field) {
        (Some(a), Some(x)) => format!("`{a}.{x}`"),
        _ => format!("argument {}", f.arg),
    }
}

/// The variants (of `accept`, by name) of crate `krate`'s enum that reach the argument or
/// field `f` of the call.
fn members(
    ctx: &Ctx<'_>,
    site: &Site,
    krate: &str,
    f: &FieldRef,
    accept: &BTreeSet<&str>,
    arg_origins: &[Origin],
) -> Found {
    let mut found = Found::default();
    let Some(base) = arg_origins.get(f.arg) else {
        found
            .unresolved
            .push((format!("no argument {}", f.arg), Via::Fixed));
        return found;
    };
    let origin = match (&f.adt, &f.field) {
        (Some(adt), Some(field)) => {
            let prefix = format!("{krate}::");
            let at = ctx.fields.iter().find_map(|(path, names)| {
                (path.starts_with(&prefix) && path.rsplit("::").next() == Some(adt.as_str()))
                    .then(|| {
                        names
                            .iter()
                            .position(|n| n == field)
                            .map(|i| (path.clone(), i))
                    })
                    .flatten()
            });
            let Some((adt, field)) = at else {
                found.unresolved.push((
                    format!("no field `{field}` of a `{adt}` in the facts"),
                    Via::Fixed,
                ));
                return found;
            };
            let mut bases = Vec::new();
            struct_bases(ctx, base, &adt, field, &mut bases, 0);
            for b in bases {
                let (o, via) = match b {
                    Base::Struct(b) => (
                        Origin::Field {
                            adt: adt.clone(),
                            field,
                            base: Box::new(b),
                            args: None,
                        },
                        Via::Fixed,
                    ),
                    Base::Field(v, f) => (v, Via::Object(f)),
                };
                collect(
                    ctx,
                    &o,
                    &site.owner.path,
                    krate,
                    accept,
                    0,
                    false,
                    &via,
                    &mut found,
                );
            }
            return found;
        }
        _ => base.clone(),
    };
    collect(
        ctx,
        &origin,
        &site.owner.path,
        krate,
        accept,
        0,
        false,
        &Via::Fixed,
        &mut found,
    );
    found
}

/// A standard-library function on a standard-library type (or none): `Result::unwrap`,
/// `vec![..]`'s `into_vec`. Not a standard trait's method on another crate's type
/// (`<Header as Default>::default`, `<Algorithm as Clone>::clone`): that crate's code.
fn std_call(krate: &str, self_ty: Option<&str>) -> bool {
    let is_std = |k: &str| matches!(k, "core" | "std" | "alloc");
    let self_krate = |t: &str| {
        let t = t.strip_prefix("dyn ").unwrap_or(t);
        t.split("::").next().unwrap_or(t).to_string()
    };
    is_std(krate) && self_ty.is_none_or(|t| is_std(&self_krate(t)))
}

enum Base {
    /// A value the struct is read from.
    Struct(Origin),
    /// The field's own value, as a function stores it.
    Field(Origin, String),
}

/// Where the field `field` of a struct of type `adt` an argument holds comes from: through
/// standard-library calls that hand the struct on (`DecodingKey::from_ec_pem(pem).unwrap()`);
/// what a function the struct comes from returns, each way it returns (`from_jwk`: `from_rsa_
/// components(..)`, `from_ec_components(..)`, .. or `Ok(DecodingKey { family: Hmac, .. })`;
/// a program's `fn hdr() -> Option<Header>`), its parameters being the call's arguments; what
/// it stores in the field when nothing it returns is recorded; through the struct's own methods
/// called on it by `&mut self` (`v.set_required_spec_claims(..)`, which the origin writes as a
/// call with the value as its receiver), the value before and what the method stores.
fn struct_bases(
    ctx: &Ctx<'_>,
    o: &Origin,
    adt: &str,
    field: usize,
    out: &mut Vec<Base>,
    depth: usize,
) {
    if depth > 8 {
        out.push(Base::Struct(o.clone()));
        return;
    }
    match o {
        // the error a `?` returns, a field-less enum's value (an `ErrorKind`): no struct
        Origin::Call { callee, .. } if callee.ends_with("FromResidual::from_residual") => {}
        Origin::Unit { .. } => {}
        Origin::Call {
            callee,
            krate,
            self_ty,
            args,
            ..
        } if std_call(krate, self_ty.as_deref()) => {
            for a in args {
                struct_bases(ctx, a, adt, field, out, depth + 1);
            }
            // `hdr().unwrap_or_default()`: the type's default where there is no value
            if callee.ends_with("::unwrap_or_default") {
                let default = Origin::Call {
                    callee: "core::default::Default::default".to_string(),
                    krate: "core".to_string(),
                    self_ty: Some(adt.to_string()),
                    args: Vec::new(),
                    span: None,
                    runs: None,
                };
                struct_bases(ctx, &default, adt, field, out, depth + 1);
            }
        }
        // the links read the field from what the function returns in it
        Origin::Call { callee, .. } if ctx.flow.returns_field(callee, field) => {
            out.push(Base::Struct(o.clone()))
        }
        Origin::Call { callee, args, .. } if !ctx.flow.returned(callee).is_empty() => {
            for r in ctx.flow.returned(callee) {
                let r = crate::links::substitute(&r, args);
                struct_bases(ctx, &r, adt, field, out, depth + 1);
            }
        }
        Origin::Call {
            callee,
            self_ty,
            args,
            ..
        } => {
            let stores = ctx.flow.stored_by(adt, field, callee);
            let mutator =
                self_ty.as_deref() == Some(adt) && !ctx.flow.returns_of(callee) && !args.is_empty();
            if !stores.is_empty() {
                out.extend(
                    stores
                        .iter()
                        .map(|v| Base::Field(crate::links::substitute(v, args), callee.clone())),
                );
                if mutator {
                    struct_bases(ctx, &args[0], adt, field, out, depth + 1);
                }
            } else if mutator {
                struct_bases(ctx, &args[0], adt, field, out, depth + 1);
            } else {
                out.push(Base::Struct(o.clone()));
            }
        }
        Origin::Any(xs) => {
            for x in xs {
                struct_bases(ctx, x, adt, field, out, depth + 1);
            }
        }
        _ => out.push(Base::Struct(o.clone())),
    }
}

/// The variant of crate `krate`'s field-less enum whose variants are `accept` that has
/// discriminant `v`.
fn variant(ctx: &Ctx<'_>, krate: &str, accept: &BTreeSet<&str>, v: i128) -> Option<String> {
    let prefix = format!("{krate}::");
    ctx.variants
        .iter()
        .filter(|(path, vs)| {
            path.starts_with(&prefix) && vs.iter().all(|(n, _)| accept.contains(n.as_str()))
        })
        .find_map(|(_, vs)| vs.iter().find(|(_, d)| *d == v).map(|(n, _)| n.clone()))
}

#[allow(clippy::too_many_arguments)]
fn collect(
    ctx: &Ctx<'_>,
    o: &Origin,
    owner: &str,
    krate: &str,
    accept: &BTreeSet<&str>,
    depth: usize,
    in_std: bool,
    via: &Via,
    out: &mut Found,
) {
    if depth > 12 {
        out.unresolved
            .push(("a chain of values too long".into(), via.clone()));
        return;
    }
    match o {
        Origin::Unit { path, .. } if path.starts_with(&format!("{krate}::")) => {
            let v = path.rsplit("::").next().unwrap_or(path);
            if accept.contains(v) {
                out.add(v.to_string(), via);
            }
        }
        // a constant of the enum (`const ALG: Algorithm = Algorithm::ES384`): its discriminant
        Origin::Data { value: Some(v), .. } if variant(ctx, krate, accept, *v).is_some() => {
            if let Some(n) = variant(ctx, krate, accept, *v) {
                out.add(n, via);
            }
        }
        // another value (`Option::None`, a length): not one of the variants
        Origin::Unit { .. } | Origin::Const { .. } => {}
        // a value written into an element of the list (`v.algorithms[0] = HS256`): in the list
        // beside the others
        Origin::Any(xs)
            if xs.iter().any(
                |x| matches!(x, Origin::Through { callee } if callee == rcbom_facts::ELEMENT_WRITE),
            ) =>
        {
            let by = via.then(Via::Container(owner.to_string()));
            for x in xs {
                if !matches!(x, Origin::Through { .. }) {
                    collect(ctx, x, owner, krate, accept, depth, in_std, &by, out);
                }
            }
        }
        Origin::Any(xs) | Origin::All(xs) => {
            for x in xs {
                collect(ctx, x, owner, krate, accept, depth, in_std, via, out);
            }
        }
        Origin::Set { value, .. } => {
            collect(ctx, value, owner, krate, accept, depth, in_std, via, out)
        }
        // a standard-library call passes its arguments' values on (`vec![alg]`, `alg.clone()`,
        // `Ok(key).map_err(..)`)
        Origin::Call {
            callee,
            krate: k,
            self_ty,
            args,
            ..
        } if std_call(k, self_ty.as_deref()) => {
            // a read from a container (`map[kid]`, `v.get(i)`) gives what it holds, not the key
            let read = ["Index::index", "IndexMut::index_mut", "::get", "::get_mut"]
                .iter()
                .any(|m| strip_generics(callee).ends_with(m));
            let args = if read {
                &args[..args.len().min(1)]
            } else {
                &args[..]
            };
            // what a container's method put in it (`map.insert(kid, (HS512, secret))`, the
            // value, not the key): one of the values it holds, possible at a read of it; a
            // list extended (`v.push(x)`, `extend_from_slice(&[x])`, `append`) holds the values
            // it held beside the new ones
            let bare = strip_generics(callee);
            // a list replaced by another's values (`algorithms.clone_from(&other)`): those
            if bare.ends_with("Clone::clone_from") && args.len() == 2 {
                let by = via.then(Via::Container(bare.clone()));
                collect(
                    ctx,
                    &args[1],
                    owner,
                    krate,
                    accept,
                    depth + 1,
                    true,
                    &by,
                    out,
                );
                return;
            }
            let extend = [
                "::extend_from_slice",
                "::append",
                "Extend::extend",
                "::resize",
            ]
            .iter()
            .any(|m| bare.ends_with(m));
            // (`fill`: every element of the list set to the value, `v.algorithms.fill(HS256)`)
            let store = crate::provenance::container_store(callee)
                || extend
                || bare.ends_with("slice::fill");
            let map = store && bare.ends_with("Map::insert");
            let list = store && !map && !bare.ends_with("Set::insert");
            // the elements of a list literal (`vec![a, b]`, `Vec::from([a, b])`, `[a,
            // b].to_vec()`): each in the list beside the others
            let builds_list = callee.contains("into_vec")
                || bare.contains("::Vec")
                || self_ty.as_deref().is_some_and(|t| t.ends_with("::Vec"))
                || bare.contains("slice::")
                || bare.ends_with("::to_vec")
                || bare.ends_with("::collect")
                || extend;
            // (an array literal through iterator adaptors: `[a, b].into_iter().collect()`)
            fn literal(o: &Origin, depth: usize) -> Option<&Vec<Origin>> {
                match o {
                    Origin::All(xs) => Some(xs),
                    Origin::Call {
                        callee,
                        krate,
                        args,
                        ..
                    } if depth < 4
                        && matches!(krate.as_str(), "core" | "std" | "alloc")
                        && ["::into_iter", "::iter", "::copied", "::cloned", "::into"]
                            .iter()
                            .any(|m| strip_generics(callee).ends_with(m)) =>
                    {
                        literal(args.first()?, depth + 1)
                    }
                    _ => None,
                }
            }
            if let Some(xs) = args
                .iter()
                .find_map(|a| (builds_list && !read).then(|| literal(a, 0)).flatten())
            {
                // (the elements, nested in the box's parts: `All[new_uninit(), All[a, b]]`)
                fn elements<'o>(xs: &'o [Origin], out: &mut Vec<&'o Origin>) {
                    for x in xs {
                        match x {
                            Origin::All(inner) => elements(inner, out),
                            Origin::Call { krate, .. } if krate == "alloc" => {}
                            _ => out.push(x),
                        }
                    }
                }
                let mut elems = Vec::new();
                elements(xs, &mut elems);
                if elems.len() > 1 {
                    let name = if callee.contains("into_vec") {
                        "vec![..]".to_string()
                    } else {
                        bare.clone()
                    };
                    let by = via.then(Via::Container(name));
                    for x in elems {
                        collect(ctx, x, owner, krate, accept, depth + 1, true, &by, out);
                    }
                    for a in args.iter().filter(|a| !matches!(a, Origin::All(_))) {
                        let by = if list { by.clone() } else { via.clone() };
                        collect(ctx, a, owner, krate, accept, depth + 1, true, &by, out);
                    }
                    return;
                }
            }
            for (i, a) in args.iter().enumerate() {
                if map && i == 1 {
                    continue;
                }
                // a list extended with values the facts give as data (`extend_from_slice(&[
                // Algorithm::HS256])`, a constant slice): which ones is not known
                if list && i > 0 && matches!(a, Origin::Const { value: None, .. }) {
                    out.unresolved.push((
                        "values added to the list the analysis does not follow".into(),
                        via.clone(),
                    ));
                    continue;
                }
                let by = if store && i > 0 {
                    via.then(Via::Container(bare.clone()))
                } else if store && list {
                    via.then(Via::Container(format!("+{bare}")))
                } else {
                    via.clone()
                };
                collect(ctx, a, owner, krate, accept, depth + 1, true, &by, out);
            }
        }
        // more alternatives, or steps, than the search keeps
        Origin::Truncated => out
            .unresolved
            .push(("the search for the value hit its bound".into(), via.clone())),
        // inside a standard-library call, what is not followed is the container's own (its
        // capacity, its allocation), not the values it holds; but a value written through a
        // borrow a call returned (`keyring.insert(..)` into a map's entry) is one it holds
        Origin::Through { .. } if in_std => out.unresolved.push((
            "a value written into a container the analysis does not follow".into(),
            via.clone(),
        )),
        Origin::Unknown | Origin::Loop if in_std => {}
        Origin::Unknown | Origin::Loop | Origin::Through { .. } => {
            out.unresolved.push((unresolved_reason(o), via.clone()))
        }
        // a parameter, a field, a call's result: what reaches it from elsewhere
        _ => match ctx.flow.values_via(o, owner) {
            Some(vs) if !(vs.len() == 1 && vs[0].0 == *o) => {
                for (v, w, by) in vs {
                    // the value itself among others (a call through a trait object, one of
                    // whose types' results is not followed): not followed
                    let by = via.then(by);
                    if v == *o && w == owner {
                        out.unresolved.push((unresolved_reason(o), by));
                        continue;
                    }
                    collect(ctx, &v, &w, krate, accept, depth + 1, in_std, &by, out);
                }
            }
            _ => out.unresolved.push((unresolved_reason(o), via.clone())),
        },
    }
}
