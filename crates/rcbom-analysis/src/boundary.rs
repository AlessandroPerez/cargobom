//! Boundary models (`[[boundary]]`): a protocol crate's API whose algorithm is a value the
//! program chooses (jsonwebtoken's `encode(&header, ..)` signs with `header.alg`). The call is
//! reported with the variants of the algorithm enum (`[[enum]]`) that reach the argument, or
//! the field of the struct behind it, followed across functions (`links`); several are a
//! candidate set chosen at run time (`selector: configuration`). A member the analysis cannot
//! follow makes the call an unknown algorithm too, unless the variants found are already all
//! of the enum's. A key's family enum (`key`) narrows the variants: jsonwebtoken refuses an
//! algorithm whose family is not the key's.

use std::collections::BTreeSet;

use rcbom_facts::{Origin, Site, Target};
use rcbom_kb::{Algo, FieldRef};

use crate::matcher::{Match, strip_generics};
use crate::{Ctx, Kind, SiteMatch, UNKNOWN, unresolved_reason};

/// What reaches an argument: the variants found, and why some members were not followed.
#[derive(Default)]
struct Found {
    names: BTreeSet<String>,
    unresolved: Vec<String>,
}

/// The occurrences of a call a boundary model describes; `None` when none does.
pub(crate) fn site_matches(ctx: &Ctx<'_>, site: &Site) -> Option<Vec<SiteMatch>> {
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
    let e = ctx.kb.enums.iter().find(|e| e.name == b.enumeration)?;
    let all: BTreeSet<&str> = e.variants.keys().map(String::as_str).collect();
    // the variants the call can use: those the key's family allows
    let mut possible = all.len();
    let mut found = members(ctx, site, &b.krate, &b.algorithm, &all, arg_origins);
    let what = described(&b.algorithm);
    let mut detail = Vec::new();
    // the key's family allows some of them
    if let Some(k) = &b.key {
        let families: BTreeSet<&str> = e
            .variants
            .values()
            .filter_map(|v| v.key.as_deref())
            .collect();
        let key = members(ctx, site, &b.krate, k, &families, arg_origins);
        if key.unresolved.is_empty() && !key.names.is_empty() {
            let allowed = |n: &str| {
                e.variants[n]
                    .key
                    .as_ref()
                    .is_none_or(|f| key.names.contains(f))
            };
            let before = found.names.len();
            found.names.retain(|n| allowed(n));
            possible = all.iter().filter(|n| allowed(n)).count();
            // none the key allows (`Validation::new(HS256)` with an RSA key): jsonwebtoken
            // refuses the token before any verification
            if before > 0 && found.names.is_empty() && found.unresolved.is_empty() {
                return Some(Vec::new());
            }
            detail.push(format!(
                "the key's family ({}) allows these",
                key.names.iter().cloned().collect::<Vec<_>>().join(", ")
            ));
        }
    }
    let provider = ctx.package_of_crate(&callee.krate.name, &callee.krate.stable_id);
    let symbol = callee.path.clone();
    let n = found.names.len();
    let mut out = Vec::new();
    for name in &found.names {
        let algo = e.variants[name].algo.clone();
        let function = ctx
            .kb
            .use_of(&b.function, &algo.primitive)
            .unwrap_or_else(|| b.function.clone());
        let mut d = vec![if n > 1 {
            format!("algorithm one of {n} chosen at run time (selector: configuration) from {what}")
        } else {
            format!("algorithm from {what}")
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
        let reasons: BTreeSet<String> = found.unresolved.into_iter().collect();
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
        found.unresolved.push(format!("no argument {}", f.arg));
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
                found
                    .unresolved
                    .push(format!("no field `{field}` of a `{adt}` in the facts"));
                return found;
            };
            let mut bases = Vec::new();
            struct_bases(ctx, base, &adt, field, &mut bases, 0);
            for b in bases {
                let o = match b {
                    Base::Struct(b) => Origin::Field {
                        adt: adt.clone(),
                        field,
                        base: Box::new(b),
                        args: None,
                    },
                    Base::Field(v) => v,
                };
                collect(
                    ctx,
                    &o,
                    &site.owner.path,
                    krate,
                    accept,
                    0,
                    false,
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
        &mut found,
    );
    found
}

/// A standard-library function on a standard-library type (or none): `Result::unwrap`,
/// `vec![..]`'s `into_vec`. Not a standard trait's method on another crate's type
/// (`<Header as Default>::default`, `<Algorithm as Clone>::clone`): that crate's code.
fn std_call(krate: &str, self_ty: Option<&str>) -> bool {
    let is_std = |k: &str| matches!(k, "core" | "std" | "alloc");
    is_std(krate) && self_ty.is_none_or(|t| is_std(t.split("::").next().unwrap_or(t)))
}

enum Base {
    /// A value the struct is read from.
    Struct(Origin),
    /// The field's own value.
    Field(Origin),
}

/// Where the field `field` of a struct of type `adt` an argument holds comes from: through
/// standard-library calls that hand the struct on (`DecodingKey::from_ec_pem(pem).unwrap()`);
/// what a function the struct comes from stores in the field when what it returns is no
/// summary of the field (`from_ec_pem` builds `Ok(DecodingKey { family: Ec, .. })`), its
/// parameters being the call's arguments; through the struct's own methods called on it by
/// `&mut self` (`v.set_required_spec_claims(..)`, which the origin writes as a call with the
/// value as its receiver), the value before and what the method stores.
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
        Origin::Call {
            krate,
            self_ty,
            args,
            ..
        } if std_call(krate, self_ty.as_deref()) => {
            for a in args {
                struct_bases(ctx, a, adt, field, out, depth + 1);
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
            if !stores.is_empty() && !ctx.flow.returns_field(callee, field) {
                out.extend(
                    stores
                        .iter()
                        .map(|v| Base::Field(crate::links::substitute(v, args))),
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

#[allow(clippy::too_many_arguments)]
fn collect(
    ctx: &Ctx<'_>,
    o: &Origin,
    owner: &str,
    krate: &str,
    accept: &BTreeSet<&str>,
    depth: usize,
    in_std: bool,
    out: &mut Found,
) {
    if depth > 12 {
        out.unresolved.push("a chain of values too long".into());
        return;
    }
    match o {
        Origin::Unit { path, .. } if path.starts_with(&format!("{krate}::")) => {
            let v = path.rsplit("::").next().unwrap_or(path);
            if accept.contains(v) {
                out.names.insert(v.to_string());
            }
        }
        // another value (`Option::None`, a length): not one of the variants
        Origin::Unit { .. } | Origin::Const { .. } => {}
        Origin::Any(xs) | Origin::All(xs) => {
            for x in xs {
                collect(ctx, x, owner, krate, accept, depth, in_std, out);
            }
        }
        Origin::Set { value, .. } => collect(ctx, value, owner, krate, accept, depth, in_std, out),
        // a standard-library call passes its arguments' values on (`vec![alg]`, `alg.clone()`,
        // `Ok(key).map_err(..)`)
        Origin::Call {
            krate: k,
            self_ty,
            args,
            ..
        } if std_call(k, self_ty.as_deref()) => {
            for a in args {
                collect(ctx, a, owner, krate, accept, depth + 1, true, out);
            }
        }
        Origin::Truncated => out
            .unresolved
            .push("a choice among more alternatives than the analysis keeps".into()),
        // inside a standard-library call, what is not followed is the container's own (its
        // capacity, its allocation), not the values it holds
        Origin::Unknown | Origin::Loop | Origin::Through { .. } if in_std => {}
        Origin::Unknown | Origin::Loop | Origin::Through { .. } => {
            out.unresolved.push(unresolved_reason(o))
        }
        // a parameter, a field, a call's result: what reaches it from elsewhere
        _ => match ctx.flow.values(o, owner) {
            Some(vs) if !(vs.len() == 1 && vs[0].0 == *o) => {
                for (v, w) in vs {
                    collect(ctx, &v, &w, krate, accept, depth + 1, in_std, out);
                }
            }
            _ => out.unresolved.push(unresolved_reason(o)),
        },
    }
}
