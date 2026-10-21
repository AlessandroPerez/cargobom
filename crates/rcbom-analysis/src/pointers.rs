//! Calls through function pointers. A call whose pointer the driver could not follow inside
//! its body (`(h.f)(..)`, a parameter, a returned pointer) is a `Pointer` site with the
//! pointer's origin; followed across functions (`links`), the origin leads to the functions
//! named as values (`Origin::Unit` with the position of a `Call::value` site). Each becomes a
//! call of that function at the pointer call, with the pointer call's arguments, as when the
//! driver follows the pointer itself (`Call::through`). The naming is then no occurrence of its
//! own: the function runs at the call.

use std::collections::{HashMap, HashSet};

use rcbom_facts::{CrateFacts, FnShape, Loc, Origin, OwnerKind, Site, Target};

use crate::links::LinkIndex;

/// A function named as a value: (where, its defining path).
pub(crate) type Naming = (Loc, String);

/// A call through a pointer of a function no value site names (the program's own): (callee,
/// caller, arguments), for the links' calls, so that its parameters get the arguments.
pub(crate) type PointerCall = (String, String, Vec<Origin>);

/// The calls made through pointers, as call sites of each crate (by index into `facts`), the
/// namings these calls account for, and the calls of functions with no value site.
pub(crate) fn resolve(
    facts: &[CrateFacts],
    flow: &LinkIndex,
) -> (Vec<Vec<Site>>, HashSet<Naming>, Vec<PointerCall>) {
    let mut values: HashMap<(&Loc, &str), &Site> = HashMap::new();
    // the functions a static's initializer names (`static H: fn(..) = digest::digest`), by the
    // static's id
    let mut in_statics: HashMap<&str, Vec<(Loc, String)>> = HashMap::new();
    for s in facts.iter().flat_map(|f| &f.sites) {
        if let Target::Call {
            callee,
            value: true,
            ..
        } = &s.target
        {
            values.insert((&s.span, callee.path.as_str()), s);
            if s.owner.kind == OwnerKind::Static {
                in_statics
                    .entry(s.owner.id.as_str())
                    .or_default()
                    .push((s.span.clone(), callee.path.clone()));
            }
        }
    }
    let mut out = vec![Vec::new(); facts.len()];
    let mut used = HashSet::new();
    let mut calls = Vec::new();
    // the pointer calls that may run functions not named where the pointer comes from, and the
    // pointers handed to code not followed: (function, number of parameters)
    let mut opened: Vec<(String, usize, String)> = facts
        .iter()
        .flat_map(|f| &f.links.opaque)
        .map(|a| (a.func.clone(), a.arity, a.sig.clone()))
        .collect();
    for (i, f) in facts.iter().enumerate() {
        for s in &f.sites {
            match &s.target {
                // a pointer the driver followed: its naming is accounted for
                Target::Call {
                    callee,
                    through: Some(t),
                    ..
                } => {
                    used.insert((t.clone(), callee.path.clone()));
                }
                Target::Pointer {
                    origin,
                    const_args,
                    arg_origins,
                    arg_lens,
                    sig,
                } => {
                    let found = flow
                        .values(origin, &s.owner.path)
                        .unwrap_or_else(|| vec![(origin.clone(), s.owner.path.clone())]);
                    let mut named = Vec::new();
                    let mut open = false;
                    for (v, w) in &found {
                        open |= !functions(v, w, &in_statics, flow, 0, Walk::default(), &mut named);
                    }
                    named.sort();
                    named.dedup();
                    // a pointer that may be a function not named here: any function of the
                    // program made a pointer of its type may run with these values (not one
                    // in the standard library's own code, `<Box<F> as Fn<A>>::call`: what it
                    // calls is what the program's call through the box calls, or what the
                    // program handed it, followed there)
                    if open && !is_std(&s.owner.krate.name) {
                        if std::env::var_os("RCBOM_DEBUG").is_some() {
                            eprintln!(
                                "analysis: pointer call in {} at {}:{} not all followed: {}",
                                s.owner.path,
                                s.span.line,
                                s.span.col,
                                serde_json::to_string(
                                    &found.iter().map(|f| &f.0).collect::<Vec<_>>()
                                )
                                .unwrap_or_default()
                                .chars()
                                .take(1500)
                                .collect::<String>()
                            );
                        }
                        opened.push((
                            s.owner.path.clone(),
                            arg_origins.len(),
                            sig.clone().unwrap_or_else(|| "*".into()),
                        ));
                    }
                    for (at, path) in named {
                        // a function no value site names (the program's own): its parameters
                        // receive the call's arguments
                        let Some(v) = values.get(&(&at, path.as_str())) else {
                            calls.push((path, s.owner.path.clone(), arg_origins.clone()));
                            continue;
                        };
                        let Target::Call {
                            callee,
                            method,
                            self_ty,
                            args,
                            ..
                        } = &v.target
                        else {
                            continue;
                        };
                        used.insert((at.clone(), path.clone()));
                        out[i].push(Site {
                            target: Target::Call {
                                callee: callee.clone(),
                                method: method.clone(),
                                self_ty: self_ty.clone(),
                                args: args.clone(),
                                const_args: const_args.clone(),
                                arg_origins: arg_origins.clone(),
                                arg_lens: arg_lens.clone(),
                                through: Some(at.clone()),
                                value: false,
                            },
                            ..s.clone()
                        });
                    }
                }
                _ => {}
            }
        }
    }
    // each of the program's functions made a pointer is called there with values not followed
    opened.sort();
    opened.dedup();
    let named: HashSet<&FnShape> = facts.iter().flat_map(|f| &f.links.named).collect();
    for (caller, n, sig) in &opened {
        for f in &named {
            let typed = sig == "*" || f.sig == "*" || *sig == f.sig;
            if typed && (*n == usize::MAX || *n == f.arity) {
                calls.push((
                    f.func.clone(),
                    caller.clone(),
                    vec![Origin::Unknown; f.arity],
                ));
            }
        }
    }
    (out, used, calls)
}

/// The functions named as values that `o` can be: (where named, defining path); through the
/// standard library's containers and wrappers (`vec![f][0]`, `Some(f)`), what a closure
/// returns (`(|| digest::digest as HashFn)()`), and statics holding one (`static H: fn(..) =
/// digest::digest`, the program's `static MY: HashFn = my`, `static B: &HashFn = &A`).
///
/// Whether that is all it can be: `false` when it meets a value not followed (`Unknown`, a
/// parameter or a field not resolved, a call whose code is not followed), which may be any
/// function made a pointer. A closure is one (its parameters get values not followed where it
/// is made a pointer: the driver's escape); what it returns counts only where it is called
/// (`returns`, under `Fn::call`).
fn functions(
    o: &Origin,
    owner: &str,
    in_statics: &HashMap<&str, Vec<(Loc, String)>>,
    flow: &LinkIndex,
    depth: usize,
    walk: Walk,
    out: &mut Vec<(Loc, String)>,
) -> bool {
    if depth > 8 {
        return false;
    }
    let go = |o: &Origin, walk: Walk, out: &mut Vec<(Loc, String)>| {
        functions(o, owner, in_statics, flow, depth + 1, walk, out)
    };
    let alts = Walk {
        returns: false,
        alternatives: true,
    };
    match o {
        Origin::Unit {
            path,
            span: Some(at),
            ..
        } => {
            out.push((at.clone(), path.clone()));
            true
        }
        // a variant or a field-less value, a constant: no function
        Origin::Unit { span: None, .. } | Origin::Const { .. } => true,
        // as the value search reads them: an iterator advanced by `next`, the marker of a value
        // written into an element (the elements are followed beside it), the value's own
        // earlier value among alternatives
        Origin::Through { callee }
            if callee.ends_with("Iterator::next")
                || rcbom_facts::element_writer(callee).is_some() =>
        {
            true
        }
        Origin::Loop => walk.alternatives,
        Origin::Any(vs) | Origin::All(vs) => {
            let mut all = true;
            for a in vs {
                all &= go(a, alts, out);
            }
            all
        }
        Origin::Set { value, .. } => go(value, walk, out),
        Origin::Call { callee, args, .. } if callee == "<closure>" => {
            let mut all = true;
            for a in args {
                all &= go(
                    a,
                    Walk {
                        returns: false,
                        ..walk
                    },
                    out,
                );
            }
            all || !walk.returns
        }
        Origin::Call {
            callee,
            krate,
            args,
            ..
        } if matches!(krate.as_str(), "core" | "std" | "alloc") => {
            let calls = callee.ends_with("::call")
                || callee.ends_with("::call_mut")
                || callee.ends_with("::call_once");
            let mut all = true;
            for a in args {
                all &= go(
                    a,
                    Walk {
                        returns: calls,
                        ..walk
                    },
                    out,
                );
            }
            all
        }
        // (one whose value is not recorded, `static D: &dyn Fn(D) = &h`, may be any)
        Origin::Data { def, .. } => {
            let named = in_statics.get(def.id.as_str());
            out.extend(named.into_iter().flatten().cloned());
            let values = flow.static_values(&def.id);
            let mut all = flow.mutable_static(&def.id).is_none()
                && (named.is_some_and(|n| !n.is_empty()) || !values.is_empty());
            for v in values {
                all &= go(v, Walk::default(), out);
            }
            all
        }
        // a parameter, a field, a call of the program's function inside the value (`next(&mut
        // into_iter(fs))`): what it is where it comes from, each read in its own function
        _ => match flow.values(o, owner) {
            Some(vs) if !vs.is_empty() => {
                let mut all = true;
                for (v, w) in &vs {
                    all &= functions(v, w, in_statics, flow, depth + 1, Walk::default(), out);
                }
                all
            }
            _ => false,
        },
    }
}

/// Where `functions` is in a value: under a call of it (what a closure returns is the
/// pointer), among alternatives (a loop's own earlier value is one of them, as the value
/// search counts them: inside calls too).
#[derive(Clone, Copy, Default)]
struct Walk {
    returns: bool,
    alternatives: bool,
}

fn is_std(krate: &str) -> bool {
    matches!(krate, "core" | "std" | "alloc")
}

/// Is `site` a naming that a call through a pointer accounts for?
pub(crate) fn accounted(site: &Site, used: &HashSet<Naming>) -> bool {
    matches!(&site.target, Target::Call { callee, value: true, .. }
        if used.contains(&(site.span.clone(), callee.path.clone())))
}
