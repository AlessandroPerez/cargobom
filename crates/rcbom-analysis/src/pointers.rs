//! Calls through function pointers. A call whose pointer the driver could not follow inside
//! its body (`(h.f)(..)`, a parameter, a returned pointer) is a `Pointer` site with the
//! pointer's origin; followed across functions (`links`), the origin leads to the functions
//! named as values (`Origin::Unit` with the position of a `Call::value` site). Each becomes a
//! call of that function at the pointer call, with the pointer call's arguments, as when the
//! driver follows the pointer itself (`Call::through`). The naming is then no occurrence of its
//! own: the function runs at the call.

use std::collections::{HashMap, HashSet};

use rcbom_facts::{CrateFacts, Loc, Origin, Site, Target};

use crate::links::LinkIndex;

/// A function named as a value: (where, its defining path).
pub(crate) type Naming = (Loc, String);

/// The calls made through pointers, as call sites of each crate (by index into `facts`), and
/// the namings these calls account for.
pub(crate) fn resolve(facts: &[CrateFacts], flow: &LinkIndex) -> (Vec<Vec<Site>>, HashSet<Naming>) {
    let mut values: HashMap<(&Loc, &str), &Site> = HashMap::new();
    for s in facts.iter().flat_map(|f| &f.sites) {
        if let Target::Call {
            callee,
            value: true,
            ..
        } = &s.target
        {
            values.insert((&s.span, callee.path.as_str()), s);
        }
    }
    let mut out = vec![Vec::new(); facts.len()];
    let mut used = HashSet::new();
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
                } => {
                    let found = flow
                        .values(origin, &s.owner.path)
                        .unwrap_or_else(|| vec![(origin.clone(), s.owner.path.clone())]);
                    let mut named = Vec::new();
                    for (v, _) in &found {
                        functions(v, &mut named);
                    }
                    named.sort();
                    named.dedup();
                    for (at, path) in named {
                        let Some(v) = values.get(&(at, path)) else {
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
                        used.insert((at.clone(), path.to_string()));
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
    (out, used)
}

/// The functions named as values that `o` can be: (where named, defining path).
fn functions<'o>(o: &'o Origin, out: &mut Vec<(&'o Loc, &'o str)>) {
    match o {
        Origin::Unit {
            path,
            span: Some(at),
            ..
        } => out.push((at, path)),
        Origin::Any(alts) | Origin::All(alts) => {
            for a in alts {
                functions(a, out);
            }
        }
        Origin::Set { value, .. } => functions(value, out),
        _ => {}
    }
}

/// Is `site` a naming that a call through a pointer accounts for?
pub(crate) fn accounted(site: &Site, used: &HashSet<Naming>) -> bool {
    matches!(&site.target, Target::Call { callee, value: true, .. }
        if used.contains(&(site.span.clone(), callee.path.clone())))
}
