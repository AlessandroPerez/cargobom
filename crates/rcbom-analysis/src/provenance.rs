//! Provenance of key material: the knowledge base's roles say which argument of an API is a
//! key, nonce, salt...; the driver's origin tree says where that argument came from inside
//! the enclosing function; the knowledge base's sources classify it.

use std::collections::BTreeSet;

use rcbom_facts::{Origin, Target};
use rcbom_kb::Kb;

/// What a value was found to come from, with a short human-readable trace.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Class {
    /// `hard-coded`, `parameter`, `environment`, `file`, `rng`, `derived`, `computed`, `unknown`
    pub kind: String,
    pub detail: String,
}

/// Key material arguments of a call, with the classes of their origins: (role, classes).
pub fn of_call(kb: &Kb, target: &Target) -> Vec<(String, BTreeSet<Class>)> {
    let Target::Call {
        callee,
        arg_origins,
        arg_lens,
        ..
    } = target
    else {
        return Vec::new();
    };
    let path = strip_generics(&callee.path);
    let mut out = Vec::new();
    for r in kb
        .roles
        .iter()
        .filter(|r| r.pattern.is_match(&path) || r.pattern.is_match(&callee.path))
    {
        for (i, role) in &r.args {
            if let Some(o) = arg_origins.get(*i) {
                let mut classes = BTreeSet::new();
                classify(kb, o, 0, &mut classes);
                // a hard-coded array whose length the type gives: say so
                if let Some(Some(n)) = arg_lens.get(*i) {
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

fn classify(kb: &Kb, o: &Origin, depth: usize, out: &mut BTreeSet<Class>) {
    let class = |kind: &str, detail: String| Class {
        kind: kind.to_string(),
        detail,
    };
    if depth > 8 {
        out.insert(class("unknown", String::new()));
        return;
    }
    match o {
        Origin::Const { len, span, .. } => {
            let mut d = Vec::new();
            if let Some(n) = len {
                d.push(format!("{n} bytes"));
            }
            if let Some(s) = span {
                d.push(format!("literal at line {}", s.line));
            }
            out.insert(class("hard-coded", d.join(", ")));
        }
        // a static or const that is not an algorithm descriptor: data compiled in
        Origin::Data { def } => {
            out.insert(class("hard-coded", format!("static {}", short(&def.path))));
        }
        Origin::Param { index } => {
            out.insert(class(
                "parameter",
                format!("argument {index} of the enclosing function"),
            ));
        }
        Origin::Call {
            callee,
            krate,
            args,
        } => {
            let path = strip_generics(callee);
            if let Some(s) = kb
                .sources
                .iter()
                .find(|s| s.pattern.is_match(&path) || s.pattern.is_match(callee))
            {
                out.insert(class(&s.kind, short(&path)));
            } else if kb.fns.iter().any(|f| {
                f.algo.primitive == "kdf"
                    && f.krates.contains(krate)
                    && f.pattern.is_match(last(&path))
            }) {
                out.insert(class("derived", short(&path)));
            } else if args.is_empty() {
                // returned by code that takes nothing from here: an interprocedural question
                out.insert(class("computed", short(&path)));
            } else {
                // plumbing and wrappers (`as_bytes`, `unwrap`, `SaltString::encode_b64`,
                // `Nonce::assume_unique_for_key`): the value comes from the arguments. Indexing
                // and slicing take their data from the receiver only (`&key[..32]`: the range
                // is not key material).
                // In the standard library the value comes from the receiver (`expect(msg)`,
                // `ok_or(err)`, `map_err(f)`, `&key[..32]`), except for the fallbacks that can
                // supply it from another argument (`unwrap_or_else(|_| "literal")`). Elsewhere
                // (wrappers like `SaltString::encode_b64`) every argument may contribute.
                let std = matches!(krate.as_str(), "core" | "std" | "alloc");
                let receiver_only = INDEXING.iter().any(|m| path.ends_with(m))
                    || (std && !FALLBACKS.iter().any(|m| path.ends_with(m)));
                for a in args.iter().take(if receiver_only { 1 } else { args.len() }) {
                    classify(kb, a, depth + 1, out);
                }
            }
        }
        Origin::Any(alts) => alts.iter().for_each(|a| classify(kb, a, depth + 1, out)),
        Origin::Unknown => {}
    }
}

/// Algorithm descriptor statics reachable in a call's argument origins: the
/// `&AES_256_GCM` behind `k` in `k.seal_in_place_append_tag(..)`.
pub fn data_in_args(target: &Target) -> Vec<rcbom_facts::DefRef> {
    let Target::Call { arg_origins, .. } = target else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for o in arg_origins {
        collect_data(o, 0, &mut out);
    }
    out
}

fn collect_data(o: &Origin, depth: usize, out: &mut Vec<rcbom_facts::DefRef>) {
    if depth > 8 {
        return;
    }
    match o {
        Origin::Data { def } if !out.contains(def) => out.push(def.clone()),
        Origin::Call { args, .. } => args.iter().for_each(|a| collect_data(a, depth + 1, out)),
        Origin::Any(alts) => alts.iter().for_each(|a| collect_data(a, depth + 1, out)),
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
}
