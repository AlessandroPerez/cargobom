//! Values across functions, from the facts' `links`: what a struct field holds (any value
//! stored in it in the build), what a call of the program's own function returns, what a
//! parameter receives (any argument its callers pass), what a mutable static holds at run time.
//! Flow- and context-insensitive, and used where the function-local origin ends: to find the
//! algorithm a call uses when its key or algorithm comes from a field or another function
//! (`self.inner.sign(..)`, rustls's record keys), and the provenance of a static set at run
//! time.
//!
//! A read of a field inside a field (`self.0.0`, an `AeadAlgorithm` inside a
//! `Chacha20Poly1305Aead`) is looked up whole first: what the program stores there through the
//! outer struct (`Chacha20Poly1305Aead(AeadAlgorithm(&CHACHA20_POLY1305))`), not everything any
//! `AeadAlgorithm` holds.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;

use rcbom_facts::{CrateFacts, Origin};

#[derive(Default)]
pub struct LinkIndex {
    /// By struct and field path.
    fields: HashMap<(String, Vec<usize>), Vec<Stored>>,
    /// By function and part of the returned value.
    returns: HashMap<(String, Vec<usize>), Vec<Origin>>,
    /// By function called: its callers, with the arguments they pass.
    calls: HashMap<String, Vec<(String, Vec<Origin>)>>,
    /// By def id: (contents change at run time, values put there).
    statics: HashMap<String, (bool, Vec<Origin>)>,
    /// Lookups left for the current `values` call.
    budget: Cell<usize>,
    /// Answers already given: the same field is read at many calls.
    memo: RefCell<HashMap<(Origin, String), Values>>,
    /// For the current question: the functions each descriptor found was named in (`""`: a
    /// static's initializer, or what a static holds at run time).
    named_in: RefCell<HashMap<String, std::collections::BTreeSet<String>>>,
}

type Values = Option<Vec<(Origin, String)>>;

#[derive(PartialEq)]
struct Stored {
    value: Origin,
    /// The function storing it, whose parameters `value` names.
    func: String,
    /// Stored in a struct reached through a reference, which may be a part of another one.
    via_ref: bool,
}

/// Values found per lookup, lookups chained, and lookups per question.
const MAX_VALUES: usize = 64;
const MAX_DEPTH: usize = 10;
const MAX_STEPS: usize = 4096;

/// A field read, from the outermost struct in: (struct, field).
type FieldPath = [(String, usize)];

impl LinkIndex {
    pub fn new(facts: &[CrateFacts]) -> LinkIndex {
        let mut ix = LinkIndex::default();
        for f in facts {
            for s in &f.links.fields {
                let v = ix
                    .fields
                    .entry((s.adt.clone(), s.path.clone()))
                    .or_default();
                let stored = Stored {
                    value: s.value.clone(),
                    func: s.func.clone(),
                    via_ref: s.via_ref,
                };
                if !v.contains(&stored) {
                    v.push(stored);
                }
            }
            for r in &f.links.returns {
                let v = ix
                    .returns
                    .entry((r.func.clone(), r.path.clone()))
                    .or_default();
                if !v.contains(&r.value) {
                    v.push(r.value.clone());
                }
            }
            for c in &f.links.calls {
                let v = ix.calls.entry(c.callee.clone()).or_default();
                let call = (c.caller.clone(), c.args.clone());
                if !v.contains(&call) {
                    v.push(call);
                }
            }
            for s in &f.links.statics {
                let e = ix.statics.entry(s.def.id.clone()).or_default();
                e.0 |= s.mutable;
                for v in &s.values {
                    if !e.1.contains(v) {
                        e.1.push(v.clone());
                    }
                }
            }
        }
        ix
    }

    /// Notes that descriptor `id` was found named in function `owner`.
    pub fn note(&self, id: &str, owner: &str) {
        self.named_in
            .borrow_mut()
            .entry(id.to_string())
            .or_default()
            .insert(owner.to_string());
    }

    /// The functions noted since the last call, by descriptor.
    pub fn take_named(&self) -> HashMap<String, std::collections::BTreeSet<String>> {
        std::mem::take(&mut *self.named_in.borrow_mut())
    }

    /// A static whose contents change at run time, with the values recorded for it.
    pub fn mutable_static(&self, id: &str) -> Option<&[Origin]> {
        self.statics
            .get(id)
            .filter(|(m, _)| *m)
            .map(|(_, v)| v.as_slice())
    }

    /// What `o`, read in function `owner` (its defining path), can be once the values that
    /// reach it from elsewhere are followed: a field read becomes the values stored in that
    /// field, a call of a function of the program (or of a crate outside the knowledge base)
    /// what it returns, its parameters replaced by the call's arguments, and a parameter of a
    /// function the program calls the arguments its callers pass. Each value comes with the
    /// function it is read in, whose parameters and fields it names (a value stored in a field
    /// names those of the function that stored it). `None` when nothing is known from
    /// elsewhere.
    pub fn values(&self, o: &Origin, owner: &str) -> Values {
        let key = (o.clone(), owner.to_string());
        if let Some(v) = self.memo.borrow().get(&key) {
            return v.clone();
        }
        let v = self.lookup(o, owner);
        self.memo.borrow_mut().insert(key, v.clone());
        v
    }

    fn lookup(&self, o: &Origin, owner: &str) -> Values {
        let mut out = Vec::new();
        self.budget.set(MAX_STEPS);
        self.resolve(o, &[], owner, 0, &mut out);
        if std::env::var("RCBOM_DEBUG_LINKS").is_ok() {
            eprintln!("links: {owner}: {o:?}\n  -> {out:?}");
        }
        // nothing learned: `o` itself
        if let [(v, w)] = out.as_slice()
            && v == peel(o)
            && w == owner
        {
            return None;
        }
        (!out.is_empty()).then_some(out)
    }

    /// The values of `o.path` (the fields of `path`, read from `o`), read in `owner`. Where
    /// the values from elsewhere say nothing (a caller passing a value not known), those the
    /// program stores in `path` stand for them.
    fn resolve(
        &self,
        o: &Origin,
        path: &FieldPath,
        owner: &str,
        depth: usize,
        out: &mut Vec<(Origin, String)>,
    ) {
        if depth > MAX_DEPTH || out.len() >= MAX_VALUES || self.budget.get() == 0 {
            return;
        }
        self.budget.set(self.budget.get() - 1);
        let o = peel(o);
        match o {
            // the field read, outermost struct first (bounded by the origin: not a hop)
            Origin::Field { adt, field, base } => {
                let mut p = vec![(adt.clone(), *field)];
                p.extend_from_slice(path);
                return self.resolve(base, &p, owner, depth, out);
            }
            Origin::Any(alts) | Origin::All(alts) => {
                for a in alts {
                    self.resolve(a, path, owner, depth, out);
                }
                return;
            }
            // a parameter of a function the program calls: what its callers pass
            Origin::Param { index } => {
                if let Some(callers) = self.calls.get(owner) {
                    let mut unknown = false;
                    for (caller, args) in callers {
                        let mut found = Vec::new();
                        if let Some(a) = args.get(*index) {
                            self.resolve(a, path, caller, depth + 1, &mut found);
                        }
                        unknown |= found.is_empty();
                        found.into_iter().for_each(|v| push(out, v));
                    }
                    if !unknown {
                        return;
                    }
                }
            }
            // a call of the program's own function: what it returns, the part read first; a
            // trait method's call (`r._err()` on a `Result`), what the implementation for the
            // `Self` type it names returns
            Origin::Call {
                callee,
                args,
                self_ty,
                ..
            } => {
                let names = std::iter::once(callee.clone())
                    .chain(self_ty.iter().map(|t| rcbom_facts::impl_key(callee, t)));
                if let Some((name, k)) = names
                    .flat_map(|n| (0..=path.len()).rev().map(move |k| (n.clone(), k)))
                    .find(|(n, k)| self.returns.contains_key(&(n.clone(), fields(&path[..*k]))))
                {
                    let mut found = Vec::new();
                    for r in &self.returns[&(name, fields(&path[..k]))] {
                        let v = substitute(r, args);
                        self.resolve(&v, &path[k..], owner, depth + 1, &mut found);
                    }
                    if !found.is_empty() {
                        found.into_iter().for_each(|v| push(out, v));
                        return;
                    }
                }
            }
            _ => {}
        }
        if path.is_empty() {
            push(out, (o.clone(), owner.to_string()));
        } else {
            self.stored(path, depth, out);
        }
    }

    /// The values the program stores in the fields of `path`: the stores of the longest part
    /// of the path that has any (`Chacha20Poly1305Aead.0.0` before `AeadAlgorithm.0`), with
    /// those of the shorter parts made through a reference.
    fn stored(&self, path: &FieldPath, depth: usize, out: &mut Vec<(Origin, String)>) {
        let keys: Vec<(String, Vec<usize>)> = (0..path.len())
            .map(|j| (path[j].0.clone(), fields(&path[j..])))
            .collect();
        let Some(first) = keys.iter().position(|k| self.fields.contains_key(k)) else {
            return;
        };
        for (j, key) in keys.iter().enumerate().skip(first) {
            for s in self.fields.get(key).into_iter().flatten() {
                if j == first || s.via_ref {
                    self.resolve(&s.value, &[], &s.func, depth + 1, out);
                }
            }
        }
    }
}

fn fields(path: &FieldPath) -> Vec<usize> {
    path.iter().map(|(_, f)| *f).collect()
}

/// Standard-library calls whose result is their first argument's value, unwrapped, wrapped or
/// borrowed: `?` (`Try::branch`), `unwrap`, `map_err`, `clone`, `Arc::new`, `deref`.
const WRAPPERS: &[&str] = &[
    "Try::branch",
    "::unwrap",
    "::expect",
    "::unwrap_unchecked",
    "::map_err",
    "::ok_or",
    "::ok_or_else",
    "::ok",
    "Clone::clone",
    "Deref::deref",
    "AsRef::as_ref",
    "Borrow::borrow",
    "Box::<T>::new",
    "Arc::<T>::new",
    "Rc::<T>::new",
    // what a lock or a once-cell holds, and what is put in one
    "Mutex::<T>::new",
    "Mutex::<T>::lock",
    "RwLock::<T>::new",
    "RwLock::<T>::read",
    "RwLock::<T>::write",
    "OnceLock::<T>::get",
    "OnceCell::<T>::get",
    "LazyLock::<T, F>::force",
];

/// `o` without the standard-library calls that only unwrap, wrap or borrow a value
/// (`p256_key_pair_from_pkcs8(..)?`, `Arc::new(key)`).
pub fn peel(o: &Origin) -> &Origin {
    let mut o = o;
    while let Origin::Call {
        callee,
        krate,
        args,
        ..
    } = o
        && matches!(krate.as_str(), "core" | "std" | "alloc")
        && WRAPPERS.iter().any(|w| callee.ends_with(w))
        && let Some(a) = args.first()
    {
        o = a;
    }
    o
}

fn push(out: &mut Vec<(Origin, String)>, v: (Origin, String)) {
    if !out.contains(&v) && out.len() < MAX_VALUES {
        out.push(v);
    }
}

/// `r`, a function's return value in terms of its parameters, with the call's arguments for
/// them.
fn substitute(r: &Origin, args: &[Origin]) -> Origin {
    match r {
        Origin::Param { index } => args.get(*index).cloned().unwrap_or(Origin::Unknown),
        Origin::Field { adt, field, base } => Origin::Field {
            adt: adt.clone(),
            field: *field,
            base: Box::new(substitute(base, args)),
        },
        Origin::Call {
            callee,
            krate,
            self_ty,
            args: inner,
            span,
        } => Origin::Call {
            callee: callee.clone(),
            krate: krate.clone(),
            self_ty: self_ty.clone(),
            args: inner.iter().map(|a| substitute(a, args)).collect(),
            span: span.clone(),
        },
        Origin::Any(v) => Origin::Any(v.iter().map(|a| substitute(a, args)).collect()),
        Origin::All(v) => Origin::All(v.iter().map(|a| substitute(a, args)).collect()),
        other => other.clone(),
    }
}
