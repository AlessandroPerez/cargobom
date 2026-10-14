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
use std::collections::{HashMap, HashSet};

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
    /// By function and parameter: what it writes through the parameter.
    writes: HashMap<(String, usize), Vec<Origin>>,
    /// Lookups left for the current `values` call.
    budget: Cell<usize>,
    /// The reads being resolved (value, path, function), outermost first: one met again is a
    /// cycle.
    active: RefCell<HashSet<Read>>,
    /// Answers already given: the same field is read at many calls.
    memo: RefCell<HashMap<(Origin, String), Option<Found>>>,
    /// For the current question: the functions each descriptor found was named in (`""`: a
    /// static's initializer, or what a static holds at run time).
    named_in: RefCell<HashMap<String, std::collections::BTreeSet<String>>>,
}

type Values = Option<Vec<(Origin, String)>>;

/// How a value reaches the read (the set label of each member, with its witness): named in the
/// function itself, passed by a caller, returned or written by a function, or one of the values
/// the program stores in a field of the type anywhere (a flow-insensitive join: possible, not
/// shown to reach this read). Ordered from the most to the least specific.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Via {
    Fixed,
    /// The calling function.
    Caller(String),
    /// The function returning or writing it.
    Object(String),
    /// The function (or `static ..`) storing it in the field.
    Join(String),
}

impl Via {
    fn rank(&self) -> u8 {
        match self {
            Via::Fixed => 0,
            Via::Caller(_) | Via::Object(_) => 1,
            Via::Join(_) => 2,
        }
    }

    /// The less specific of the two: a value passed by a caller that read it from a field's
    /// join is a join member.
    pub(crate) fn then(&self, next: Via) -> Via {
        if next.rank() >= self.rank() {
            next
        } else {
            self.clone()
        }
    }
}

type Found = Vec<(Origin, String, Via)>;

#[derive(PartialEq)]
struct Stored {
    value: Origin,
    /// The function storing it, whose parameters `value` names.
    func: String,
    /// Stored in a struct reached through a reference, which may be a part of another one.
    via_ref: bool,
    /// The struct's type arguments, when known.
    args: Option<String>,
}

/// Values found per lookup, lookups chained, and lookups per question.
const MAX_VALUES: usize = 64;
const MAX_DEPTH: usize = 10;
const MAX_STEPS: usize = 4096;

/// A field read, from the outermost struct in: (struct, field, the struct's type arguments when
/// known).
type FieldPath = [(String, usize, Option<String>)];

/// A read being resolved: the value, the fields read from it, the function it is read in.
type Read = (Origin, Vec<(String, usize, Option<String>)>, String);

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
                    args: s.args.clone(),
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
            for w in &f.links.writes {
                let v = ix.writes.entry((w.func.clone(), w.index)).or_default();
                if !v.contains(&w.value) {
                    v.push(w.value.clone());
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

    /// A call of a trait method the program implements for the type it names, with a result
    /// that does not depend on the arguments (`<LS as Deref>::deref` of a `lazy_static!`).
    pub fn own_impl(&self, o: &Origin) -> bool {
        let Origin::Call {
            callee,
            self_ty: Some(t),
            ..
        } = o
        else {
            return false;
        };
        self.returns
            .get(&(rcbom_facts::impl_key(callee, t), Vec::new()))
            .is_some_and(|rs| rs.iter().all(|r| !names_param(r)))
    }

    /// What the program's implementations of a trait method (its path ending in `method`) for
    /// type `self_ty` return.
    pub fn impl_returns(&self, method: &str, self_ty: &str) -> Vec<Origin> {
        let suffix = format!(" for {self_ty}");
        self.returns
            .iter()
            .filter(|((f, path), _)| {
                path.is_empty()
                    && f.strip_suffix(&suffix)
                        .is_some_and(|m| m.ends_with(&format!("::{method}")) || m == method)
            })
            .flat_map(|(_, v)| v.iter().cloned())
            .collect()
    }

    /// Does the crate record what function `func` returns?
    pub fn returns_of(&self, func: &str) -> bool {
        self.returns.keys().any(|(f, _)| f == func)
    }

    /// Adds calls (callee, caller, arguments) found after the index was built (calls through
    /// function pointers); answers given before are forgotten.
    pub(crate) fn add_calls(&mut self, calls: Vec<(String, String, Vec<Origin>)>) {
        if calls.is_empty() {
            return;
        }
        for (callee, caller, args) in calls {
            let v = self.calls.entry(callee).or_default();
            let call = (caller, args);
            if !v.contains(&call) {
                v.push(call);
            }
        }
        self.memo.borrow_mut().clear();
    }

    /// What `func` returns, whole.
    pub fn returned(&self, func: &str) -> Vec<Origin> {
        self.returns
            .get(&(func.to_string(), Vec::new()))
            .cloned()
            .unwrap_or_default()
    }

    /// Does it record what `func` returns in field `field` of its result?
    pub fn returns_field(&self, func: &str, field: usize) -> bool {
        self.returns.contains_key(&(func.to_string(), vec![field]))
    }

    /// The values function `func` stores in field `field` of struct `adt` (`self.alg = a` in a
    /// setter), as written there.
    pub fn stored_by(&self, adt: &str, field: usize, func: &str) -> Vec<Origin> {
        self.fields
            .get(&(adt.to_string(), vec![field]))
            .into_iter()
            .flatten()
            .filter(|s| s.func == func)
            .map(|s| s.value.clone())
            .collect()
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
        self.values_via(o, owner)
            .map(|vs| vs.into_iter().map(|(v, w, _)| (v, w)).collect())
    }

    /// `values`, each with how it reaches the read (`Via`).
    pub fn values_via(&self, o: &Origin, owner: &str) -> Option<Found> {
        let key = (o.clone(), owner.to_string());
        if let Some(v) = self.memo.borrow().get(&key) {
            return v.clone();
        }
        let v = self.lookup(o, owner);
        self.memo.borrow_mut().insert(key, v.clone());
        v
    }

    fn lookup(&self, o: &Origin, owner: &str) -> Option<Found> {
        let mut out = Vec::new();
        self.budget.set(MAX_STEPS);
        self.resolve(o, &[], owner, 0, &Via::Fixed, &mut out);
        if std::env::var("RCBOM_DEBUG_LINKS").is_ok() {
            eprintln!("links: {owner}: {o:?}\n  -> {out:?}");
        }
        // nothing learned: `o` itself
        if let [(v, w, _)] = out.as_slice()
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
        via: &Via,
        out: &mut Found,
    ) {
        if out.len() >= MAX_VALUES {
            return;
        }
        // the bound: what lies further is not known, and the values say so (a set found
        // beside it is not all), never dropped
        if depth > MAX_DEPTH || self.budget.get() == 0 {
            push(out, (Origin::Truncated, owner.to_string(), via.clone()));
            return;
        }
        // a read met again inside its own resolution is a cycle (a field stored from itself:
        // rustls's `Context(self.0.clone())` in `fork`): what it reaches, the outer read
        // reaches; it adds nothing and cuts nothing
        let key = (o.clone(), path.to_vec(), owner.to_string());
        if !self.active.borrow_mut().insert(key.clone()) {
            return;
        }
        self.resolve_step(o, path, owner, depth, via, out);
        self.active.borrow_mut().remove(&key);
    }

    /// One step of `resolve`, within its bounds.
    fn resolve_step(
        &self,
        o: &Origin,
        path: &FieldPath,
        owner: &str,
        depth: usize,
        via: &Via,
        out: &mut Found,
    ) {
        self.budget.set(self.budget.get() - 1);
        let o = peel_ix(Some(self), o);
        match o {
            // a field of the error a `?` returns, or of a field-less value (an enum variant, a
            // unit struct): none (not the struct a field of the type would be stored in)
            Origin::Call { callee, .. }
                if !path.is_empty() && callee.ends_with("FromResidual::from_residual") =>
            {
                return;
            }
            Origin::Unit { .. } if !path.is_empty() => return,
            // the field read, outermost struct first (bounded by the origin: not a hop)
            Origin::Field {
                adt,
                field,
                base,
                args,
            } => {
                let mut p = vec![(adt.clone(), *field, args.clone())];
                p.extend_from_slice(path);
                return self.resolve(base, &p, owner, depth, via, out);
            }
            // what a function the program calls leaves behind the parameter (`set_slot(&mut
            // c.alg)`), its parameters being the call's arguments: its value on entry is the
            // value before the call (argument `index`); a function that records no write
            // leaves that value as it was (`touch(&mut d)`)
            Origin::Written {
                callee,
                index,
                args,
            } => {
                let mut found = Vec::new();
                let by = via.then(Via::Object(callee.clone()));
                match self.writes.get(&(callee.clone(), *index)) {
                    Some(ws) => {
                        for w in ws {
                            let v = substitute(w, args);
                            self.resolve(&v, path, owner, depth + 1, &by, &mut found);
                        }
                    }
                    None => {
                        if let Some(before) = args.get(*index) {
                            self.resolve(before, path, owner, depth + 1, via, &mut found);
                        }
                    }
                }
                found.into_iter().for_each(|v| push(out, v));
                return;
            }
            // a field read of a value with fields written after it was made (`h.alg = X`
            // after `h = Header::default()`): a write that happens on every way to the read
            // replaces what the value held in that field
            Origin::All(alts) if !path.is_empty() => {
                let want = fields(path);
                let covers = |a: &Origin| matches!(a, Origin::Set { path: p, strong: true, .. } if want.starts_with(p));
                let replaced = alts.iter().any(covers);
                for a in alts {
                    if replaced && !matches!(a, Origin::Set { .. }) {
                        continue;
                    }
                    self.resolve(a, path, owner, depth, via, out);
                }
                return;
            }
            Origin::Any(alts) | Origin::All(alts) => {
                for a in alts {
                    self.resolve(a, path, owner, depth, via, out);
                }
                return;
            }
            // a write into a field: the field read, if it is that field (or inside it); a
            // write elsewhere is no part of it; a read of the whole is made of it too
            Origin::Set { path: p, value, .. } => {
                let want = fields(path);
                if want.starts_with(p) {
                    return self.resolve(value, &path[p.len()..], owner, depth, via, out);
                }
                if p.starts_with(&want) {
                    return self.resolve(value, &[], owner, depth, via, out);
                }
                return;
            }
            // a parameter of a function the program calls: what its callers pass
            // (of the function it names: a closure reads its parent's through a capture)
            Origin::Param { index, owner: of } => {
                let owner = of.as_deref().unwrap_or(owner);
                if let Some(callers) = self.calls.get(owner) {
                    let mut unknown = false;
                    for (caller, args) in callers {
                        let mut found = Vec::new();
                        if let Some(a) = args.get(*index) {
                            let by = via.then(Via::Caller(caller.clone()));
                            self.resolve(a, path, caller, depth + 1, &by, &mut found);
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
                    let by = via.then(Via::Object(name.clone()));
                    for r in &self.returns[&(name, fields(&path[..k]))] {
                        let v = substitute(r, args);
                        self.resolve(&v, &path[k..], owner, depth + 1, &by, &mut found);
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
            push(out, (o.clone(), owner.to_string(), via.clone()));
        } else {
            // a field of a value the driver's search cut (a chain of writes through `&mut
            // self` longer than it follows): the cut stays among the values, beside the
            // field's stores, so that the reader says the search hit its bound
            if matches!(o, Origin::Truncated) {
                push(out, (Origin::Truncated, owner.to_string(), via.clone()));
            }
            self.stored(path, depth, via, out);
        }
    }

    /// The values the program stores in the fields of `path`: the stores of the longest part
    /// of the path that has any (`Chacha20Poly1305Aead.0.0` before `AeadAlgorithm.0`), with
    /// those of the shorter parts made through a reference.
    fn stored(&self, path: &FieldPath, depth: usize, via: &Via, out: &mut Found) {
        let keys: Vec<(String, Vec<usize>)> = (0..path.len())
            .map(|j| (path[j].0.clone(), fields(&path[j..])))
            .collect();
        // a store in a struct of other type arguments (`Wrapper<&aead::Algorithm>` for a read
        // of a `Wrapper<&digest::Algorithm>`) is not seen; either unknown, it is
        let seen = |j: usize, s: &Stored| match (&path[j].2, &s.args) {
            (Some(a), Some(b)) => a == b,
            _ => true,
        };
        let Some(first) = keys.iter().enumerate().position(|(j, k)| {
            self.fields
                .get(k)
                .is_some_and(|v| v.iter().any(|s| seen(j, s)))
        }) else {
            return;
        };
        for (j, key) in keys.iter().enumerate().skip(first) {
            for s in self.fields.get(key).into_iter().flatten() {
                if (j == first || s.via_ref) && seen(j, s) {
                    let by = via.then(Via::Join(s.func.clone()));
                    self.resolve(&s.value, &[], &s.func, depth + 1, &by, out);
                }
            }
        }
    }
}

fn fields(path: &FieldPath) -> Vec<usize> {
    path.iter().map(|(_, f, _)| *f).collect()
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
    // a cell's value, a `thread_local!` cell's (`TA.get()`), what is put in one
    "Cell::<T>::new",
    "Cell::<T>::get",
    "RefCell::<T>::new",
    "RefCell::<T>::borrow",
    "Cell<T>>::get",
];

/// Calls outside the standard library that read a static's value: `lazy_static!`'s
/// `Lazy::get(&LAZY, init)`.
const STATIC_READS: &[&str] = &["lazy_static::lazy::Lazy::<T>::get"];

/// `o` without the standard-library calls that only unwrap, wrap or borrow a value
/// (`p256_key_pair_from_pkcs8(..)?`, `Arc::new(key)`).
pub fn peel(o: &Origin) -> &Origin {
    peel_ix(None, o)
}

/// `peel`, keeping a call of a trait method the program implements with a result that does
/// not depend on its arguments (`lazy_static!`'s `Deref` of a static: `*LS` is what the
/// static was initialized with, not the unit-like `LS`).
pub fn peel_ix<'a>(ix: Option<&LinkIndex>, o: &'a Origin) -> &'a Origin {
    let mut o = o;
    while let Origin::Call {
        callee,
        krate,
        args,
        ..
    } = o
        && ((matches!(krate.as_str(), "core" | "std" | "alloc")
            && WRAPPERS.iter().any(|w| callee.ends_with(w)))
            || STATIC_READS.contains(&callee.as_str()))
        && !ix.is_some_and(|ix| ix.own_impl(o))
        && let Some(a) = args.first()
    {
        o = a;
    }
    o
}

/// Does `o` name a parameter of its function?
fn names_param(o: &Origin) -> bool {
    match o {
        Origin::Param { .. } => true,
        Origin::Call { args, .. } | Origin::Written { args, .. } => args.iter().any(names_param),
        Origin::Field { base, .. } => names_param(base),
        Origin::Any(v) | Origin::All(v) => v.iter().any(names_param),
        Origin::Set { value, .. } => names_param(value),
        _ => false,
    }
}

/// Adds a value once; reached several ways, it keeps the most specific.
fn push(out: &mut Found, v: (Origin, String, Via)) {
    if let Some(e) = out.iter_mut().find(|e| e.0 == v.0 && e.1 == v.1) {
        if v.2 < e.2 {
            e.2 = v.2;
        }
    } else if out.len() < MAX_VALUES {
        out.push(v);
    }
}

/// `r`, a function's return value in terms of its parameters, with the call's arguments for
/// them.
pub(crate) fn substitute(r: &Origin, args: &[Origin]) -> Origin {
    match r {
        Origin::Param { index, owner: None } => {
            args.get(*index).cloned().unwrap_or(Origin::Unknown)
        }
        Origin::Field {
            adt,
            field,
            base,
            args: a,
        } => Origin::Field {
            adt: adt.clone(),
            field: *field,
            base: Box::new(substitute(base, args)),
            args: a.clone(),
        },
        Origin::Written {
            callee,
            index,
            args: inner,
        } => Origin::Written {
            callee: callee.clone(),
            index: *index,
            args: inner.iter().map(|a| substitute(a, args)).collect(),
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
        Origin::Set {
            path,
            value,
            strong,
        } => Origin::Set {
            path: path.clone(),
            value: Box::new(substitute(value, args)),
            strong: *strong,
        },
        other => other.clone(),
    }
}
