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
    /// By trait: the types coerced to a trait object of it, with where, and the body each
    /// method runs for them.
    coerced: HashMap<String, Vec<Coerced>>,
    /// The instances whose summaries the driver's bound left unrecorded (`Links::truncated`).
    truncated: HashSet<String>,
    /// By static def id: the values functions put there at run time, with the function.
    static_writers: HashMap<String, Vec<(String, Origin)>>,
    /// The trait methods some type of the program implements (`<A as app::Pick>::alg` returns
    /// or writes recorded): for them a call whose body is not known is no call of the default
    /// body.
    implemented: HashSet<String>,
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
    /// For the current question: how each descriptor found reaches it, the most specific way
    /// (the set label of the member), and the way of the value being followed now.
    named_via: RefCell<HashMap<String, Via>>,
    current_via: RefCell<Via>,
    /// The functions an entry point reaches, by defining path, once known: in a lookup made
    /// with `live_only`, a caller outside them (dead code) is not followed.
    reached: RefCell<Option<HashSet<String>>>,
    live_only: Cell<bool>,
    memo_live: RefCell<HashMap<(Origin, String), Option<Found>>>,
    /// The generic functions whose instances' summaries are recorded (`app::pass` for
    /// `app::pass::<app::A>`), none cut by the bound: what the generic item's own body records
    /// (its calls, its stores, for no type in particular) is said by the instances.
    instanced: HashSet<String>,
}

/// The generic item an instance's name names (`app::pass::<app::A>`: `app::pass`;
/// `<A as Tr>::m::<T>::{closure#0}`: `<A as Tr>::m::{closure#0}`).
fn instance_base(name: &str) -> String {
    let mut out = String::new();
    let mut rest = name;
    while let Some(i) = rest.find("::<") {
        out.push_str(&rest[..i]);
        let mut depth = 0usize;
        let mut end = rest.len();
        for (j, ch) in rest[i + 2..].char_indices() {
            match ch {
                '<' => depth += 1,
                '>' => {
                    depth -= 1;
                    if depth == 0 {
                        end = i + 2 + j + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

type Values = Option<Vec<(Origin, String)>>;

/// How a value reaches the read (the set label of each member, with its witness): named in the
/// function itself, passed by a caller, returned or written by a function, or one of the values
/// the program stores in a field of the type anywhere (a flow-insensitive join: possible, not
/// shown to reach this read), or what a type coerced to a trait object returns from a call
/// through it. Ordered from the most to the least specific.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Via {
    #[default]
    Fixed,
    /// The calling function.
    Caller(String),
    /// The function returning or writing it.
    Object(String),
    /// The implementation of type `ty`, coerced to `dyn trait_path` at `at`, called through
    /// the trait object; `only`: no other type is coerced to it.
    Dyn {
        trait_path: String,
        ty: String,
        at: Option<rcbom_facts::Loc>,
        /// The coercion is in a static's value (`at`: the static's item).
        in_static: bool,
        only: bool,
    },
    /// The standard-library method that put it in a container it is read from
    /// (`HashMap::insert`; `+` before it: a value already in the list it adds to), or the
    /// function writing it into an element of a list (`v.algorithms[0] = HS256`).
    Container(String),
    /// One of the implementations (its path) a trait method called on a type parameter may
    /// run.
    Impl(String),
    /// The function (or `static ..`) storing it in the field.
    Join(String),
    /// Stored in a static that never changes by its initializer (`rcbom_facts::static_owner`):
    /// a table's element or a field read from it.
    Table(String),
    /// Held by a static whose contents change at run time (`rcbom_facts::static_owner`): its
    /// initializer's value (with a `=` before it: a static no function of the program puts a
    /// value in, a `LazyLock`'s: the value it holds).
    Static(String),
    /// Put in a static that changes at run time (`statik`, as `Static` names it) by function
    /// `writer`.
    Store { writer: String, statik: String },
}

impl Via {
    pub(crate) fn rank(&self) -> u8 {
        match self {
            Via::Fixed => 0,
            Via::Caller(_) | Via::Object(_) | Via::Dyn { only: true, .. } | Via::Table(_) => 1,
            Via::Dyn { .. }
            | Via::Container(_)
            | Via::Impl(_)
            | Via::Join(_)
            | Via::Static(_)
            | Via::Store { .. } => 2,
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
const MAX_VALUES: usize = 256;
const MAX_DEPTH: usize = 10;
const MAX_STEPS: usize = 4096;

/// A field read, from the outermost struct in: (struct, field, the struct's type arguments when
/// known).
type FieldPath = [(String, usize, Option<String>)];

/// A type coerced to a trait object: the type, where (in a static's value or not), and the
/// body each method of the object runs for it.
type Coerced = (
    String,
    Option<rcbom_facts::Loc>,
    bool,
    Vec<(String, String)>,
);

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
            ix.truncated.extend(f.links.truncated.iter().cloned());
            for name in f
                .links
                .calls
                .iter()
                .map(|c| &c.caller)
                .chain(f.links.fields.iter().map(|s| &s.func))
            {
                let base = instance_base(name);
                if base != *name {
                    ix.instanced.insert(base);
                }
            }
            for w in &f.links.writes {
                let v = ix.writes.entry((w.func.clone(), w.index)).or_default();
                if !v.contains(&w.value) {
                    v.push(w.value.clone());
                }
            }
            for c in &f.links.coercions {
                let v = ix.coerced.entry(c.trait_path.clone()).or_default();
                if !v.iter().any(|(t, ..)| *t == c.ty) {
                    v.push((c.ty.clone(), c.at.clone(), c.in_static, c.methods.clone()));
                }
            }
            for s in &f.links.statics {
                let w = ix.static_writers.entry(s.def.id.clone()).or_default();
                for x in &s.writers {
                    if !w.contains(x) {
                        w.push(x.clone());
                    }
                }
                let e = ix.statics.entry(s.def.id.clone()).or_default();
                e.0 |= s.mutable;
                for v in &s.values {
                    if !e.1.contains(v) {
                        e.1.push(v.clone());
                    }
                }
            }
        }
        // a trait object made from another (`&dyn Sub` upcast to `&dyn Super`): the types
        // coerced to that one, transitively
        // the trait methods types implement: `<A as app::Pick>::alg`, `app::Pick::alg for A`
        let bodies: Vec<String> = ix
            .returns
            .keys()
            .map(|(f, _)| f.clone())
            .chain(ix.writes.keys().map(|(f, _)| f.clone()))
            .collect();
        ix.implemented = bodies
            .iter()
            .filter_map(|f| implemented_method(f))
            .collect();
        for _ in 0..MAX_DEPTH {
            let mut changed = false;
            let traits: Vec<String> = ix.coerced.keys().cloned().collect();
            for t in traits {
                let mut v = ix.coerced[&t].clone();
                let subs: Vec<String> = v
                    .iter()
                    .filter_map(|(ty, ..)| ty.strip_prefix("dyn ").map(str::to_string))
                    .collect();
                for sub in subs {
                    for e in ix.coerced.get(&sub).cloned().unwrap_or_default() {
                        if !v.iter().any(|(ty, ..)| *ty == e.0) {
                            v.push(e);
                            changed = true;
                        }
                    }
                }
                ix.coerced.insert(t, v);
            }
            if !changed {
                break;
            }
        }
        for v in ix.coerced.values_mut() {
            v.retain(|(ty, ..)| !ty.starts_with("dyn "));
        }
        ix
    }

    /// Notes that descriptor `id` was found named in function `owner`.
    pub fn note(&self, id: &str, owner: &str) {
        let via = self.current_via.borrow().clone();
        self.named_via
            .borrow_mut()
            .entry(id.to_string())
            .and_modify(|v| {
                if via < *v {
                    *v = via.clone();
                }
            })
            .or_insert_with(|| via.clone());
        self.named_in
            .borrow_mut()
            .entry(id.to_string())
            .or_default()
            .insert(owner.to_string());
    }

    /// How each descriptor noted since the last call reaches the question, by descriptor.
    pub fn take_named_via(&self) -> HashMap<String, Via> {
        std::mem::take(&mut *self.named_via.borrow_mut())
    }

    /// Runs `f` with `via` as the way the values it notes reach the question.
    pub fn with_via<T>(&self, via: Via, f: impl FnOnce() -> T) -> T {
        let old = self.current_via.replace(via);
        let r = f();
        *self.current_via.borrow_mut() = old;
        r
    }

    /// The way the value being followed reaches the question.
    pub fn current_via(&self) -> Via {
        self.current_via.borrow().clone()
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

    /// The values recorded for a static (its initializer's, for one holding a function
    /// pointer; what the program puts there, for one that changes at run time).
    pub fn static_values(&self, id: &str) -> &[Origin] {
        self.statics
            .get(id)
            .map(|(_, v)| v.as_slice())
            .unwrap_or_default()
    }

    /// Field `field` of struct `adt` in `w`, the values in it once the writes into the value's
    /// fields are taken into account: what a call of the program's function writes through a
    /// parameter (an `Origin::Written`, per its summary), or a value with field writes (`All` with
    /// `Set`s): the values a write to that field puts there, and the field of the value before
    /// where it may not write it; none for a write to another field (`self.n += 7` is no part of
    /// `self.key`). `None` for any other value.
    pub fn field_parts(&self, w: &Origin, adt: &str, field: usize) -> Option<Vec<Origin>> {
        // a value with fields written into it (`k.n = 7` after `k = K { .. }`): those writes
        // projected the same way
        if let Origin::All(alts) = w
            && alts.iter().any(|a| matches!(a, Origin::Set { .. }))
        {
            let mut out = Vec::new();
            project(w, adt, field, &mut out);
            return Some(out);
        }
        let Origin::Written {
            callee,
            index,
            args,
            self_ty,
            ..
        } = w
        else {
            // a field of a field (`o.inner.key`): the inner field's parts, each projected
            if let Origin::Field {
                adt: a,
                field: f,
                base,
                ..
            } = w
                && let Some(inner) = self.field_parts(peel(base), a, *f)
            {
                let mut out = Vec::new();
                for p in inner {
                    match self.field_parts(peel(&p), adt, field) {
                        Some(parts) => out.extend(parts),
                        None => project(&p, adt, field, &mut out),
                    }
                }
                return Some(out);
            }
            return None;
        };
        // the bodies it may run: its own, or a trait method's implementations (`dyn`, `impl`)
        let bodies = match self_ty.as_deref() {
            None => vec![callee.clone()],
            Some(t) => self
                .implementations(callee, t)?
                .into_iter()
                .map(|(b, _)| b)
                .collect(),
        };
        let mut out = Vec::new();
        for b in bodies {
            match self.writes.get(&(b, *index)) {
                Some(ws) => {
                    for s in ws {
                        project(&substitute(s, args), adt, field, &mut out);
                    }
                }
                None => project(args.get(*index)?, adt, field, &mut out),
            }
        }
        Some(out)
    }

    /// Does the initializer of static `id` store values in fields (a table of structs, a
    /// struct): a field read of it is what it stores there.
    pub fn static_fields(&self, id: &str) -> bool {
        let mut id = id.to_string();
        // (through statics that refer to another: `static REF: &Cfg = &FIX`)
        for _ in 0..MAX_DEPTH {
            if self
                .fields
                .values()
                .flatten()
                .any(|s| rcbom_facts::owner_static(&s.func).is_some_and(|(_, sid)| sid == id))
            {
                return true;
            }
            match self.static_alias(&id) {
                Some(Origin::Data { def, .. }) => id = def.id,
                _ => return false,
            }
        }
        false
    }

    /// Is a field read of static `id` answered by the links: `static_fields`, or a static whose
    /// contents change at run time (that field of each value it holds: a `LazyLock`'s), or one
    /// a `const fn` makes (`static MADE: Cfg = make()`: the field of what it returns)?
    pub fn field_readable(&self, id: &str) -> bool {
        self.static_fields(id)
            || self.mutable_static(id).is_some()
            || matches!(self.static_alias(id), Some(Origin::Call { .. }))
    }

    /// The static or constant a static or constant that never changes refers to (`static REF:
    /// &Cfg = &FIX`: `FIX`; `const ALIAS: Cfg = BASE`), or the call of a `const fn` it is
    /// (`static MADE: Cfg = make()`).
    fn static_alias(&self, id: &str) -> Option<Origin> {
        match self.statics.get(id) {
            Some((false, v)) => match v.as_slice() {
                [d @ Origin::Data { def, .. }] if def.id != id => Some(d.clone()),
                [c @ Origin::Call { .. }] => Some(c.clone()),
                _ => None,
            },
            _ => None,
        }
    }

    /// The values a static whose contents change at run time holds, each with how: its
    /// initializer's (`Via::Static`), or what a function puts there (`Via::Store`, once per
    /// function).
    pub fn static_value_vias(&self, def: &rcbom_facts::DefRef) -> Vec<(Origin, Via)> {
        let owner = rcbom_facts::static_owner(&def.path, &def.id);
        let writers = self.static_writers.get(&def.id);
        let mut out = Vec::new();
        for v in self.mutable_static(&def.id).unwrap_or_default() {
            let by: Vec<&String> = writers
                .into_iter()
                .flatten()
                .filter(|(_, x)| x == v)
                .map(|(w, _)| w)
                .collect();
            if by.is_empty() {
                // (a lazy static's: what its closure returns, which nothing replaces)
                let held = writers.is_none_or(|w| w.is_empty())
                    && matches!(v, Origin::Call { callee, .. } if callee == "<closure>");
                out.push((
                    v.clone(),
                    Via::Static(if held {
                        format!("={owner}")
                    } else {
                        owner.clone()
                    }),
                ));
            }
            for w in by {
                out.push((
                    v.clone(),
                    Via::Store {
                        writer: w.clone(),
                        statik: owner.clone(),
                    },
                ));
            }
        }
        out
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

    /// The functions an entry point reaches (by defining path), for `values_via_live`.
    pub fn set_reached(&self, reached: HashSet<String>) {
        *self.reached.borrow_mut() = Some(reached);
    }

    /// `values_via`, not following callers no entry point reaches (a value found only through
    /// them reaches no call at run time).
    pub fn values_via_live(&self, o: &Origin, owner: &str) -> Option<Found> {
        let key = (o.clone(), owner.to_string());
        if let Some(v) = self.memo_live.borrow().get(&key) {
            return v.clone();
        }
        self.live_only.set(true);
        let v = self.lookup(o, owner);
        self.live_only.set(false);
        self.memo_live.borrow_mut().insert(key, v.clone());
        v
    }

    /// Is `func` a generic item whose instances' summaries say what its body does?
    fn superseded(&self, func: &str) -> bool {
        self.instanced.contains(func)
            && instance_base(func) == func
            && !self.truncated.iter().any(|t| instance_base(t) == func)
    }

    /// Is `caller` a function no entry point reaches (in a `live_only` lookup)?
    fn dead_caller(&self, caller: &str) -> bool {
        self.live_only.get()
            && !caller.is_empty()
            && !caller.contains(" for ")
            && rcbom_facts::owner_static(caller).is_none()
            && self
                .reached
                .borrow()
                .as_ref()
                .is_some_and(|r| !r.contains(caller))
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
        // RCBOM_DEBUG_LINKS: print every lookup and what it found
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
        // the bound on values: a set this large is cut, and says so
        if out.len() >= MAX_VALUES {
            push(out, (Origin::Truncated, owner.to_string(), via.clone()));
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
            // the field read, outermost struct first (bounded by the origin: not a hop); of a
            // static that never changes (`CFG.alg`), what its initializer stores there: that
            // value, not every value the type holds there
            Origin::Field {
                adt,
                field,
                base,
                args,
            } => {
                let mut p = vec![(adt.clone(), *field, args.clone())];
                p.extend_from_slice(path);
                // a field of a static that changes at run time (`CFG.lock().unwrap().h`): that
                // field of each value it holds (its initializer's, what functions put there)
                if let Origin::Data { def, .. } = peel(base)
                    && self.mutable_static(&def.id).is_some()
                {
                    for (v, by) in self.static_value_vias(def) {
                        let mut parts = Vec::new();
                        project(&v, adt, *field, &mut parts);
                        // (a value a function puts there names that function's parameters:
                        // `fn set_h(a) { CFG.lock().unwrap().h = a }`)
                        let w = match &by {
                            Via::Store { writer, .. } => writer.clone(),
                            _ => String::new(),
                        };
                        for part in parts {
                            self.resolve(&part, path, &w, depth + 1, &via.then(by.clone()), out);
                        }
                    }
                    return;
                }
                if let Origin::Data { def, .. } = peel(base)
                    && self.mutable_static(&def.id).is_none()
                {
                    let key = (adt.clone(), fields(&p));
                    let own: Vec<&Stored> = self
                        .fields
                        .get(&key)
                        .into_iter()
                        .flatten()
                        .filter(|s| {
                            rcbom_facts::owner_static(&s.func).is_some_and(|(_, id)| id == def.id)
                        })
                        .collect();
                    if !own.is_empty() {
                        for s in own {
                            // (a constant copied into a table, `[BASE, ..]`: the table the call
                            // reads stays the witness; a static it points to stores the value)
                            let by = if matches!(via, Via::Table(_)) && s.func.starts_with("const ")
                            {
                                via.clone()
                            } else {
                                via.then(Via::Table(s.func.clone()))
                            };
                            self.resolve(&s.value, &[], &s.func, depth + 1, &by, out);
                        }
                        return;
                    }
                    // a static holding a reference to another (`static REF: &Cfg = &FIX`):
                    // that one's field
                    if let Some(other) = self.static_alias(&def.id) {
                        let o = Origin::Field {
                            adt: adt.clone(),
                            field: *field,
                            base: Box::new(other),
                            args: args.clone(),
                        };
                        return self.resolve(&o, path, owner, depth + 1, via, out);
                    }
                }
                return self.resolve(base, &p, owner, depth, via, out);
            }
            // what a function the program calls leaves behind the parameter (`set_slot(&mut
            // c.alg)`), its parameters being the call's arguments: its value on entry is the
            // value before the call (argument `index`); a function that records no write
            // leaves that value as it was (`touch(&mut d)`). A trait method called on a trait
            // object or a type parameter: what each implementation it may run leaves there.
            Origin::Written {
                callee,
                index,
                args,
                self_ty,
                place_ty,
            } => {
                let mut found = Vec::new();
                let before = |found: &mut Found, via: &Via| {
                    if let Some(b) = args.get(*index) {
                        self.resolve(b, path, owner, depth + 1, via, found);
                    }
                };
                let bodies = match self_ty.as_deref() {
                    Some(t) => self.implementations(callee, t),
                    None => Some(vec![(
                        callee.clone(),
                        via.then(Via::Object(callee.clone())),
                    )]),
                };
                match bodies {
                    Some(bodies) => {
                        for (f, by) in bodies {
                            match self.writes.get(&(f.clone(), *index)) {
                                Some(ws) => {
                                    for w in ws {
                                        // the object written is of a known type: the
                                        // trait-object calls on it inside run that type's
                                        // implementation
                                        let w = match place_ty {
                                            Some(t) => self.specialize(w, *index, t),
                                            None => w.clone(),
                                        };
                                        let v = substitute(&w, args);
                                        self.resolve(&v, path, owner, depth + 1, &by, &mut found);
                                    }
                                }
                                // a summary the driver's bound cut: not known
                                None if self.truncated.contains(&f) => {
                                    push(&mut found, (Origin::Truncated, owner.to_string(), by))
                                }
                                None => before(&mut found, &by),
                            }
                        }
                    }
                    // implementations not known: the value before, and an unknown beside it
                    None => {
                        before(&mut found, via);
                        push(&mut found, (o.clone(), owner.to_string(), via.clone()));
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
            // a value written into an element of a list (`v.algorithms[0] = HS256`): one of the
            // values the list holds, beside the others
            Origin::Any(alts)
                if alts.iter().any(|a| {
                    matches!(a, Origin::Through { callee } if callee == rcbom_facts::ELEMENT_WRITE)
                }) =>
            {
                let by = via.then(Via::Container(owner.to_string()));
                for a in alts {
                    // (the marker itself is no value)
                    if !matches!(a, Origin::Through { callee } if callee == rcbom_facts::ELEMENT_WRITE)
                    {
                        self.resolve(a, path, owner, depth, &by, out);
                    }
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
                        if self.dead_caller(caller) || self.superseded(caller) {
                            continue;
                        }
                        let mut found = Vec::new();
                        // a caller passing on what is being resolved (`rec(a, n - 1)` inside
                        // `rec`): a cycle, which adds nothing and leaves nothing unknown
                        if let Some(a) = args.get(*index)
                            && self.active.borrow().contains(&(
                                a.clone(),
                                path.to_vec(),
                                caller.clone(),
                            ))
                        {
                            continue;
                        }
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
                self_ty: Some(t), ..
            } if t.starts_with("dyn ") => {
                let (found, all) = self.dispatch(o, &t["dyn ".len()..], path, owner, depth, via);
                found.into_iter().for_each(|v| push(out, v));
                if all {
                    return;
                }
            }
            Origin::Call {
                callee,
                args,
                self_ty,
                runs,
                ..
            } => {
                // the body the driver resolved the call to (the implementation for the `Self`
                // type, the trait's default body, a generic function's instance) and only it;
                // else the implementation by the `Self` type's path before the trait's default
                // body
                // (a trait's default body only when the call's `Self` is that of no
                // implementation the program has: on a type parameter, or a type that may
                // override it, which implementation runs is not known)
                // a body the driver's bound left without a summary: a cut
                if let Some(r) = runs
                    && self.truncated.contains(r)
                {
                    push(out, (Origin::Truncated, owner.to_string(), via.clone()));
                    return;
                }
                let names: Vec<String> = match runs {
                    Some(r) => vec![r.clone()],
                    None => self_ty
                        .iter()
                        .map(|t| rcbom_facts::impl_key(callee, t))
                        .chain(
                            (!self.implemented.contains(callee)).then(|| callee.clone()),
                        )
                        .collect(),
                };
                if let Some((name, k)) = names
                    .into_iter()
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
            // a part written through a borrow a function returned (`*self.slot() = v`): which
            // part is not followed, and the value stays among the values, beside the stores
            if matches!(o, Origin::Through { .. }) {
                push(out, (o.clone(), owner.to_string(), via.clone()));
            }
            self.stored(path, depth, via, out);
        }
    }

    /// A write summary of a function whose parameter `param` points to an object of type `ty`
    /// (`fn up_dyn(u: &mut dyn Up)` called on a `B`): the trait-object calls it makes on that
    /// parameter run `ty`'s implementation, and the functions it passes the parameter to write
    /// an object of that type.
    fn specialize(&self, o: &Origin, param: usize, ty: &str) -> Origin {
        let on_param = |args: &[Origin], i: usize| matches!(args.get(i), Some(Origin::Param { index, owner: None }) if *index == param);
        match o {
            Origin::Written {
                callee,
                index,
                args,
                self_ty,
                place_ty,
            } => {
                let args: Vec<Origin> =
                    args.iter().map(|a| self.specialize(a, param, ty)).collect();
                if !on_param(&args, *index) {
                    return Origin::Written {
                        callee: callee.clone(),
                        index: *index,
                        args,
                        self_ty: self_ty.clone(),
                        place_ty: place_ty.clone(),
                    };
                }
                match self_ty.as_deref().and_then(|t| t.strip_prefix("dyn ")) {
                    // the type's own body for the method
                    Some(tr) => {
                        let body = self
                            .coerced
                            .get(tr)
                            .and_then(|v| v.iter().find(|(t, ..)| t == ty))
                            .and_then(|(.., methods)| {
                                methods
                                    .iter()
                                    .find(|(m, _)| m == callee)
                                    .map(|(_, b)| b.clone())
                            })
                            .unwrap_or_else(|| {
                                let (t, m) = callee.rsplit_once("::").unwrap_or(("", callee));
                                format!("<{ty} as {t}>::{m}")
                            });
                        Origin::Written {
                            callee: body,
                            index: *index,
                            args,
                            self_ty: None,
                            place_ty: None,
                        }
                    }
                    // a function the object is passed on to
                    _ => Origin::Written {
                        callee: callee.clone(),
                        index: *index,
                        args,
                        self_ty: self_ty.clone(),
                        place_ty: Some(ty.to_string()),
                    },
                }
            }
            Origin::Any(v) => {
                Origin::Any(v.iter().map(|a| self.specialize(a, param, ty)).collect())
            }
            Origin::All(v) => {
                Origin::All(v.iter().map(|a| self.specialize(a, param, ty)).collect())
            }
            Origin::Set {
                path,
                value,
                strong,
            } => Origin::Set {
                path: path.clone(),
                value: Box::new(self.specialize(value, param, ty)),
                strong: *strong,
            },
            other => other.clone(),
        }
    }

    /// The bodies a call of trait method `callee` may run, dispatched as `self_ty` says (`dyn
    /// <trait>`: the types coerced to the trait object; `impl <trait>`: every implementation
    /// the program records a write for, and the trait's default body), each with how it
    /// reaches the read; `None` when none is known.
    fn implementations(&self, callee: &str, self_ty: &str) -> Option<Vec<(String, Via)>> {
        let (tr, method) = callee.rsplit_once("::")?;
        let mut out = Vec::new();
        if let Some(t) = self_ty.strip_prefix("dyn ") {
            let types = self.coerced.get(t)?;
            for (ty, at, in_static, methods) in types {
                let name = match methods.iter().find(|(m, _)| m == callee) {
                    Some((_, body)) => body.clone(),
                    // a body the driver could not name (another crate's generic impl): the
                    // type's own method, as an impl's item
                    None => format!("<{ty} as {tr}>::{method}"),
                };
                let via = Via::Dyn {
                    trait_path: t.to_string(),
                    ty: ty.clone(),
                    at: at.clone(),
                    in_static: *in_static,
                    only: types.len() == 1,
                };
                out.push((name, via));
            }
        } else {
            let suffix = format!(" as {tr}>::{method}");
            let mut names: Vec<String> = self
                .writes
                .keys()
                .filter(|(f, _)| f.starts_with('<') && f.ends_with(&suffix))
                .map(|(f, _)| f.clone())
                .collect();
            names.sort();
            names.dedup();
            if self.writes.keys().any(|(f, _)| f == callee) {
                names.push(callee.to_string());
            }
            out.extend(names.into_iter().map(|n| (n.clone(), Via::Impl(n))));
        }
        (!out.is_empty()).then_some(out)
    }

    /// A call of a trait method on a trait object of `trait_path`: what the implementations of
    /// the types the walked code coerces to it return (a member each, labelled with its
    /// coercion), and whether that is all. It is not when no type is coerced, or a type's
    /// implementation (or the trait's default body it runs) records no result: the call stays
    /// among the values.
    fn dispatch(
        &self,
        o: &Origin,
        trait_path: &str,
        path: &FieldPath,
        owner: &str,
        depth: usize,
        via: &Via,
    ) -> (Found, bool) {
        let mut out = Vec::new();
        let Origin::Call { callee, args, .. } = o else {
            return (out, false);
        };
        let Some(types) = self.coerced.get(trait_path) else {
            return (out, false);
        };
        let mut all = true;
        for (ty, at, in_static, methods) in types {
            // the body the method runs for the type (its implementation, or the trait's
            // default body), as the driver resolved it; else the type's own method (by its
            // type's path, or as an impl's item: `<u8 as app::Pick>::alg`)
            let names = match methods.iter().find(|(m, _)| m == callee) {
                Some((_, body)) => vec![body.clone()],
                None => {
                    let (tr, method) = callee.rsplit_once("::").unwrap_or(("", callee));
                    vec![
                        rcbom_facts::impl_key(callee, ty),
                        format!("<{ty} as {tr}>::{method}"),
                    ]
                }
            };
            let Some((name, k)) = names
                .iter()
                .flat_map(|n| (0..=path.len()).rev().map(move |k| (n, k)))
                .find(|(n, k)| {
                    self.returns
                        .contains_key(&((*n).clone(), fields(&path[..*k])))
                })
                .map(|(n, k)| (n.clone(), k))
            else {
                all = false;
                continue;
            };
            let by = via.then(Via::Dyn {
                trait_path: trait_path.to_string(),
                ty: ty.clone(),
                at: at.clone(),
                in_static: *in_static,
                only: types.len() == 1,
            });
            let mut found = Vec::new();
            for r in &self.returns[&(name, fields(&path[..k]))] {
                let v = substitute(r, args);
                self.resolve(&v, &path[k..], owner, depth + 1, &by, &mut found);
            }
            all &= !found.is_empty();
            found.into_iter().for_each(|v| push(&mut out, v));
        }
        (out, all)
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
                if (j == first || s.via_ref) && seen(j, s) && !self.superseded(&s.func) {
                    let by = via.then(Via::Join(s.func.clone()));
                    self.resolve(&s.value, &[], &s.func, depth + 1, &by, out);
                }
            }
        }
    }
}

/// Field `field` of struct `adt` in `o`, a value made of parts with writes into its fields (a
/// function's write summary, `All[before, Set { [1], .. }]`): the value a write to the field
/// puts there (only those where it is written on every way), the field of the other parts,
/// nothing from a write to another field.
fn project(o: &Origin, adt: &str, field: usize, out: &mut Vec<Origin>) {
    match o {
        Origin::All(alts) => {
            let strong = alts.iter().any(|a| {
                matches!(a, Origin::Set { path, strong: true, .. } if path.first() == Some(&field))
            });
            for a in alts {
                if strong && !matches!(a, Origin::Set { .. }) {
                    continue;
                }
                project(a, adt, field, out);
            }
        }
        Origin::Any(alts) => alts.iter().for_each(|a| project(a, adt, field, out)),
        // what a closure returns (a `LazyLock`'s value): its values
        Origin::Call { callee, args, .. } if callee == "<closure>" => {
            args.iter().for_each(|a| project(a, adt, field, out))
        }
        Origin::Set { path, value, .. } => match path.as_slice() {
            [f] if *f == field => out.push((**value).clone()),
            [f, ..] if *f == field => out.push(o.clone()),
            _ => {}
        },
        _ => out.push(Origin::Field {
            adt: adt.to_string(),
            field,
            base: Box::new(o.clone()),
            args: None,
        }),
    }
}

/// The trait method a body of a type implements (or runs as the trait's default body for the
/// type), by its defining path: `app::Pick::alg` for `<app::A as app::Pick>::alg` (generic
/// arguments of the trait dropped) and for `app::Pick::alg for app::A`.
fn implemented_method(f: &str) -> Option<String> {
    if let Some((m, _)) = f.split_once(" for ") {
        return Some(m.to_string());
    }
    let rest = f.strip_prefix('<')?;
    let mut depth = 1usize;
    let mut as_at = None;
    for (i, c) in rest.char_indices() {
        match c {
            '<' => depth += 1,
            '>' => {
                depth -= 1;
                if depth == 0 {
                    let tr = &rest[as_at? + 4..i];
                    let method = rest[i + 1..].strip_prefix("::")?;
                    return Some(format!("{}::{method}", crate::matcher::strip_generics(tr)));
                }
            }
            ' ' if depth == 1 && rest[i..].starts_with(" as ") => as_at = Some(i),
            _ => {}
        }
    }
    None
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

/// Adds a value once; reached several ways, it keeps the most specific. Past `MAX_VALUES`,
/// a cut (`Truncated`) stands for the values refused.
fn push(out: &mut Found, v: (Origin, String, Via)) {
    if let Some(e) = out.iter_mut().find(|e| e.0 == v.0 && e.1 == v.1) {
        if v.2 < e.2 {
            e.2 = v.2;
        }
    } else if out.len() < MAX_VALUES {
        out.push(v);
    } else if !out.iter().any(|e| matches!(e.0, Origin::Truncated)) {
        out.push((Origin::Truncated, v.1, v.2));
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
            self_ty,
            place_ty,
        } => Origin::Written {
            callee: callee.clone(),
            index: *index,
            args: inner.iter().map(|a| substitute(a, args)).collect(),
            self_ty: self_ty.clone(),
            place_ty: place_ty.clone(),
        },
        Origin::Call {
            callee,
            krate,
            self_ty,
            args: inner,
            span,
            runs,
        } => Origin::Call {
            callee: callee.clone(),
            krate: krate.clone(),
            self_ty: self_ty.clone(),
            args: inner.iter().map(|a| substitute(a, args)).collect(),
            span: span.clone(),
            runs: runs.clone(),
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
