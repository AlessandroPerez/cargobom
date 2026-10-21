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

use rcbom_facts::{CrateFacts, NOT_FOLLOWED, Origin};

#[derive(Default)]
pub struct LinkIndex {
    /// By struct and field path.
    fields: HashMap<(String, Vec<usize>), Vec<Stored>>,
    /// By function and part of the returned value.
    returns: HashMap<(String, Vec<usize>), Vec<Origin>>,
    /// By function called: its callers, with the arguments they pass.
    calls: HashMap<String, Vec<(String, Vec<Origin>)>>,
    /// Calls between the program's functions whose arguments carry no algorithm
    /// (`Links::arg_calls`), by callee: only for `callers_of`.
    arg_calls: HashMap<String, Vec<(String, Vec<Origin>)>>,
    /// By def id: (contents change at run time, values put there).
    statics: HashMap<String, (bool, Vec<Origin>)>,
    /// By function, parameter and the fields of a borrow it holds (none: the parameter
    /// itself): what it writes through it.
    writes: HashMap<(String, usize, Vec<usize>), Vec<Origin>>,
    /// By trait: the types coerced to a trait object of it, with where, and the body each
    /// method runs for them.
    coerced: HashMap<String, Vec<Coerced>>,
    /// By body: the calls on trait objects that may run it (`Links::dyn_calls`), each caller
    /// with the arguments it passes (the receiver unknown) and the coercion it runs through.
    dyn_calls: HashMap<String, Vec<(String, Vec<Origin>, Via)>>,
    /// The trait methods called on a trait object whose bodies are not known (no type of the
    /// call's coerced to it, a call whose type is not known): the parameters of their
    /// implementations are not all followed.
    dyn_open: HashSet<String>,
    /// The instances whose summaries the driver's bound left unrecorded (`Links::truncated`).
    truncated: HashSet<String>,
    /// The functions (and instances) the facts show the driver summarised: those some record
    /// names as its maker (a call it makes, a value it stores or returns, what it writes), or
    /// lists as summarised with nothing else recorded (`Links::summarised`). The
    /// driver merges a body's records only once its whole summary is made, the writes through
    /// its `&mut` parameters included, and records a write only where the value changes: for
    /// these, no write recorded is a parameter left as it was; for another, it is not known.
    summarised: HashSet<String>,
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
    /// The functions an entry point reaches, by defining path, once known: a value found
    /// through a caller outside them (dead code) is labelled with that caller.
    reached: RefCell<Option<HashSet<String>>>,
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

/// A value the links do not follow, with why (`what `f` writes: no summary of it`): the value
/// search reports it as a gap, never as the value before or as another part of the value.
pub(crate) fn marker(reason: String) -> Origin {
    Origin::Through {
        callee: format!("{NOT_FOLLOWED} {reason}"),
    }
}

/// Why the links did not follow a value (`marker`), for a marker.
pub(crate) fn not_followed(o: &Origin) -> Option<&str> {
    match o {
        Origin::Through { callee } => callee.strip_prefix(NOT_FOLLOWED).map(str::trim_start),
        _ => None,
    }
}

/// Constructors of values with interior mutability (locks, cells, once-cells, atomics,
/// `thread_local!` keys and their storage), by the end of their path without generic
/// arguments: a static holding one can be written through any borrow of it.
const INTERIOR: &[&str] = &[
    "::Mutex::new",
    "::RwLock::new",
    "::ReentrantLock::new",
    "::ReentrantMutex::new",
    "::Cell::new",
    "::RefCell::new",
    "::UnsafeCell::new",
    "::OnceCell::new",
    "::OnceLock::new",
    "::LocalKey::new",
    "::Storage::new",
];

/// Does the value a static is initialised with hold a value with interior mutability
/// (`Mutex::new(..)`, a `LazyLock`'s closure making one, an atomic)?
fn interior(o: &Origin, depth: usize) -> bool {
    if depth > 8 {
        return false;
    }
    match o {
        Origin::Call { callee, args, .. } => {
            let bare = crate::matcher::strip_generics(callee);
            INTERIOR.iter().any(|t| bare.ends_with(t))
                || bare.contains("::atomic::Atomic")
                || ((callee == "<closure>" || bare.ends_with("LazyLock::new"))
                    && args.iter().any(|a| interior(a, depth + 1)))
        }
        Origin::Any(v) | Origin::All(v) => v.iter().any(|a| interior(a, depth + 1)),
        _ => false,
    }
}

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

    /// Is this a more specific way to the same value than `other`: the declaration order, a
    /// type-join (any value stored in a field of that type) after every other (a static's own
    /// value, or a store into it, before the join of another function's field store).
    pub(crate) fn before(&self, other: &Via) -> bool {
        let join = |v: &Via| matches!(v, Via::Join(_));
        (join(self), self) < (join(other), other)
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
/// body each method of the object runs for it, with its type past the receiver.
type Coerced = (
    String,
    Option<rcbom_facts::Loc>,
    bool,
    Vec<(String, String, String)>,
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
            for c in &f.links.arg_calls {
                let v = ix.arg_calls.entry(c.callee.clone()).or_default();
                let call = (c.caller.clone(), c.args.clone());
                if !v.contains(&call) {
                    v.push(call);
                }
            }
            ix.truncated.extend(f.links.truncated.iter().cloned());
            ix.summarised.extend(
                f.links
                    .calls
                    .iter()
                    .chain(&f.links.arg_calls)
                    .map(|c| c.caller.clone())
                    .chain(f.links.fields.iter().map(|s| s.func.clone()))
                    .chain(f.links.returns.iter().map(|r| r.func.clone()))
                    .chain(f.links.writes.iter().map(|w| w.func.clone()))
                    .chain(
                        f.links
                            .statics
                            .iter()
                            .flat_map(|s| s.writers.iter().map(|(w, _)| w.clone())),
                    )
                    .chain(f.links.summarised.iter().cloned()),
            );
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
                let v = ix
                    .writes
                    .entry((w.func.clone(), w.index, w.path.clone()))
                    .or_default();
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
            .chain(ix.writes.keys().map(|(f, ..)| f.clone()))
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
        // a call on a trait object: of the body each type coerced to it runs where that body is
        // of the call's type (a member each, labelled with its coercion); with no type coerced
        // to it, or a call whose type is not known, the implementations' parameters are not all
        // followed
        let mut dyn_calls: HashMap<String, Vec<(String, Vec<Origin>, Via)>> = HashMap::new();
        for c in facts.iter().flat_map(|f| &f.links.dyn_calls) {
            let fits = |s: &str| s == c.sig || s == "*";
            let bodies: Vec<(&String, &Coerced)> = ix
                .coerced
                .get(&c.trait_path)
                .filter(|_| c.sig != "*")
                .into_iter()
                .flatten()
                .filter_map(|t| {
                    let (_, body, sig) = t.3.iter().find(|(m, ..)| *m == c.call.callee)?;
                    fits(sig).then_some((body, t))
                })
                .collect();
            if bodies.is_empty() {
                ix.dyn_open.insert(c.call.callee.clone());
            }
            for (body, (ty, at, in_static, _)) in &bodies {
                let via = Via::Dyn {
                    trait_path: c.trait_path.clone(),
                    ty: ty.clone(),
                    at: at.clone(),
                    in_static: *in_static,
                    only: bodies.len() == 1,
                };
                let v = dyn_calls.entry((*body).clone()).or_default();
                let call = (c.call.caller.clone(), c.call.args.clone(), via);
                if !v.contains(&call) {
                    v.push(call);
                }
            }
        }
        ix.dyn_calls = dyn_calls;
        ix
    }

    /// Notes that descriptor `id` was found named in function `owner`.
    pub fn note(&self, id: &str, owner: &str) {
        let via = self.current_via.borrow().clone();
        self.named_via
            .borrow_mut()
            .entry(id.to_string())
            .and_modify(|v| {
                if via.before(v) {
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
            path: part,
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
            match self.writes.get(&(b, *index, part.clone())) {
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
            // a table of references to statics or constants whose fields are answered
            || self.static_table(id).is_some_and(|v| {
                v.iter().all(|e| matches!(e, Origin::Data { def, .. }
                    if def.id != id && self.static_fields(&def.id)))
            })
    }

    /// The statics or constants a table of references that never changes points to (`static
    /// AREF: [&Cfg; 2] = [&S1, &S2]`, `static AREF: &[&Cfg] = &[&C1, &C2]`): a field read of an
    /// element at any index is that field of one of them.
    fn static_table(&self, id: &str) -> Option<&[Origin]> {
        match self.statics.get(id) {
            Some((false, v)) => match v.as_slice() {
                [Origin::All(e) | Origin::Any(e)]
                    if !e.is_empty()
                        && e.iter()
                            .all(|x| matches!(x, Origin::Data { def, .. } if def.id != id)) =>
                {
                    Some(e)
                }
                _ => None,
            },
            _ => None,
        }
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

    /// The statics whose contents change at run time that static or constant `id` is, or refers
    /// to (`static REF1: &Mutex<..> = &M1`, `const CREF: &Mutex<..> = &M2`), or holds references
    /// to (`static TAB: [&Mutex<..>; 1] = [&M1]`): a read through it reads them.
    pub fn mutable_statics_of(&self, def: &rcbom_facts::DefRef) -> Vec<rcbom_facts::DefRef> {
        fn walk(
            ix: &LinkIndex,
            def: &rcbom_facts::DefRef,
            depth: usize,
            out: &mut Vec<rcbom_facts::DefRef>,
        ) {
            if depth > 4 || out.iter().any(|d| d.id == def.id) {
                return;
            }
            if ix.mutable_static(&def.id).is_some() {
                out.push(def.clone());
                return;
            }
            let values: Vec<&Origin> = match ix.statics.get(&def.id) {
                Some((false, v)) => v.iter().collect(),
                _ => return,
            };
            fn datas<'o>(o: &'o Origin, acc: &mut Vec<&'o rcbom_facts::DefRef>) {
                match o {
                    Origin::Data { def, .. } => acc.push(def),
                    Origin::Any(v) | Origin::All(v) => v.iter().for_each(|x| datas(x, acc)),
                    _ => {}
                }
            }
            let mut targets = Vec::new();
            for v in values {
                datas(v, &mut targets);
            }
            for t in targets {
                if t.id != def.id {
                    walk(ix, t, depth + 1, out);
                }
            }
        }
        let mut out = Vec::new();
        walk(self, def, 0, &mut out);
        out
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
                // (a static no function of the program puts a value in: a lazy static, a
                // thread-local nothing sets, a lock nothing writes by name)
                let held = writers.is_none_or(|w| w.is_empty());
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

    /// Why what a static whose contents change at run time holds is not all followed, when its
    /// value has interior mutability (a lock, a cell, a once-cell, an atomic, a `thread_local!`
    /// key) or functions write it at run time: the facts record the writes made through the
    /// static's name, through a guard of it and through a function given it, not every borrow
    /// of it (one kept in a struct, a closure capturing it, another crate's code given it).
    /// `None` for one only its initializer fills (a `LazyLock`, a `lazy_static!`).
    pub fn interior_mutable(&self, id: &str) -> Option<String> {
        let (mutable, values) = self.statics.get(id)?;
        if !mutable {
            return None;
        }
        let written = self.static_writers.get(id).is_some_and(|w| !w.is_empty());
        if !(written || values.iter().any(|v| interior(v, 0))) {
            return None;
        }
        Some("a value written into a static with interior mutability through a borrow of it".into())
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

    /// What function `func` returns, whole (its summaries' values, its parameters unresolved).
    pub fn returned_values(&self, func: &str) -> Vec<Origin> {
        self.returns
            .get(&(func.to_string(), Vec::new()))
            .cloned()
            .unwrap_or_default()
    }

    /// The program's calls of `func`: each caller with the arguments it passes, those that
    /// can carry an algorithm or not.
    pub fn callers_of(&self, func: &str) -> impl Iterator<Item = &(String, Vec<Origin>)> {
        self.calls
            .get(func)
            .into_iter()
            .chain(self.arg_calls.get(func))
            .flatten()
    }

    /// The functions an entry point reaches (by defining path).
    pub fn set_reached(&self, reached: HashSet<String>) {
        *self.reached.borrow_mut() = Some(reached);
    }

    /// Is `func` a generic item whose instances' summaries say what its body does?
    fn superseded(&self, func: &str) -> bool {
        self.instanced.contains(func)
            && instance_base(func) == func
            && !self.truncated.iter().any(|t| instance_base(t) == func)
    }

    /// Is a summary the driver's bound left unrecorded (`Links::truncated`) one of an
    /// implementation of trait method `callee` (`<app::W<app::A> as app::Pick>::alg` for
    /// `app::Pick::alg`)? Then a call whose body is not known may run it.
    fn cut_implementation(&self, callee: &str) -> bool {
        self.truncated
            .iter()
            .any(|t| implemented_method(t).is_some_and(|m| m == callee))
    }

    /// Is `caller` a function no entry point reaches (once the reached functions are known)?
    fn unreached_caller(&self, caller: &str) -> bool {
        !caller.is_empty()
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

    /// What a call through the pointer `p` with `args` runs, read in `owner`: a call of each
    /// function named as a value the pointer may be (its body as the driver resolved it), and
    /// the values a closure made a pointer returns (in its function); `None` when the pointer may
    /// be anything else (a value not followed, a cut).
    fn pointer_runs(
        &self,
        p: &Origin,
        args: &[Origin],
        owner: &str,
        depth: usize,
        via: &Via,
    ) -> Option<Vec<(Origin, String)>> {
        let mut values = Vec::new();
        self.resolve(p, &[], owner, depth + 1, via, &mut values);
        let mut out = Vec::new();
        let mut stack: Vec<(Origin, String, usize)> =
            values.into_iter().map(|(v, w, _)| (v, w, 0)).collect();
        while let Some((v, w, n)) = stack.pop() {
            if n > 4 {
                return None;
            }
            match v {
                Origin::Unit {
                    path,
                    krate,
                    value: None,
                    span: Some(_),
                    runs,
                } => out.push((
                    Origin::Call {
                        callee: path,
                        krate,
                        self_ty: None,
                        args: args.to_vec(),
                        span: None,
                        runs,
                        pointer: None,
                        fed: None,
                    },
                    owner.to_string(),
                )),
                Origin::Call {
                    callee, args: r, ..
                } if callee == "<closure>" => {
                    out.extend(r.into_iter().map(|x| (x, w.clone())));
                }
                Origin::Any(alts) => stack.extend(alts.into_iter().map(|a| (a, w.clone(), n + 1))),
                Origin::Data { def, .. } if self.mutable_static(&def.id).is_none() => {
                    let vs = self.static_values(&def.id);
                    if vs.is_empty() {
                        return None;
                    }
                    stack.extend(vs.iter().map(|a| (a.clone(), w.clone(), n + 1)));
                }
                _ => return None,
            }
        }
        (!out.is_empty()).then_some(out)
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
                    // and what the program writes into that field through a reference anywhere
                    // (a type-join, possible), but in a function known to write another static:
                    // a value written through the lock where the static is not named (a helper
                    // given the lock, its guard, a field holding it, another crate's code) is
                    // one of them
                    let key = (adt.clone(), fields(&p));
                    // (functions naming another static they write, not a helper given a lock)
                    let writers_elsewhere: HashSet<&String> = self
                        .static_writers
                        .iter()
                        .filter(|(id, _)| **id != def.id)
                        .flat_map(|(_, w)| {
                            w.iter()
                                .filter(|(_, v)| !matches!(v, Origin::Written { .. }))
                                .map(|(f, _)| f)
                        })
                        .collect();
                    let statik = rcbom_facts::static_owner(&def.path, &def.id);
                    for s in self.fields.get(&key).into_iter().flatten() {
                        if s.via_ref
                            && !writers_elsewhere.contains(&s.func)
                            && rcbom_facts::owner_static(&s.func).is_none()
                            && !self.superseded(&s.func)
                        {
                            let by = via.then(Via::Join(s.func.clone()));
                            let mut found = Vec::new();
                            self.resolve(&s.value, &[], &s.func, depth + 1, &by, &mut found);
                            for f in found {
                                // (a value this function puts in this static, found above
                                // however its write is recorded: through a helper's parameter,
                                // into a field of a field: the static's, not a join)
                                let counted = out.iter().any(|e| {
                                    e.0 == f.0
                                        && matches!(&e.2, Via::Store { writer, statik: st }
                                            if *writer == s.func && *st == statik)
                                });
                                if !counted {
                                    push(out, f);
                                }
                            }
                        }
                    }
                    // a lock or a cell: written through borrows the facts do not all record
                    if let Some(why) = self.interior_mutable(&def.id) {
                        push(out, (marker(why), owner.to_string(), via.clone()));
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
                    // a table of references to others (`[&S1, &S2]`): that field of each
                    if let Some(elems) = self.static_table(&def.id) {
                        for e in elems {
                            let o = Origin::Field {
                                adt: adt.clone(),
                                field: *field,
                                base: Box::new(e.clone()),
                                args: args.clone(),
                            };
                            self.resolve(&o, path, owner, depth + 1, via, out);
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
                path: part,
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
                            match self.writes.get(&(f.clone(), *index, part.clone())) {
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
                                // a function the driver summarised that records no write: it
                                // leaves the value as it was (`touch(&mut d)`)
                                None if self.summarised.contains(&f) => before(&mut found, &by),
                                // no summary of the function known: the value before, and what
                                // it may write, not known, beside it
                                None => {
                                    before(&mut found, &by);
                                    push(
                                        &mut found,
                                        (
                                            marker(format!(
                                                "what `{}` writes through its parameter (no \
                                                 summary of it)",
                                                crate::short(&f)
                                            )),
                                            owner.to_string(),
                                            by,
                                        ),
                                    );
                                }
                            }
                        }
                    }
                    // implementations not known (a trait object no type is coerced to, a type
                    // parameter): the value before, and an unknown beside it
                    None => {
                        before(&mut found, via);
                        push(
                            &mut found,
                            (
                                marker(format!(
                                    "what `{}` writes through its parameter on a type not \
                                     known",
                                    crate::short(callee)
                                )),
                                owner.to_string(),
                                via.clone(),
                            ),
                        );
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
                    matches!(a, Origin::Through { callee }
                        if rcbom_facts::element_writer(callee).is_some())
                }) =>
            {
                // (the function making the write, which the marker names)
                let writer = alts
                    .iter()
                    .find_map(|a| match a {
                        Origin::Through { callee } => rcbom_facts::element_writer(callee),
                        _ => None,
                    })
                    .filter(|w| !w.is_empty())
                    .unwrap_or(owner);
                let by = via.then(Via::Container(writer.to_string()));
                for a in alts {
                    // (the marker itself is no value)
                    if !matches!(a, Origin::Through { callee }
                        if rcbom_facts::element_writer(callee).is_some())
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
                // (and the calls on trait objects running it, through the type's coercion)
                let callers: Vec<(&String, &Vec<Origin>, Via)> = self
                    .calls
                    .get(owner)
                    .into_iter()
                    .flatten()
                    .map(|(c, a)| (c, a, Via::Caller(c.clone())))
                    .chain(
                        self.dyn_calls
                            .get(owner)
                            .into_iter()
                            .flatten()
                            .map(|(c, a, v)| (c, a, v.clone())),
                    )
                    .collect();
                if !callers.is_empty() {
                    // (an implementation of a method called on a trait object whose bodies
                    // are not known, or the trait's default body: run with values not
                    // followed)
                    let method = implemented_method(owner);
                    let mut unknown = self.dyn_open.contains(method.as_deref().unwrap_or(owner));
                    for (caller, args, way) in callers {
                        if self.superseded(caller) {
                            continue;
                        }
                        let direct = matches!(way, Via::Caller(_));
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
                            let by = via.then(way);
                            self.resolve(a, path, caller, depth + 1, &by, &mut found);
                        }
                        // (through a caller no entry point reaches: that caller is how they
                        // reach it, whatever they are further on; not a call on a trait
                        // object, whose bodies are reached through the types coerced to it)
                        if direct && self.unreached_caller(caller) {
                            for v in found.iter_mut() {
                                v.2 = Via::Caller(caller.clone());
                            }
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
            // a call through a function pointer the driver did not resolve in its body (a
            // parameter, a field, a table's element): each function the pointer may be, run with
            // the call's arguments, and what a closure made a pointer returns; where the pointer
            // may be anything else, the call stays as it is (a gap)
            Origin::Call {
                callee,
                args,
                pointer: Some(p),
                fed: None,
                ..
            } if callee == "<indirect>" => {
                if let Some(runs) = self.pointer_runs(p, args, owner, depth, via) {
                    let mut found = Vec::new();
                    for (v, w) in runs {
                        self.resolve(&v, path, &w, depth + 1, via, &mut found);
                    }
                    if !found.is_empty() {
                        found.into_iter().for_each(|v| push(out, v));
                        return;
                    }
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
                            (!self.implemented.contains(callee)
                                && !self.cut_implementation(callee))
                            .then(|| callee.clone()),
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
            if !self.stored(path, depth, via, out) && !matches!(o, Origin::Truncated) {
                // no code the facts record stores in the field: not known
                push(
                    out,
                    (
                        marker(format!(
                            "a field of `{}` no recorded code stores",
                            crate::short(&path[path.len() - 1].0)
                        )),
                        owner.to_string(),
                        via.clone(),
                    ),
                );
            }
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
                path,
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
                        path: path.clone(),
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
                                    .find(|(m, ..)| m == callee)
                                    .map(|(_, b, _)| b.clone())
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
                            path: path.clone(),
                        }
                    }
                    // a function the object is passed on to
                    _ => Origin::Written {
                        callee: callee.clone(),
                        index: *index,
                        args,
                        self_ty: self_ty.clone(),
                        place_ty: Some(ty.to_string()),
                        path: path.clone(),
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
    /// <trait>`: the types coerced to the trait object), each with how it reaches the read;
    /// `None` when they are not known: no type coerced to the object, or a type parameter
    /// (`impl <trait>`), whose instantiations the facts do not name (every implementation the
    /// program has is not what the call runs: R4.7 counts the reachable instantiations only).
    fn implementations(&self, callee: &str, self_ty: &str) -> Option<Vec<(String, Via)>> {
        let (tr, method) = callee.rsplit_once("::")?;
        let mut out = Vec::new();
        if let Some(t) = self_ty.strip_prefix("dyn ") {
            let types = self.coerced.get(t)?;
            for (ty, at, in_static, methods) in types {
                let name = match methods.iter().find(|(m, ..)| m == callee) {
                    Some((_, body, _)) => body.clone(),
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
            let names = match methods.iter().find(|(m, ..)| m == callee) {
                Some((_, body, _)) => vec![body.clone()],
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
    fn stored(&self, path: &FieldPath, depth: usize, via: &Via, out: &mut Found) -> bool {
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
            return false;
        };
        for (j, key) in keys.iter().enumerate().skip(first) {
            for s in self.fields.get(key).into_iter().flatten() {
                if (j == first || s.via_ref) && seen(j, s) && !self.superseded(&s.func) {
                    let by = via.then(Via::Join(s.func.clone()));
                    self.resolve(&s.value, &[], &s.func, depth + 1, &by, out);
                }
            }
        }
        true
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
        if v.2.before(&e.2) {
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
            path,
        } => Origin::Written {
            callee: callee.clone(),
            index: *index,
            args: inner.iter().map(|a| substitute(a, args)).collect(),
            self_ty: self_ty.clone(),
            place_ty: place_ty.clone(),
            path: path.clone(),
        },
        Origin::Call {
            callee,
            krate,
            self_ty,
            args: inner,
            span,
            runs,
            pointer,
            fed,
        } => Origin::Call {
            callee: callee.clone(),
            krate: krate.clone(),
            self_ty: self_ty.clone(),
            args: inner.iter().map(|a| substitute(a, args)).collect(),
            span: span.clone(),
            runs: runs.clone(),
            pointer: pointer.as_ref().map(|p| Box::new(substitute(p, args))),
            fed: fed.as_ref().map(|f| Box::new(substitute(f, args))),
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
