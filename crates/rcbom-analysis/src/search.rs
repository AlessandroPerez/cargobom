//! The value search: which algorithm descriptors (the statics and constants the knowledge base
//! names, `ring::digest::SHA256`) a value a call reads can be, and whether that answer is
//! complete. It is the one source of truth for both: every way a value can come about is
//! either followed by a modelled rule (an `Origin` the match below handles, a standard-library
//! call of `STD`, a call into a crypto crate, a value from another function through the links)
//! or it is a gap, with the reason, beside whatever the search found. A gap is never dropped:
//! the caller reports the algorithms found and the unknown beside them.
//!
//! Two ways to read a value: `Mode::Value`, the value itself (`digest(&SHA256, ..)`'s first
//! argument), and `Mode::Chain`, an object a crypto call made, whose algorithm is the one its
//! constructor named (`key.seal_in_place_append_tag(..)` with `key` from
//! `LessSafeKey::new(UnboundKey::new(&AES_256_GCM, ..))`: the descriptor in the arguments of the
//! first call along the receiver chain that names one).

use std::collections::{HashMap, HashSet};

use rcbom_facts::{DefRef, Origin, Target};
use rcbom_kb::Kb;

use crate::links::{LinkIndex, Via, peel, peel_ix};
use crate::matcher::strip_generics;

/// Why the answer of a search is not complete: a value it met and did not follow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Gap {
    pub reason: String,
    pub kind: GapKind,
    /// Met only through code no entry point reaches (a caller never called, a store made by
    /// dead code): no value of the call at run time.
    pub dead: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GapKind {
    /// A value from another function (a parameter, a field, the program's function, a static
    /// whose contents change at run time): a search that follows the links follows it.
    Elsewhere,
    /// The search hit a bound.
    Cut,
    /// A value the analysis does not follow.
    Unknown,
}

/// What a search found: descriptors, the other statics and constants named (a table of
/// descriptors, `DIGESTS[i]`, whose elements the caller looks up), and the gaps.
#[derive(Clone, Debug, Default)]
pub(crate) struct Found {
    pub defs: Vec<DefRef>,
    pub gaps: Vec<Gap>,
    /// A value met again inside its own search (`Loop`, a value stored from itself): what it
    /// is, the alternatives around it give.
    pub cyclic: bool,
}

impl Found {
    fn def(&mut self, d: &DefRef) {
        if !self.defs.contains(d) {
            self.defs.push(d.clone());
        }
    }

    fn gap(&mut self, kind: GapKind, reason: String, dead: bool) {
        let g = Gap { reason, kind, dead };
        if !self.gaps.contains(&g) {
            self.gaps.push(g);
        }
    }

    fn merge(&mut self, other: Found) {
        self.cyclic |= other.cyclic;
        for d in other.defs {
            self.def(&d);
        }
        for g in other.gaps {
            if !self.gaps.contains(&g) {
                self.gaps.push(g);
            }
        }
    }
}

/// How a value is read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Mode {
    /// The value itself: a descriptor, or one a modelled call passes on.
    Value,
    /// An object made by a crypto call (a key, a context): the descriptors its constructor's
    /// arguments name, else its receiver's. `lengths`: a descriptor given only as an output
    /// length along the chain (`expand(info, HKDF_SHA256)`) is skipped, for an operation of the
    /// HKDF itself (`Okm::fill`).
    Chain { lengths: bool },
}

/// How the value of a standard-library call is made of its arguments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Std {
    /// The value is argument `n`'s, or one of its elements or parts: a wrapper, a borrow, a
    /// read from a container, an iterator over it, a container built from it, a conversion
    /// between standard types.
    Arg(usize),
    /// One of the values of these arguments (`a.iter().chain(b.iter())`).
    Args(&'static [usize]),
    /// A container after a store: the values it held (argument 0), and argument `n` stored in
    /// it (`v.push(x)`: 1; `m.insert(k, x)`: 2, never the key).
    Store(usize),
    /// An `Option`'s or a `Result`'s value, or a fallback (`unwrap_or(x)`; `or_else(f)`: what
    /// `f` makes), or what a once-cell holds or the function initialising it makes.
    Choice,
    /// What a closure or a function makes of a value, or a default (`map(f)`, `map_or(d, f)`,
    /// a `thread_local!` key's `with(f)`): never the value itself.
    Map,
    /// The value a place held before the call replaced it (`mem::replace(p, v)`, `opt.take()`).
    Old,
    /// The error side of a `Result` (`r.err()`, `r.unwrap_err()`).
    ErrRead,
    /// The value, or the type's default (`unwrap_or_default()`): the default of a type that is
    /// data is given by the driver as a second argument, another one is not followed.
    OrDefault,
    /// A value that carries no algorithm: an empty container, an uninitialised one, the error
    /// a `?` returns, a count, a flag.
    Nothing,
}

/// The standard-library calls the search models, by their defining path without generic
/// arguments (its last segments), with what their value is made of. A standard-library call
/// not listed here is not followed: a gap.
pub(crate) const STD: &[(&str, Std)] = &[
    // `Option` and `Result`: the value inside
    ("option::Option::as_ref", Std::Arg(0)),
    ("option::Option::as_mut", Std::Arg(0)),
    ("option::Option::as_deref", Std::Arg(0)),
    ("option::Option::as_deref_mut", Std::Arg(0)),
    ("option::Option::as_pin_ref", Std::Arg(0)),
    ("option::Option::as_pin_mut", Std::Arg(0)),
    ("option::Option::as_slice", Std::Arg(0)),
    ("option::Option::copied", Std::Arg(0)),
    ("option::Option::cloned", Std::Arg(0)),
    ("option::Option::filter", Std::Arg(0)),
    ("option::Option::inspect", Std::Arg(0)),
    ("option::Option::iter", Std::Arg(0)),
    ("option::Option::iter_mut", Std::Arg(0)),
    ("option::Option::unwrap", Std::Arg(0)),
    ("option::Option::expect", Std::Arg(0)),
    ("option::Option::unwrap_unchecked", Std::Arg(0)),
    ("option::Option::ok_or", Std::Arg(0)),
    ("option::Option::ok_or_else", Std::Arg(0)),
    ("option::Option::transpose", Std::Arg(0)),
    ("option::Option::flatten", Std::Arg(0)),
    ("option::Option::insert", Std::Arg(1)),
    ("option::Option::zip", Std::Args(&[0, 1])),
    ("result::Result::as_ref", Std::Arg(0)),
    ("result::Result::as_mut", Std::Arg(0)),
    ("result::Result::as_deref", Std::Arg(0)),
    ("result::Result::as_deref_mut", Std::Arg(0)),
    ("result::Result::copied", Std::Arg(0)),
    ("result::Result::cloned", Std::Arg(0)),
    ("result::Result::ok", Std::Arg(0)),
    ("result::Result::unwrap", Std::Arg(0)),
    ("result::Result::expect", Std::Arg(0)),
    ("result::Result::unwrap_unchecked", Std::Arg(0)),
    ("result::Result::map_err", Std::Arg(0)),
    ("result::Result::inspect", Std::Arg(0)),
    ("result::Result::inspect_err", Std::Arg(0)),
    ("result::Result::iter", Std::Arg(0)),
    ("result::Result::transpose", Std::Arg(0)),
    ("result::Result::flatten", Std::Arg(0)),
    ("option::Option::unwrap_or", Std::Choice),
    ("option::Option::unwrap_or_else", Std::Choice),
    ("option::Option::or", Std::Choice),
    ("option::Option::or_else", Std::Choice),
    ("option::Option::xor", Std::Choice),
    ("option::Option::get_or_insert", Std::Choice),
    ("option::Option::get_or_insert_with", Std::Choice),
    ("result::Result::unwrap_or", Std::Choice),
    ("result::Result::unwrap_or_else", Std::Choice),
    ("result::Result::or", Std::Choice),
    ("result::Result::or_else", Std::Choice),
    ("option::Option::map", Std::Map),
    ("option::Option::and_then", Std::Map),
    ("option::Option::map_or", Std::Map),
    ("option::Option::map_or_else", Std::Map),
    ("result::Result::map", Std::Map),
    ("result::Result::and_then", Std::Map),
    ("result::Result::map_or", Std::Map),
    ("result::Result::map_or_else", Std::Map),
    ("bool::then", Std::Map),
    ("bool::then_some", Std::Arg(1)),
    ("iterator::Iterator::map", Std::Map),
    ("iterator::Iterator::filter_map", Std::Map),
    ("iterator::Iterator::find_map", Std::Map),
    ("iterator::Iterator::flat_map", Std::Map),
    ("option::Option::unwrap_or_default", Std::OrDefault),
    ("result::Result::unwrap_or_default", Std::OrDefault),
    ("option::Option::take", Std::Old),
    ("option::Option::replace", Std::Old),
    ("result::Result::err", Std::ErrRead),
    ("result::Result::unwrap_err", Std::ErrRead),
    ("result::Result::expect_err", Std::ErrRead),
    // the standard traits on standard types: the value, borrowed, converted, cloned
    ("ops::try_trait::Try::branch", Std::Arg(0)),
    ("ops::try_trait::FromResidual::from_residual", Std::Nothing),
    ("ops::deref::Deref::deref", Std::Arg(0)),
    ("ops::deref::DerefMut::deref_mut", Std::Arg(0)),
    ("convert::AsRef::as_ref", Std::Arg(0)),
    ("convert::AsMut::as_mut", Std::Arg(0)),
    ("borrow::Borrow::borrow", Std::Arg(0)),
    ("borrow::BorrowMut::borrow_mut", Std::Arg(0)),
    ("borrow::ToOwned::to_owned", Std::Arg(0)),
    ("clone::Clone::clone", Std::Arg(0)),
    ("clone::Clone::clone_from", Std::Store(1)),
    ("convert::From::from", Std::Arg(0)),
    ("convert::identity", Std::Arg(0)),
    ("hint::black_box", Std::Arg(0)),
    ("hint::must_use", Std::Arg(0)),
    ("default::Default::default", Std::Nothing),
    // containers: a read is one of the elements (R4.3), a store adds one
    ("ops::index::Index::index", Std::Arg(0)),
    ("ops::index::IndexMut::index_mut", Std::Arg(0)),
    ("collect::IntoIterator::into_iter", Std::Arg(0)),
    ("collect::FromIterator::from_iter", Std::Arg(0)),
    ("collect::Extend::extend", Std::Store(1)),
    ("iterator::Iterator::next", Std::Arg(0)),
    ("double_ended::DoubleEndedIterator::next_back", Std::Arg(0)),
    ("double_ended::DoubleEndedIterator::nth_back", Std::Arg(0)),
    ("iterator::Iterator::nth", Std::Arg(0)),
    ("iterator::Iterator::last", Std::Arg(0)),
    ("iterator::Iterator::find", Std::Arg(0)),
    ("iterator::Iterator::min", Std::Arg(0)),
    ("iterator::Iterator::max", Std::Arg(0)),
    ("iterator::Iterator::min_by", Std::Arg(0)),
    ("iterator::Iterator::max_by", Std::Arg(0)),
    ("iterator::Iterator::min_by_key", Std::Arg(0)),
    ("iterator::Iterator::max_by_key", Std::Arg(0)),
    ("iterator::Iterator::copied", Std::Arg(0)),
    ("iterator::Iterator::cloned", Std::Arg(0)),
    ("iterator::Iterator::rev", Std::Arg(0)),
    ("iterator::Iterator::skip", Std::Arg(0)),
    ("iterator::Iterator::take", Std::Arg(0)),
    ("iterator::Iterator::step_by", Std::Arg(0)),
    ("iterator::Iterator::peekable", Std::Arg(0)),
    ("iterator::Iterator::fuse", Std::Arg(0)),
    ("iterator::Iterator::filter", Std::Arg(0)),
    ("iterator::Iterator::skip_while", Std::Arg(0)),
    ("iterator::Iterator::take_while", Std::Arg(0)),
    ("iterator::Iterator::inspect", Std::Arg(0)),
    ("iterator::Iterator::collect", Std::Arg(0)),
    ("iterator::Iterator::cycle", Std::Arg(0)),
    ("iterator::Iterator::by_ref", Std::Arg(0)),
    ("iterator::Iterator::chain", Std::Args(&[0, 1])),
    ("repeat::repeat", Std::Arg(0)),
    ("repeat_n::repeat_n", Std::Arg(0)),
    ("slice::get", Std::Arg(0)),
    ("slice::get_mut", Std::Arg(0)),
    ("slice::get_unchecked", Std::Arg(0)),
    ("slice::get_unchecked_mut", Std::Arg(0)),
    ("slice::first", Std::Arg(0)),
    ("slice::last", Std::Arg(0)),
    ("slice::first_mut", Std::Arg(0)),
    ("slice::last_mut", Std::Arg(0)),
    ("slice::split_first", Std::Arg(0)),
    ("slice::split_last", Std::Arg(0)),
    ("slice::iter", Std::Arg(0)),
    ("slice::iter_mut", Std::Arg(0)),
    ("slice::to_vec", Std::Arg(0)),
    ("slice::into_vec", Std::Arg(0)),
    ("slice::from_ref", Std::Arg(0)),
    ("slice::sort", Std::Arg(0)),
    ("slice::sort_by", Std::Arg(0)),
    ("slice::sort_by_key", Std::Arg(0)),
    ("slice::sort_unstable", Std::Arg(0)),
    ("slice::sort_unstable_by", Std::Arg(0)),
    ("slice::sort_unstable_by_key", Std::Arg(0)),
    ("slice::reverse", Std::Arg(0)),
    ("slice::rotate_left", Std::Arg(0)),
    ("slice::rotate_right", Std::Arg(0)),
    ("slice::swap", Std::Arg(0)),
    ("slice::fill", Std::Store(1)),
    ("slice::copy_from_slice", Std::Store(1)),
    ("slice::clone_from_slice", Std::Store(1)),
    ("boxed::box_assume_init_into_vec_unsafe", Std::Arg(0)),
    ("vec::from_elem", Std::Arg(0)),
    ("vec::Vec::pop", Std::Arg(0)),
    ("vec::Vec::remove", Std::Arg(0)),
    ("vec::Vec::swap_remove", Std::Arg(0)),
    ("vec::Vec::as_slice", Std::Arg(0)),
    ("vec::Vec::as_mut_slice", Std::Arg(0)),
    ("vec::Vec::into_boxed_slice", Std::Arg(0)),
    ("vec::Vec::drain", Std::Arg(0)),
    ("vec::Vec::split_off", Std::Arg(0)),
    ("vec::Vec::retain", Std::Arg(0)),
    ("vec::Vec::retain_mut", Std::Arg(0)),
    ("vec::Vec::truncate", Std::Arg(0)),
    ("vec::Vec::clear", Std::Arg(0)),
    ("vec::Vec::dedup", Std::Arg(0)),
    ("vec::Vec::dedup_by", Std::Arg(0)),
    ("vec::Vec::dedup_by_key", Std::Arg(0)),
    ("vec::Vec::reserve", Std::Arg(0)),
    ("vec::Vec::shrink_to_fit", Std::Arg(0)),
    ("vec::Vec::leak", Std::Arg(0)),
    ("vec::Vec::push", Std::Store(1)),
    ("vec::Vec::insert", Std::Store(2)),
    ("vec::Vec::extend_from_slice", Std::Store(1)),
    ("vec::Vec::append", Std::Store(1)),
    ("vec::Vec::resize", Std::Store(2)),
    ("vec_deque::VecDeque::pop_front", Std::Arg(0)),
    ("vec_deque::VecDeque::pop_back", Std::Arg(0)),
    ("vec_deque::VecDeque::front", Std::Arg(0)),
    ("vec_deque::VecDeque::back", Std::Arg(0)),
    ("vec_deque::VecDeque::get", Std::Arg(0)),
    ("vec_deque::VecDeque::iter", Std::Arg(0)),
    ("vec_deque::VecDeque::remove", Std::Arg(0)),
    ("vec_deque::VecDeque::push_back", Std::Store(1)),
    ("vec_deque::VecDeque::push_front", Std::Store(1)),
    ("vec_deque::VecDeque::insert", Std::Store(2)),
    ("HashMap::get", Std::Arg(0)),
    ("HashMap::get_mut", Std::Arg(0)),
    ("HashMap::remove", Std::Arg(0)),
    ("HashMap::values", Std::Arg(0)),
    ("HashMap::values_mut", Std::Arg(0)),
    ("HashMap::into_values", Std::Arg(0)),
    ("HashMap::insert", Std::Store(2)),
    ("BTreeMap::get", Std::Arg(0)),
    ("BTreeMap::get_mut", Std::Arg(0)),
    ("BTreeMap::remove", Std::Arg(0)),
    ("BTreeMap::values", Std::Arg(0)),
    ("BTreeMap::values_mut", Std::Arg(0)),
    ("BTreeMap::into_values", Std::Arg(0)),
    ("BTreeMap::insert", Std::Store(2)),
    ("HashSet::get", Std::Arg(0)),
    ("HashSet::iter", Std::Arg(0)),
    ("HashSet::take", Std::Arg(0)),
    ("HashSet::insert", Std::Store(1)),
    ("BTreeSet::get", Std::Arg(0)),
    ("BTreeSet::iter", Std::Arg(0)),
    ("BTreeSet::first", Std::Arg(0)),
    ("BTreeSet::last", Std::Arg(0)),
    ("BTreeSet::insert", Std::Store(1)),
    // empty containers and other values that carry no algorithm
    ("vec::Vec::new", Std::Nothing),
    ("vec::Vec::with_capacity", Std::Nothing),
    ("vec_deque::VecDeque::new", Std::Nothing),
    ("vec_deque::VecDeque::with_capacity", Std::Nothing),
    ("HashMap::new", Std::Nothing),
    ("HashMap::with_capacity", Std::Nothing),
    ("BTreeMap::new", Std::Nothing),
    ("HashSet::new", Std::Nothing),
    ("HashSet::with_capacity", Std::Nothing),
    ("BTreeSet::new", Std::Nothing),
    ("string::String::new", Std::Nothing),
    ("boxed::Box::new_uninit", Std::Nothing),
    ("maybe_uninit::MaybeUninit::uninit", Std::Nothing),
    ("once_lock::OnceLock::new", Std::Nothing),
    ("once::OnceCell::new", Std::Nothing),
    // boxes, reference counts, pins: the value inside
    ("boxed::Box::new", Std::Arg(0)),
    ("boxed::Box::pin", Std::Arg(0)),
    ("boxed::Box::leak", Std::Arg(0)),
    ("boxed::Box::into_inner", Std::Arg(0)),
    ("rc::Rc::new", Std::Arg(0)),
    ("rc::Rc::try_unwrap", Std::Arg(0)),
    ("rc::Rc::unwrap_or_clone", Std::Arg(0)),
    ("rc::Rc::into_inner", Std::Arg(0)),
    ("sync::Arc::new", Std::Arg(0)),
    ("sync::Arc::try_unwrap", Std::Arg(0)),
    ("sync::Arc::unwrap_or_clone", Std::Arg(0)),
    ("sync::Arc::into_inner", Std::Arg(0)),
    ("pin::Pin::new", Std::Arg(0)),
    ("pin::Pin::new_unchecked", Std::Arg(0)),
    ("pin::Pin::as_ref", Std::Arg(0)),
    ("pin::Pin::as_mut", Std::Arg(0)),
    ("pin::Pin::get_ref", Std::Arg(0)),
    ("pin::Pin::get_mut", Std::Arg(0)),
    ("pin::Pin::get_unchecked_mut", Std::Arg(0)),
    ("pin::Pin::into_ref", Std::Arg(0)),
    ("manually_drop::ManuallyDrop::new", Std::Arg(0)),
    ("manually_drop::ManuallyDrop::into_inner", Std::Arg(0)),
    // locks, cells, once-cells, lazy values, `thread_local!` keys: what they hold (the static
    // holding one has its own rule: `LinkIndex::interior_mutable`)
    ("mutex::Mutex::new", Std::Arg(0)),
    ("mutex::Mutex::lock", Std::Arg(0)),
    ("mutex::Mutex::try_lock", Std::Arg(0)),
    ("mutex::Mutex::into_inner", Std::Arg(0)),
    ("mutex::Mutex::get_mut", Std::Arg(0)),
    ("rwlock::RwLock::new", Std::Arg(0)),
    ("rwlock::RwLock::read", Std::Arg(0)),
    ("rwlock::RwLock::write", Std::Arg(0)),
    ("rwlock::RwLock::try_read", Std::Arg(0)),
    ("rwlock::RwLock::try_write", Std::Arg(0)),
    ("rwlock::RwLock::into_inner", Std::Arg(0)),
    ("rwlock::RwLock::get_mut", Std::Arg(0)),
    ("cell::Cell::new", Std::Arg(0)),
    ("cell::Cell::get", Std::Arg(0)),
    ("cell::Cell::into_inner", Std::Arg(0)),
    ("cell::Cell::replace", Std::Old),
    ("cell::Cell::take", Std::Old),
    ("cell::RefCell::new", Std::Arg(0)),
    ("cell::RefCell::borrow", Std::Arg(0)),
    ("cell::RefCell::borrow_mut", Std::Arg(0)),
    ("cell::RefCell::try_borrow", Std::Arg(0)),
    ("cell::RefCell::try_borrow_mut", Std::Arg(0)),
    ("cell::RefCell::into_inner", Std::Arg(0)),
    ("cell::RefCell::replace", Std::Old),
    ("cell::RefCell::take", Std::Old),
    ("once_lock::OnceLock::get", Std::Arg(0)),
    ("once_lock::OnceLock::get_mut", Std::Arg(0)),
    ("once_lock::OnceLock::into_inner", Std::Arg(0)),
    ("once_lock::OnceLock::get_or_init", Std::Choice),
    ("once::OnceCell::get", Std::Arg(0)),
    ("once::OnceCell::get_or_init", Std::Choice),
    ("lazy_lock::LazyLock::force", Std::Arg(0)),
    ("lazy::LazyCell::force", Std::Arg(0)),
    ("local::LocalKey::new", Std::Nothing),
    ("eager::Storage::new", Std::Arg(0)),
    ("lazy::Storage::new", Std::Arg(0)),
    ("local::LocalKey::get", Std::Arg(0)),
    ("local::LocalKey::with", Std::Map),
    ("local::LocalKey::with_borrow", Std::Map),
    ("local::LocalKey::with_borrow_mut", Std::Map),
    ("local::LocalKey::replace", Std::Old),
    ("local::LocalKey::take", Std::Old),
    ("mem::replace", Std::Old),
    ("mem::take", Std::Old),
];

/// What the standard library's call `callee` (its defining path) is made of, when it is
/// modelled (`STD`).
pub(crate) fn std_semantics(callee: &str) -> Option<Std> {
    let bare = strip_generics(callee);
    STD.iter()
        .find(|(p, _)| bare.ends_with(&format!("::{p}")) || bare == *p)
        .map(|(_, s)| *s)
}

fn is_std(krate: &str) -> bool {
    matches!(krate, "core" | "std" | "alloc")
}

/// The crate a type path names (`app::Cfg`: `app`; `dyn app::Tr`: `app`).
fn type_crate(t: &str) -> &str {
    let t = t.strip_prefix("dyn ").unwrap_or(t);
    t.split("::").next().unwrap_or(t)
}

/// Depth of the origin tree the search follows inside one function, and the values it looks
/// at for one question: past them the answer is cut, and says so.
const MAX_DEPTH: usize = 24;
const MAX_STEPS: usize = 20_000;

/// One question: the descriptors that reach a value, through the links (`follow`) or not.
pub(crate) struct Search<'a> {
    kb: &'a Kb,
    ix: &'a LinkIndex,
    /// Values from other functions are followed through the links; else they are gaps of kind
    /// `Elsewhere`.
    follow: bool,
    /// Does a value met this way reach the call at run time (its caller or writer is reached)?
    live: &'a dyn Fn(&Via) -> bool,
    /// Does a static or constant that is no descriptor lead to one in its data (`DIGESTS`, a
    /// table of them; not `LESS`, a number)? An argument naming one carries the algorithm.
    leads: Option<&'a dyn Fn(&DefRef) -> bool>,
    /// Answers already given for a value from elsewhere, by (mode, met only through dead code,
    /// value, function it is read in).
    memo: HashMap<(Mode, bool, Origin, String), Found>,
    /// The values from elsewhere being followed now: one met again is a cycle, which adds
    /// nothing.
    active: HashSet<(Mode, Origin, String)>,
    /// The value being followed was met only through code no entry point reaches.
    dead: bool,
    /// The alternatives (`Origin::Any`) of the origin tree being followed that enclose the
    /// value: a `Loop` inside one is the value's own earlier value, which they give.
    alternatives: usize,
    steps: usize,
}

impl<'a> Search<'a> {
    pub fn new(
        kb: &'a Kb,
        ix: &'a LinkIndex,
        follow: bool,
        live: &'a dyn Fn(&Via) -> bool,
    ) -> Search<'a> {
        Search {
            kb,
            ix,
            follow,
            live,
            leads: None,
            memo: HashMap::new(),
            active: HashSet::new(),
            dead: false,
            alternatives: 0,
            steps: MAX_STEPS,
        }
    }

    /// With `leads`: which statics and constants that are no descriptor lead to one.
    pub fn with_leads(mut self, leads: &'a dyn Fn(&DefRef) -> bool) -> Search<'a> {
        self.leads = Some(leads);
        self
    }

    /// Does what the search found name the algorithm: a descriptor, or data leading to one?
    /// Else it is data (key bytes, a number), whose gaps are none of the algorithm's.
    fn names_algorithm(&self, f: &Found) -> bool {
        f.defs.iter().any(|d| {
            crate::provenance::is_descriptor(self.kb, d) || self.leads.is_some_and(|l| l(d))
        })
    }

    /// Is `d` a static or constant that is no descriptor but leads to some (`const RC: Result<..>
    /// = Err(&SHA1)`, a table)? Its data is known, not which variant of it holds what.
    fn leads_only(&self, d: &DefRef) -> bool {
        !crate::provenance::is_descriptor(self.kb, d) && self.leads.is_some_and(|l| l(d))
    }

    /// The descriptors value `o`, read in function `owner`, can be, read as `mode` says.
    pub fn value(&mut self, o: &Origin, owner: &str, mode: Mode) -> Found {
        self.search(o, owner, 0, mode)
    }

    fn search(&mut self, o: &Origin, owner: &str, depth: usize, mode: Mode) -> Found {
        let mut out = Found::default();
        if depth > MAX_DEPTH || self.steps == 0 {
            out.gap(
                GapKind::Cut,
                "the search for the value hit its bound".into(),
                self.dead,
            );
            return out;
        }
        self.steps -= 1;
        let ix = self.ix;
        // a static whose contents change at run time, also behind standard wrappers (`*LAZY`,
        // `ONCE.get().unwrap()`): what the program puts there and its initial value
        if let Origin::Data { def, .. } = peel_ix(Some(ix), o)
            && ix.mutable_static(&def.id).is_some()
        {
            return self.mutable_static(def, depth, mode);
        }
        // (one read through a static or constant referring to it: `REF1.lock()` with `static
        // REF1: &Mutex<..> = &M1`, a table of such references)
        if let Origin::Data { def, .. } = peel_ix(Some(ix), o) {
            let targets = ix.mutable_statics_of(def);
            if !targets.is_empty() {
                for t in &targets {
                    out.merge(self.mutable_static(t, depth, mode));
                }
                return out;
            }
        }
        // a field read of a static (`TABLE.alg`, `TABLE[i].h`, `LAZY.h`): what the static's
        // initializer, or the program at run time, stores in that field
        let p = peel_ix(Some(ix), o);
        if let Origin::Field { .. } = p
            && let Some(def) = static_root(p)
        {
            if ix.field_readable(&def.id) {
                if !self.follow {
                    out.gap(
                        GapKind::Elsewhere,
                        format!("a field of `static {}`", short(&def.path)),
                        self.dead,
                    );
                    return out;
                }
                // (what the links know of the field; when they know nothing, the static's own
                // data says, below)
                if ix.values_via(p, owner).is_some() {
                    return self.elsewhere(p, owner, depth, mode);
                }
            }
            // the static itself: the caller looks up what its data names (one algorithm, or a
            // list of them; else the unknown)
            if self.follow {
                ix.note(&def.id, "");
            }
            out.def(def);
            return out;
        }
        // a value from another function: what reaches it through the links
        if self.elsewhere_value(o) {
            if !self.follow {
                out.gap(GapKind::Elsewhere, unresolved_kind(p), self.dead);
                return out;
            }
            return self.elsewhere(o, owner, depth, mode);
        }
        match p {
            Origin::Data { def, .. } => {
                if self.follow {
                    ix.note(&def.id, owner);
                }
                out.def(def);
            }
            // literal data, a value of a field-less type: no algorithm
            Origin::Const { .. } | Origin::Unit { .. } => {}
            // a value written into an element of a list (`v[0] = x`): its marker is no value,
            // the value written is beside it
            Origin::Any(alts) => {
                self.alternatives += 1;
                for a in alts {
                    out.merge(self.search(a, owner, depth + 1, mode));
                }
                self.alternatives -= 1;
            }
            Origin::All(alts) => {
                for a in alts {
                    out.merge(self.search(a, owner, depth + 1, mode));
                }
            }
            Origin::Set { value, .. } => out.merge(self.search(value, owner, depth + 1, mode)),
            // an iterator advanced by `next` (`for a in DIGESTS.iter()`): its elements are the
            // container's, followed beside it; the marker of a value written into an element
            Origin::Through { callee }
                if callee.ends_with("Iterator::next")
                    || rcbom_facts::element_writer(callee).is_some() => {}
            Origin::Truncated => out.gap(
                GapKind::Cut,
                "the search for the value hit its bound".into(),
                self.dead,
            ),
            // the value's own earlier value (`ctx = ctx.update(d)` in a loop, `a = next(a)`):
            // where it starts and what each step makes are the alternatives around it, followed
            // there; alone, nothing says where it starts
            Origin::Loop if self.alternatives > 0 => out.cyclic = true,
            Origin::Through { .. } | Origin::Unknown | Origin::Loop => {
                out.gap(GapKind::Unknown, unresolved_kind(p), self.dead)
            }
            // (values from elsewhere are followed above)
            Origin::Param { .. } | Origin::Field { .. } | Origin::Written { .. } => {
                out.gap(GapKind::Unknown, unresolved_kind(p), self.dead)
            }
            Origin::Call { .. } => return self.call(p, owner, depth, mode),
        }
        out
    }

    /// A call's value: a closure's result, a modelled standard-library call, a crypto crate's
    /// call (its getter, or the object it makes), or a gap.
    fn call(&mut self, o: &Origin, owner: &str, depth: usize, mode: Mode) -> Found {
        let mut out = Found::default();
        let Origin::Call {
            callee,
            krate,
            self_ty,
            args,
            ..
        } = o
        else {
            return out;
        };
        // a `Result`'s error value: not the value read (`r.ok()`, `r?`, `unwrap_or`)
        if callee == rcbom_facts::RESULT_ERR {
            return out;
        }
        // the error side of a `Result`, given to a closure (`r.unwrap_or_else(|e| e)`)
        if callee == crate::provenance::ERROR_OF {
            if let Some(r) = args.first() {
                out.merge(self.err_side(r, owner, depth + 1, mode));
            }
            return out;
        }
        // what a closure of this function returns
        if callee == "<closure>" {
            for a in args {
                out.merge(self.search(a, owner, depth + 1, mode));
            }
            return out;
        }
        // a standard trait's method on a crypto crate's type (`<LessSafeKey as From<
        // UnboundKey>>::from`) is that crate's code
        let crypto_self = self_ty.as_deref().is_some_and(|t| {
            !t.starts_with("dyn ")
                && self
                    .kb
                    .crate_by_name(type_crate(t))
                    .is_some_and(|c| c.role != rcbom_kb::Role::Protocol)
        });
        if is_std(krate) && !crypto_self {
            let Some(sem) = std_semantics(callee) else {
                out.gap(
                    GapKind::Unknown,
                    format!(
                        "the result of `{}`, a standard-library call the analysis does not model",
                        short(callee)
                    ),
                    self.dead,
                );
                return out;
            };
            return self.std_call(o, sem, owner, depth, mode);
        }
        // a crypto crate's call
        let bare = strip_generics(callee);
        // the algorithm a value was made with (`if c { &SHA256 } else { ctx.algorithm() }`):
        // the descriptor its receiver's chain names
        if crate::provenance::algorithm_getter(self.kb, krate, callee) {
            let f = self.crypto(o, owner, depth, Mode::Chain { lengths: false });
            out.gaps = f.gaps;
            for d in f.defs {
                if crate::provenance::is_descriptor(self.kb, &d) {
                    out.def(&d);
                }
            }
            return out;
        }
        // another getter returning an algorithm (`algorithm().digest_algorithm()`): not
        // followed
        if bare.ends_with("_algorithm") {
            out.gap(GapKind::Unknown, unresolved_kind(o), self.dead);
            return out;
        }
        match mode {
            // an object a crypto call makes, read as a value (a key passed as data): no
            // descriptor itself; its algorithm is its receiver chain's, read there
            Mode::Value => out,
            Mode::Chain { .. } => self.crypto(o, owner, depth, mode),
        }
    }

    /// An object a crypto call made: the descriptors its arguments name, else its receiver's
    /// chain (`LessSafeKey::new(UnboundKey::new(&AES_256_GCM, ..))`). The arguments are data
    /// (key bytes) unless they name a descriptor: only theirs are part of the answer.
    fn crypto(&mut self, o: &Origin, owner: &str, depth: usize, mode: Mode) -> Found {
        let mut out = Found::default();
        let Origin::Call { callee, args, .. } = o else {
            return out;
        };
        let skip = match mode {
            Mode::Chain { lengths: true } => {
                crate::provenance::length_args(self.kb, &[strip_generics(callee), callee.clone()])
            }
            _ => HashSet::new(),
        };
        let mut named = false;
        for (i, a) in args.iter().enumerate() {
            if skip.contains(&i) {
                continue;
            }
            let f = self.search(a, owner, depth + 1, Mode::Value);
            named |= f
                .defs
                .iter()
                .any(|d| crate::provenance::is_descriptor(self.kb, d));
            if self.names_algorithm(&f) {
                out.merge(f);
            } else {
                // data: its gaps are none of the algorithm's
                for d in &f.defs {
                    out.def(d);
                }
            }
        }
        if named {
            return out;
        }
        match args.first() {
            Some(r) => {
                let f = self.search(r, owner, depth + 1, mode);
                let nothing = f.defs.is_empty() && f.gaps.is_empty() && !f.cyclic;
                out.merge(f);
                if nothing && out.defs.is_empty() {
                    out.gap(
                        GapKind::Unknown,
                        format!("{}, whose algorithm is not named", unresolved_kind(o)),
                        self.dead,
                    );
                }
            }
            None => out.gap(
                GapKind::Unknown,
                format!("{}, whose algorithm is not named", unresolved_kind(o)),
                self.dead,
            ),
        }
        out
    }

    /// A modelled standard-library call (`STD`).
    fn std_call(&mut self, o: &Origin, sem: Std, owner: &str, depth: usize, mode: Mode) -> Found {
        let mut out = Found::default();
        let Origin::Call { callee, args, .. } = o else {
            return out;
        };
        let ix = self.ix;
        // one side of a `Result` constant or static (`RC.unwrap_or(x)`, `RS.ok()`): which side
        // holds what it leads to is not recorded (an `Option`'s data is all in `Some`)
        let mut args = args.clone();
        if sem != Std::ErrRead
            && strip_generics(callee).contains("result::Result::")
            && let Some(Origin::Data { def, .. }) = args.first().map(peel)
            && self.leads_only(def)
        {
            out.gap(
                GapKind::Unknown,
                format!("the side of `{}` read, not followed", short(&def.path)),
                self.dead,
            );
            args[0] = Origin::Const {
                value: None,
                len: None,
                span: None,
                zero: false,
            };
        }
        let args = &args;
        // an element of a container a standard-library call reads (`vec![a, b][0]`, `[a,
        // b].get(i)`): one of the values it holds
        let element = |s: &mut Search<'_>, a: &Origin| {
            if matches!(peel(a), Origin::All(v) if v.len() > 1) {
                let by = if callee.contains("into_vec") {
                    "vec![..]".to_string()
                } else {
                    strip_generics(callee)
                };
                ix.with_via(ix.current_via().then(Via::Container(by)), || {
                    s.search(a, owner, depth + 1, mode)
                })
            } else {
                s.search(a, owner, depth + 1, mode)
            }
        };
        match sem {
            Std::Arg(n) => {
                if let Some(a) = args.get(n) {
                    out.merge(element(self, a));
                }
            }
            Std::Args(ns) => {
                for n in ns {
                    if let Some(a) = args.get(*n) {
                        out.merge(element(self, a));
                    }
                }
            }
            Std::Store(n) => {
                // a container built by stores (`v.push(&SHA256); v.push(&SHA512)`): a read of
                // it is any value stored (flow-insensitive), and the container's earlier stores
                if let Some(a) = args.get(n) {
                    let by = ix
                        .current_via()
                        .then(Via::Container(strip_generics(callee)));
                    out.merge(ix.with_via(by, || element(self, a)));
                }
                if let Some(c) = args.first() {
                    out.merge(self.search(c, owner, depth + 1, mode));
                }
            }
            Std::Choice => {
                for a in &crate::provenance::choice_values(callee, args) {
                    out.merge(self.search(a, owner, depth + 1, mode));
                }
            }
            Std::Map => {
                for a in &crate::provenance::mapped_values(callee, args) {
                    out.merge(self.search(a, owner, depth + 1, mode));
                }
            }
            Std::Old => {
                if let Some(a) = args.first() {
                    out.merge(self.search(a, owner, depth + 1, mode));
                }
            }
            Std::ErrRead => {
                if let Some(r) = args.first() {
                    out.merge(self.err_side(r, owner, depth + 1, mode));
                }
            }
            Std::OrDefault => {
                if let Some(a) = args.first() {
                    out.merge(self.search(a, owner, depth + 1, mode));
                }
                // (the driver gives the default of a type that is data as a constant)
                match args.get(1) {
                    Some(d) => out.merge(self.search(d, owner, depth + 1, mode)),
                    None => out.gap(
                        GapKind::Unknown,
                        format!(
                            "the default value of the type, which `{}` falls back to",
                            short(callee)
                        ),
                        self.dead,
                    ),
                }
            }
            Std::Nothing => {}
        }
        out
    }

    /// A static whose contents change at run time: what its initializer and the program put
    /// there (each read in the function that put it there, whose reachability decides whether
    /// it does), and, for one with interior mutability, the unknown beside them.
    fn mutable_static(&mut self, def: &DefRef, depth: usize, mode: Mode) -> Found {
        let mut out = Found::default();
        let ix = self.ix;
        if !self.follow {
            out.gap(
                GapKind::Elsewhere,
                format!("what `static {}` holds at run time", short(&def.path)),
                self.dead,
            );
            return out;
        }
        let key = (
            mode,
            self.dead,
            Origin::Data {
                def: def.clone(),
                value: None,
                zero: false,
            },
            String::new(),
        );
        if let Some(f) = self.memo.get(&key) {
            return f.clone();
        }
        let active = (mode, key.2.clone(), String::new());
        if !self.active.insert(active.clone()) {
            out.cyclic = true;
            return out;
        }
        for (v, by) in ix.static_value_vias(def) {
            let w = match &by {
                Via::Store { writer, .. } => writer.clone(),
                _ => String::new(),
            };
            let dead = self.dead || !(self.live)(&by);
            let f = ix.with_via(ix.current_via().then(by), || {
                let was = std::mem::replace(&mut self.dead, dead);
                let around = std::mem::take(&mut self.alternatives);
                let f = self.search(&v, &w, depth + 1, mode);
                self.dead = was;
                self.alternatives = around;
                f
            });
            out.merge(f);
        }
        if let Some(why) = ix.interior_mutable(&def.id) {
            out.gap(GapKind::Unknown, why, self.dead);
        }
        self.active.remove(&active);
        self.memo.insert(key, out.clone());
        out
    }

    /// A value from another function, read in `owner`: the values the links find for it, each
    /// read in its own function; the value itself among them, or nothing found, is a gap.
    fn elsewhere(&mut self, o: &Origin, owner: &str, depth: usize, mode: Mode) -> Found {
        let mut out = Found::default();
        let ix = self.ix;
        let key = (mode, self.dead, o.clone(), owner.to_string());
        if let Some(f) = self.memo.get(&key) {
            return f.clone();
        }
        let active = (mode, o.clone(), owner.to_string());
        if !self.active.insert(active.clone()) {
            // a cycle (a value stored from itself): what it reaches, the outer read reaches
            out.cyclic = true;
            return out;
        }
        let me = peel_ix(Some(ix), o);
        match ix.values_via(o, owner) {
            None => out.gap(GapKind::Unknown, unresolved_kind(me), self.dead),
            Some(vs) => {
                for (v, w, by) in vs {
                    let dead = self.dead || !(self.live)(&by);
                    if v == *me && w == owner {
                        out.gap(GapKind::Unknown, unresolved_kind(me), dead);
                        continue;
                    }
                    let f = ix.with_via(ix.current_via().then(by), || {
                        let was = std::mem::replace(&mut self.dead, dead);
                        let around = std::mem::take(&mut self.alternatives);
                        let f = self.search(&v, &w, depth + 1, mode);
                        self.dead = was;
                        self.alternatives = around;
                        f
                    });
                    out.merge(f);
                }
            }
        }
        self.active.remove(&active);
        self.memo.insert(key, out.clone());
        out
    }

    /// A value that comes from outside the function: a field read, a parameter, what a
    /// function writes through a `&mut`, a call of a function whose code is analysed (not the
    /// standard library's, nor an algorithm or trait crate's: a protocol crate's, rustls's,
    /// is), a standard trait's method on a type of the program or behind a trait object.
    fn elsewhere_value(&self, o: &Origin) -> bool {
        let ix = self.ix;
        match peel_ix(Some(ix), o) {
            Origin::Field { .. } | Origin::Param { .. } | Origin::Written { .. } => true,
            c @ Origin::Call { .. } if ix.own_impl(c) => true,
            Origin::Call {
                callee,
                krate,
                self_ty,
                ..
            } => {
                if callee == "<closure>"
                    || callee == rcbom_facts::RESULT_ERR
                    || callee == crate::provenance::ERROR_OF
                {
                    false
                } else if is_std(krate) {
                    self_ty.as_deref().is_some_and(|t| {
                        t.starts_with("dyn ")
                            || (!is_std(type_crate(t))
                                && self
                                    .kb
                                    .crate_by_name(type_crate(t))
                                    .is_none_or(|c| c.role == rcbom_kb::Role::Protocol))
                    })
                } else {
                    self.kb
                        .crate_by_name(krate)
                        .is_none_or(|c| c.role == rcbom_kb::Role::Protocol)
                }
            }
            _ => false,
        }
    }

    /// The error side of a `Result` value (`r.err()`): the values its `Err` holds, from where
    /// the `Result` is made (`Err(e)`, `opt.ok_or(e)`, `r.map_err(f)`, a function's result),
    /// each modelled (`ERR`); any other way it is made is a gap.
    fn err_side(&mut self, o: &Origin, owner: &str, depth: usize, mode: Mode) -> Found {
        let mut out = Found::default();
        if depth > MAX_DEPTH || self.steps == 0 {
            out.gap(
                GapKind::Cut,
                "the search for the value hit its bound".into(),
                self.dead,
            );
            return out;
        }
        self.steps -= 1;
        let ix = self.ix;
        match o {
            // a `Result` constant or static (`const RC: Result<..> = Err(&SHA1)`): which side holds
            // what it leads to is not recorded
            Origin::Data { def, .. } if self.leads_only(def) => out.gap(
                GapKind::Unknown,
                format!("the error side of `{}`, not followed", short(&def.path)),
                self.dead,
            ),
            // an `Ok` value, `None`, literal data: no error value
            Origin::Data { .. } | Origin::Const { .. } | Origin::Unit { .. } => {}
            Origin::Any(v) | Origin::All(v) => {
                for x in v {
                    out.merge(self.err_side(x, owner, depth + 1, mode));
                }
            }
            Origin::Set { value, .. } => out.merge(self.err_side(value, owner, depth + 1, mode)),
            Origin::Call { callee, args, .. } if callee == rcbom_facts::RESULT_ERR => {
                if let Some(e) = args.first() {
                    out.merge(self.search(e, owner, depth + 1, mode));
                }
            }
            // (a standard-library call on a standard type, not peeled as a wrapper: `map_err`
            // and `ok_or` keep the value, not the error)
            Origin::Call {
                callee,
                krate,
                self_ty,
                args,
                ..
            } if is_std(krate)
                && self_ty
                    .as_deref()
                    .is_none_or(|t| !t.starts_with("dyn ") && is_std(type_crate(t))) =>
            {
                let bare = strip_generics(callee);
                match ERR.iter().find(|(p, _)| bare.ends_with(&format!("::{p}"))) {
                    // the error a function makes (`map_err(f)`: `f`'s result)
                    Some((_, ErrSide::Made(n))) => {
                        if let Some(f) = args.get(*n) {
                            for v in crate::provenance::fn_values(f, Some(&Origin::Unknown)) {
                                out.merge(self.search(&v, owner, depth + 1, mode));
                            }
                        }
                    }
                    // the error given (`ok_or(e)`)
                    Some((_, ErrSide::Value(n))) => {
                        if let Some(e) = args.get(*n) {
                            out.merge(self.search(e, owner, depth + 1, mode));
                        }
                    }
                    // the error of these `Result`s (`r.as_ref()`; `r.or(other)`: `other`'s)
                    Some((_, ErrSide::Of(ns))) => {
                        for n in *ns {
                            if let Some(r) = args.get(*n) {
                                out.merge(self.err_side(r, owner, depth + 1, mode));
                            }
                        }
                    }
                    // the error of the `Result` a function makes (`and_then(f)`, `or_else(f)`),
                    // and of the receiver's (for `and_then`)
                    Some((_, ErrSide::Then(keep))) => {
                        if *keep && let Some(r) = args.first() {
                            out.merge(self.err_side(r, owner, depth + 1, mode));
                        }
                        for f in args.iter().skip(1) {
                            for v in crate::provenance::fn_values(f, None) {
                                out.merge(self.err_side(&v, owner, depth + 1, mode));
                            }
                        }
                    }
                    None => out.gap(
                        GapKind::Unknown,
                        format!(
                            "the error side of `{}`, a standard-library call the analysis does \
                             not model",
                            short(callee)
                        ),
                        self.dead,
                    ),
                }
            }
            // a crypto crate's error (`ring::error::Unspecified`): no algorithm
            Origin::Call { krate, .. }
                if !self.elsewhere_value(o) && self.kb.crate_by_name(krate).is_some() => {}
            // what a closure returns: the error sides of its results
            Origin::Call { callee, args, .. } if callee == "<closure>" => {
                for a in args {
                    out.merge(self.err_side(a, owner, depth + 1, mode));
                }
            }
            // a `Result` from another function: the error sides of the values that reach it
            _ if self.elsewhere_value(o) => {
                let me = peel_ix(Some(ix), o);
                if !self.follow {
                    out.gap(GapKind::Elsewhere, unresolved_kind(me), self.dead);
                    return out;
                }
                let key = (mode, o.clone(), format!("err {owner}"));
                if !self.active.insert(key.clone()) {
                    return out;
                }
                match ix.values_via(o, owner) {
                    None => out.gap(GapKind::Unknown, unresolved_kind(me), self.dead),
                    Some(vs) => {
                        for (v, w, by) in vs {
                            let dead = self.dead || !(self.live)(&by);
                            if v == *me && w == owner {
                                out.gap(GapKind::Unknown, unresolved_kind(me), dead);
                                continue;
                            }
                            let f = ix.with_via(ix.current_via().then(by), || {
                                let was = std::mem::replace(&mut self.dead, dead);
                                let f = self.err_side(&v, &w, depth + 1, mode);
                                self.dead = was;
                                f
                            });
                            out.merge(f);
                        }
                    }
                }
                self.active.remove(&key);
            }
            Origin::Truncated => out.gap(
                GapKind::Cut,
                "the search for the value hit its bound".into(),
                self.dead,
            ),
            _ => out.gap(
                GapKind::Unknown,
                format!("the error side of {}", unresolved_kind(o)),
                self.dead,
            ),
        }
        out
    }
}

/// How a standard-library call makes the error side of the `Result` it returns.
enum ErrSide {
    /// What the function in argument `n` makes (`map_err(f)`, `ok_or_else(f)`).
    Made(usize),
    /// Argument `n` itself (`ok_or(e)`).
    Value(usize),
    /// The error side of the `Result`s in these arguments (`r.as_ref()`, `r.or(other)`).
    Of(&'static [usize]),
    /// The error side of the `Result` the function in argument 1 makes, and, when `true`, of
    /// the receiver's (`and_then(f)`: either; `or_else(f)`: `f`'s).
    Then(bool),
}

/// The standard-library calls whose `Result`'s error side the search follows.
const ERR: &[(&str, ErrSide)] = &[
    ("result::Result::map_err", ErrSide::Made(1)),
    ("option::Option::ok_or_else", ErrSide::Made(1)),
    ("option::Option::ok_or", ErrSide::Value(1)),
    ("result::Result::as_ref", ErrSide::Of(&[0])),
    ("result::Result::as_mut", ErrSide::Of(&[0])),
    ("result::Result::as_deref", ErrSide::Of(&[0])),
    ("result::Result::copied", ErrSide::Of(&[0])),
    ("result::Result::cloned", ErrSide::Of(&[0])),
    ("result::Result::map", ErrSide::Of(&[0])),
    ("result::Result::inspect", ErrSide::Of(&[0])),
    ("result::Result::inspect_err", ErrSide::Of(&[0])),
    ("result::Result::or", ErrSide::Of(&[1])),
    ("clone::Clone::clone", ErrSide::Of(&[0])),
    ("ops::deref::Deref::deref", ErrSide::Of(&[0])),
    ("convert::AsRef::as_ref", ErrSide::Of(&[0])),
    ("result::Result::and_then", ErrSide::Then(true)),
    ("result::Result::or_else", ErrSide::Then(false)),
];

/// The static a field read reads from (`TABLE.inner.alg`).
pub(crate) fn static_root(o: &Origin) -> Option<&DefRef> {
    match peel(o) {
        Origin::Field { base, .. } => static_root(base),
        Origin::Data { def, .. } => Some(def),
        _ => None,
    }
}

/// What the call's arguments name, in two places to try in turn: its own arguments
/// (`digest(&SHA256, msg)`, `UnboundKey::new(&AES_256_GCM, key)`), then those its receiver was
/// built from (`key.seal_in_place_append_tag(..)` with `key` from `LessSafeKey::new(
/// UnboundKey::new(&AES_256_GCM, ..))`). The receiver's are for a call whose own say nothing of
/// it: `prk.expand(&[info], &AES_256_GCM)` is an HKDF use, of the `HKDF_SHA256` `prk` was built
/// with. Other arguments are data, not the algorithm: a buffer filled by `digest(&SHA256, ..)`
/// passed to `seal_in_place_append_tag` does not make the seal SHA-256.
///
/// Each place gives the descriptors and the other statics and constants named (the user's
/// `TABLE`, whose descriptors the caller looks up), and its gaps: those of the arguments that
/// name something and of the argument that carries the algorithm (`algorithm`, for an
/// operation), and, for the receiver's place, those along the chain.
pub(crate) fn data_in_args(
    search: &mut Search<'_>,
    owner: &str,
    target: &Target,
    algorithm: Option<usize>,
) -> [Found; 2] {
    let Target::Call {
        arg_origins,
        method,
        ..
    } = target
    else {
        return Default::default();
    };
    // an argument that only gives a length names no algorithm (`prk.expand(info,
    // hkdf::HKDF_SHA256)` expands with the PRK's algorithm; the descriptor is its output length)
    let lengths = crate::provenance::length_args(search.kb, &crate::provenance::call_paths(target));
    let mut own = Found::default();
    let mut algorithm_gaps = Vec::new();
    for (i, o) in arg_origins.iter().enumerate() {
        if lengths.contains(&i) {
            continue;
        }
        let f = search.value(o, owner, Mode::Value);
        if Some(i) == algorithm {
            algorithm_gaps.extend(f.gaps.iter().cloned());
        }
        if search.names_algorithm(&f) {
            own.merge(f);
        } else {
            // data: its gaps are none of the algorithm's
            for d in &f.defs {
                own.def(d);
            }
        }
    }
    for g in &algorithm_gaps {
        if !own.gaps.contains(g) {
            own.gaps.push(g.clone());
        }
    }
    let mut chain = Found::default();
    let hkdf_use = !lengths.is_empty() || search.kb.output_steps.iter().any(|m| m == method);
    if let Some(r) = arg_origins.first() {
        chain = search.value(r, owner, Mode::Chain { lengths: hkdf_use });
    }
    chain.defs.retain(|d| !own.defs.contains(d));
    for g in algorithm_gaps {
        if !chain.gaps.contains(&g) {
            chain.gaps.push(g);
        }
    }
    [own, chain]
}

/// Why a value is not followed, from where it comes (`the result of `Scheme::alg``).
pub(crate) fn unresolved_kind(o: &Origin) -> String {
    if let Some(r) = crate::links::not_followed(o) {
        return r.to_string();
    }
    match o {
        Origin::Param { .. } => {
            "a parameter, whose arguments (where a recorded call passes one) name no algorithm"
                .into()
        }
        Origin::Call { callee, .. } => format!("the result of `{}`", short(callee)),
        Origin::Field { adt, .. } if adt == rcbom_facts::TUPLE => "an element of a tuple".into(),
        Origin::Field { adt, .. } => format!("a field of `{}`", short(adt)),
        Origin::Written { callee, .. } => format!("what `{}` writes", short(callee)),
        Origin::Through { callee } if rcbom_facts::element_writer(callee).is_some() => {
            "a value written into an element of a list".into()
        }
        Origin::Through { callee } => format!("a value written through `{}`", short(callee)),
        Origin::Data { def, .. } => {
            format!("`{}`, which leads to no single algorithm", short(&def.path))
        }
        Origin::Any(_) => "one of several values, none naming an algorithm".into(),
        Origin::Truncated => "the search for the value hit its bound".into(),
        Origin::Set { value, .. } => unresolved_kind(peel(value)),
        Origin::Loop | Origin::All(_) | Origin::Const { .. } | Origin::Unit { .. } => {
            "a value the analysis does not follow".into()
        }
        Origin::Unknown => "a value of unknown origin".into(),
    }
}

/// A path for reading, as the CBOM's details give it (`crate::short`).
fn short(path: &str) -> String {
    crate::short(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcbom_facts::{CrateFacts, CrateInfo, CrateRef, Links, ParamWrite, Returned, StaticValue};

    fn data(krate: &str, path: &str) -> Origin {
        Origin::Data {
            def: def(krate, path),
            value: None,
            zero: false,
        }
    }

    fn def(krate: &str, path: &str) -> DefRef {
        DefRef {
            krate: CrateRef {
                name: krate.into(),
                stable_id: "0".into(),
            },
            path: path.into(),
            id: path.into(),
        }
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

    fn param(index: usize) -> Origin {
        Origin::Param { index, owner: None }
    }

    fn index(links: Links) -> LinkIndex {
        LinkIndex::new(&[CrateFacts {
            facts_version: rcbom_facts::FACTS_VERSION,
            krate: CrateInfo {
                name: "app".into(),
                stable_id: "0".into(),
                package: "app".into(),
                version: "0.1.0".into(),
                cwd: "/".into(),
                unit: String::new(),
            },
            sites: Vec::new(),
            data_edges: Vec::new(),
            reach: None,
            links,
            fields: Default::default(),
            variants: Default::default(),
        }])
    }

    fn names(f: &Found) -> Vec<&str> {
        let mut v: Vec<&str> = f.defs.iter().map(|d| d.path.as_str()).collect();
        v.sort();
        v
    }

    fn unknowns(f: &Found) -> usize {
        f.gaps
            .iter()
            .filter(|g| g.kind != GapKind::Elsewhere && !g.dead)
            .count()
    }

    const LIVE: &dyn Fn(&Via) -> bool = &|_| true;

    /// Every `Origin` the search does not follow, and a standard-library call it does not
    /// model, is a gap beside what it finds; never nothing.
    #[test]
    fn what_the_search_does_not_model_is_an_unknown() {
        let kb = Kb::seed().unwrap();
        let ix = LinkIndex::default();
        let sha = data("ring", "ring::digest::SHA256");
        let not_modelled = [
            Origin::Unknown,
            Origin::Truncated,
            Origin::Through {
                callee: "core::slice::<impl [T]>::chunks_mut".into(),
            },
            // a standard-library call the table does not list
            call(
                "core::iter::traits::iterator::Iterator::fold",
                "core",
                vec![sha.clone(), param(0)],
            ),
            // a closure called through a pointer
            call("core::ops::function::Fn::call", "core", vec![param(0)]),
            // a crypto crate's getter other than `algorithm()`
            call(
                "ring::digest::Context::digest_algorithm",
                "ring",
                vec![param(0)],
            ),
        ];
        for o in not_modelled {
            for mode in [Mode::Value, Mode::Chain { lengths: false }] {
                let mut s = Search::new(&kb, &ix, true, LIVE);
                let f = s.value(
                    &Origin::Any(vec![sha.clone(), o.clone()]),
                    "app::main",
                    mode,
                );
                assert_eq!(names(&f), ["ring::digest::SHA256"], "{o:?}");
                assert_eq!(unknowns(&f), 1, "{o:?} gives no unknown");
            }
        }
    }

    /// A value's own earlier value (`Loop`) adds nothing where alternatives around it say
    /// where it starts (a context updated in a loop); alone, it is an unknown.
    #[test]
    fn a_loop_is_its_alternatives() {
        let kb = Kb::seed().unwrap();
        let ix = LinkIndex::default();
        let start = call(
            "ring::hmac::Context::with_key",
            "ring",
            vec![call(
                "ring::hmac::Key::new",
                "ring",
                vec![data("ring", "ring::hmac::HMAC_SHA256"), param(1)],
            )],
        );
        let step = |r: Origin| call("ring::hmac::Context::update", "ring", vec![r, param(2)]);
        let ctx = Origin::Any(vec![step(start), step(Origin::Loop)]);
        let chain = Mode::Chain { lengths: false };
        let f = Search::new(&kb, &ix, true, LIVE).value(&step(ctx), "app::f", chain);
        assert_eq!(names(&f), ["ring::hmac::HMAC_SHA256"]);
        assert_eq!(unknowns(&f), 0);
        let f = Search::new(&kb, &ix, true, LIVE).value(&step(Origin::Loop), "app::f", chain);
        assert!(names(&f).is_empty());
        assert_eq!(unknowns(&f), 1);
    }

    /// A value from another function is a gap a search with the links follows; followed and
    /// not known, it is an unknown.
    #[test]
    fn values_from_elsewhere_are_followed_or_unknown() {
        let kb = Kb::seed().unwrap();
        let ix = LinkIndex::default();
        let o = Origin::Any(vec![data("ring", "ring::digest::SHA256"), param(0)]);
        let mut local = Search::new(&kb, &ix, false, LIVE);
        let f = local.value(&o, "app::f", Mode::Value);
        assert!(f.gaps.iter().any(|g| g.kind == GapKind::Elsewhere));
        // no caller recorded: not known
        let mut linked = Search::new(&kb, &ix, true, LIVE);
        let f = linked.value(&o, "app::f", Mode::Value);
        assert_eq!(names(&f), ["ring::digest::SHA256"]);
        assert_eq!(unknowns(&f), 1);
    }

    /// The modelled standard-library calls give their members, and only them: an `Option`'s
    /// fallback, a container's elements and stores (not a map's keys), the value a place held
    /// before, never a `Result`'s error side for its value.
    #[test]
    fn modelled_calls_give_their_members() {
        let kb = Kb::seed().unwrap();
        let ix = LinkIndex::default();
        let sha = |n: &str| data("ring", &format!("ring::digest::{n}"));
        // `v.first().copied().unwrap_or(&SHA512)` with `v = vec![&SHA256, &SHA384]`
        let v = call(
            "alloc::boxed::box_assume_init_into_vec_unsafe",
            "alloc",
            vec![Origin::All(vec![
                call("alloc::boxed::Box::<T>::new_uninit", "alloc", vec![]),
                Origin::All(vec![sha("SHA256"), sha("SHA384")]),
            ])],
        );
        let first = call(
            "core::option::Option::<&T>::copied",
            "core",
            vec![call("core::slice::<impl [T]>::first", "core", vec![v])],
        );
        let o = call(
            "core::option::Option::<T>::unwrap_or",
            "core",
            vec![first, sha("SHA512")],
        );
        let mut s = Search::new(&kb, &ix, true, LIVE);
        let f = s.value(&o, "app::main", Mode::Value);
        assert_eq!(
            names(&f),
            [
                "ring::digest::SHA256",
                "ring::digest::SHA384",
                "ring::digest::SHA512"
            ]
        );
        assert_eq!(unknowns(&f), 0);
        // `m.insert(&SHA1_KEY, &SHA256); m.get(..)`: the value, not the key
        let m = call(
            "std::collections::HashMap::<K, V, S>::insert",
            "std",
            vec![
                call("std::collections::HashMap::<K, V>::new", "std", vec![]),
                sha("SHA1_FOR_LEGACY_USE_ONLY"),
                sha("SHA256"),
            ],
        );
        let o = call(
            "std::collections::HashMap::<K, V, S>::get",
            "std",
            vec![
                m,
                Origin::Const {
                    value: None,
                    len: Some(1),
                    span: None,
                    zero: false,
                },
            ],
        );
        let f = Search::new(&kb, &ix, true, LIVE).value(&o, "app::main", Mode::Value);
        assert_eq!(names(&f), ["ring::digest::SHA256"]);
        assert_eq!(unknowns(&f), 0);
        // `mem::replace(&mut a, &SHA512)`: what `a` held
        let o = call(
            "core::mem::replace",
            "core",
            vec![sha("SHA384"), sha("SHA512")],
        );
        let f = Search::new(&kb, &ix, true, LIVE).value(&o, "app::main", Mode::Value);
        assert_eq!(names(&f), ["ring::digest::SHA384"]);
        // `Err(&SHA1).unwrap_or(&SHA256)`: the fallback only
        let o = call(
            "core::result::Result::<T, E>::unwrap_or",
            "core",
            vec![
                call(
                    rcbom_facts::RESULT_ERR,
                    "core",
                    vec![sha("SHA1_FOR_LEGACY_USE_ONLY")],
                ),
                sha("SHA256"),
            ],
        );
        let f = Search::new(&kb, &ix, true, LIVE).value(&o, "app::main", Mode::Value);
        assert_eq!(names(&f), ["ring::digest::SHA256"]);
        assert_eq!(unknowns(&f), 0);
        // `o.ok_or(&SHA512).err().unwrap_or(&SHA256)`: the error side `ok_or` makes, and the
        // fallback; the error side of a call not modelled (`s.parse()`) is a gap
        let err = |r: Origin| {
            call(
                "core::option::Option::<T>::unwrap_or",
                "core",
                vec![
                    call("core::result::Result::<T, E>::err", "core", vec![r]),
                    sha("SHA256"),
                ],
            )
        };
        let o = err(call(
            "core::option::Option::<T>::ok_or",
            "core",
            vec![Origin::Unknown, sha("SHA512")],
        ));
        let f = Search::new(&kb, &ix, true, LIVE).value(&o, "app::main", Mode::Value);
        assert_eq!(names(&f), ["ring::digest::SHA256", "ring::digest::SHA512"]);
        assert_eq!(unknowns(&f), 0);
        let o = err(call("core::str::<impl str>::parse", "core", vec![param(0)]));
        let f = Search::new(&kb, &ix, true, LIVE).value(&o, "app::main", Mode::Value);
        assert_eq!(names(&f), ["ring::digest::SHA256"]);
        assert_eq!(unknowns(&f), 1);
        // every listed call is modelled
        for (p, _) in STD {
            assert!(std_semantics(&format!("core::{p}")).is_some(), "{p}");
        }
    }

    /// An object a crypto call made has the algorithm its constructor names; the key bytes
    /// beside it are data, whose gaps are none of the algorithm's; an alternative whose
    /// algorithm is not named is an unknown.
    #[test]
    fn a_crypto_object_has_its_constructors_algorithm() {
        let kb = Kb::seed().unwrap();
        let ix = LinkIndex::default();
        let key = call(
            "ring::aead::LessSafeKey::new",
            "ring",
            vec![call(
                "ring::aead::UnboundKey::new",
                "ring",
                vec![data("ring", "ring::aead::AES_256_GCM"), Origin::Unknown],
            )],
        );
        let chain = Mode::Chain { lengths: false };
        let f = Search::new(&kb, &ix, true, LIVE).value(&key, "app::main", chain);
        assert_eq!(names(&f), ["ring::aead::AES_256_GCM"]);
        assert_eq!(unknowns(&f), 0);
        let other = call(
            "ring::aead::LessSafeKey::new",
            "ring",
            vec![Origin::Const {
                value: None,
                len: Some(32),
                span: None,
                zero: false,
            }],
        );
        let f = Search::new(&kb, &ix, true, LIVE).value(
            &Origin::Any(vec![key, other]),
            "app::main",
            chain,
        );
        assert_eq!(names(&f), ["ring::aead::AES_256_GCM"]);
        assert_eq!(unknowns(&f), 1);
    }

    /// A static with interior mutability (a lock) holds its initial value, what the program
    /// writes into it by name, and the unknown beside them.
    #[test]
    fn a_lock_static_has_the_unknown_beside_its_values() {
        let kb = Kb::seed().unwrap();
        let lock = def("app", "app::ALG");
        let ix = index(Links {
            statics: vec![StaticValue {
                def: lock.clone(),
                mutable: true,
                values: vec![
                    call(
                        "std::sync::poison::mutex::Mutex::<T>::new",
                        "std",
                        vec![data("ring", "ring::digest::SHA256")],
                    ),
                    data("ring", "ring::digest::SHA512"),
                ],
                writers: vec![("app::set".into(), data("ring", "ring::digest::SHA512"))],
            }],
            ..Default::default()
        });
        let o = call(
            "core::ops::deref::Deref::deref",
            "core",
            vec![call(
                "std::sync::poison::mutex::Mutex::<T>::lock",
                "std",
                vec![Origin::Data {
                    def: lock,
                    value: None,
                    zero: false,
                }],
            )],
        );
        let f = Search::new(&kb, &ix, true, LIVE).value(&o, "app::main", Mode::Value);
        assert!(names(&f).contains(&"ring::digest::SHA512"));
        assert_eq!(unknowns(&f), 1);
        // a `LazyLock` only its initializer fills: its value, nothing beside
        let lazy = def("app", "app::LAZY");
        let ix = index(Links {
            statics: vec![StaticValue {
                def: lazy.clone(),
                mutable: true,
                values: vec![call(
                    "<closure>",
                    "",
                    vec![data("ring", "ring::digest::SHA384")],
                )],
                writers: Vec::new(),
            }],
            ..Default::default()
        });
        let o = Origin::Data {
            def: lazy,
            value: None,
            zero: false,
        };
        let f = Search::new(&kb, &ix, true, LIVE).value(&o, "app::main", Mode::Value);
        assert_eq!(names(&f), ["ring::digest::SHA384"]);
        assert_eq!(unknowns(&f), 0);
    }

    fn written(callee: &str, self_ty: Option<&str>) -> Origin {
        Origin::Written {
            callee: callee.into(),
            index: 0,
            args: vec![data("ring", "ring::digest::SHA256")],
            self_ty: self_ty.map(str::to_string),
            place_ty: None,
            path: Vec::new(),
        }
    }

    /// What a function writes through `&mut`, with no summary recorded, is the value before and
    /// the unknown beside it, never only the value before; on a type parameter (`impl Tr`),
    /// every implementation's write is not what the call runs: the unknown, not those values.
    #[test]
    fn writes_not_known_are_unknowns_not_members() {
        let kb = Kb::seed().unwrap();
        let w = |v: &str| ParamWrite {
            func: format!("<app::{v} as app::Up>::up"),
            index: 0,
            value: data("ring", &format!("ring::digest::{v}")),
            path: Vec::new(),
        };
        let ix = index(Links {
            writes: vec![w("SHA384"), w("SHA512")],
            ..Default::default()
        });
        for o in [
            written("app::touch", None),
            written("app::Up::up", Some("impl app::Up")),
        ] {
            let f = Search::new(&kb, &ix, true, LIVE).value(&o, "app::main", Mode::Value);
            assert_eq!(names(&f), ["ring::digest::SHA256"], "{o:?}");
            assert_eq!(unknowns(&f), 1, "{o:?}");
        }
        // a function the facts show was summarised (here: it calls another of the program's, or
        // is listed as summarised with no write), with no write recorded, leaves the value as
        // it was
        for ix in [
            index(Links {
                arg_calls: vec![rcbom_facts::LocalCall {
                    callee: "app::log".into(),
                    caller: "app::touch".into(),
                    args: Vec::new(),
                }],
                ..Default::default()
            }),
            index(Links {
                summarised: vec!["app::touch".into()],
                ..Default::default()
            }),
        ] {
            let f = Search::new(&kb, &ix, true, LIVE).value(
                &written("app::touch", None),
                "app::main",
                Mode::Value,
            );
            assert_eq!(names(&f), ["ring::digest::SHA256"]);
            assert_eq!(unknowns(&f), 0);
        }
    }

    /// A trait method called where the body it runs is not resolved takes the trait's default
    /// body only when no implementation may override it, an implementation whose summary the
    /// driver's bound cut included.
    #[test]
    fn the_default_body_is_not_taken_beside_a_cut_implementation() {
        let kb = Kb::seed().unwrap();
        let o = call("app::Pick::alg", "app", vec![param(0)]);
        let links = |truncated: Vec<String>| Links {
            returns: vec![Returned {
                func: "app::Pick::alg".into(),
                path: Vec::new(),
                value: data("ring", "ring::digest::SHA256"),
            }],
            truncated,
            ..Default::default()
        };
        let ix = index(links(Vec::new()));
        let f = Search::new(&kb, &ix, true, LIVE).value(&o, "app::main", Mode::Value);
        assert_eq!(names(&f), ["ring::digest::SHA256"]);
        assert_eq!(unknowns(&f), 0);
        let ix = index(links(vec!["<app::Fast as app::Pick>::alg".into()]));
        let f = Search::new(&kb, &ix, true, LIVE).value(&o, "app::main", Mode::Value);
        assert!(names(&f).is_empty());
        assert_eq!(unknowns(&f), 1);
    }
}
