//! Intraprocedural origins of call arguments: where the value passed to a crypto API comes
//! from, as a bounded tree over the body's def-use chains.
//!
//! `UnboundKey::new(&AES_256_GCM, &secret.as_bytes()[..32])` gives, for argument 1, a chain of
//! calls (`Index::index`, `str::as_bytes`) down to `std::env::var`; for the nonce of
//! `Nonce::assume_unique_for_key([0u8; 12])` a 12-byte constant. The tree is knowledge-base
//! agnostic: deciding that `env::var` is external input or `thread_rng` a CSPRNG happens in the
//! analysis, which also sees through standard-library plumbing.
//!
//! The analysis is a reaching-definitions analysis over places: a local with its field path
//! (`cfg.key`, a closure's captured `(*_1).0`, an `async` body's saved `((*_1) as variant#3).0`).
//! A definition counts only if it can reach the use; an assignment to a place kills earlier
//! definitions of that place and of its parts. Writes through references and calls that take
//! `&mut` (out-parameters) define what the reference points to, without killing. Indexing
//! ends a path: an element stands for its array.
use std::cell::{Cell, OnceCell, RefCell};
use std::collections::{HashMap, HashSet};

use rcbom_facts::{Loc, MAX_ORIGIN_DEPTH, Origin};
use rustc_middle::ty::{GenericArgsRef, TyCtxt};
use rustc_public::mir::alloc::GlobalAlloc;
use rustc_public::mir::{
    AggregateKind, Body, BorrowKind, Local, MutBorrowKind, Mutability, Operand, Place,
    ProjectionElem, Rvalue, StatementKind, Terminator, TerminatorKind,
};
use rustc_public::ty::{ConstantKind, IntTy, RigidTy, Span, Ty, TyKind, UintTy};
use rustc_public::{CrateDef, rustc_internal};
use rustc_span::def_id::DefId;

use crate::{def_ref_internal, locate, path_of};

mod constants;
mod flow;
mod instances;
mod pointees;
mod spans;
mod types;
mod values;

use constants::*;
use flow::*;
use instances::*;
use pointees::*;
use types::*;

// (used elsewhere in the crate, as `crate::origins::..`)
pub(crate) use instances::{body_name, runs_of, set_summarised, take_instances, write_callee};
pub(crate) use pointees::returned_pointers;
pub(crate) use types::{holder_of, holder_steps, holds_cell, self_adt_path};

/// Call, aggregate and closure hops followed before the origin is cut (`Truncated`); moves,
/// borrows and casts are free.
const MAX_DEPTH: usize = 10;
/// Alternatives, call arguments and aggregate parts kept per node: a `match` over every
/// variant of a selector (jwt-cli's 12 JWT algorithms) is kept whole.
const MAX_WIDTH: usize = 16;
/// Fields of a struct literal given each its own value (`Origin::Set`); further ones are cut.
const MAX_FIELDS: usize = 32;
/// Nodes (operands) per origin tree; past them nothing more is read, places either.
const MAX_NODES: usize = 400;
/// Projections of a place followed: a loop walking a list (`q = (*q).next`) reads a longer
/// path at each turn, and moves and borrows are free of the other limits.
const MAX_PATH: usize = 16;
/// Steps of one search for what a pointer points to: a pointer re-pointed in a loop into one
/// of several parts (`t = match t { A(e) => &mut e.l, B(e) => &mut e.r, .. }`, syn's
/// `stmt_expr`) branches at each turn, and the search is cut past this many places.
const MAX_SEARCH: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Step {
    Deref,
    Field(usize),
    Variant(usize),
    /// Some element or elements of an array or slice (`a[i]`, `a[2..]`, slice patterns): a
    /// part of it, not the whole.
    Elem,
    /// Element `n` of an array, counted from the start (`let [a, b] = arr;`): a part of it.
    Index(usize),
    /// Some part of a value, which one not known: what a borrow function `.0` returned into
    /// its argument points to (`*self.slot() = v`, `fn slot(&mut self) -> &mut &Digest`).
    Part(String),
}

impl Step {
    /// The same part of a place: an element at a known index is one of the elements an
    /// unknown index (`Elem`) may be.
    fn same(&self, other: &Step) -> bool {
        match (self, other) {
            (Step::Elem, Step::Elem | Step::Index(_)) | (Step::Index(_), Step::Elem) => true,
            _ => self == other,
        }
    }
}

type Path = Vec<Step>;

pub(crate) fn variant_index(v: &rustc_public::ty::VariantIdx) -> usize {
    // `VariantIdx` prints as `VariantIdx(n, ..)`; its index accessor is not public
    format!("{v:?}")
        .trim_start_matches("VariantIdx(")
        .split(|c: char| !c.is_ascii_digit())
        .next()
        .and_then(|n| n.parse().ok())
        .unwrap_or(usize::MAX)
}

fn path_of_place(p: &Place) -> Path {
    let mut out = Vec::new();
    for e in &p.projection {
        match e {
            ProjectionElem::Deref => out.push(Step::Deref),
            ProjectionElem::Field(f, _) => out.push(Step::Field(*f)),
            ProjectionElem::Downcast(v) => out.push(Step::Variant(variant_index(v))),
            ProjectionElem::OpaqueCast(_) => {}
            // `let [a, b] = arr;`: element `offset` from the start
            ProjectionElem::ConstantIndex {
                offset,
                from_end: false,
                ..
            } => out.push(Step::Index(*offset as usize)),
            // `a[i]`, `a[2..]`, slice patterns: some part of the array, whichever it is (and a
            // field of that element: `TABLE[i].h`)
            _ => out.push(Step::Elem),
        }
    }
    out
}

/// A program point: statement `idx` of block `bb`; `idx == statements.len()` is the terminator.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct At {
    bb: usize,
    idx: usize,
}

enum DefKind {
    /// The function's own argument (or, in a closure or coroutine, its environment).
    Entry,
    Assign(Rvalue, Span),
    Call {
        func: Operand,
        args: Vec<Operand>,
    },
    /// The place was passed by `&mut` to this call, which may have written it
    /// (`OsRng.fill_bytes(&mut nonce)`, `pbkdf2_hmac(.., &mut out)`).
    OutParam {
        func: Operand,
        args: Vec<Operand>,
        /// The argument that points at the place (`None`: a value holding a pointer to it).
        index: Option<usize>,
        /// With `index`, the fields of that argument's value (behind it, for a borrow of the
        /// value) where the borrow pointing at the place sits, which the function's summary
        /// follows (`wset(W { slot: &mut x })`: `[0]`, `holder_param`); empty: the argument
        /// itself points at it.
        path: Vec<usize>,
    },
    /// The place was mutably borrowed by this call, which returned a value holding the borrow
    /// (`key.chunks_mut(16)`, `split_at_mut`): later writes go through that value.
    Through {
        func: Operand,
    },
    /// A closure built here that assigns to the place through a capture it holds, handed to a
    /// call that may run it (`[0].iter().for_each(|_| a = &SHA384)`, `run(|| a = x)`, `f()`):
    /// the place may hold one of these values, or what it held (a weak definition). While the
    /// closure holds the borrow nothing else reads or writes the place.
    Value(Origin),
    /// The place may have been written through a pointer whose targets were followed past
    /// the bound (`MAX_PATH` reborrows): the write is a cut, not dropped.
    Cut,
    /// The place's `&mut` was put in a value (`vec![&mut x]`, `Some(&mut x)`) and a write went
    /// through a pointer the search does not follow (one taken out of that value by an
    /// iterator): it may have written the place, with a value not followed.
    Lost,
}

struct Def {
    local: Local,
    path: Path,
    at: At,
    kind: DefKind,
    /// Overwrites the place: earlier definitions of it and its parts are dead.
    strong: bool,
    /// An initialization (a constant, `String::new()`): a later out-parameter call that fills
    /// the place replaces it.
    init: bool,
    /// The definition certainly lands on this place (not one of several a pointer may target):
    /// only then does an out-parameter call replace the place's initialization.
    sole: bool,
}

/// What kind of body this is, for its first local.
#[derive(Clone, Copy, PartialEq, Eq)]
enum BodyKind {
    Fn,
    /// `_1` is the closure itself; captures are its fields.
    Closure,
    /// `_1` is the pinned coroutine; captures are fields of `*_1.0`.
    Coroutine,
}

pub(crate) struct Origins<'a, 'tcx> {
    tcx: TyCtxt<'tcx>,
    body: &'a Body,
    def: Option<DefId>,
    kind: BodyKind,
    /// The definitions and where they reach, computed when an origin is first asked for: most
    /// bodies the scanner visits have no call that needs one, and the largest (minisign's
    /// unrolled `Blake2b::compress`, thousands of overflow-check blocks) would cost minutes.
    flow: OnceCell<Flow>,
    /// Followed from a caller (a closure passed as an argument): its own parameters are not
    /// the caller's.
    followed: bool,
    /// Followed for `Origin::Call::fed`: a closure's own parameters are
    /// `Param { owner: Some(CLOSURE_INPUT) }`, not `Unknown`.
    inputs: bool,
    /// Origins of the captures, when known (a closure followed from the place it is built).
    captures: Option<Vec<Origin>>,
    /// Captures looked up in the parent body (capture, what is read of it), computed once.
    parent_captures: RefCell<HashMap<CaptureRead, Option<Origin>>>,
    nodes: Cell<usize>,
    /// For an instance body (a generic function's instance, a closure in the walk): the item
    /// it was instantiated from and the instance's generic arguments. The instance body has its
    /// named constants evaluated away (`&ECDSA_P256_SHA256_ASN1` is a bare pointer there); the
    /// item's MIR, at the same span, still names them.
    item: Option<(DefId, GenericArgsRef<'tcx>)>,
    /// The item MIR's unevaluated constants by span (`None`: several share the span).
    item_consts: OnceCell<HashMap<rustc_span::Span, Option<Uneval<'tcx>>>>,
}

/// A capture of a closure and what is read of it (`(*(*_1).0).key`: capture 0, then `.key`).
type CaptureRead = (usize, Vec<Step>);

/// An unevaluated constant, as `rustc_middle` has it: item, arguments, promoted index.
type Uneval<'tcx> = (
    DefId,
    GenericArgsRef<'tcx>,
    Option<rustc_middle::mir::Promoted>,
);

/// Reaching definitions of one body.
struct Flow {
    defs: Vec<Def>,
    by_local: HashMap<Local, Vec<usize>>,
    /// Reaching definitions at the entry of each block.
    entry: Vec<BitSet>,
    /// Block of each terminator, by address: the scanner asks about the call it is visiting.
    term_bb: HashMap<*const Terminator, usize>,
    /// Locals whose cells may change through an alias the definitions do not follow
    /// (`open_cells`): a read of their cell is also the unknown.
    open_cells: HashSet<Local>,
}

impl<'a, 'tcx> Origins<'a, 'tcx> {
    pub(crate) fn new(tcx: TyCtxt<'tcx>, body: &'a Body, def: Option<DefId>) -> Self {
        let kind = match def {
            Some(d) if tcx.is_coroutine(d) => BodyKind::Coroutine,
            Some(d) if tcx.is_closure_like(d) => BodyKind::Closure,
            _ => BodyKind::Fn,
        };
        Origins {
            tcx,
            body,
            def,
            kind,
            flow: OnceCell::new(),
            followed: false,
            inputs: false,
            captures: None,
            parent_captures: RefCell::new(HashMap::new()),
            nodes: Cell::new(0),
            item: None,
            item_consts: OnceCell::new(),
        }
    }

    /// The origins of an instance body, whose constants are looked up in the MIR of `item` at
    /// the same span, and whose generic constants resolve with the instance's `args`.
    pub(crate) fn with_item(mut self, item: DefId, args: GenericArgsRef<'tcx>) -> Self {
        self.item = Some((item, args));
        self
    }

    /// The instance's generic arguments, when this is an instance body.
    fn inst_args(&self) -> Option<GenericArgsRef<'tcx>> {
        self.item.map(|(_, a)| a)
    }

    /// The item MIR's unevaluated constant at `span`, if exactly one is there. Read with
    /// `rustc_middle`: converting a generic body to `rustc_public` fails on constants whose
    /// layout depends on a parameter (`None::<&T>` in the standard library's optimized MIR).
    fn item_const(&self, span: Span) -> Option<Uneval<'tcx>> {
        let (item, _) = self.item?;
        let tcx = self.tcx;
        self.item_consts
            .get_or_init(|| {
                use rustc_middle::mir::visit::Visitor;
                struct V<'tcx>(HashMap<rustc_span::Span, Option<Uneval<'tcx>>>);
                impl<'tcx> Visitor<'tcx> for V<'tcx> {
                    fn visit_const_operand(
                        &mut self,
                        c: &rustc_middle::mir::ConstOperand<'tcx>,
                        _: rustc_middle::mir::Location,
                    ) {
                        if let rustc_middle::mir::Const::Unevaluated(uv, _) = c.const_ {
                            let u = (uv.def, uv.args, uv.promoted);
                            self.0
                                .entry(c.span)
                                .and_modify(|e| {
                                    if *e != Some(u) {
                                        *e = None;
                                    }
                                })
                                .or_insert(Some(u));
                        }
                    }
                }
                let mut v = V(HashMap::new());
                if tcx.is_mir_available(item) {
                    v.visit_body(tcx.optimized_mir(item));
                }
                v.0
            })
            .get(&rustc_internal::internal(tcx, span))
            .copied()
            .flatten()
    }

    fn flow(&self) -> &Flow {
        self.flow.get_or_init(|| {
            Flow::new(
                self.tcx,
                self.body,
                self.kind == BodyKind::Coroutine,
                &|f| self.local_fn(f),
            )
        })
    }
}

type Key = (Local, Path, At);

/// What a pointer-typed place may point to, from the definitions that took the address.
struct Pointees<'a> {
    body: &'a Body,
    direct: &'a HashMap<Local, Vec<&'a DefKind>>,
    /// A search for targets went past the bound since it was last cleared.
    cut: Cell<bool>,
    /// The places the current search has looked at (`MAX_SEARCH`).
    steps: Cell<usize>,
    /// A search for targets met a pointer it does not follow (one taken out of a container or
    /// an iterator, `for r in vec![&mut x]`) since it was last cleared.
    lost: Cell<bool>,
    /// Locals some statement writes a part of (`h.r = &mut y`): their aggregates' fields are
    /// not all they hold.
    partly: HashSet<Local>,
    /// The pointer stores into parts of locals (`h.r = &mut y`), by local: path, where, value.
    part_stores: HashMap<Local, Vec<(Path, At, Operand)>>,
    /// Where the write being followed is (the statement whose pointer is looked up).
    cur_at: Cell<Option<At>>,
    /// Pointers to values that hold a `&mut` (`&mut W` with `W { r: &mut T }`): a borrow a call
    /// returns into one may point through it.
    holders: HashSet<Local>,
    /// Locals the body lends by `&mut` (`o.insert(..)` on `&mut o`): what a value built in one
    /// holds may change through the loan.
    lent_locals: HashSet<Local>,
    /// Pointers whose own place a loan may change (`repointed`).
    repointed: HashSet<Local>,
    /// Locals whose value holds a `&mut` (`W { r: &mut x }`, a closure capturing one, a type
    /// parameter's): handed to a call, it may be written through.
    mut_holding: HashSet<Local>,
    /// The locals of type `Option<&mut T>` (`option_holder`): a holder at `Some`'s field.
    options: HashSet<Local>,
    /// The number of arguments.
    nargs: usize,
    /// The pointer types whose standard-library containers the body only moves pointers into
    /// and out of (`Vec<&mut T>` by `push`, `pop`, `into_iter`, `next`; `vec![&mut x]`,
    /// `Box::new`, `Option::insert`), never re-pointing one they hold nor handing them to other
    /// code (`Bags`): what such a container holds is what was put in it (`bag_targets`).
    bags: Bags,
    /// The containers whose contents are being looked up (one fed from itself adds nothing).
    bag_stack: RefCell<Vec<Local>>,
    /// What the results of the functions the body calls hold of the borrows they are given, by
    /// function (`returned_pointers`).
    returns: HashMap<rustc_public::DefId, Returns>,
}

/// What `closed_bags` finds in a body.
#[derive(Default)]
struct Bags {
    closed: HashSet<Ty>,
    /// The calls that move pointers (`moves_only`), by function and arguments.
    moves: Vec<(Operand, Vec<Operand>)>,
    /// What `vec![..]` stores in its box's allocation: the box and the value.
    box_inits: Vec<(Local, Rvalue)>,
}

/// A place a pointer may point to. `alias` marks the place through the pointer itself
/// (`(*_7)` behind `_6 = &mut (*_7)`), listed next to what `_7` was found to point at: it stands
/// for that place, not for another one.
struct Target {
    local: Local,
    path: Path,
    alias: bool,
}

/// The standard library's containers whose pointers `bag_content` follows (by the type's last
/// path segment): they only store what they are given and hand it back.
const BAG_TYPES: &[&str] = &[
    "Vec",
    "VecDeque",
    "Option",
    "Box",
    "MaybeUninit",
    "ManuallyDrop",
    "IntoIter",
    "Once",
    "Unique",
    "NonNull",
];

/// Standard-library functions (by their last two path segments) that only move pointers into
/// and out of containers, or read their length: they write through none of the pointers they
/// are given, nor hand them to code of the program.
const MOVES: &[&str] = &[
    "Vec::new",
    "Vec::with_capacity",
    "Vec::push",
    "Vec::pop",
    "Vec::insert",
    "Vec::remove",
    "Vec::swap_remove",
    "Vec::truncate",
    "Vec::clear",
    "Vec::len",
    "Vec::is_empty",
    "Option::unwrap",
    "Option::expect",
    "Option::take",
    "Option::replace",
    "Option::insert",
    "Option::get_or_insert",
    "Option::as_mut",
    "Option::is_some",
    "Option::is_none",
    "Box::new",
    "Box::new_uninit",
    "boxed::box_assume_init_into_vec_unsafe",
    "slice::into_vec",
    "iter::once",
];

/// Trait methods that do the same when their `Self` is such a container and their other type
/// arguments are containers, pointers or numbers (`<vec::IntoIter<_> as Iterator>::next`, `<Vec<_>
/// as IndexMut<usize>>::index_mut`, `<Option<_> as From<_>>::from`): not an implementation by the
/// program (`impl From<Mine> for Vec<&mut T>`).
const MOVES_OF: &[&str] = &[
    "Iterator::next",
    "IntoIterator::into_iter",
    "IndexMut::index_mut",
    "Index::index",
    "From::from",
];

/// A closure's capture that is a `&mut`: its index, what it points to, and whether that is
/// one place.
type Capture = (usize, Vec<Target>, bool);

/// Where a pointer a function's result holds points (`returned_pointers`).
#[derive(Clone, Debug, PartialEq)]
enum Returned {
    /// Into what argument `k` points to, at a part of it (`W { r: x }`: `(0, [])`; `(&mut
    /// self.a, ..)`: `(0, [Field(0)])`).
    Borrow(usize, Path),
    /// Where the pointer argument `k`'s value holds at these fields points (`fn pass(h: W) -> W {
    /// h }`).
    Held(usize, Path),
}

/// The pointers a function's result holds (a struct, a tuple, an `Option`; not a pointer
/// itself), by where they sit in it, and where each points; `once`: the result is built once.
#[derive(Clone, Debug)]
pub(crate) struct Returns {
    ptrs: Vec<(Path, Returned)>,
    once: bool,
}

/// Standard-library methods handing out a guard through which a cell's value is written
/// (`*c.borrow_mut() = v`, `*m.lock().unwrap() = v`): the write is `Through` at the call.
const GUARDS: &[&str] = &[
    "RefCell::<T>::borrow_mut",
    "RefCell::<T>::try_borrow_mut",
    "Mutex::<T>::lock",
    "Mutex::<T>::try_lock",
    "RwLock::<T>::write",
    "RwLock::<T>::try_write",
];

/// Standard-library functions taking a shared borrow of a cell that only read it (its value, a
/// read guard, its formatting or comparison). Any other may write the cell (`Cell::swap`,
/// `take`, `OnceCell::set`, `get_or_init`, an atomic's `store`, the guards of `borrow_mut`,
/// `lock`, `write`): what it holds after the call is not known. A lazy value's first access
/// (`deref`, `force`) stores its initializer's value, which is what it is known to hold.
const CELL_READS: &[&str] = &[
    "::deref",
    "::force",
    "Cell::<T>::get",
    "RefCell::<T>::borrow",
    "RefCell::<T>::try_borrow",
    "OnceCell::<T>::get",
    "OnceLock::<T>::get",
    "RwLock::<T>::read",
    "RwLock::<T>::try_read",
    "Mutex::<T>::is_poisoned",
    "RwLock::<T>::is_poisoned",
    "::load",
    "::fmt",
    "::clone",
    "::eq",
    "::ne",
    "::partial_cmp",
    "::cmp",
    "::hash",
    "::new_debug",
    "::new_display",
];

/// Which pointers a search for a cell looks through.
#[derive(Clone, Copy, PartialEq)]
enum Through {
    None,
    Owned,
    All,
}

#[derive(Clone)]
struct BitSet(Vec<u64>);

thread_local! {
    /// The instances of the program's generic functions (a trait's default body, a closure
    /// inside a generic function among them) that a summary names (`body_name`), by name: the
    /// driver records their summaries under that name (`links::instance_links`).
    static INSTANCES: RefCell<Vec<(String, rustc_public::mir::mono::Instance)>> =
        const { RefCell::new(Vec::new()) };
    /// The crates whose generic items are named per instance: the program's, not the standard
    /// library's nor the stop crates' (set once per compilation).
    static SUMMARISED: RefCell<HashSet<rustc_span::def_id::CrateNum>> =
        RefCell::new(HashSet::new());
}
