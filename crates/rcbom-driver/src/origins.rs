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
    AggregateKind, Body, Local, Mutability, Operand, Place, ProjectionElem, Rvalue, StatementKind,
    Terminator, TerminatorKind,
};
use rustc_public::ty::{ConstantKind, IntTy, RigidTy, Span, Ty, TyKind, UintTy};
use rustc_public::{CrateDef, rustc_internal};
use rustc_span::def_id::DefId;

use crate::{def_ref_internal, locate, path_of};

/// Call, aggregate and closure hops followed before the origin is cut (`Truncated`); moves,
/// borrows and casts are free.
const MAX_DEPTH: usize = 10;
/// Alternatives, call arguments and aggregate parts kept per node: a `match` over every
/// variant of a selector (jwt-cli's 12 JWT algorithms) is kept whole.
const MAX_WIDTH: usize = 16;
/// Fields of a struct literal given each its own value (`Origin::Set`); further ones are cut.
const MAX_FIELDS: usize = 32;
/// Nodes per origin tree.
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

impl Flow {
    /// `local_fn`: is a callee a function of the crate (whose writes through `&mut` its links
    /// summarize, the value before included where it may not write)?
    fn new<'tcx>(
        tcx: TyCtxt<'tcx>,
        body: &Body,
        coroutine: bool,
        local_fn: &dyn Fn(&Operand) -> bool,
    ) -> Self {
        let internal = |t: Ty| rustc_internal::internal(tcx, t);
        // does a value of the type (of a local, along a path) hold a `&mut` (`W<'a> { r: &'a mut
        // T }`, `Option<&mut T>`)?
        let mut_holder =
            |t: rustc_middle::ty::Ty<'tcx>, p: &Path| holds_mut_borrow(tcx, walk_ty(tcx, t, p), 0);
        let nargs = body.arg_locals().len();
        let mut defs = Vec::new();
        for l in 1..=nargs {
            defs.push(Def {
                local: l,
                path: Vec::new(),
                at: At { bb: 0, idx: 0 },
                kind: DefKind::Entry,
                strong: true,
                init: false,
                sole: true,
            });
        }
        let mut term_bb = HashMap::new();
        let mut by_local: HashMap<Local, Vec<usize>> = HashMap::new();
        // first pass: direct definitions, to know what each pointer points to
        let mut pending = Vec::new();
        for (bb, block) in body.blocks.iter().enumerate() {
            term_bb.insert(&block.terminator as *const Terminator, bb);
            for (idx, s) in block.statements.iter().enumerate() {
                if let StatementKind::Assign(place, rv) = &s.kind {
                    pending.push((
                        place.clone(),
                        At { bb, idx },
                        DefKind::Assign(rv.clone(), s.source_info.span),
                    ));
                }
            }
            if let TerminatorKind::Call {
                func,
                args,
                destination,
                ..
            } = &block.terminator.kind
            {
                pending.push((
                    destination.clone(),
                    At {
                        bb,
                        idx: block.statements.len(),
                    },
                    DefKind::Call {
                        func: func.clone(),
                        args: args.clone(),
                    },
                ));
            }
        }
        let direct: HashMap<Local, Vec<&DefKind>> = {
            let mut m: HashMap<Local, Vec<&DefKind>> = HashMap::new();
            for (p, _, k) in &pending {
                if p.projection.is_empty() {
                    m.entry(p.local).or_default().push(k);
                }
            }
            m
        };
        let mut part_stores: HashMap<Local, Vec<(Path, At, Operand)>> = HashMap::new();
        for (p, at, k) in &pending {
            if !p.projection.is_empty()
                && !p
                    .projection
                    .iter()
                    .any(|e| matches!(e, ProjectionElem::Deref))
                && let DefKind::Assign(Rvalue::Use(op, _), _) = k
            {
                part_stores
                    .entry(p.local)
                    .or_default()
                    .push((path_of_place(p), *at, op.clone()));
            }
        }
        // (with the compiler's own types: a local of an `async` closure's type, which
        // `rustc_public` cannot convert, is read without converting it)
        let holders: HashSet<Local> =
            body.locals()
                .iter()
                .enumerate()
                .filter(|(_, l)| match internal(l.ty).kind() {
                    rustc_middle::ty::TyKind::Ref(_, i, _)
                    | rustc_middle::ty::TyKind::RawPtr(i, _) => holds_mut_borrow(tcx, *i, 0),
                    _ => false,
                })
                .map(|(i, _)| i)
                .collect();
        let ptr = Pointees {
            body,
            bags: closed_bags(body),
            bag_stack: RefCell::new(Vec::new()),
            returns: callee_returns(tcx, body),
            direct: &direct,
            cut: Cell::new(false),
            steps: Cell::new(0),
            lost: Cell::new(false),
            partly: pending
                .iter()
                .filter(|(p, ..)| !p.projection.is_empty())
                .map(|(p, ..)| p.local)
                .collect(),
            part_stores,
            cur_at: Cell::new(None),
            holders,
            mut_holding: body
                .locals()
                .iter()
                .enumerate()
                .filter(|(_, l)| holds_mut_borrow(tcx, internal(l.ty), 0))
                .map(|(i, _)| i)
                .collect(),
            // (all of it or a part of it, `&mut s.f`; not a place reached through a pointer)
            lent_locals: body
                .blocks
                .iter()
                .flat_map(|b| &b.statements)
                .filter_map(|st| match &st.kind {
                    StatementKind::Assign(
                        _,
                        Rvalue::Ref(_, rustc_public::mir::BorrowKind::Mut { .. }, q)
                        | Rvalue::AddressOf(rustc_public::mir::RawPtrKind::Mut, q),
                    ) if !q
                        .projection
                        .iter()
                        .any(|e| matches!(e, ProjectionElem::Deref)) =>
                    {
                        Some(q.local)
                    }
                    _ => None,
                })
                .collect(),
            nargs,
        };
        // the places the body lends by `&mut` (`&mut a`, `&mut s.f`): where a write through a
        // pointer whose targets were cut may land
        let lent: Vec<(Local, Path)> = {
            let mut v: Vec<(Local, Path)> = Vec::new();
            for st in body.blocks.iter().flat_map(|b| &b.statements) {
                if let StatementKind::Assign(
                    _,
                    Rvalue::Ref(_, rustc_public::mir::BorrowKind::Mut { .. }, q)
                    | Rvalue::AddressOf(rustc_public::mir::RawPtrKind::Mut, q),
                ) = &st.kind
                {
                    let qp = path_of_place(q);
                    if !qp.contains(&Step::Deref) && !v.contains(&(q.local, qp.clone())) {
                        v.push((q.local, qp));
                    }
                }
            }
            // and what the `&mut` parameters point to (`fn f(p: &mut T)`: `*p`)
            for l in 1..=nargs {
                if matches!(
                    internal(body.locals()[l].ty).kind(),
                    rustc_middle::ty::TyKind::Ref(_, _, rustc_middle::ty::Mutability::Mut)
                        | rustc_middle::ty::TyKind::RawPtr(_, rustc_middle::ty::Mutability::Mut)
                ) {
                    v.push((l, vec![Step::Deref]));
                }
            }
            v
        };
        // can a place of `lent` hold a value of type `written` (its type, a field, an element)?
        // Where: the place itself (`Some(true)`, the same type), a part of it not known
        // (`Some(false)`), not at all (`None`)
        let fits = |l: Local, p: &Path, written: Option<rustc_middle::ty::Ty<'tcx>>| {
            let lt = walk_ty(tcx, internal(body.locals()[l].ty), p);
            match written {
                None => Some(false),
                Some(w)
                    if tcx.erase_and_anonymize_regions(lt)
                        == tcx.erase_and_anonymize_regions(w) =>
                {
                    Some(true)
                }
                Some(w) => type_contains(tcx, lt, w, 0).then_some(false),
            }
        };
        // the path a cut or lost write is defined at: the place, or a part of it not known
        let at_part = |p: &Path, whole: bool| {
            let mut p = p.clone();
            if !whole {
                p.push(Step::Part(String::new()));
            }
            p
        };
        // (place, path, at, kind, single target, written by the call as its receiver)
        let mut extra = Vec::new();
        // the writes whose pointer targets were cut, or not followed, with the type written
        // (`None`: not known)
        type Noted<'t> = Vec<(At, Option<rustc_middle::ty::Ty<'t>>)>;
        let mut cut_at: Noted<'tcx> = Vec::new();
        let mut lost_at: Noted<'tcx> = Vec::new();
        let note = |at: At,
                    ty: Option<rustc_middle::ty::Ty<'tcx>>,
                    cut_at: &mut Noted<'tcx>,
                    lost_at: &mut Noted<'tcx>| {
            if ptr.cut.replace(false) {
                cut_at.push((at, ty));
            }
            if ptr.lost.replace(false) {
                lost_at.push((at, ty));
            }
        };
        // a shared pointer to a value holding a cell (`&Cell<T>`, `&RefCell<T>`, `&Mutex<T>`,
        // a struct with one)
        let cell_ptr =
            |p: &Place| match walk_ty(tcx, internal(body.locals()[p.local].ty), &path_of_place(p))
                .kind()
            {
                rustc_middle::ty::TyKind::Ref(_, i, rustc_middle::ty::Mutability::Not)
                | rustc_middle::ty::TyKind::RawPtr(i, rustc_middle::ty::Mutability::Not) => {
                    holds_cell(tcx, *i, 0)
                }
                _ => false,
            };
        // the type a pointer points to (with the compiler's own types, as above)
        let pointee =
            |p: &Place| match walk_ty(tcx, internal(body.locals()[p.local].ty), &path_of_place(p))
                .kind()
            {
                rustc_middle::ty::TyKind::Ref(_, i, _) | rustc_middle::ty::TyKind::RawPtr(i, _) => {
                    Some(*i)
                }
                _ => None,
            };
        for (place, at, kind) in &pending {
            ptr.cur_at.set(Some(*at));
            let path = path_of_place(place);
            if let Some(i) = path.iter().position(|s| *s == Step::Deref) {
                // `*r = x`, `(*r).f = x`: defines what `r` points to (weakly), and the place
                // through `r` for reads that go through it
                // with a single possible target the write certainly lands there (a strong
                // update); otherwise it may (weak), as through a pointer not all of whose
                // targets are known
                let targets = ptr.through_held(ptr.targets(place.local, &path[..i], 0));
                let single = sole_target(&targets) && !ptr.lost.get() && !ptr.cut.get();
                note(
                    *at,
                    Some(walk_ty(tcx, internal(body.locals()[place.local].ty), &path)),
                    &mut cut_at,
                    &mut lost_at,
                );
                for Target {
                    local: t, path: tp, ..
                } in targets
                {
                    let mut p = tp;
                    p.extend_from_slice(&path[i + 1..]);
                    extra.push((t, p, *at, clone_kind(kind), single, false));
                }
            }
            let DefKind::Call { func, args } = kind else {
                continue;
            };
            let name = callee_name(body, func).unwrap_or_default();
            // `mem::replace(&mut key, v)`, `mem::swap(&mut a, &mut b)`: what the pointers point
            // to becomes the other value
            let deref = |o: &Operand| match o {
                Operand::Copy(p) | Operand::Move(p) => {
                    let mut q = p.clone();
                    q.projection.push(ProjectionElem::Deref);
                    Some(q)
                }
                _ => None,
            };
            let span = body.blocks[at.bb].terminator.source_info.span;
            let moved: Vec<(usize, Rvalue)> = match name.as_str() {
                "core::mem::replace" | "std::mem::replace" if args.len() == 2 => {
                    vec![(
                        0,
                        Rvalue::Use(args[1].clone(), rustc_public::mir::WithRetag::No),
                    )]
                }
                // a cell's value replaced through a shared borrow (`c.set(v)`, `c.replace(v)`),
                // an `Option` set to `Some(v)` (`o.replace(v)`, `o.insert(v)`; `Some(v)` is the
                // value `v` to the origins): as `mem::replace` (what the borrow points to becomes
                // `v`)
                n if args.len() == 2
                    && [
                        "cell::Cell::<T>::set",
                        "cell::Cell::<T>::replace",
                        "cell::RefCell::<T>::replace",
                        "option::Option::<T>::replace",
                        "option::Option::<T>::insert",
                    ]
                    .iter()
                    .any(|m| n.ends_with(m)) =>
                {
                    vec![(
                        0,
                        Rvalue::Use(args[1].clone(), rustc_public::mir::WithRetag::No),
                    )]
                }
                "core::mem::swap" | "std::mem::swap" if args.len() == 2 => {
                    match (deref(&args[0]), deref(&args[1])) {
                        (Some(a), Some(b)) => vec![
                            (
                                0,
                                Rvalue::Use(Operand::Copy(b), rustc_public::mir::WithRetag::No),
                            ),
                            (
                                1,
                                Rvalue::Use(Operand::Copy(a), rustc_public::mir::WithRetag::No),
                            ),
                        ],
                        _ => Vec::new(),
                    }
                }
                _ => Vec::new(),
            };
            if !moved.is_empty() {
                for (k, rv) in moved {
                    if let Some(Operand::Copy(p) | Operand::Move(p)) = args.get(k) {
                        let targets = ptr.targets(p.local, &path_of_place(p), 0);
                        let single = sole_target(&targets) && !ptr.lost.get() && !ptr.cut.get();
                        note(*at, pointee(p), &mut cut_at, &mut lost_at);
                        for Target {
                            local: t, path: tp, ..
                        } in targets
                        {
                            extra.push((
                                t,
                                tp,
                                *at,
                                DefKind::Assign(rv.clone(), span),
                                single,
                                false,
                            ));
                        }
                    }
                }
                continue;
            }
            // out-parameters, unless the call only hands out a borrow into its argument
            // (`index_mut`, `as_mut`, `deref_mut`): the caller writes through the result. A
            // method returning its receiver (`hasher.update(d)` is `&mut Self`) wrote it.
            let hands_out = returns_mut_ref(body, place) && !returns_receiver(body, place, args);
            if hands_out {
                continue;
            }
            // a call returning a value that holds the borrow (`chunks_mut`, `split_at_mut`):
            // the writes come later, through that value; not a store into a standard-library
            // container, whose result is the value it replaced (`map.insert(k, (alg, &key[..]))`
            // returns an `Option<(Algorithm, &[u8])>`, no borrow of the map)
            // (a function of this crate writes through its `&mut` parameter as its summary
            // says: `take_val(&mut x)` doing `mem::replace(slot, v)`; and when its result holds
            // a `&mut` (`wrap(&mut x) -> W { r: x }`, `Option<&mut T>`), the writes made later
            // through the result are not followed: both)
            let local = local_fn(func);
            let through = !returns_mut_ref(body, place)
                && holds_borrow(body, place)
                && (!local
                    || mut_holder(
                        internal(body.locals()[place.local].ty),
                        &path_of_place(place),
                    ))
                && !callee_name(body, func).is_some_and(|c| std_store(&c));
            // (of a function of the crate, the arguments whose pointee the result holds a `&mut`
            // of: `process(&mut x, &mut scratch) -> Out<'a>` borrows `scratch` only; all of them
            // when none is seen)
            let result_ty = Some(walk_ty(
                tcx,
                internal(body.locals()[place.local].ty),
                &path_of_place(place),
            ));
            let held_arg = |p: &Place| {
                pointee(p).is_some_and(|t| result_ty.is_some_and(|r| holds_mut_of(tcx, r, t, 0)))
            };
            let any_held = args.iter().any(|a| {
                matches!(a, Operand::Copy(p) | Operand::Move(p) if is_mut_ptr(body, p) && held_arg(p))
            });
            // a call that writes the whole buffer it is given (`rng.fill_bytes(nonce)`,
            // `read_exact(buf)`): what was there before is gone
            let whole = fills_whole(body, func);
            let std_callee = ["core::", "std::", "alloc::"]
                .iter()
                .any(|c| name.starts_with(c));
            // a call of the standard library that only moves pointers into and out of closed
            // containers (`v.push(&mut x)`, `Box::new(&mut x)`, `v.into_iter()`): it writes
            // through none of them; a write through one taken out is followed to what was put in
            let moves = moves_only(body, func);
            for (k, a) in args.iter().enumerate() {
                let (stored, lent_bag) = match a {
                    Operand::Copy(p) | Operand::Move(p) if moves => ptr.moved(p),
                    _ => (false, false),
                };
                if stored {
                    continue;
                }
                // a closure or a struct handed over (by value or `&mut`) that holds a `&mut` to
                // a place (`|| rng.fill_bytes(&mut k1)` called, `fill_out(Out { buf: &mut k2 })`):
                // the call may write that place through it
                if !through
                    && !lent_bag
                    && let Operand::Copy(p) | Operand::Move(p) = a
                {
                    let holders: Vec<Local> = if is_mut_ptr(body, p) {
                        ptr.targets(p.local, &path_of_place(p), 0)
                            .into_iter()
                            .filter(|t| t.path.is_empty())
                            .map(|t| t.local)
                            .collect()
                    } else if p.projection.is_empty() {
                        vec![p.local]
                    } else {
                        // a part of a value handed over (`f(s.holder)`, `f(t.0)`) that holds a
                        // `&mut`: what it points to is not followed
                        if mut_holder(internal(body.locals()[p.local].ty), &path_of_place(p)) {
                            ptr.lost.set(true);
                        }
                        Vec::new()
                    };
                    note(*at, pointee(p), &mut cut_at, &mut lost_at);
                    for h in holders {
                        // a closure built here that assigns through a capture, handed to what
                        // may run it (`for_each(|_| a = &SHA384)`, `run(f)`): the place holds
                        // what it held, or what the closure assigns (`DefKind::Value`)
                        if let Some((cdef, caps)) = ptr.held_closure(h) {
                            // (as for any holder: a pointer search cut or not followed on the
                            // way is noted)
                            note(
                                *at,
                                if is_mut_ptr(body, p) {
                                    pointee(p)
                                } else {
                                    None
                                },
                                &mut cut_at,
                                &mut lost_at,
                            );
                            let mut rest = Vec::new();
                            for (k, targets, single) in caps {
                                match capture_writes(tcx, cdef, k) {
                                    Some(values) => {
                                        let value = match values.len() {
                                            0 => continue,
                                            1 => values.into_iter().next().unwrap(),
                                            _ => Origin::Any(values),
                                        };
                                        for Target {
                                            local: t, path: tp, ..
                                        } in targets
                                        {
                                            extra.push((
                                                t,
                                                tp,
                                                *at,
                                                DefKind::Value(value.clone()),
                                                false,
                                                false,
                                            ));
                                        }
                                    }
                                    None => rest.push((targets, single)),
                                }
                            }
                            // (as for any holder: what the call writes through it, the pointer's
                            // one place replaced)
                            for (targets, single) in rest {
                                for Target {
                                    local: t, path: tp, ..
                                } in targets
                                {
                                    extra.push((
                                        t,
                                        tp,
                                        *at,
                                        DefKind::OutParam {
                                            func: func.clone(),
                                            args: args.clone(),
                                            index: None,
                                            path: Vec::new(),
                                        },
                                        single,
                                        false,
                                    ));
                                }
                            }
                            continue;
                        }
                        let held = ptr.held(h, is_mut_ptr(body, p));
                        let lost = ptr.lost.get();
                        note(
                            *at,
                            if is_mut_ptr(body, p) {
                                pointee(p)
                            } else {
                                None
                            },
                            &mut cut_at,
                            &mut lost_at,
                        );
                        // (lent by `&mut`, `pset(&mut v)` of a `vec![&mut x]`: a write not
                        // followed through what it holds lands where its borrows point, a place
                        // of their pointee's type, not of the holder's)
                        if lost && is_mut_ptr(body, p) {
                            match pointee(p).and_then(|t| mut_pointees(tcx, t)) {
                                Some(ts) => lost_at.extend(ts.into_iter().map(|t| (*at, Some(t)))),
                                None => lost_at.push((*at, None)),
                            }
                        }
                        for (targets, single, field) in held {
                            // (at a field of a holder the program's function takes as such, `fn
                            // wset(w: W)`: what its summary says it writes there, the value
                            // before where it may not)
                            let summarized =
                                field.and_then(|f| holder_param(tcx, body, func, k, f));
                            for Target {
                                local: t, path: tp, ..
                            } in targets
                            {
                                extra.push((
                                    t,
                                    tp,
                                    *at,
                                    DefKind::OutParam {
                                        func: func.clone(),
                                        args: args.clone(),
                                        index: summarized.as_ref().map(|_| k),
                                        path: summarized.clone().unwrap_or_default(),
                                    },
                                    single,
                                    summarized.is_some(),
                                ));
                            }
                        }
                    }
                }
                // (or a shared borrow of a value with a cell inside, `set(&cell)`, which the
                // function may write through; of the standard library's own cell methods, those
                // handing out a guard written through later, `borrow_mut`, `lock`, `write`: the
                // others are modelled above or only read)
                if let Operand::Copy(p) | Operand::Move(p) = a
                    && (is_mut_ptr(body, p)
                        || (cell_ptr(p)
                            && (!std_callee || WRITE_GUARDS.iter().any(|g| name.ends_with(g)))))
                {
                    let targets = ptr.targets(p.local, &path_of_place(p), 0);
                    let single = sole_target(&targets) && !ptr.lost.get() && !ptr.cut.get();
                    note(*at, pointee(p), &mut cut_at, &mut lost_at);
                    // (a result the body follows, per its function's summary, `let w =
                    // wrap(&mut x)`: written through where it is used, not unknown here)
                    let through = through
                        && (!local || !any_held || held_arg(p))
                        && ptr.returns_of(func).is_none();
                    for Target {
                        local: t, path: tp, ..
                    } in targets
                    {
                        if through {
                            if local {
                                extra.push((
                                    t,
                                    tp.clone(),
                                    *at,
                                    DefKind::OutParam {
                                        func: func.clone(),
                                        args: args.clone(),
                                        index: Some(k),
                                        path: Vec::new(),
                                    },
                                    false,
                                    false,
                                ));
                            }
                            let mut part = tp;
                            part.push(Step::Elem);
                            extra.push((
                                t,
                                part,
                                *at,
                                DefKind::Through { func: func.clone() },
                                false,
                                false,
                            ));
                        } else if tp.is_empty()
                            && is_rng(body, t)
                            && !callee_name(body, func).is_some_and(|c| c.contains("Rng"))
                        {
                            // a generator lent to a call that draws from it (`pk.encrypt(&mut
                            // rng, ..)`, `RsaPrivateKey::new(&mut rng, ..)`), not one of its own
                            // methods (`RngCore::fill_bytes`): still the same generator, the
                            // call's data is not put in it
                        } else {
                            extra.push((
                                t,
                                tp,
                                *at,
                                DefKind::OutParam {
                                    func: func.clone(),
                                    args: args.clone(),
                                    index: Some(k),
                                    path: Vec::new(),
                                },
                                single,
                                k == 0 || whole || local_fn(func),
                            ));
                        }
                    }
                }
            }
        }
        // a write through a pointer whose targets were cut, or not followed: any place the
        // body lends by `&mut` (or a `&mut` parameter points to) that can hold what was written
        // may hold it
        for (a, ty) in cut_at {
            for (l, p) in &lent {
                if let Some(whole) = fits(*l, p, ty) {
                    extra.push((*l, at_part(p, whole), a, DefKind::Cut, false, false));
                }
            }
        }
        for (a, ty) in lost_at {
            for (l, p) in &lent {
                if let Some(whole) = fits(*l, p, ty) {
                    extra.push((*l, at_part(p, whole), a, DefKind::Lost, false, false));
                }
            }
        }
        // a write to an element (`key[31] = 1`, through `&mut key[3]`, or a fill of
        // `&mut key[..16]`) changes part of the array: it neither overwrites the whole nor
        // replaces its initialization
        // in a coroutine, the locals holding its pinned self (`_44 = copy (_1.0)`)
        let self_ptrs: HashSet<Local> = if coroutine {
            body.blocks
                .iter()
                .flat_map(|b| &b.statements)
                .filter_map(|st| match &st.kind {
                    StatementKind::Assign(
                        lhs,
                        Rvalue::Use(Operand::Copy(q) | Operand::Move(q), _),
                    )
                    | StatementKind::Assign(lhs, Rvalue::CopyForDeref(q))
                        if lhs.projection.is_empty()
                            && q.local == 1
                            && matches!(q.projection.as_slice(), [ProjectionElem::Field(0, _)]) =>
                    {
                        Some(lhs.local)
                    }
                    _ => None,
                })
                .collect()
        } else {
            HashSet::new()
        };
        // `&mut` parameters the body never reassigns: each points at one place for the whole
        // body, so a write through it (`*slot = v`, `(*self).alg = v`) certainly lands there
        let reassigned: HashSet<Local> = pending
            .iter()
            .filter(|(p, ..)| p.projection.is_empty())
            .map(|(p, ..)| p.local)
            .collect();
        let unique = |l: Local| {
            !coroutine
                && (1..=nargs).contains(&l)
                && !reassigned.contains(&l)
                && matches!(
                    body.locals()[l].ty.kind().rigid(),
                    Some(RigidTy::Ref(_, _, Mutability::Mut))
                )
        };
        for (place, at, kind) in pending {
            let path = path_of_place(&place);
            // a coroutine's saved local (`((*_44) as variant#3).0`, a local of an `async` body
            // kept across an `.await`) is reached through its pinned self, which points at the
            // coroutine alone: written, it is overwritten
            let saved = coroutine
                && ((place.local == 1
                    && matches!(path.as_slice(), [Step::Field(0), Step::Deref, rest @ ..]
                        if !rest.contains(&Step::Deref)))
                    || (self_ptrs.contains(&place.local)
                        && matches!(path.as_slice(), [Step::Deref, rest @ ..]
                            if !rest.contains(&Step::Deref))));
            let through_param = matches!(path.as_slice(), [Step::Deref, rest @ ..]
                    if !rest.contains(&Step::Deref))
                && unique(place.local);
            let strong =
                (saved || through_param || !path.contains(&Step::Deref)) && !partial(&path);
            let init = is_init(body, &kind) && !partial(&path);
            defs.push(Def {
                local: place.local,
                path,
                at,
                kind,
                strong,
                init,
                sole: true,
            });
        }
        for (local, path, at, kind, single, receiver) in extra {
            let out_param = matches!(kind, DefKind::OutParam { .. } | DefKind::Through { .. });
            let init = is_init(body, &kind) && !partial(&path);
            // through a reference: certain only with a single target; an out-parameter call
            // may or may not write, so it never overwrites, unless it is the call's receiver
            // (its new value is the call's, which takes the old one as an argument:
            // `mac.update(secret)`) or the call fills the whole buffer (`fills_whole`)
            let strong = single && (!out_param || receiver) && !partial(&path);
            let sole = single && !partial(&path);
            defs.push(Def {
                local,
                path,
                at,
                kind,
                strong,
                init,
                sole,
            });
        }
        for (i, d) in defs.iter().enumerate() {
            by_local.entry(d.local).or_default().push(i);
        }
        let entry = reaching(body, &defs, &by_local, nargs);
        Flow {
            defs,
            by_local,
            entry,
            term_bb,
        }
    }
}

impl<'a, 'tcx> Origins<'a, 'tcx> {
    /// Origin of `op` read at statement `idx` of block `bb` (the terminator if `idx` is the
    /// number of statements).
    pub(crate) fn operand_at(&self, op: &Operand, bb: usize, idx: usize) -> Origin {
        self.nodes.set(0);
        self.operand(op, At { bb, idx }, 0, &mut HashSet::new())
            .capped(MAX_ORIGIN_DEPTH)
    }

    pub(crate) fn body(&self) -> &'a Body {
        self.body
    }

    /// Origin of the part `rest` of `op` (`op.aead.alg`) read at statement `idx` of block `bb`;
    /// a constant is taken whole.
    pub(crate) fn operand_part_at(
        &self,
        op: &Operand,
        rest: &[Step],
        bb: usize,
        idx: usize,
    ) -> Origin {
        self.nodes.set(0);
        let at = At { bb, idx };
        match op {
            Operand::Copy(p) | Operand::Move(p) => {
                let mut path = path_of_place(p);
                path.extend_from_slice(rest);
                self.place(p.local, path, at, 0, &mut HashSet::new())
            }
            // a part of a constant (`Outer { inner: BASE }` stored per field of `inner`): that
            // field of it
            Operand::Constant(c) if rest.iter().any(|s| matches!(s, Step::Field(_))) => {
                let o = self.operand(op, at, 0, &mut HashSet::new());
                if matches!(o, Origin::Data { .. }) {
                    let ty = rustc_internal::internal(self.tcx, c.const_.ty());
                    self.read_fields(ty, rest, o)
                } else {
                    o
                }
            }
            _ => self.operand(op, at, 0, &mut HashSet::new()),
        }
        .capped(MAX_ORIGIN_DEPTH)
    }

    /// Origin of the part `rest` of what `rv` computes at statement `idx` of block `bb`.
    pub(crate) fn rvalue_part_at(
        &self,
        rv: &Rvalue,
        span: Span,
        rest: &[Step],
        bb: usize,
        idx: usize,
    ) -> Origin {
        self.nodes.set(0);
        self.rvalue(rv, span, rest, At { bb, idx }, 0, &mut HashSet::new())
            .capped(MAX_ORIGIN_DEPTH)
    }

    /// What the function returns, or the part `rest` of it: the return place at each `return`.
    pub(crate) fn returned_part(&self, rest: &[Step]) -> Origin {
        self.at_returns(rustc_public::mir::RETURN_LOCAL, rest)
    }

    /// What the place `path` of parameter `local` holds when the function returns (`*w.slot` of
    /// `fn wset(w: W)`, through a borrow the parameter holds): what the function wrote there, its
    /// value on entry (`Param`) where it may not have.
    pub(crate) fn behind_at_returns(&self, local: Local, path: &[Step]) -> Origin {
        self.at_returns(local, path)
    }

    /// What a `&mut` parameter (argument `index`) points to when the function returns: what
    /// the function wrote there, its value on entry (`Param`) where it may not have.
    pub(crate) fn written_through(&self, index: usize) -> Origin {
        self.at_returns(index + 1, &[Step::Deref])
    }

    fn at_returns(&self, local: Local, rest: &[Step]) -> Origin {
        let mut alts = Vec::new();
        for (bb, block) in self.body.blocks.iter().enumerate() {
            if matches!(block.terminator.kind, TerminatorKind::Return) {
                self.nodes.set(0);
                let at = At {
                    bb,
                    idx: block.statements.len(),
                };
                let o = self
                    .place(local, rest.to_vec(), at, 0, &mut HashSet::new())
                    .capped(MAX_ORIGIN_DEPTH);
                if !alts.contains(&o) {
                    alts.push(o);
                }
            }
        }
        match alts.len() {
            0 => Origin::Unknown,
            1 => alts.pop().unwrap(),
            _ => Origin::Any(alts),
        }
    }

    /// The origin of a closure passed as a value (`LazyLock::new(|| ..)`): what it returns; of
    /// a function passed as one (`LazyLock::new(pick)`), a call of it.
    pub(crate) fn closure_value(&self, op: &Operand, bb: usize, idx: usize) -> Origin {
        if let Operand::Constant(c) = op
            && let Some(RigidTy::FnDef(def, _)) = c.const_.ty().kind().rigid()
        {
            let did = rustc_internal::internal(self.tcx, def.def_id());
            return Origin::Call {
                callee: path_of(self.tcx, did),
                krate: self.tcx.crate_name(did.krate).to_string(),
                self_ty: None,
                args: Vec::new(),
                span: None,
                runs: None,
                pointer: None,
                fed: None,
            };
        }
        match self.operand_at(op, bb, idx) {
            // a function made a pointer first (`LazyLock::new(pick)` for a `LazyLock<T>`)
            Origin::Unit { path, krate, .. }
                if op
                    .ty(self.body.locals())
                    .is_ok_and(|t| matches!(t.kind().rigid(), Some(RigidTy::FnPtr(_)))) =>
            {
                Origin::Call {
                    callee: path,
                    krate,
                    self_ty: None,
                    args: Vec::new(),
                    span: None,
                    runs: None,
                    pointer: None,
                    fed: None,
                }
            }
            o => o,
        }
    }

    /// `o`, the origin of a value of type `ty`, read further along `rest`: a field of a struct
    /// whose origin the search ends at (a parameter, a call's result, a static) is a read of
    /// that field (`Origin::Field`), which the analysis looks up in what the crate stores there.
    fn read_fields(&self, ty: rustc_middle::ty::Ty<'tcx>, rest: &[Step], o: Origin) -> Origin {
        let tcx = self.tcx;
        let mut ty = ty;
        let mut o = o;
        let mut variant = None;
        for step in rest {
            match step {
                Step::Deref => match ty.builtin_deref(true) {
                    Some(t) => ty = t,
                    None => break,
                },
                Step::Variant(v) => variant = Some(*v),
                Step::Field(f) => match ty.kind() {
                    rustc_middle::ty::Adt(adt, args) => {
                        let v = match (adt.is_enum(), variant) {
                            (true, Some(v)) => adt.variant(rustc_abi::VariantIdx::from_usize(v)),
                            (true, None) => break,
                            _ => adt.non_enum_variant(),
                        };
                        let Some(field) = v.fields.get(rustc_abi::FieldIdx::from_usize(*f)) else {
                            break;
                        };
                        // a field of a struct, or of a variant of an enum outside the standard
                        // library, named by the variant (`KeyPairKind::Ec`, as
                        // `links::body_links` stores it); `Some(k)` stands for the whole value
                        let std = matches!(
                            tcx.crate_name(adt.did().krate).as_str(),
                            "core" | "std" | "alloc"
                        );
                        if !adt.is_enum() || !std {
                            let named = if adt.is_enum() { v.def_id } else { adt.did() };
                            o = Origin::Field {
                                adt: crate::path_of(tcx, named),
                                field: *f,
                                base: Box::new(o),
                                args: crate::adt_args(tcx, args),
                            };
                        } else if variant == Some(1)
                            && crate::path_of(tcx, adt.did()) == "core::result::Result"
                        {
                            // the error of a `Result` (`Err(e) => e` in a match): its error side
                            o = Origin::Call {
                                callee: "core::result::Result::<T, E>::unwrap_err".to_string(),
                                krate: "core".to_string(),
                                self_ty: Some("core::result::Result".to_string()),
                                args: vec![o],
                                span: None,
                                runs: None,
                                pointer: None,
                                fed: None,
                            };
                        }
                        ty = field.ty(tcx, args).skip_norm_wip();
                        variant = None;
                    }
                    rustc_middle::ty::Tuple(ts) => match ts.get(*f) {
                        Some(t) => {
                            // an element of a tuple held by a static or a constant
                            // (`PAIRS[i].0`, `NEST.0.1`): what its initializer puts there
                            if on_data(&o) {
                                o = Origin::Field {
                                    adt: rcbom_facts::TUPLE.to_string(),
                                    field: *f,
                                    base: Box::new(o),
                                    args: None,
                                };
                            }
                            ty = *t
                        }
                        None => break,
                    },
                    _ => break,
                },
                Step::Elem | Step::Index(_) => match ty.builtin_index() {
                    Some(t) => ty = t,
                    None => break,
                },
                Step::Part(_) => break,
            }
        }
        o
    }

    /// The type of `local`, as `rustc_middle` has it, followed along `path`.
    fn local_ty(&self, local: Local) -> rustc_middle::ty::Ty<'tcx> {
        rustc_internal::internal(self.tcx, self.body.locals()[local].ty)
    }

    /// Origin of argument `op` of the call terminating a block.
    pub(crate) fn of_arg(&self, op: &Operand, term: &Terminator) -> Origin {
        let Some(&bb) = self.flow().term_bb.get(&(term as *const Terminator)) else {
            return Origin::Unknown;
        };
        self.nodes.set(0);
        let at = At {
            bb,
            idx: self.body.blocks[bb].statements.len(),
        };
        self.operand(op, at, 0, &mut HashSet::new())
            .capped(MAX_ORIGIN_DEPTH)
    }

    /// The span that names the callee of the call terminating `term` when it is held in a
    /// place rather than named at the call: in a local (`let f = Sha256::digest; f(d)`), a
    /// field of a struct or tuple built here (`(h.f)(&SHA384, d)`), or a closure's capture
    /// (`let f = digest; move |x| f(&SHA256, x)`): where the function item was named.
    pub(crate) fn callee_name_span(&self, func: &Operand, term: &Terminator) -> Option<Span> {
        let bb = *self.flow().term_bb.get(&(term as *const Terminator))?;
        let at = At {
            bb,
            idx: self.body.blocks[bb].statements.len(),
        };
        self.callee_span_at(func, at)
    }

    fn callee_span_at(&self, func: &Operand, at: At) -> Option<Span> {
        match func {
            Operand::Constant(c) => Some(c.span),
            Operand::Copy(p) | Operand::Move(p) => {
                self.fn_item_span(p.local, &path_of_place(p), at, 0)
            }
            _ => None,
        }
    }

    /// Where the function item held in `local.path` at `at` was named; the first naming when
    /// several definitions reach (a function item type names one function, so any of them
    /// names it).
    fn fn_item_span(&self, local: Local, path: &[Step], at: At, depth: usize) -> Option<Span> {
        if depth > 8 {
            return None;
        }
        for i in self.reaching_at(local, at) {
            let d = &self.flow().defs[i];
            let Some(rest) = path.strip_prefix(d.path.as_slice()) else {
                continue;
            };
            let found = match &d.kind {
                DefKind::Entry => self.capture_fn_span(local, rest, depth),
                DefKind::Assign(rv, _) => self.rvalue_fn_span(rv, rest, d.at, depth),
                _ => None,
            };
            if found.is_some() {
                return found;
            }
        }
        None
    }

    fn rvalue_fn_span(&self, rv: &Rvalue, rest: &[Step], at: At, depth: usize) -> Option<Span> {
        let place_span = |q: &Place, tail: &[Step]| {
            let mut p = path_of_place(q);
            p.extend_from_slice(tail);
            self.fn_item_span(q.local, &p, at, depth + 1)
        };
        let operand_span = |o: &Operand, tail: &[Step]| match o {
            Operand::Constant(c) if tail.is_empty() => {
                matches!(c.const_.ty().kind().rigid(), Some(RigidTy::FnDef(..))).then_some(c.span)
            }
            Operand::Copy(q) | Operand::Move(q) => place_span(q, tail),
            _ => None,
        };
        match rv {
            Rvalue::Use(o, _) | Rvalue::Cast(_, o, _) => operand_span(o, rest),
            Rvalue::CopyForDeref(q) => place_span(q, rest),
            Rvalue::Ref(_, _, q) | Rvalue::Reborrow(_, _, q) | Rvalue::AddressOf(_, q) => {
                place_span(q, rest.strip_prefix(&[Step::Deref]).unwrap_or(rest))
            }
            // a struct or tuple built here: the field read
            Rvalue::Aggregate(kind, ops) => {
                let (f, tail) = match (kind, rest) {
                    (
                        AggregateKind::Adt(_, v, ..),
                        [Step::Variant(w), Step::Field(f), tail @ ..],
                    ) if variant_index(v) == *w => (*f, tail),
                    (_, [Step::Field(f), tail @ ..]) => (*f, tail),
                    _ => return None,
                };
                operand_span(ops.get(f)?, tail)
            }
            _ => None,
        }
    }

    /// A closure's capture holding a function item: where the parent named it.
    fn capture_fn_span(&self, local: Local, rest: &[Step], depth: usize) -> Option<Span> {
        if local != 1 || self.kind != BodyKind::Closure {
            return None;
        }
        let (k, tail) = match rest {
            [Step::Deref, Step::Field(k), tail @ ..] | [Step::Field(k), tail @ ..] => (*k, tail),
            _ => return None,
        };
        let did = self.def?;
        let parent = self.tcx.parent(did);
        let body = rustc_public::CrateItem(rustc_internal::stable(parent)).body()?;
        let mut outer = Origins::new(self.tcx, &body, Some(parent));
        // a closure of a generic function's instance: the parent's constants with that
        // instance's arguments (`let alg = T::ALG;` captured in `each::<P512>`)
        if let Some(a) = self.inst_args() {
            let n = self.tcx.generics_of(parent).count().min(a.len());
            outer = outer.with_item(parent, self.tcx.mk_args(&a[..n]));
        }
        for (bb, block) in body.blocks.iter().enumerate() {
            for (idx, s) in block.statements.iter().enumerate() {
                let StatementKind::Assign(_, Rvalue::Aggregate(AggregateKind::Closure(d, _), ops)) =
                    &s.kind
                else {
                    continue;
                };
                if rustc_internal::internal(self.tcx, d.def_id()) != did {
                    continue;
                }
                let at = At { bb, idx };
                // a capture by reference holds `&f`: what it points to
                let tail = tail.strip_prefix(&[Step::Deref]).unwrap_or(tail);
                let found = match ops.get(k)? {
                    Operand::Constant(c) if tail.is_empty() => Some(c.span),
                    Operand::Copy(q) | Operand::Move(q) => {
                        let mut p = path_of_place(q);
                        p.extend_from_slice(tail);
                        outer.fn_item_span(q.local, &p, at, depth + 1)
                    }
                    _ => None,
                };
                if found.is_some() {
                    return found;
                }
            }
        }
        None
    }

    /// The function a call through a function pointer calls, when the pointer is a single KB
    /// function reified in this body (`let h: fn(..) = digest::digest; h(&SHA512, d)`): the
    /// function, its generic arguments, and where it is named.
    pub(crate) fn callee_through_pointer(
        &self,
        func: &Operand,
    ) -> Option<(rustc_public::ty::FnDef, rustc_public::ty::GenericArgs, Span)> {
        let (Operand::Copy(p) | Operand::Move(p)) = func else {
            return None;
        };
        let mut local = p.local;
        for _ in 0..8 {
            let mut defs = self
                .flow()
                .by_local
                .get(&local)?
                .iter()
                .map(|&i| &self.flow().defs[i].kind);
            let k = defs.next()?;
            if defs.next().is_some() {
                return None;
            }
            match k {
                DefKind::Assign(Rvalue::Use(Operand::Copy(q) | Operand::Move(q), _), _)
                    if q.projection.is_empty() =>
                {
                    local = q.local
                }
                DefKind::Assign(Rvalue::Cast(_, Operand::Constant(c), _), _) => {
                    let ty = c.const_.ty();
                    let kind = ty.kind();
                    let Some(RigidTy::FnDef(def, args)) = kind.rigid() else {
                        return None;
                    };
                    return Some((*def, args.clone(), c.span));
                }
                _ => return None,
            }
        }
        None
    }

    /// Length of the array behind an argument of the call terminating `term` (`&mut [0u8; 32]`
    /// passed as `&mut [u8]`), found in the types along the definitions that reach the call.
    pub(crate) fn array_len(&self, op: &Operand, term: &Terminator) -> Option<u64> {
        let bb = *self.flow().term_bb.get(&(term as *const Terminator))?;
        let at = At {
            bb,
            idx: self.body.blocks[bb].statements.len(),
        };
        self.len_of_operand(op, at, 0)
    }

    fn len_of_operand(&self, op: &Operand, at: At, depth: usize) -> Option<u64> {
        if depth > MAX_DEPTH {
            return None;
        }
        let ty = op.ty(self.body.locals()).ok()?;
        if let Some(n) = array_len_of_ty(&ty) {
            return Some(n);
        }
        match op {
            Operand::Copy(p) | Operand::Move(p) if p.projection.is_empty() => {
                self.len_of_local(p.local, at, depth + 1)
            }
            _ => None,
        }
    }

    /// The length of the array `l` holds or points to at `at`: the same for every definition
    /// that reaches there (`let out = &mut big; .. out = &mut small;` is `small`'s).
    fn len_of_local(&self, l: Local, at: At, depth: usize) -> Option<u64> {
        if depth > MAX_DEPTH {
            return None;
        }
        if let Some(n) = array_len_of_ty(&self.body.locals()[l].ty) {
            return Some(n);
        }
        let mut lens = self.reaching_at(l, at).into_iter().map(|i| {
            let d = &self.flow().defs[i];
            if !d.path.is_empty() {
                return None;
            }
            match &d.kind {
                DefKind::Assign(Rvalue::Use(op, _), _)
                | DefKind::Assign(Rvalue::Cast(_, op, _), _) => {
                    self.len_of_operand(op, d.at, depth + 1)
                }
                DefKind::Assign(Rvalue::Ref(_, _, p), _)
                | DefKind::Assign(Rvalue::AddressOf(_, p), _)
                | DefKind::Assign(Rvalue::Reborrow(_, _, p), _)
                | DefKind::Assign(Rvalue::CopyForDeref(p), _) => {
                    self.len_of_local(p.local, d.at, depth + 1)
                }
                _ => None,
            }
        });
        let first = lens.next()??;
        lens.all(|n| n == Some(first)).then_some(first)
    }

    /// Definitions of `local` that reach the point `at`.
    fn reaching_at(&self, local: Local, at: At) -> Vec<usize> {
        let Some(mine) = self.flow().by_local.get(&local) else {
            return Vec::new();
        };
        let mut live: Vec<usize> = mine
            .iter()
            .copied()
            .filter(|&i| self.flow().entry[at.bb].contains(i))
            .collect();
        // definitions earlier in the same block
        let mut here: Vec<usize> = mine
            .iter()
            .copied()
            .filter(|&i| {
                let d = &self.flow().defs[i];
                d.at.bb == at.bb && d.at.idx < at.idx && !matches!(d.kind, DefKind::Entry)
            })
            .collect();
        here.sort_by_key(|&i| self.flow().defs[i].at.idx);
        for i in here {
            let d = &self.flow().defs[i];
            live.retain(|&e| !kills(d, &self.flow().defs[e]));
            live.push(i);
        }
        live
    }

    fn budget(&self) -> bool {
        self.nodes.set(self.nodes.get() + 1);
        self.nodes.get() <= MAX_NODES
    }

    fn operand(&self, op: &Operand, at: At, depth: usize, seen: &mut HashSet<Key>) -> Origin {
        if !self.budget() {
            return Origin::Truncated;
        }
        match op {
            Operand::Copy(p) | Operand::Move(p) => {
                self.place(p.local, path_of_place(p), at, depth, seen)
            }
            Operand::Constant(c) => self.constant(c, depth),
            _ => Origin::Unknown,
        }
    }

    fn place(
        &self,
        local: Local,
        path: Path,
        at: At,
        depth: usize,
        seen: &mut HashSet<Key>,
    ) -> Origin {
        if path.len() > MAX_PATH {
            return Origin::Truncated;
        }
        let key = (local, path.clone(), at);
        if !seen.insert(key.clone()) {
            // the place is being computed (`seen` holds the places under way): its value depends
            // on its own earlier value (a loop, `ctr += 1`); the other definitions say where it
            // starts
            return Origin::Loop;
        }
        let defs = self.reaching_at(local, at);
        // definitions of the place, or of a whole it is part of: it is one of these
        let mut alts: Vec<Origin> = Vec::new();
        // writes to a part of it (`key[31] = 1`, `cfg.key = ..`): it is also made of these
        let mut parts: Vec<Origin> = Vec::new();
        for &i in &defs {
            let d = &self.flow().defs[i];
            let part = !is_prefix(&d.path, &path) && is_prefix(&path, &d.path);
            let (list, rest) = if is_prefix(&d.path, &path) {
                if self.shadowed(i, &defs, &path, at) {
                    continue;
                }
                // `Pick::B(y)` read from a `Pick::A(x)` built here: never this definition's
                // value (the read happens only when the value is the other variant)
                if other_variant(&d.kind, &path[d.path.len()..]) {
                    continue;
                }
                (&mut alts, path[d.path.len()..].to_vec())
            } else if is_prefix(&path, &d.path) {
                (&mut parts, Vec::new())
            } else if matches!(d.kind, DefKind::Through { .. }) && through_overlap(&d.path, &path) {
                // a value holding a borrow of it (`let (p, _q) = s.slots()`), written later
                // through that value, read at a field (`s.a`): which part is not known
                let o = self.def_origin(d, &[], depth, seen);
                if !alts.contains(&o) {
                    alts.push(o);
                }
                continue;
            } else if let Some(f) = part_overlap(&d.path, &path) {
                // a write through a borrow a function returned (`*a.slot() = v`) where the read
                // is of a part (`a.alg`): it may be the part written, or not (an unnamed part:
                // a cut or lost write, its own origin says so)
                let o = self.def_origin(d, &[], depth, seen);
                let o = if f.is_empty() {
                    o
                } else {
                    Origin::Any(vec![o, Origin::Through { callee: f }])
                };
                if !alts.contains(&o) {
                    alts.push(o);
                }
                continue;
            } else {
                continue;
            };
            let mut o = self.def_origin(d, &rest, depth, seen);
            // a field of a parameter or of a call's result: what the crate stores there
            if matches!(
                d.kind,
                DefKind::Entry | DefKind::Call { .. } | DefKind::OutParam { .. }
            ) && rest.iter().any(|s| matches!(s, Step::Field(_)))
                && !matches!(o, Origin::Unknown | Origin::Truncated)
                && !(self.kind != BodyKind::Fn && matches!(d.kind, DefKind::Entry) && local == 1)
            {
                let mut ty = self.local_ty(local);
                // the definition's own path first (the place it defines)
                ty = walk_ty(self.tcx, ty, &d.path);
                o = self.read_fields(ty, &rest, o);
            }
            // a write to a part not known (through a borrow a function returned): that value
            // somewhere in it, or not where it is read
            if part
                && let Some(Step::Part(f)) = d.path[path.len()..]
                    .iter()
                    .find(|s| matches!(s, Step::Part(_)))
                && !f.is_empty()
            {
                o = Origin::Any(vec![o, Origin::Through { callee: f.clone() }]);
            }
            // a write to a field of it (`h.alg = ..`, `set_slot(&mut c.alg)`): which field
            if part && let Some(fields) = field_steps(&d.path[path.len()..]) {
                let strong = d.strong && self.part_always_after(&defs, i, &path, at);
                o = Origin::Set {
                    path: fields,
                    value: Box::new(o),
                    strong,
                };
            } else if part && let Some(fields) = fields_to_element(&d.path[path.len()..]) {
                // a write to an element of a field (`v.algorithms[0] = RS512`): one of the
                // values the field holds, beside the others
                o = Origin::Set {
                    path: fields,
                    value: Box::new(Origin::Any(vec![o, self.element_write()])),
                    strong: false,
                };
            } else if part
                && matches!(
                    d.path[path.len()..].first(),
                    Some(Step::Elem | Step::Index(_))
                )
            {
                // a write to an element of the list read itself (`l[0] = HS384` through a `&mut
                // Vec` parameter, `v.algorithms` returned after `v.algorithms[1] = HS256`): the
                // same, beside the others
                o = Origin::Any(vec![o, self.element_write()]);
            }
            if !list.contains(&o) {
                if list.len() >= MAX_WIDTH {
                    list.push(Origin::Truncated);
                    break;
                }
                list.push(o);
            }
        }
        seen.remove(&key);
        let whole = match alts.len() {
            0 => None,
            1 => alts.pop(),
            _ => Some(Origin::Any(alts)),
        };
        match (whole, parts.len()) {
            (None, 0) => Origin::Unknown,
            (Some(w), 0) => w,
            (None, 1) => parts.pop().unwrap(),
            (None, _) => Origin::All(parts),
            (Some(w), _) => {
                parts.insert(0, w);
                Origin::All(parts)
            }
        }
    }

    /// The marker of a write into an element of a list, naming this body's function.
    fn element_write(&self) -> Origin {
        Origin::Through {
            callee: rcbom_facts::element_write(
                &self
                    .def
                    .map(|d| crate::path_of(self.tcx, d))
                    .unwrap_or_default(),
            ),
        }
    }

    /// Is `func` a function of this crate?
    fn local_fn(&self, func: &Operand) -> bool {
        matches!(func.ty(self.body.locals()).ok().map(|t| t.kind()),
            Some(TyKind::RigidTy(RigidTy::FnDef(def, _)))
                if rustc_internal::internal(self.tcx, def.def_id()).is_local())
    }

    /// What a call of a function of the program (`d`, an out-parameter definition) writes
    /// through the argument pointing at the place: `Written`, which the links resolve to the
    /// values the function stores there. `None` for another crate's function, whose result
    /// stands for what it writes (`rng.fill_bytes(&mut c.key)`, `v.push(x)`).
    fn written(&self, d: &Def, depth: usize, seen: &mut HashSet<Key>) -> Option<Origin> {
        let DefKind::OutParam {
            func,
            args,
            index: Some(index),
            path,
        } = &d.kind
        else {
            return None;
        };
        let Some(TyKind::RigidTy(RigidTy::FnDef(def, _))) =
            func.ty(self.body.locals()).ok().map(|t| t.kind())
        else {
            return None;
        };
        let did = rustc_internal::internal(self.tcx, def.def_id());
        if !did.is_local() {
            return None;
        }
        // A chain of writes through `&mut self` (`self.a(); self.b(); ..`) nests each value
        // before in the next call's arguments: cut like a call.
        if depth >= MAX_DEPTH {
            return Some(Origin::Truncated);
        }
        let mut args: Vec<Origin> = args
            .iter()
            .take(MAX_WIDTH)
            .map(|a| self.operand(a, d.at, depth + 1, seen))
            .collect();
        // the value before is the place's own (`u.up()` with `u` pointing to `a1` or `b3`: for
        // `a1`, `a1`'s value, not the pointer's either), when the pointer may point to several,
        // or sits in a holder (`wset(W { slot: &mut x })`: `x`'s, not the holder's)
        if (!d.sole || !path.is_empty())
            && let Some(a) = args.get_mut(*index)
        {
            *a = self.place(d.local, d.path.clone(), d.at, depth + 1, seen);
        }
        let gargs = match func.ty(self.body.locals()).ok().map(|t| t.kind()) {
            Some(TyKind::RigidTy(RigidTy::FnDef(_, g))) => rustc_internal::internal(self.tcx, g),
            _ => return None,
        };
        let place = walk_ty(self.tcx, self.local_ty(d.local), &d.path);
        let (callee, self_ty) = write_callee(self.tcx, did, gargs, Some(place));
        // a function taking the place as a trait object (`fn up_dyn(u: &mut dyn Up)` on a
        // `B`): the object's type, which its trait-object calls dispatch on
        let takes_dyn = self_ty.is_none()
            && self
                .tcx
                .fn_sig(did)
                .instantiate(self.tcx, gargs)
                .skip_binder()
                .inputs()
                .get(*index)
                .and_then(|t| t.builtin_deref(true))
                .is_some_and(|t| matches!(t.kind(), rustc_middle::ty::Dynamic(..)));
        let place_ty = takes_dyn
            .then(|| crate::type_name(self.tcx, place))
            .flatten();
        Some(Origin::Written {
            callee,
            index: *index,
            args,
            self_ty,
            place_ty,
            path: path.clone(),
        })
    }

    /// Does the write `j` to a part of the place `path` lie on every way to the read at `at`
    /// from each definition of the whole that reaches it (`h.alg = ..` after `h = Header::
    /// default()`)?
    fn part_always_after(&self, defs: &[usize], j: usize, path: &[Step], at: At) -> bool {
        let e = &self.flow().defs[j];
        defs.iter()
            .map(|&i| &self.flow().defs[i])
            .filter(|d| is_prefix(&d.path, path))
            .all(|d| self.always_through(d, e.at, at))
    }

    /// Is definition `i`, of a whole that contains `path`, overwritten for `path` before the
    /// read at `at`: does a definition of a more specific place covering `path` (`c.key =
    /// [8; 32]` after `c = Cfg { key: env_key(), .. }`) lie on every way from `i` to `at`?
    fn shadowed(&self, i: usize, defs: &[usize], path: &[Step], at: At) -> bool {
        let d = &self.flow().defs[i];
        defs.iter().any(|&j| {
            let e = &self.flow().defs[j];
            if j == i || e.path.len() <= d.path.len() {
                return false;
            }
            // a call filling the part (`rng.fill_bytes(&mut cfg.key)`) replaces what an
            // initialization (`Cfg { key: [0; 32], .. }`) or the entry value had there
            let fills = || {
                matches!(e.kind, DefKind::OutParam { .. })
                    && e.sole
                    && (d.init
                        || matches!(d.kind, DefKind::Entry)
                        || self.part_init(d, &e.path[d.path.len()..]))
            };
            (e.strong || fills())
                && is_prefix(&d.path, &e.path)
                && is_prefix(&e.path, path)
                && self.always_through(d, e.at, at)
        })
    }

    /// Is the part `rest` of what definition `d` builds an initialization: the field of a
    /// struct literal given as a constant (`Cfg { key: [0u8; 32], .. }`, its `[0u8; 32]` in a
    /// temporary)?
    fn part_init(&self, d: &Def, rest: &[Step]) -> bool {
        let DefKind::Assign(Rvalue::Aggregate(kind, ops), _) = &d.kind else {
            return false;
        };
        let f = match (kind, rest) {
            (AggregateKind::Adt(_, v, ..), [Step::Variant(w), Step::Field(f), ..])
                if variant_index(v) == *w =>
            {
                *f
            }
            (_, [Step::Field(f), ..]) | (AggregateKind::Array(_), [Step::Index(f), ..]) => *f,
            _ => return false,
        };
        match ops.get(f) {
            Some(Operand::Constant(_)) => true,
            Some(Operand::Copy(q) | Operand::Move(q)) if q.projection.is_empty() => {
                let defs = self.reaching_at(q.local, d.at);
                !defs.is_empty()
                    && defs.iter().all(|&i| {
                        let e = &self.flow().defs[i];
                        e.path.is_empty() && e.init
                    })
            }
            _ => false,
        }
    }

    /// Does every way from definition `d` to the point `to` pass through the point `via`?
    fn always_through(&self, d: &Def, via: At, to: At) -> bool {
        let blocks = &self.body.blocks;
        // the positions after `d` (an argument is defined before the first statement)
        let start = if matches!(d.kind, DefKind::Entry) {
            At { bb: 0, idx: 0 }
        } else {
            At {
                bb: d.at.bb,
                idx: d.at.idx + 1,
            }
        };
        let mut work = vec![start];
        let mut seen: HashSet<(usize, usize)> = HashSet::new();
        while let Some(p) = work.pop() {
            if !seen.insert((p.bb, p.idx)) {
                continue;
            }
            let len = blocks[p.bb].statements.len();
            let mut blocked = false;
            for idx in p.idx..=len {
                if p.bb == to.bb && idx == to.idx {
                    return false; // reached the read without passing `via`
                }
                if p.bb == via.bb && idx == via.idx {
                    blocked = true;
                    break;
                }
            }
            if !blocked {
                for s in blocks[p.bb].terminator.successors() {
                    work.push(At { bb: s, idx: 0 });
                }
            }
        }
        true
    }

    fn def_origin(&self, d: &Def, rest: &[Step], depth: usize, seen: &mut HashSet<Key>) -> Origin {
        match &d.kind {
            DefKind::Entry => self.entry_origin(d.local, rest, depth),
            DefKind::Assign(rv, span) => self.rvalue(rv, *span, rest, d.at, depth, seen),
            DefKind::Call { func, args } => self.call(func, args, d.at, depth, seen),
            // a function of the program writing it through `&mut` (`set_slot(&mut a)`): what
            // it writes there; another crate's call stands for what it writes
            // (`rng.fill_bytes(&mut key)`)
            DefKind::OutParam { func, args, .. } => self
                .written(d, depth, seen)
                .unwrap_or_else(|| self.call(func, args, d.at, depth, seen)),
            DefKind::Through { func } => Origin::Through {
                callee: callee_name(self.body, func).unwrap_or_default(),
            },
            DefKind::Cut => Origin::Truncated,
            DefKind::Lost => Origin::Unknown,
            DefKind::Value(o) => o.clone(),
        }
    }

    fn call(
        &self,
        func: &Operand,
        args: &[Operand],
        at: At,
        depth: usize,
        seen: &mut HashSet<Key>,
    ) -> Origin {
        if depth >= MAX_DEPTH {
            return Origin::Truncated;
        }
        // `Algorithm::default()` of a field-less enum: the variant its `Default` returns
        // (`Argon2::new(Algorithm::default(), ..)` is Argon2id)
        if args.is_empty()
            && let Some(TyKind::RigidTy(RigidTy::FnDef(def, gargs))) =
                func.ty(self.body.locals()).ok().map(|t| t.kind())
            && let Some(o) = self.default_variant(def.def_id(), &gargs)
        {
            return o;
        }
        let mut runs = None;
        let (callee, krate, self_ty) = match func.ty(self.body.locals()).ok().map(|t| t.kind()) {
            Some(TyKind::RigidTy(RigidTy::FnDef(def, gargs))) => {
                let did = rustc_internal::internal(self.tcx, def.def_id());
                let gargs = rustc_internal::internal(self.tcx, gargs);
                runs = runs_of(self.tcx, did, gargs);
                (
                    path_of(self.tcx, did),
                    self.tcx.crate_name(did.krate).to_string(),
                    self_adt_path(self.tcx, did, gargs).or_else(|| dyn_self(self.tcx, did, gargs)),
                )
            }
            // a pointer to a function reified here (`let h: fn(..) = digest; h(..)`)
            _ => match self.callee_through_pointer(func) {
                Some((def, gargs, _)) => {
                    let did = rustc_internal::internal(self.tcx, def.def_id());
                    let gargs = rustc_internal::internal(self.tcx, gargs);
                    // a generic function made a pointer (`let f = pick::<Fast>; f(..)`): its
                    // instance
                    runs = item_runs(self.tcx, did, gargs);
                    (
                        path_of(self.tcx, did),
                        self.tcx.crate_name(did.krate).to_string(),
                        self_adt_path(self.tcx, did, gargs),
                    )
                }
                None => ("<indirect>".to_string(), String::new(), None),
            },
        };
        let mut out = Vec::new();
        for (n, a) in args.iter().enumerate() {
            if n >= MAX_WIDTH {
                out.push(Origin::Truncated);
                break;
            }
            out.push(self.operand(a, at, depth + 1, seen));
        }
        // `opt.unwrap_or_default()`: the default is a constant when the type's default is data
        // (an array of zeros, a number), nothing when it is empty (a `String`, a `Vec`)
        if krate == "core"
            && callee.ends_with("::unwrap_or_default")
            && let Some(TyKind::RigidTy(RigidTy::FnDef(_, gargs))) =
                func.ty(self.body.locals()).ok().map(|t| t.kind())
            && let Some(rustc_public::ty::GenericArgKind::Type(t)) = gargs.0.first()
            && matches!(
                t.kind().rigid(),
                Some(
                    RigidTy::Array(..)
                        | RigidTy::Int(_)
                        | RigidTy::Uint(_)
                        | RigidTy::Bool
                        | RigidTy::Char
                )
            )
        {
            out.push(Origin::Const {
                value: None,
                len: bytes_of_ty(t),
                span: None,
                zero: false,
            });
        }
        // the position the scanner gives this call's site
        let span = self
            .callee_span_at(func, at)
            .or_else(|| self.callee_through_pointer(func).map(|(_, _, s)| s))
            .map(|s| crate::locate_stable(self.tcx, s).0)
            .filter(|l| l.line > 0);
        // a pointer not resolved here (a parameter, a field, a table's element): where it comes
        // from, for the analysis to follow across functions
        let pointer =
            (callee == "<indirect>").then(|| Box::new(self.operand(func, at, depth + 1, seen)));
        Origin::Call {
            callee,
            krate,
            self_ty,
            args: out,
            span,
            runs,
            pointer,
            fed: None,
        }
    }

    fn rvalue(
        &self,
        rv: &Rvalue,
        span: Span,
        rest: &[Step],
        at: At,
        depth: usize,
        seen: &mut HashSet<Key>,
    ) -> Origin {
        match rv {
            Rvalue::Use(Operand::Copy(q) | Operand::Move(q), _) | Rvalue::CopyForDeref(q) => {
                let mut p = path_of_place(q);
                p.extend_from_slice(rest);
                self.place(q.local, p, at, depth, seen)
            }
            Rvalue::Use(op @ Operand::Constant(c), _)
                if rest.iter().any(|s| matches!(s, Step::Field(_))) =>
            {
                let o = self.operand(op, at, depth, seen);
                if matches!(o, Origin::Data { .. }) {
                    let ty = rustc_internal::internal(self.tcx, c.const_.ty());
                    self.read_fields(ty, rest, o)
                } else {
                    o
                }
            }
            // `*b` for a box `b`, as MIR lowers it: `b.0 as *const T`, a pointer to what the box
            // holds; reading through it continues there, as through `&raw const *b`
            Rvalue::Cast(_, Operand::Copy(q) | Operand::Move(q), _)
                if let Some(k) = self.box_pointer(q) =>
            {
                let mut p = path_of_place(q);
                p.truncate(p.len() - k);
                p.push(Step::Deref);
                p.extend_from_slice(rest.strip_prefix(&[Step::Deref]).unwrap_or(&[]));
                self.place(q.local, p, at, depth, seen)
            }
            Rvalue::Use(op, _) | Rvalue::Cast(_, op, _) => self.operand(op, at, depth, seen),
            // a reference stands for what it points to; reading through it continues there
            Rvalue::Ref(_, _, q) | Rvalue::AddressOf(_, q) | Rvalue::Reborrow(_, _, q) => {
                let mut p = path_of_place(q);
                p.extend_from_slice(rest.strip_prefix(&[Step::Deref]).unwrap_or(&[]));
                self.place(q.local, p, at, depth, seen)
            }
            // an element of `[E { .. }; 2]`, or a part of it
            Rvalue::Repeat(Operand::Copy(q) | Operand::Move(q), _)
                if matches!(rest.first(), Some(Step::Elem | Step::Index(_))) =>
            {
                let mut p = path_of_place(q);
                p.extend_from_slice(&rest[1..]);
                self.place(q.local, p, at, depth, seen)
            }
            // `[BASE; 2]` read at a field of an element: that field of the constant
            Rvalue::Repeat(op @ Operand::Constant(_), _)
                if matches!(rest.first(), Some(Step::Elem | Step::Index(_)))
                    && rest[1..].iter().any(|s| matches!(s, Step::Field(_))) =>
            {
                self.constant_part(op, &rest[1..], at, depth, seen)
            }
            // `[0u8; 12]`
            Rvalue::Repeat(op, n) => match op {
                Operand::Constant(c) => Origin::Const {
                    value: None,
                    len: byte_len(&c.const_.ty(), n.eval_target_usize().ok()),
                    span: Some(self.loc(span)),
                    zero: crate::const_int(op) == Some(0)
                        && n.eval_target_usize().is_ok_and(|n| n > 0),
                },
                _ => self.operand(op, at, depth, seen),
            },
            Rvalue::Aggregate(kind, ops) => self.aggregate(kind, ops, span, rest, at, depth, seen),
            // `key[0] & 248`, `seq ^ IV`: a value computed from both operands
            Rvalue::BinaryOp(_, a, b) | Rvalue::CheckedBinaryOp(_, a, b) => {
                let a = self.operand(a, at, depth + 1, seen);
                let b = self.operand(b, at, depth + 1, seen);
                if a == b { a } else { Origin::All(vec![a, b]) }
            }
            Rvalue::UnaryOp(_, a) => self.operand(a, at, depth + 1, seen),
            _ => Origin::Unknown,
        }
    }

    /// Is `q` a box's pointer (`b.0`, its `Unique`, or a field further in): how many fields
    /// from the box `b`.
    fn box_pointer(&self, q: &Place) -> Option<usize> {
        let n = q.projection.len();
        (1..=n.min(3)).find(|&k| {
            q.projection[n - k..]
                .iter()
                .all(|e| matches!(e, ProjectionElem::Field(0, _)))
                && Place {
                    local: q.local,
                    projection: q.projection[..n - k].to_vec(),
                }
                .ty(self.body.locals())
                .is_ok_and(|t| rustc_internal::internal(self.tcx, t).is_box())
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn aggregate(
        &self,
        kind: &AggregateKind,
        ops: &[Operand],
        span: Span,
        rest: &[Step],
        at: At,
        depth: usize,
        seen: &mut HashSet<Key>,
    ) -> Origin {
        // reading one field of a struct literal: only that part (`cfg.key` of
        // `Cfg { key: env::var(..), rounds: 100_000 }`)
        let field = match (kind, rest) {
            (AggregateKind::Adt(_, v, ..), [Step::Variant(w), Step::Field(f), ..])
                if variant_index(v) == *w =>
            {
                Some((*f, &rest[2..]))
            }
            (_, [Step::Field(f), ..]) => Some((*f, &rest[1..])),
            // one element of an array literal at a known index (`let [a, _b] = [x, lit];`)
            (AggregateKind::Array(_), [Step::Index(i), ..]) => Some((*i, &rest[1..])),
            // at an index not known (`arr[i].h`): that part of one of them
            (AggregateKind::Array(_), [Step::Elem, tail @ ..]) if !tail.is_empty() => {
                let mut alts = Vec::new();
                for op in ops.iter().take(MAX_WIDTH) {
                    let o = match op {
                        Operand::Copy(q) | Operand::Move(q) => {
                            let mut p = path_of_place(q);
                            p.extend_from_slice(tail);
                            self.place(q.local, p, at, depth + 1, seen)
                        }
                        _ => self.constant_part(op, tail, at, depth + 1, seen),
                    };
                    if !alts.contains(&o) {
                        alts.push(o);
                    }
                }
                return match alts.len() {
                    1 => alts.pop().unwrap_or(Origin::Unknown),
                    _ => Origin::Any(alts),
                };
            }
            _ => None,
        };
        if let Some((f, tail)) = field
            && let Some(op) = ops.get(f)
        {
            return match op {
                Operand::Copy(q) | Operand::Move(q) => {
                    let mut p = path_of_place(q);
                    p.extend_from_slice(tail);
                    self.place(q.local, p, at, depth, seen)
                }
                _ => self.constant_part(op, tail, at, depth, seen),
            };
        }
        match kind {
            // a closure built here: followed to what it returns, captures included
            AggregateKind::Closure(def, _) => {
                let did = rustc_internal::internal(self.tcx, def.def_id());
                let caps: Vec<Origin> = ops
                    .iter()
                    .map(|o| self.operand(o, at, depth + 1, seen))
                    .collect();
                self.follow_closure(did, Some(caps), depth)
            }
            AggregateKind::Adt(def, v, ..) if ops.is_empty() => {
                let adt = rustc_internal::internal(self.tcx, def.def_id());
                let adt_def = self.tcx.adt_def(adt);
                let idx = rustc_abi::VariantIdx::from_usize(variant_index(v));
                let variant = adt_def.variant(idx);
                // an enum variant is also a number (`Algorithm::Argon2i` is 1)
                let (did, value) = if adt_def.is_enum() {
                    (variant.def_id, discriminant(self.tcx, adt_def, idx))
                } else {
                    (adt, None)
                };
                Origin::Unit {
                    path: path_of(self.tcx, did),
                    krate: self.tcx.crate_name(did.krate).to_string(),
                    value,
                    span: None,
                    runs: None,
                }
            }
            AggregateKind::Tuple if ops.is_empty() => Origin::Unknown,
            // `Err(e)`: the error side, kept apart from the value (`r.ok()`, `r?`, `unwrap_or`
            // read the `Ok` side; `r.err()` this one)
            AggregateKind::Adt(def, v, ..)
                if ops.len() == 1 && variant_index(v) == 1 && {
                    let adt = rustc_internal::internal(self.tcx, def.def_id());
                    path_of(self.tcx, adt) == "core::result::Result"
                } =>
            {
                Origin::Call {
                    callee: rcbom_facts::RESULT_ERR.to_string(),
                    krate: "core".to_string(),
                    self_ty: Some("core::result::Result".to_string()),
                    args: vec![self.operand(&ops[0], at, depth + 1, seen)],
                    span: None,
                    runs: None,
                    pointer: None,
                    fed: None,
                }
            }
            // a struct literal read whole (`&Header { alg: HS384, ..Default::default() }`
            // passed on): each field's value at that field, so that a read of one field
            // elsewhere finds it, not every value the program stores in fields of its type
            AggregateKind::Adt(def, ..)
                if rest.is_empty() && !ops.is_empty() && self.program_struct(def.def_id()) =>
            {
                if depth >= MAX_DEPTH {
                    return Origin::Truncated;
                }
                let mut parts = Vec::new();
                for (f, o) in ops.iter().enumerate() {
                    if f >= MAX_FIELDS {
                        parts.push(Origin::Truncated);
                        break;
                    }
                    parts.push(Origin::Set {
                        path: vec![f],
                        value: Box::new(self.operand(o, at, depth + 1, seen)),
                        strong: true,
                    });
                }
                Origin::All(parts)
            }
            // literal data (`[0u8; 4]`, `(1, 2)`), not a value holding a descriptor or a static
            // (`Some(&SHA1)`)
            _ if !ops.is_empty()
                && ops.iter().all(|o| {
                    matches!(o, Operand::Constant(_))
                        && matches!(self.operand(o, at, depth + 1, seen), Origin::Const { .. })
                }) =>
            {
                let len = match kind {
                    AggregateKind::Array(t) => byte_len(t, Some(ops.len() as u64)),
                    _ => None,
                };
                Origin::Const {
                    value: None,
                    len,
                    span: Some(self.loc(span)),
                    zero: ops.iter().all(|o| crate::const_int(o) == Some(0)),
                }
            }
            _ => {
                if depth >= MAX_DEPTH {
                    return Origin::Truncated;
                }
                let mut parts: Vec<Origin> = Vec::new();
                for o in ops {
                    let x = self.operand(o, at, depth + 1, seen);
                    if !parts.contains(&x) {
                        if parts.len() >= MAX_WIDTH {
                            parts.push(Origin::Truncated);
                            break;
                        }
                        parts.push(x);
                    }
                }
                match parts.len() {
                    0 => Origin::Unknown,
                    1 => parts.pop().unwrap(),
                    // one element of an array literal (`[a, b][i]`): one of them
                    _ if matches!(rest.first(), Some(Step::Elem | Step::Index(_))) => {
                        Origin::Any(parts)
                    }
                    // the value itself: made of all of them (`[user, b"pepper"].concat()`)
                    _ => Origin::All(parts),
                }
            }
        }
    }

    /// The part `rest` of a constant operand: of a static or a constant (`[BASE, FIX][i].h`),
    /// that field of it; else the constant.
    fn constant_part(
        &self,
        op: &Operand,
        rest: &[Step],
        at: At,
        depth: usize,
        seen: &mut HashSet<Key>,
    ) -> Origin {
        let o = self.operand(op, at, depth, seen);
        match op {
            Operand::Constant(c)
                if matches!(o, Origin::Data { .. })
                    && rest.iter().any(|s| matches!(s, Step::Field(_))) =>
            {
                let ty = rustc_internal::internal(self.tcx, c.const_.ty());
                self.read_fields(ty, rest, o)
            }
            _ => o,
        }
    }

    /// A struct (not an enum, a union) of a crate other than the standard library's.
    fn program_struct(&self, def: rustc_public::DefId) -> bool {
        let did = rustc_internal::internal(self.tcx, def);
        self.tcx.adt_def(did).is_struct()
            && !matches!(
                self.tcx.crate_name(did.krate).as_str(),
                "core" | "std" | "alloc"
            )
    }

    /// A closure's return value, with its captures' origins when the caller knows them.
    fn follow_closure(&self, did: DefId, captures: Option<Vec<Origin>>, depth: usize) -> Origin {
        if self.followed || depth >= MAX_DEPTH {
            return Origin::Truncated;
        }
        let def = rustc_internal::stable(did);
        let Some(body) = rustc_public::CrateItem(def).body() else {
            return Origin::Unknown;
        };
        // what it returns, its own parameters `Unknown`; and, for a closure taking some, with
        // them as the input the analysis gives it where a combinator says (`fed`)
        let returned = |inputs: bool| {
            let mut inner = Origins::new(self.tcx, &body, Some(did));
            inner.followed = true;
            inner.inputs = inputs;
            inner.captures = captures.clone();
            let mut alts = Vec::new();
            for (bb, block) in body.blocks.iter().enumerate() {
                if matches!(block.terminator.kind, TerminatorKind::Return) {
                    let at = At {
                        bb,
                        idx: block.statements.len(),
                    };
                    let o = inner.place(
                        rustc_public::mir::RETURN_LOCAL,
                        Vec::new(),
                        at,
                        depth + 1,
                        &mut HashSet::new(),
                    );
                    if !alts.contains(&o) {
                        alts.push(o);
                    }
                }
            }
            match alts.len() {
                0 => Origin::Unknown,
                1 => alts.pop().unwrap(),
                _ => Origin::Any(alts),
            }
        };
        let ret = returned(false);
        let fed = (body.arg_locals().len() > 1)
            .then(|| returned(true))
            .filter(|f| *f != ret)
            .map(Box::new);
        Origin::Call {
            callee: "<closure>".into(),
            krate: String::new(),
            self_ty: None,
            args: vec![ret],
            span: None,
            runs: None,
            pointer: None,
            fed,
        }
    }

    /// An argument read before any assignment: a parameter, or a capture of a closure or
    /// coroutine.
    fn entry_origin(&self, local: Local, rest: &[Step], depth: usize) -> Origin {
        match self.kind {
            BodyKind::Fn if self.followed => Origin::Unknown,
            BodyKind::Fn => Origin::Param {
                index: local - 1,
                owner: None,
            },
            BodyKind::Closure | BodyKind::Coroutine if local == 1 => {
                // captures: `(*_1).k` (by reference), `_1.k` (by value), `(*_1.0).k` (pinned);
                // what is read of the capture after it (`(*(*_1).0).key`, the field of a value
                // the closure captured whole) is read of the parent's value
                let (k, tail) = match (self.kind, rest) {
                    (
                        BodyKind::Coroutine,
                        [Step::Field(0), Step::Deref, Step::Field(k), tail @ ..],
                    ) => (Some(*k), tail),
                    (BodyKind::Closure, [Step::Deref, Step::Field(k), tail @ ..])
                    | (BodyKind::Closure, [Step::Field(k), tail @ ..]) => (Some(*k), tail),
                    _ => (None, &[][..]),
                };
                match k.and_then(|k| self.capture(k, tail, depth)) {
                    Some(o) => o,
                    None => Origin::Unknown,
                }
            }
            // a coroutine's other argument is its resume value
            BodyKind::Coroutine => Origin::Unknown,
            BodyKind::Closure if self.followed && self.inputs => Origin::Param {
                index: local - 2,
                owner: Some(rcbom_facts::CLOSURE_INPUT.to_string()),
            },
            BodyKind::Closure if self.followed => Origin::Unknown,
            BodyKind::Closure => Origin::Param {
                index: local - 2,
                owner: None,
            },
        }
    }

    fn capture(&self, k: usize, tail: &[Step], depth: usize) -> Option<Origin> {
        if let Some(c) = &self.captures {
            return c.get(k).cloned();
        }
        if self.followed {
            return None;
        }
        let key = (k, tail.to_vec());
        if let Some(o) = self.parent_captures.borrow().get(&key) {
            return o.clone();
        }
        let found = self.captures_from_parent(k, tail, depth);
        self.parent_captures.borrow_mut().insert(key, found.clone());
        found
    }

    /// Capture `k` as the parent's body builds this closure (or coroutine), as an origin there,
    /// with `tail` read of it: a captured key is what the parent put in; a capture of the
    /// parent's parameter is that parameter of the parent (`Origin::Param`'s `owner`).
    fn captures_from_parent(&self, k: usize, tail: &[Step], depth: usize) -> Option<Origin> {
        let did = self.def?;
        if depth >= MAX_DEPTH {
            return None;
        }
        let parent = self.tcx.parent(did);
        let body = rustc_public::CrateItem(rustc_internal::stable(parent)).body()?;
        let mut outer = Origins::new(self.tcx, &body, Some(parent));
        // a closure of a generic function's instance: the parent's constants with that
        // instance's arguments (`let alg = T::ALG;` captured in `each::<P512>`)
        if let Some(a) = self.inst_args() {
            let n = self.tcx.generics_of(parent).count().min(a.len());
            outer = outer.with_item(parent, self.tcx.mk_args(&a[..n]));
        }
        let mut found: Option<Vec<Origin>> = None;
        for (bb, block) in body.blocks.iter().enumerate() {
            for (idx, s) in block.statements.iter().enumerate() {
                let StatementKind::Assign(_, Rvalue::Aggregate(kind, ops)) = &s.kind else {
                    continue;
                };
                let cdef = match kind {
                    AggregateKind::Closure(d, _) => d.def_id(),
                    AggregateKind::Coroutine(d, _) => d.def_id(),
                    AggregateKind::CoroutineClosure(d, _) => d.def_id(),
                    _ => continue,
                };
                if rustc_internal::internal(self.tcx, cdef) != did {
                    continue;
                }
                let at = At { bb, idx };
                let Some(o) = ops.get(k) else { continue };
                let x = match o {
                    Operand::Copy(p) | Operand::Move(p) if !tail.is_empty() => {
                        let mut path = path_of_place(p);
                        path.extend_from_slice(tail);
                        outer.place(p.local, path, at, depth + 1, &mut HashSet::new())
                    }
                    _ => outer.operand(o, at, depth + 1, &mut HashSet::new()),
                };
                let v = found.get_or_insert_with(Vec::new);
                if !v.contains(&x) {
                    v.push(x);
                }
            }
        }
        let owner = path_of(self.tcx, parent);
        found.map(|mut v| {
            let o = match v.len() {
                0 => Origin::Unknown,
                1 => v.pop().unwrap(),
                _ => Origin::Any(v),
            };
            // a parameter of the parent (a closure too); its own captures name theirs
            o.params_of(&owner)
        })
    }

    fn constant(&self, c: &rustc_public::mir::ConstOperand, depth: usize) -> Origin {
        let ty = c.const_.ty();
        match ty.kind().rigid() {
            // a closure without captures passed as a value: followed to what it returns
            Some(RigidTy::Closure(def, _)) => {
                let did = rustc_internal::internal(self.tcx, def.def_id());
                return self.follow_closure(did, Some(Vec::new()), depth);
            }
            // a function passed as a value is code, not data: a value without data
            Some(RigidTy::FnDef(def, gargs)) => {
                let did = rustc_internal::internal(self.tcx, def.def_id());
                let gargs = rustc_internal::internal(self.tcx, gargs);
                return Origin::Unit {
                    path: path_of(self.tcx, did),
                    krate: self.tcx.crate_name(did.krate).to_string(),
                    value: None,
                    span: Some(self.loc(c.span)),
                    runs: item_runs(self.tcx, did, gargs),
                };
            }
            Some(RigidTy::Tuple(ts)) if ts.is_empty() => return Origin::Unknown,
            _ => {}
        }
        if let Some(unit) = self.unit_value(&ty) {
            // a named const of a field-less struct names its item: aws-lc-rs's Ed25519
            // descriptor is one (`signature::ED25519: EdDSAParameters`)
            if let ConstantKind::Unevaluated(u) = c.const_.kind()
                && let Some(o) = self.unevaluated(
                    (
                        rustc_internal::internal(self.tcx, u.def.def_id()),
                        rustc_internal::internal(self.tcx, &u.args),
                        u.promoted.map(rustc_middle::mir::Promoted::from_u32),
                    ),
                    &ty,
                    None,
                    false,
                )
            {
                return o;
            }
            return unit;
        }
        let span = Some(self.loc(c.span));
        // integers, and values of a field-less enum, which are their discriminant
        // (`const ALG: Algorithm = Algorithm::Argon2d`)
        let int_ty = matches!(ty.kind().rigid(), Some(RigidTy::Uint(_) | RigidTy::Int(_)))
            || self.fieldless_enum(&ty);
        match c.const_.kind() {
            ConstantKind::Allocated(a) => {
                let value = match ty.kind().rigid() {
                    Some(RigidTy::Int(_)) => a.read_int().ok(),
                    _ if int_ty => a.read_uint().ok().and_then(|v| i128::try_from(v).ok()),
                    _ => None,
                };
                // an instance body: the item body may name what was evaluated here
                if let Some(u) = self.item_const(c.span)
                    && let Some(o) = self.unevaluated(u, &ty, value, true)
                {
                    return o;
                }
                // a static array of an enum's variants (`&HS_S`): those variants
                if let Some(o) = self.enum_elements(a, &ty) {
                    return o;
                }
                // `&STATIC`: a pointer to a static allocation
                let mut statics = Vec::new();
                for (_, prov) in &a.provenance.ptrs {
                    if let GlobalAlloc::Static(s) = GlobalAlloc::from(prov.0) {
                        let did = rustc_internal::internal(self.tcx, s.def_id());
                        let o = Origin::Data {
                            def: def_ref_internal(self.tcx, did),
                            value: None,
                            zero: self.item_zero(did),
                        };
                        if !statics.contains(&o) {
                            statics.push(o);
                        }
                    }
                }
                match statics.len() {
                    0 => {}
                    1 => return statics.pop().unwrap(),
                    _ => return Origin::Any(statics),
                }
                if let Some(o) = self.enum_elements(a, &ty) {
                    return o;
                }
                let (len, zero) = literal_data(a, &ty);
                Origin::Const {
                    value,
                    len,
                    span,
                    zero,
                }
            }
            // `&CONST`, `&[42u8; 32]`, `const { &SHA256 }`: what the promoted or inline
            // constant names, else literal data of this function
            ConstantKind::Unevaluated(u) => {
                let uneval = (
                    rustc_internal::internal(self.tcx, u.def.def_id()),
                    rustc_internal::internal(self.tcx, &u.args),
                    u.promoted.map(rustc_middle::mir::Promoted::from_u32),
                );
                // a named constant array or slice of an enum's variants (`const RSA_ALGS:
                // &[Algorithm] = &[RS256, RS384]`): those variants
                if let Some(v) = self.evaluate(uneval) {
                    let c: rustc_public::ty::MirConst = rustc_internal::stable(
                        rustc_middle::mir::Const::Val(v, rustc_internal::internal(self.tcx, ty)),
                    );
                    if let ConstantKind::Allocated(a) = c.kind()
                        && let Some(o) = self.enum_elements(a, &ty)
                    {
                        return o;
                    }
                }
                self.unevaluated(uneval, &ty, None, int_ty)
                    .unwrap_or_else(|| {
                        // a promoted literal (`&[0; 32]` in an item body): its data, as an
                        // instance body has it evaluated
                        let evaluated = uneval.2.and_then(|_| self.evaluate(uneval)).map(|v| {
                            let c: rustc_public::ty::MirConst =
                                rustc_internal::stable(rustc_middle::mir::Const::Val(
                                    v,
                                    rustc_internal::internal(self.tcx, ty),
                                ));
                            c
                        });
                        // an array of an enum's variants (`&[Algorithm::HS256]`)
                        if let Some(c) = &evaluated
                            && let ConstantKind::Allocated(a) = c.kind()
                            && let Some(o) = self.enum_elements(a, &ty)
                        {
                            return o;
                        }
                        let (len, zero) = evaluated
                            .and_then(|c| match c.kind() {
                                ConstantKind::Allocated(a) => Some(literal_data(a, &ty)),
                                _ => None,
                            })
                            .unwrap_or((bytes_of_ty(&ty), false));
                        Origin::Const {
                            value: None,
                            len,
                            span,
                            zero,
                        }
                    })
            }
            _ => Origin::Const {
                value: None,
                len: bytes_of_ty(&ty),
                span,
                zero: false,
            },
        }
    }

    /// What an unevaluated constant names: a named const (an associated const resolved to the
    /// impl's item when the arguments are known), or the statics and consts a promoted or
    /// inline constant names, else those its evaluated value points at (`const { pick() }`).
    /// `None` when it names nothing. An integer const carries its value (`value` if the
    /// caller already has it, else evaluated here when `int` and the arguments are known).
    fn unevaluated(
        &self,
        (did, uargs, promoted): Uneval<'tcx>,
        ty: &Ty,
        value: Option<i128>,
        int: bool,
    ) -> Option<Origin> {
        use rustc_middle::ty::TypeVisitableExt;
        let tcx = self.tcx;
        // the constant's arguments in terms of the instance (when this is one)
        let args = match self.inst_args() {
            Some(a) if uargs.has_non_region_param() => {
                rustc_middle::ty::EarlyBinder::bind(tcx, uargs)
                    .instantiate(tcx, a)
                    .skip_norm_wip()
            }
            _ => uargs,
        };
        let mut named = match promoted {
            // promoted constants share the enclosing item's generics
            Some(p) => named_in(tcx, &tcx.promoted_mir(did)[p], self.inst_args()),
            None if matches!(tcx.def_kind(did), rustc_hir::def::DefKind::AnonConst) => {
                match crate::statics::ctfe_mir(tcx, did) {
                    Ok(body) => named_in(tcx, body, Some(args)),
                    Err((v, t)) => crate::statics::statics_of_value(tcx, v, t),
                }
            }
            // a named const (aws-lc-rs algorithms) not yet evaluated
            None => crate::statics::resolve_const(tcx, did, uargs, self.inst_args())
                .into_iter()
                .collect(),
        };
        let evaluate = || self.evaluate((did, uargs, promoted));
        // a promoted or inline constant that names nothing itself (`const { pick() }`, a
        // `const fn` result): the statics its value points at
        if named.is_empty()
            && (promoted.is_some()
                || matches!(tcx.def_kind(did), rustc_hir::def::DefKind::AnonConst))
            && let Some(v) = evaluate()
        {
            named = crate::statics::statics_of_value(tcx, v, rustc_internal::internal(tcx, ty));
        }
        named.dedup();
        // a promoted value naming nothing that holds a function (`&Holder { f: digest::digest
        // }`): what its body builds, the function named where it is
        if named.is_empty()
            && let Some(p) = promoted
            && let Some(o) = self.promoted_origin(did, p)
        {
            return Some(o);
        }
        let value = match named.as_slice() {
            [_] if int => value.or_else(|| match evaluate()? {
                rustc_middle::mir::ConstValue::Scalar(
                    rustc_middle::mir::interpret::Scalar::Int(i),
                ) => Some(match ty.kind().rigid() {
                    Some(RigidTy::Int(_)) => i.to_int(i.size()),
                    _ => i128::try_from(i.to_uint(i.size())).ok()?,
                }),
                _ => None,
            }),
            _ => None,
        };
        let mut data: Vec<Origin> = named
            .into_iter()
            .map(|d| Origin::Data {
                def: def_ref_internal(tcx, d),
                value,
                zero: self.item_zero(d),
            })
            .collect();
        data.dedup();
        match data.len() {
            0 => None,
            1 => data.pop(),
            _ => Some(Origin::Any(data)),
        }
    }

    /// What promoted constant `p` of `did` builds, when it holds a function named as a value.
    fn promoted_origin(&self, did: DefId, p: rustc_middle::mir::Promoted) -> Option<Origin> {
        fn names_fn(o: &Origin) -> bool {
            match o {
                Origin::Unit { span: Some(_), .. } => true,
                Origin::Any(xs) | Origin::All(xs) => xs.iter().any(names_fn),
                Origin::Set { value, .. } => names_fn(value),
                Origin::Call { args, .. } => args.iter().any(names_fn),
                _ => false,
            }
        }
        if !self.tcx.is_mir_available(did) {
            return None;
        }
        let body: Body = rustc_internal::stable(&self.tcx.promoted_mir(did)[p]);
        let mut inner = Origins::new(self.tcx, &body, Some(did));
        inner.followed = true;
        let o = inner.returned_part(&[]);
        names_fn(&o).then_some(o)
    }

    /// The value of an unevaluated constant, when its arguments are known (in terms of the
    /// instance, when this is one).
    fn evaluate(
        &self,
        (did, uargs, promoted): Uneval<'tcx>,
    ) -> Option<rustc_middle::mir::ConstValue> {
        use rustc_middle::ty::TypeVisitableExt;
        let tcx = self.tcx;
        let args = match self.inst_args() {
            Some(a) if uargs.has_non_region_param() => {
                rustc_middle::ty::EarlyBinder::bind(tcx, uargs)
                    .instantiate(tcx, a)
                    .skip_norm_wip()
            }
            // a closure's own body: its arguments name the closure's synthetic parameters
            // (kind, signature, captures); its type has them
            None if uargs.has_non_region_param() && tcx.is_closure_like(did) => {
                match tcx
                    .type_of(did)
                    .instantiate_identity()
                    .skip_norm_wip()
                    .kind()
                {
                    rustc_middle::ty::Closure(_, a)
                    | rustc_middle::ty::Coroutine(_, a)
                    | rustc_middle::ty::CoroutineClosure(_, a) => a,
                    _ => uargs,
                }
            }
            _ => uargs,
        };
        let def = match promoted {
            Some(_) => Some(did),
            None => crate::statics::resolve_const(tcx, did, args, None),
        };
        if args.has_non_region_param()
            || !def.is_some_and(|d| crate::statics::evaluable(tcx, d, promoted))
        {
            return None;
        }
        tcx.const_eval_resolve(
            rustc_middle::ty::TypingEnv::fully_monomorphized(),
            rustc_middle::mir::UnevaluatedConst {
                def: did,
                args,
                promoted,
            },
            rustc_span::DUMMY_SP,
        )
        .ok()
    }

    /// Is a const or static item of data (an integer, an array of them) all zero bytes
    /// (`const ZERO: [u8; 32] = [0; 32]`)?
    fn item_zero(&self, did: DefId) -> bool {
        let tcx = self.tcx;
        let ty = tcx.type_of(did).instantiate_identity().skip_norm_wip();
        let data = |t: rustc_middle::ty::Ty<'_>| {
            matches!(
                t.kind(),
                rustc_middle::ty::Int(_) | rustc_middle::ty::Uint(_)
            )
        };
        let is_data = match ty.kind() {
            rustc_middle::ty::Array(e, _) => data(*e),
            _ => data(ty),
        };
        // a generic item (an associated const of a generic impl) has no one value
        if !is_data || tcx.is_foreign_item(did) || tcx.generics_of(did).count() > 0 {
            return false;
        }
        match tcx.def_kind(did) {
            rustc_hir::def::DefKind::Static { .. } => {
                tcx.eval_static_initializer(did).ok().is_some_and(|a| {
                    let a = a.inner();
                    let bytes = a.inspect_with_uninit_and_ptr_outside_interpreter(0..a.len());
                    !bytes.is_empty()
                        && a.provenance().ptrs().is_empty()
                        && bytes.iter().all(|b| *b == 0)
                })
            }
            rustc_hir::def::DefKind::Const | rustc_hir::def::DefKind::AssocConst => {
                if !crate::statics::evaluable(tcx, did, None) {
                    return false;
                }
                tcx.const_eval_poly(did).ok().is_some_and(|v| {
                    let c: rustc_public::ty::MirConst =
                        rustc_internal::stable(rustc_middle::mir::Const::Val(v, ty));
                    match c.kind() {
                        ConstantKind::Allocated(a) => {
                            literal_data(a, &rustc_internal::stable(ty)).1
                        }
                        _ => false,
                    }
                })
            }
            _ => false,
        }
    }

    /// An enum whose variants have no fields: its values are their discriminants.
    fn fieldless_enum(&self, ty: &Ty) -> bool {
        let kind = ty.kind();
        let Some(RigidTy::Adt(def, _)) = kind.rigid() else {
            return false;
        };
        let adt = self
            .tcx
            .adt_def(rustc_internal::internal(self.tcx, def.def_id()));
        adt.is_enum() && adt.all_fields().next().is_none()
    }

    /// The variants a constant array (or a reference to one, a slice) of a field-less enum
    /// holds (`&[Algorithm::HS256]`), each a `Unit` with its discriminant.
    fn enum_elements(&self, a: &rustc_public::ty::Allocation, ty: &Ty) -> Option<Origin> {
        let tcx = self.tcx;
        let (elem, bytes, len) = match ty.kind().rigid() {
            Some(RigidTy::Array(e, _)) => (*e, a.bytes.clone(), None),
            Some(RigidTy::Ref(_, t, _)) => {
                let m =
                    a.provenance
                        .ptrs
                        .first()
                        .and_then(|(_, p)| match GlobalAlloc::from(p.0) {
                            GlobalAlloc::Memory(m) => Some(m),
                            // a static that never changes (`static HS_S: [Algorithm; 1] =
                            // [HS256]`): its value
                            GlobalAlloc::Static(s)
                                if !tcx.is_mutable_static(rustc_internal::internal(
                                    tcx,
                                    s.def_id(),
                                )) =>
                            {
                                s.eval_initializer().ok()
                            }
                            _ => None,
                        })?;
                match t.kind().rigid() {
                    Some(RigidTy::Array(e, _)) => (*e, m.bytes.clone(), None),
                    Some(RigidTy::Slice(e)) if a.bytes.len() == 16 => {
                        let n = a.bytes[8..16]
                            .iter()
                            .rev()
                            .try_fold(0u64, |acc, b| b.map(|b| (acc << 8) | b as u64))?;
                        (*e, m.bytes.clone(), Some(n as usize))
                    }
                    _ => return None,
                }
            }
            _ => return None,
        };
        if !self.fieldless_enum(&elem) {
            return None;
        }
        let kind = elem.kind();
        let Some(RigidTy::Adt(def, _)) = kind.rigid() else {
            return None;
        };
        let adt = tcx.adt_def(rustc_internal::internal(tcx, def.def_id()));
        let size = elem.layout().ok()?.shape().size.bytes();
        if size == 0 || size > 8 {
            return None;
        }
        let n = len.unwrap_or(bytes.len() / size);
        if n == 0 || n > MAX_WIDTH || bytes.len() < n * size {
            return None;
        }
        let mut out = Vec::new();
        for k in 0..n {
            let raw = bytes[k * size..(k + 1) * size]
                .iter()
                .rev()
                .try_fold(0u128, |acc, b| b.map(|b| (acc << 8) | b as u128))?;
            let (idx, d) = adt.discriminants(tcx).find(|(_, d)| d.val == raw)?;
            out.push(Origin::Unit {
                path: path_of(tcx, adt.variant(idx).def_id),
                krate: tcx.crate_name(adt.did().krate).to_string(),
                value: i128::try_from(d.val).ok(),
                span: None,
                runs: None,
            });
        }
        Some(Origin::All(out))
    }

    /// A value of a struct without fields (`OsRng`): it names its type.
    fn unit_value(&self, ty: &Ty) -> Option<Origin> {
        let kind = ty.kind();
        let Some(RigidTy::Adt(def, _)) = kind.rigid() else {
            return None;
        };
        let did = rustc_internal::internal(self.tcx, def.def_id());
        let adt = self.tcx.adt_def(did);
        (adt.is_struct() && adt.all_fields().next().is_none()).then(|| Origin::Unit {
            path: path_of(self.tcx, did),
            krate: self.tcx.crate_name(did.krate).to_string(),
            value: None,
            span: None,
            runs: None,
        })
    }

    fn loc(&self, span: Span) -> Loc {
        locate(self.tcx, rustc_internal::internal(self.tcx, span)).0
    }
}

type Key = (Local, Path, At);

fn clone_kind(k: &DefKind) -> DefKind {
    match k {
        DefKind::Entry => DefKind::Entry,
        DefKind::Assign(rv, s) => DefKind::Assign(rv.clone(), *s),
        DefKind::Call { func, args } => DefKind::Call {
            func: func.clone(),
            args: args.clone(),
        },
        DefKind::OutParam {
            func,
            args,
            index,
            path,
        } => DefKind::OutParam {
            func: func.clone(),
            args: args.clone(),
            index: *index,
            path: path.clone(),
        },
        DefKind::Through { func } => DefKind::Through { func: func.clone() },
        DefKind::Cut => DefKind::Cut,
        DefKind::Lost => DefKind::Lost,
        DefKind::Value(o) => DefKind::Value(o.clone()),
    }
}

/// `ty` followed along `path` (fields, derefs, elements), as far as it goes.
fn walk_ty<'tcx>(
    tcx: TyCtxt<'tcx>,
    ty: rustc_middle::ty::Ty<'tcx>,
    path: &[Step],
) -> rustc_middle::ty::Ty<'tcx> {
    let mut ty = ty;
    let mut variant = None;
    for step in path {
        ty = match step {
            Step::Deref => match ty.builtin_deref(true) {
                Some(t) => t,
                None => return ty,
            },
            Step::Variant(v) => {
                variant = Some(*v);
                continue;
            }
            Step::Field(f) => match ty.kind() {
                rustc_middle::ty::Adt(adt, args) => {
                    let v = match (adt.is_enum(), variant.take()) {
                        (true, Some(v)) => adt.variant(rustc_abi::VariantIdx::from_usize(v)),
                        (true, None) => return ty,
                        _ => adt.non_enum_variant(),
                    };
                    match v.fields.get(rustc_abi::FieldIdx::from_usize(*f)) {
                        Some(field) => field.ty(tcx, args).skip_norm_wip(),
                        None => return ty,
                    }
                }
                rustc_middle::ty::Tuple(ts) => match ts.get(*f) {
                    Some(t) => *t,
                    None => return ty,
                },
                _ => return ty,
            },
            Step::Elem | Step::Index(_) => match ty.builtin_index() {
                Some(t) => t,
                None => return ty,
            },
            Step::Part(_) => return ty,
        };
    }
    ty
}

/// A static's or a constant's value, or a field of it (`NEST.0`).
fn on_data(o: &Origin) -> bool {
    match o {
        Origin::Data { .. } => true,
        Origin::Field { base, .. } => on_data(base),
        _ => false,
    }
}

/// Does a write to `def` (a place with an unknown part, `Step::Part`) overlap the read of
/// `read` beyond their common prefix: the function whose borrow points there.
fn part_overlap(def: &[Step], read: &[Step]) -> Option<String> {
    let j = def.iter().zip(read).take_while(|(a, b)| a.same(b)).count();
    match (def.get(j), read.get(j)) {
        (Some(Step::Part(f)), Some(_)) => Some(f.clone()),
        _ => None,
    }
}

/// Does a write through a value holding a borrow (`DefKind::Through`, recorded at some element
/// `Elem` of the place) overlap a read of a field of that place (`s.a`)?
fn through_overlap(def: &[Step], read: &[Step]) -> bool {
    let j = def.iter().zip(read).take_while(|(a, b)| a.same(b)).count();
    matches!(
        (def.get(j), read.get(j)),
        (Some(Step::Elem), Some(Step::Field(_) | Step::Variant(_)))
    )
}

fn is_prefix(a: &[Step], b: &[Step]) -> bool {
    b.len() >= a.len() && a.iter().zip(b).all(|(x, y)| x.same(y))
}

/// Is the local a random generator (`ThreadRng`, `OsRng`, `StdRng`, `ChaCha20Rng`)?
fn is_rng(body: &Body, local: Local) -> bool {
    match body.locals()[local].ty.kind() {
        TyKind::RigidTy(RigidTy::Adt(def, _)) => def.name().ends_with("Rng"),
        _ => false,
    }
}

/// Calls that write every byte of the buffers they are given by `&mut`, or fail: random
/// fills (`RngCore::fill_bytes`, `try_fill_bytes`, `Rng::fill`, ring's `SecureRandom::fill`,
/// `getrandom`) and `Read::read_exact`.
fn fills_whole(body: &Body, func: &Operand) -> bool {
    let Some(TyKind::RigidTy(RigidTy::FnDef(def, _))) =
        func.ty(body.locals()).ok().map(|t| t.kind())
    else {
        return false;
    };
    let name = def.name();
    let last = name.rsplit("::").next().unwrap_or(&name);
    matches!(
        last,
        "fill_bytes" | "try_fill_bytes" | "fill" | "try_fill" | "getrandom" | "read_exact"
    )
}

/// A definition building one variant of an enum (`Pick::A(x)`), read as another
/// (`[Variant(B), Field(0)]`).
fn other_variant(d: &DefKind, rest: &[Step]) -> bool {
    matches!(
        (d, rest.first()),
        (DefKind::Assign(Rvalue::Aggregate(AggregateKind::Adt(_, v, ..), _), _), Some(Step::Variant(w)))
            if variant_index(v) != *w
    )
}

/// A part of the place, not all of it: an element.
fn partial(path: &[Step]) -> bool {
    path.iter()
        .any(|s| matches!(s, Step::Elem | Step::Index(_) | Step::Part(_)))
}

/// Does `d` end `e`? An assignment overwrites the place and its parts; a call that fills the
/// place through `&mut` (`rng.fill_bytes(&mut nonce)`) replaces its initialization
/// (`let mut nonce = [0u8; 12]`), while a constant written after the fill stays.
fn kills(d: &Def, e: &Def) -> bool {
    d.local == e.local
        && is_prefix(&d.path, &e.path)
        && (d.strong || (matches!(d.kind, DefKind::OutParam { .. }) && d.sole && e.init))
}

/// An initialization rather than a value: a constant, or a standard-library constructor taking
/// only constants (`String::new()`, `Vec::with_capacity(32)`, `Default::default()`).
fn is_init(body: &Body, d: &DefKind) -> bool {
    if is_constant_init(d) {
        return true;
    }
    let DefKind::Call { func, args } = d else {
        return false;
    };
    let Some(TyKind::RigidTy(RigidTy::FnDef(def, _))) =
        func.ty(body.locals()).ok().map(|t| t.kind())
    else {
        return false;
    };
    matches!(def.krate().name.as_str(), "core" | "std" | "alloc")
        && args.iter().all(|a| matches!(a, Operand::Constant(_)))
}

fn is_constant_init(d: &DefKind) -> bool {
    match d {
        DefKind::Assign(Rvalue::Repeat(Operand::Constant(_), _), _)
        | DefKind::Assign(Rvalue::Use(Operand::Constant(_), _), _) => true,
        DefKind::Assign(Rvalue::Aggregate(_, ops), _) => {
            ops.iter().all(|o| matches!(o, Operand::Constant(_)))
        }
        _ => false,
    }
}

/// Is `q` a box's pointer (`b.0`, its `Unique`, or a field further in): how many fields from
/// the box `b` (as `Origins::box_pointer`, from the stable types).
fn box_field(body: &Body, q: &Place) -> Option<usize> {
    let n = q.projection.len();
    (1..=n.min(3)).find(|&k| {
        q.projection[n - k..]
            .iter()
            .all(|e| matches!(e, ProjectionElem::Field(0, _)))
            && Place {
                local: q.local,
                projection: q.projection[..n - k].to_vec(),
            }
            .ty(body.locals())
            .is_ok_and(|t| t.kind().is_box())
    })
}

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
    /// Locals whose value holds a `&mut` (`W { r: &mut x }`, a closure capturing one, a type
    /// parameter's): handed to a call, it may be written through.
    mut_holding: HashSet<Local>,
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

impl Pointees<'_> {
    /// Targets reached through a pointer held in a place (`*v[0] = x` on a `Vec<&mut T>`: the
    /// element's pointer, `(v, [Elem, Deref])`): where that pointer points, as far as followed
    /// (not followed: `lost`). An argument's (`*(*_1).0`, a closure's capture) stays as it is.
    fn through_held(&self, targets: Vec<Target>) -> Vec<Target> {
        self.through_held_at(targets, 0)
    }

    /// One more place looked at by the current search; false past `MAX_SEARCH`.
    fn step(&self) -> bool {
        self.steps.set(self.steps.get() + 1);
        self.steps.get() <= MAX_SEARCH
    }

    fn through_held_at(&self, targets: Vec<Target>, depth: usize) -> Vec<Target> {
        let mut out = Vec::new();
        for t in targets {
            // (a box of followed pointers: `**b` goes through the pointer in it)
            let j = match t.path.split_first() {
                Some((Step::Deref, rest)) if self.boxed(t.local) => {
                    rest.iter().position(|s| *s == Step::Deref).map(|i| i + 1)
                }
                _ => t.path.iter().position(|s| *s == Step::Deref),
            };
            // (at the start of the path only through a reference or raw pointer held in the
            // local, `*_t` of `_t: &mut &mut D`; a box's `*b` is its own contents)
            let through_ptr = |j: usize| {
                j > 0
                    || matches!(
                        self.body.locals()[t.local].ty.kind().rigid(),
                        Some(RigidTy::Ref(..) | RigidTy::RawPtr(..))
                    )
            };
            // (an argument's own pointer stays what it was on entry; one held in a part of it
            // that the body stores into, `w.slot = other` in `fn f(mut w: W, other: ..)`, is what
            // was stored there)
            let followed = |j: usize| {
                !(1..=self.nargs).contains(&t.local)
                    || (j > 0
                        && !t.path[..j].contains(&Step::Deref)
                        && self.part_stores.get(&t.local).is_some_and(|v| {
                            v.iter().any(|(p, ..)| {
                                is_prefix(p, &t.path[..j]) || is_prefix(&t.path[..j], p)
                            })
                        }))
            };
            match j {
                Some(j) if !t.alias && followed(j) && through_ptr(j) && depth < 4 => {
                    let found = self.targets(t.local, &t.path[..j], 1);
                    if found.iter().all(|x| x.alias) {
                        self.lost.set(true);
                    }
                    let found: Vec<Target> = found
                        .into_iter()
                        .map(|mut x| {
                            x.path.extend_from_slice(&t.path[j + 1..]);
                            x
                        })
                        .collect();
                    out.extend(self.through_held_at(found, depth + 1));
                }
                Some(j) if !t.alias && followed(j) && through_ptr(j) => {
                    // (past the bound: where the held pointer points is not followed)
                    self.cut.set(true);
                    out.push(t);
                }
                _ => out.push(t),
            }
        }
        out
    }

    /// The boxes a box `local.path` is the same allocation as: itself, and, for a copy of a
    /// box read through a reference (`_28 = copy (*_4)`), the box the reference points to.
    fn same_box(&self, local: Local, path: Path, depth: usize) -> Vec<(Local, Path)> {
        let mut out = vec![(local, path.clone())];
        if depth > MAX_PATH {
            self.cut.set(true);
        }
        if depth > MAX_PATH || !path.is_empty() {
            return out;
        }
        for k in self.direct.get(&local).into_iter().flatten() {
            if let DefKind::Assign(
                Rvalue::Use(Operand::Copy(q) | Operand::Move(q), _) | Rvalue::CopyForDeref(q),
                _,
            ) = k
            {
                let qp = path_of_place(q);
                match qp.split_first() {
                    Some((Step::Deref, rest)) => {
                        for t in self.targets(q.local, &[], depth + 1) {
                            let mut p = t.path;
                            p.extend_from_slice(rest);
                            out.push((t.local, p));
                        }
                    }
                    None => out.extend(self.same_box(q.local, Vec::new(), depth + 1)),
                    _ => {}
                }
            }
        }
        out
    }

    /// Places that `local.path` (a reference or raw pointer) points to.
    fn targets(&self, local: Local, path: &[Step], depth: usize) -> Vec<Target> {
        if depth == 0 {
            self.steps.set(0);
        }
        if depth > MAX_PATH || !self.step() {
            self.cut.set(true);
            return Vec::new();
        }
        // a pointer held in a part of a value this body builds (`*h.r = v` after `let h =
        // Holder { r: &mut x }`, `*t.0 = v`)
        if !path.is_empty() {
            return self.field_targets(local, path, depth);
        }
        // a pointer no statement of this body defines: an argument's, what it points to on
        // entry; any other, not followed
        if !self.direct.contains_key(&local) {
            if (1..=self.nargs).contains(&local) {
                return vec![Target {
                    local,
                    path: vec![Step::Deref],
                    alias: false,
                }];
            }
            self.lost.set(true);
            return Vec::new();
        }
        let mut out = Vec::new();
        for k in self.direct.get(&local).into_iter().flatten() {
            match k {
                DefKind::Assign(Rvalue::Ref(_, _, q), _)
                | DefKind::Assign(Rvalue::AddressOf(_, q), _)
                | DefKind::Assign(Rvalue::Reborrow(_, _, q), _) => {
                    let qp = path_of_place(q);
                    // `&mut *r` reborrows what `r` points to
                    let mut found = false;
                    if let Some(i) = qp.iter().position(|s| *s == Step::Deref) {
                        for mut t in self.targets(q.local, &qp[..i], depth + 1) {
                            t.path.extend_from_slice(&qp[i + 1..]);
                            found |= !t.alias;
                            out.push(t);
                        }
                    }
                    out.push(Target {
                        local: q.local,
                        alias: found,
                        path: qp,
                    });
                }
                DefKind::Assign(Rvalue::Use(Operand::Copy(q) | Operand::Move(q), _), _)
                | DefKind::Assign(Rvalue::Cast(_, Operand::Copy(q) | Operand::Move(q), _), _)
                    if q.projection.is_empty() =>
                {
                    // a copy of a pointer the function was given (`let s = if c { slot } else
                    // { other }`): what it points to on entry
                    if (1..=self.body.arg_locals().len()).contains(&q.local)
                        && !self.direct.contains_key(&q.local)
                        && is_ptr(self.body, q)
                    {
                        out.push(Target {
                            local: q.local,
                            path: vec![Step::Deref],
                            alias: false,
                        });
                    }
                    out.extend(self.targets(q.local, &[], depth + 1))
                }
                // a box's pointer (`(_1.0).0 as *const T`, how `&mut *key` reaches a
                // `Box`'s contents): its contents, `*_1`; of a copy of the box made through a
                // reference to it (`_28 = copy (*_4)`, `_4 = &mut _1`), the original's
                DefKind::Assign(Rvalue::Use(Operand::Copy(q) | Operand::Move(q), _), _)
                | DefKind::Assign(Rvalue::Cast(_, Operand::Copy(q) | Operand::Move(q), _), _)
                    if let Some(k) = box_field(self.body, q) =>
                {
                    let mut qp = path_of_place(q);
                    qp.truncate(qp.len() - k);
                    let boxes = self.same_box(q.local, qp, depth + 1);
                    let originals = boxes.len() > 1;
                    for (i, (local, mut path)) in boxes.into_iter().enumerate() {
                        path.push(Step::Deref);
                        // the copy stands for the box it was read from
                        out.push(Target {
                            local,
                            path,
                            alias: i == 0 && originals,
                        });
                    }
                }
                // `_9 = copy ((*_1).0)`, `_49 = deref_copy (_1.0)`: a copy of the pointer held in
                // a place (a closure's capture by reference, an `async` body's saved locals
                // behind its pinned self); it points where that one does, `*((*_1).0)`
                DefKind::Assign(Rvalue::Use(Operand::Copy(q) | Operand::Move(q), _), _)
                | DefKind::Assign(Rvalue::CopyForDeref(q), _) => {
                    let mut qp = path_of_place(q);
                    // a pointer taken out of a value this body builds (`if let Some(r) = o`
                    // after `let o = Some(&mut x)`): what the pointer put there points to
                    let mut found = false;
                    if !qp.contains(&Step::Deref) && self.direct.contains_key(&q.local) {
                        for t in self.field_targets(q.local, &qp, depth + 1) {
                            found |= !t.alias;
                            out.push(t);
                        }
                    }
                    if !partial(&qp) {
                        qp.push(Step::Deref);
                        out.push(Target {
                            local: q.local,
                            path: qp,
                            alias: found,
                        });
                    }
                }
                // a pointer a call takes out of a closed container, or a pointer into one
                // (`o.unwrap()`, `&mut v[0]`, `o.insert(&mut x)`): what the container holds
                DefKind::Call { func, args } if self.taken_from_bag(func, local) => {
                    out.extend(self.level_sources(args, self.body.locals()[local].ty, depth));
                }
                // `index_mut(&mut buf, ..)`, `as_mut()`: a borrow into the argument, all of it
                // (`as_mut`, `deref_mut`, `&mut buf[..]`) or a part (`&mut buf[..16]`,
                // `get_mut(i)`)
                DefKind::Call { func, args } => {
                    // a pointer a call takes out of a value holding pointers (`next()` of
                    // `vec![&mut x].into_iter()`, `o.unwrap()` of an `Option<&mut T>`), or
                    // one it returns from none of its arguments: not followed
                    let before = out.len();
                    if args
                        .iter()
                        .any(|a| a.ty(self.body.locals()).is_ok_and(|t| holds_mut_arg(t, 0)))
                    {
                        self.lost.set(true);
                    }
                    let part = borrows_part(self.body, func, args);
                    let inside =
                        (!part && borrows_inside(self.body, func, args, local)).then(|| match func
                            .ty(self.body.locals())
                            .ok()
                            .map(|t| t.kind())
                        {
                            Some(TyKind::RigidTy(RigidTy::FnDef(def, _))) => def.name(),
                            _ => String::new(),
                        });
                    // the argument and part its body borrows (`&mut self.alg`, `&mut s.other`
                    // of the second); else some part of any of them, and, through a holder's
                    // pointer (`impl DerefMut for W { .. self.r }`), a place not followed
                    let borrowed = inside.as_ref().and_then(|_| returned_part(self.body, func));
                    for (k, a) in args.iter().enumerate() {
                        if let Operand::Copy(q) | Operand::Move(q) = a
                            && is_mut_ptr(self.body, q)
                        {
                            if borrowed.as_ref().is_some_and(|(b, _)| *b != k) {
                                continue;
                            }
                            if borrowed.is_none() && self.holders.contains(&q.local) {
                                self.lost.set(true);
                            }
                            for mut t in self.targets(q.local, &path_of_place(q), depth + 1) {
                                if part && !partial(&t.path) {
                                    t.path.push(Step::Elem);
                                }
                                if let Some(f) = &inside
                                    && !partial(&t.path)
                                {
                                    match &borrowed {
                                        Some((_, p)) => t.path.extend(p.iter().cloned()),
                                        None => t.path.push(Step::Part(f.clone())),
                                    }
                                }
                                out.push(t);
                            }
                        }
                    }
                    if out.len() == before {
                        self.lost.set(true);
                    }
                }
                _ => {}
            }
        }
        out
    }

    /// Places that the pointer held at `local.path` (a field, a variant's field, an element of a
    /// value this body builds) points to: what the aggregate was built with there. A part
    /// written later, or a value not built here, is not followed (`lost`).
    fn field_targets(&self, local: Local, path: &[Step], depth: usize) -> Vec<Target> {
        let mut out = Vec::new();
        if depth > MAX_PATH || !self.step() {
            self.cut.set(true);
            return out;
        }
        // a closed container (`bag`) filled or built by calls, or lent to them: any pointer put
        // in it (one only built, `[&mut a, &mut b]`, by the element below)
        if self.bag(local).is_some()
            && (self.lent_locals.contains(&local)
                || self.direct.get(&local).is_none_or(|d| {
                    d.iter()
                        .any(|k| !matches!(k, DefKind::Assign(Rvalue::Aggregate(..), _)))
                }))
        {
            return self.bag_targets(local, depth + 1);
        }
        // a part stored later (`h.r = &mut b` after `Holder { r: &mut a }`): the last such store
        // before the write in its block is what the part holds there; else any of them, not
        // followed for sure
        // (a value lent by `&mut` may be changed through the loan: `o.insert(&mut x)`)
        if self.lent_locals.contains(&local) {
            self.lost.set(true);
        }
        if self.partly.contains(&local) {
            let at = self.cur_at.get();
            let last = self
                .part_stores
                .get(&local)
                .into_iter()
                .flatten()
                .filter(|(p, a, _)| {
                    at.is_some_and(|w| a.bb == w.bb && a.idx < w.idx) && is_prefix(p, path)
                })
                .max_by_key(|(_, a, _)| a.idx);
            if let Some((p, _, Operand::Copy(q) | Operand::Move(q))) = last {
                let mut qp = path_of_place(q);
                if !qp.contains(&Step::Deref) {
                    qp.extend_from_slice(&path[p.len()..]);
                    return self.targets(q.local, &qp, depth + 1);
                }
            }
            self.lost.set(true);
        }
        let Some(defs) = self.direct.get(&local) else {
            // an argument's field holding a pointer (`*w.slot = v` in `fn wset(w: W)`): what it
            // pointed to on entry; another place no statement of this body defines, not followed
            if !(1..=self.body.arg_locals().len()).contains(&local) {
                self.lost.set(true);
            } else if !path.is_empty() && path.iter().all(|s| matches!(s, Step::Field(_))) {
                let mut p = path.to_vec();
                p.push(Step::Deref);
                out.push(Target {
                    local,
                    path: p,
                    alias: false,
                });
            }
            return out;
        };
        for k in defs {
            match k {
                DefKind::Assign(Rvalue::Aggregate(kind, ops), _) => {
                    let rest = match (kind, path) {
                        (AggregateKind::Adt(_, v, ..), [Step::Variant(w), rest @ ..]) => {
                            if variant_index(v) != *w {
                                continue;
                            }
                            rest
                        }
                        _ => path,
                    };
                    let idxs: Vec<usize> = match rest.first() {
                        Some(Step::Field(i) | Step::Index(i)) => vec![*i],
                        Some(Step::Elem) => (0..ops.len()).collect(),
                        _ => {
                            self.lost.set(true);
                            continue;
                        }
                    };
                    for i in idxs {
                        if let Some(Operand::Copy(q) | Operand::Move(q)) = ops.get(i) {
                            let mut qp = path_of_place(q);
                            if qp.contains(&Step::Deref) {
                                self.lost.set(true);
                                continue;
                            }
                            qp.extend_from_slice(&rest[1..]);
                            out.extend(self.targets(q.local, &qp, depth + 1));
                        }
                    }
                }
                DefKind::Assign(Rvalue::Use(Operand::Copy(q) | Operand::Move(q), _), _)
                    if !path_of_place(q).contains(&Step::Deref) =>
                {
                    let mut qp = path_of_place(q);
                    qp.extend_from_slice(path);
                    out.extend(self.targets(q.local, &qp, depth + 1));
                }
                // the result of the program's function holding a borrow it was given (`let w =
                // wrap(&mut x)`, `let (r, _) = guard(&mut x)`): where that borrow points
                DefKind::Call { func, args } => match self
                    .returns_of(func)
                    .and_then(|r| self.returned(r, args, Some(path), depth))
                {
                    Some(t) => out.extend(t),
                    None => self.lost.set(true),
                },
                _ => self.lost.set(true),
            }
        }
        out
    }
}

/// Does a value of the type hold a `&mut` as a type argument (`IntoIter<&mut T>`,
/// `Option<&mut T>`, `Vec<&mut T>`)?
fn holds_mut_arg(t: Ty, depth: usize) -> bool {
    if depth > 4 {
        return false;
    }
    match t.kind().rigid() {
        Some(RigidTy::Ref(_, i, Mutability::Not)) => holds_mut_arg(*i, depth + 1),
        Some(RigidTy::Ref(_, i, Mutability::Mut)) => depth > 0 || holds_mut_arg(*i, depth + 1),
        Some(RigidTy::Adt(_, args)) => args.0.iter().any(|a| {
            matches!(a, rustc_public::ty::GenericArgKind::Type(t)
                if matches!(t.kind().rigid(), Some(RigidTy::Ref(_, _, Mutability::Mut)))
                    || holds_mut_arg(*t, depth + 1))
        }),
        Some(RigidTy::Tuple(ts)) => ts.iter().any(|t| holds_mut_arg(*t, depth + 1)),
        _ => false,
    }
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

/// The pointer type a standard-library container of pointers holds: `&mut T` of `Vec<&mut T>`,
/// `Option<&mut T>`, `Box<&mut T>`, `[&mut T; 2]`, `vec::IntoIter<&mut T>`, `iter::Once<&mut T>`,
/// `Box<MaybeUninit<[&mut T; 1]>>` (`vec![..]`'s allocation); none when it holds another
/// borrow besides.
fn bag_content(t: Ty) -> Option<Ty> {
    fn walk(t: Ty, depth: usize, found: &mut Option<Ty>) -> bool {
        if depth > 6 {
            return false;
        }
        match t.kind().rigid() {
            Some(RigidTy::Ref(_, _, Mutability::Mut)) => {
                if found.is_some_and(|f| f != t) {
                    return false;
                }
                *found = Some(t);
                true
            }
            Some(RigidTy::Array(e, _) | RigidTy::Slice(e)) => walk(*e, depth + 1, found),
            Some(RigidTy::Adt(def, args))
                if matches!(def.krate().name.as_str(), "core" | "std" | "alloc")
                    && BAG_TYPES.contains(&def.name().rsplit("::").next().unwrap_or("")) =>
            {
                args.0.iter().all(|a| match a {
                    rustc_public::ty::GenericArgKind::Type(t) => walk(*t, depth + 1, found),
                    _ => true,
                })
            }
            _ => !holds_mut_arg(t, 1),
        }
    }
    if !matches!(
        t.kind().rigid(),
        Some(RigidTy::Adt(..) | RigidTy::Array(..) | RigidTy::Slice(_))
    ) {
        return None;
    }
    let mut found = None;
    (walk(t, 0, &mut found)).then_some(found).flatten()
}

/// Does a value of type `t` hold, or point to, a container of `p` pointers (`bag_content`), or
/// point to a `p` (`&mut p`, through which a held pointer is re-pointed)? A `p` itself does not.
fn risky(t: Ty, p: Ty) -> bool {
    fn walk(t: Ty, p: Ty, depth: usize) -> bool {
        if t == p || depth > 6 {
            return false;
        }
        if bag_content(t) == Some(p) {
            return true;
        }
        match t.kind().rigid() {
            Some(RigidTy::Ref(_, i, _) | RigidTy::RawPtr(i, _)) => *i == p || walk(*i, p, depth + 1),
            Some(RigidTy::Array(e, _) | RigidTy::Slice(e)) => walk(*e, p, depth + 1),
            Some(RigidTy::Tuple(ts)) => ts.iter().any(|t| walk(*t, p, depth + 1)),
            Some(
                RigidTy::Adt(_, args)
                | RigidTy::Closure(_, args)
                | RigidTy::Coroutine(_, args)
                | RigidTy::CoroutineClosure(_, args),
            ) => args.0.iter().any(|a| {
                matches!(a, rustc_public::ty::GenericArgKind::Type(t) if walk(*t, p, depth + 1))
            }),
            _ => false,
        }
    }
    walk(t, p, 0)
}

/// Does a value of type `t` hold a trait object (what it holds is not seen in its type)?
fn holds_dyn(t: Ty, depth: usize) -> bool {
    match t.kind().rigid() {
        _ if depth > 6 => true,
        Some(RigidTy::Dynamic(..)) => true,
        Some(RigidTy::Ref(_, i, _) | RigidTy::RawPtr(i, _)) => holds_dyn(*i, depth + 1),
        Some(RigidTy::Array(e, _) | RigidTy::Slice(e)) => holds_dyn(*e, depth + 1),
        Some(RigidTy::Tuple(ts)) => ts.iter().any(|t| holds_dyn(*t, depth + 1)),
        Some(RigidTy::Adt(_, args)) => args.0.iter().any(
            |a| matches!(a, rustc_public::ty::GenericArgKind::Type(t) if holds_dyn(*t, depth + 1)),
        ),
        _ => false,
    }
}

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

/// Is the callee one of `MOVES`, or of `MOVES_OF` for a container?
fn moves_only(body: &Body, func: &Operand) -> bool {
    let Some(TyKind::RigidTy(RigidTy::FnDef(def, args))) =
        func.ty(body.locals()).ok().map(|t| t.kind())
    else {
        return false;
    };
    if !matches!(def.krate().name.as_str(), "core" | "std" | "alloc") {
        return false;
    }
    let name = def.name();
    let segs: Vec<&str> = name.split("::").filter(|s| !s.starts_with('<')).collect();
    let Some(last) = segs.len().checked_sub(2).map(|i| segs[i..].join("::")) else {
        return false;
    };
    let plain = |t: &Ty| {
        bag_content(*t).is_some()
            || matches!(
                t.kind().rigid(),
                Some(
                    RigidTy::Ref(_, _, Mutability::Mut)
                        | RigidTy::Int(_)
                        | RigidTy::Uint(_)
                        | RigidTy::Bool
                        | RigidTy::Char
                )
            )
    };
    let types = || {
        args.0.iter().filter_map(|a| match a {
            rustc_public::ty::GenericArgKind::Type(t) => Some(t),
            _ => None,
        })
    };
    MOVES.contains(&last.as_str())
        || (MOVES_OF.contains(&last.as_str())
            && types().next().is_some_and(|s| bag_content(*s).is_some())
            && types().all(plain))
}

/// The pointer types whose containers (`bag_content`) the body builds, fills and empties only by
/// `moves_only` calls, `vec![..]`'s store in its box, aggregates (`Some(&mut x)`, `[&mut x]`)
/// and moves between locals: it re-points no pointer such a container holds (no store of one
/// through a pointer, no borrow into a container), and hands no container, borrow of one or
/// borrow of such a pointer to other code (a call, a closure's capture, a struct, a trait
/// object). Then what a container holds is what was put in it.
fn closed_bags(body: &Body) -> Bags {
    // (a body with a type `rustc_public` cannot convert, an `async` closure's: none followed)
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| closed_bags_in(body))).unwrap_or_else(
        |e| {
            if !crate::async_closure(&e) {
                std::panic::resume_unwind(e)
            }
            Bags::default()
        },
    )
}

fn closed_bags_in(body: &Body) -> Bags {
    let locals = body.locals();
    let cands: HashSet<Ty> = locals.iter().filter_map(|l| bag_content(l.ty)).collect();
    if cands.is_empty() {
        return Bags::default();
    }
    let mut open: HashSet<Ty> = HashSet::new();
    let mut bags = Bags::default();
    let mut box_inits = Vec::new();
    // the box a raw pointer is the allocation of (`_65 = copy (_35.0) as *const _
    // (BoxDerefTransmute)`), for `vec![..]`'s store in it
    let box_of = |l: Local| {
        let mut found = None;
        for st in body.blocks.iter().flat_map(|b| &b.statements) {
            if let StatementKind::Assign(lhs, rv) = &st.kind
                && lhs.local == l
                && lhs.projection.is_empty()
            {
                match rv {
                    Rvalue::Cast(_, Operand::Copy(q) | Operand::Move(q), _)
                    | Rvalue::Use(Operand::Copy(q) | Operand::Move(q), _)
                        if found.is_none() && box_field(body, q) == Some(q.projection.len()) =>
                    {
                        found = Some(q.local)
                    }
                    _ => return None,
                }
            }
        }
        found
    };
    // a store into a place: through a pointer, of what holds such a pointer or the pointer itself
    // (re-pointing it); into a part of a container, or of a container or pointer into one into a
    // part of a value
    let mut store = |place: &Place, rv: Option<&Rvalue>, open: &mut HashSet<Ty>| {
        let Ok(pt) = place.ty(locals) else {
            open.extend(cands.iter().copied());
            return;
        };
        let deref = place
            .projection
            .iter()
            .any(|e| matches!(e, ProjectionElem::Deref));
        if deref
            && let (Some(ProjectionElem::Deref), Some(b), Some(rv)) =
                (place.projection.first(), box_of(place.local), rv)
            && !place.projection[1..]
                .iter()
                .any(|e| matches!(e, ProjectionElem::Deref))
            && bag_content(locals[b].ty).is_some()
        {
            box_inits.push((b, rv.clone()));
            return;
        }
        for &p in &cands {
            if (deref && (pt == p || risky(pt, p)))
                || (!place.projection.is_empty()
                    && (risky(locals[place.local].ty, p) || risky(pt, p)))
            {
                open.insert(p);
            }
        }
    };
    for block in &body.blocks {
        for st in &block.statements {
            let StatementKind::Assign(place, rv) = &st.kind else {
                continue;
            };
            store(place, Some(rv), &mut open);
            let Ok(pt) = place.ty(locals) else {
                continue;
            };
            for &p in &cands {
                let risky_op = |o: &Operand| o.ty(locals).is_ok_and(|t| risky(t, p));
                let opens = match rv {
                    // (a container built with the pointers is followed; anything else holding a
                    // container or a pointer into one is not)
                    Rvalue::Aggregate(_, ops) => {
                        bag_content(pt) != Some(p) && ops.iter().any(risky_op)
                    }
                    // a borrow into a container (`&mut v[0]`, `&mut (*r).0`; a reborrow of a
                    // pointer, `&mut (*r)`, is the pointer again)
                    Rvalue::Ref(_, _, q) | Rvalue::AddressOf(_, q) => {
                        q.projection
                            .iter()
                            .any(|e| !matches!(e, ProjectionElem::Deref))
                            && risky(locals[q.local].ty, p)
                    }
                    // made from something else (a pointer forged from an address), or turned
                    // into a trait object
                    Rvalue::Cast(_, o, t) => {
                        let from = o.ty(locals).is_ok_and(|f| risky(f, p));
                        (risky(*t, p) && !from) || (from && holds_dyn(*t, 0))
                    }
                    _ => false,
                };
                if opens {
                    open.insert(p);
                }
            }
        }
        match &block.terminator.kind {
            TerminatorKind::Call {
                func,
                args,
                destination,
                ..
            } => {
                if !destination.projection.is_empty() {
                    store(destination, None, &mut open);
                }
                if moves_only(body, func) {
                    bags.moves.push((func.clone(), args.clone()));
                } else {
                    for &p in &cands {
                        if args.iter().any(|a| match a.ty(locals) {
                            Ok(t) => risky(t, p),
                            Err(_) => true,
                        }) {
                            open.insert(p);
                        }
                    }
                }
            }
            TerminatorKind::InlineAsm { .. } => open.extend(cands.iter().copied()),
            _ => {}
        }
    }
    bags.box_inits = box_inits;
    bags.closed = cands.difference(&open).copied().collect();
    if bags.closed.is_empty() {
        return Bags::default();
    }
    bags
}

impl Pointees<'_> {
    /// The pointer type a container local holds, when the body's containers of it are closed
    /// (`closed_bags`).
    fn bag(&self, local: Local) -> Option<Ty> {
        bag_content(self.body.locals()[local].ty).filter(|c| self.bags.closed.contains(c))
    }

    /// What a call's result holds of the borrows it is given (`returned_pointers`).
    fn returns_of(&self, func: &Operand) -> Option<&Returns> {
        match func.ty(self.body.locals()).ok()?.kind() {
            TyKind::RigidTy(RigidTy::FnDef(def, _)) => self.returns.get(&def.def_id()),
            _ => None,
        }
    }

    /// The places the pointers a call's result holds at `at` point to (all of them for `None`),
    /// per its function's summary `r`: into what an argument points to, or where a pointer an
    /// argument holds points. `None` when the summary has none there, or an argument is not a
    /// place.
    fn returned(
        &self,
        r: &Returns,
        args: &[Operand],
        at: Option<&[Step]>,
        depth: usize,
    ) -> Option<Vec<Target>> {
        let mut out = Vec::new();
        let mut any = false;
        for (p, src) in &r.ptrs {
            if at.is_some_and(|a| a != p.as_slice()) {
                continue;
            }
            any = true;
            let (k, rest, held) = match src {
                Returned::Borrow(k, rest) => (*k, rest, false),
                Returned::Held(k, rest) => (*k, rest, true),
            };
            let (Operand::Copy(q) | Operand::Move(q)) = args.get(k)? else {
                return None;
            };
            let mut qp = path_of_place(q);
            if held {
                qp.extend(rest.iter().cloned());
                out.extend(self.targets(q.local, &qp, depth + 1));
            } else {
                for mut t in self.targets(q.local, &qp, depth + 1) {
                    if !partial(&t.path) {
                        t.path.extend(rest.iter().cloned());
                    }
                    out.push(t);
                }
            }
        }
        (any || at.is_none()).then_some(out)
    }

    /// Is `local` a pointer a `moves_only` call returns of a closed type, or into a container
    /// of one?
    fn taken_from_bag(&self, func: &Operand, local: Local) -> bool {
        let t = self.body.locals()[local].ty;
        moves_only(self.body, func)
            && (self.bags.closed.contains(&t)
                || matches!(t.kind().rigid(),
                    Some(RigidTy::Ref(_, i, _)) if self.bags.closed.contains(i)))
    }

    /// Is `local` a box of pointers whose contents are followed?
    fn boxed(&self, local: Local) -> bool {
        self.bag(local).is_some()
            && matches!(self.body.locals()[local].ty.kind().rigid(),
                Some(RigidTy::Adt(def, _)) if def.name().rsplit("::").next() == Some("Box"))
    }

    /// For an argument of a `moves_only` call: is it a pointer of a closed type or a container of
    /// them (stored or handed on, written through by nothing), or a borrow of such a container?
    fn moved(&self, p: &Place) -> (bool, bool) {
        let Ok(t) = p.ty(self.body.locals()) else {
            return (false, false);
        };
        let closed = |c: Option<Ty>| c.is_some_and(|c| self.bags.closed.contains(&c));
        match t.kind().rigid() {
            _ if closed(Some(t)) || closed(bag_content(t)) => (true, false),
            Some(RigidTy::Ref(_, i, _) | RigidTy::RawPtr(i, _)) if closed(bag_content(*i)) => {
                (false, true)
            }
            _ => (false, false),
        }
    }

    /// The places the pointers of type `q` that a `moves_only` call's arguments give it may
    /// point to: an argument's pointer of that type itself (`Box::new(&mut x)`), those a
    /// container of them holds, by value or borrowed (`v.into_iter()`, `v.pop()`), and, for
    /// a pointer into a container (`&mut v[0]`, `o.insert(..)`, `o.as_mut()`), any of the
    /// container's elements. An argument of another type holding such pointers, or a borrow of
    /// another kind, is not followed.
    fn level_sources(&self, args: &[Operand], q: Ty, depth: usize) -> Vec<Target> {
        let mut out = Vec::new();
        for a in args {
            let (Operand::Copy(p) | Operand::Move(p)) = a else {
                continue;
            };
            let Ok(t) = p.ty(self.body.locals()) else {
                self.lost.set(true);
                continue;
            };
            let held = match t.kind().rigid() {
                Some(RigidTy::Ref(_, i, _) | RigidTy::RawPtr(i, _)) => bag_content(*i),
                _ => None,
            };
            let slot = held.is_some_and(
                |c| matches!(q.kind().rigid(), Some(RigidTy::Ref(_, j, _)) if *j == c),
            );
            if t == q {
                out.extend(self.targets(p.local, &path_of_place(p), depth + 1));
            } else if bag_content(t) == Some(q) {
                if p.projection.is_empty() {
                    out.extend(self.bag_targets(p.local, depth + 1));
                } else {
                    self.lost.set(true);
                }
            } else if held == Some(q) || slot {
                let mut found = false;
                for x in self.targets(p.local, &path_of_place(p), depth + 1) {
                    if x.alias {
                        continue;
                    }
                    found = true;
                    if slot {
                        let mut path = x.path;
                        path.push(Step::Elem);
                        out.push(Target {
                            local: x.local,
                            path,
                            alias: false,
                        });
                    } else if x.path.is_empty() && self.bag(x.local).is_some() {
                        out.extend(self.bag_targets(x.local, depth + 1));
                    } else {
                        self.lost.set(true);
                    }
                }
                if !found {
                    self.lost.set(true);
                }
            } else if mentions(t, q, 0)
                || (matches!(
                    t.kind().rigid(),
                    Some(RigidTy::Ref(_, _, Mutability::Mut) | RigidTy::RawPtr(_, Mutability::Mut))
                ) && !matches!(q.kind().rigid(), Some(RigidTy::Ref(_, j, _)) if *j == t))
            {
                // (another argument of that type in it, or a borrow it may hand out a borrow
                // into, `Option<&mut T>::from(&mut Option<T>)`; not the pointer stored where a
                // borrow of the slot it is put in is handed out, `o.get_or_insert(&mut x)`)
                self.lost.set(true);
            }
        }
        out
    }

    /// The places the pointers a closed container (`bag`) holds may point to: those it was built
    /// with or moved from, those `moves_only` calls lending it put in it (`v.push(&mut x)`), and
    /// those `vec![..]` stored in its allocation. One built otherwise (an argument, a call of
    /// the program's) is not followed (`lost`).
    fn bag_targets(&self, local: Local, depth: usize) -> Vec<Target> {
        let mut out = Vec::new();
        let Some(q) = self.bag(local) else {
            self.lost.set(true);
            return out;
        };
        if depth > MAX_PATH || !self.step() {
            self.cut.set(true);
            return out;
        }
        if self.bag_stack.borrow().contains(&local) {
            return out;
        }
        self.bag_stack.borrow_mut().push(local);
        match self.direct.get(&local) {
            None => self.lost.set(true),
            Some(defs) => {
                for k in defs {
                    match k {
                        DefKind::Assign(Rvalue::Aggregate(_, ops), _) => {
                            out.extend(self.level_sources(ops, q, depth))
                        }
                        DefKind::Assign(Rvalue::Use(op, _), _) => {
                            out.extend(self.level_sources(std::slice::from_ref(op), q, depth))
                        }
                        DefKind::Call { func, args } if moves_only(self.body, func) => {
                            out.extend(self.level_sources(args, q, depth))
                        }
                        // (`opt_mut(&mut x)` returning `Some(x)`: what it was given)
                        DefKind::Call { func, args } => match self
                            .returns_of(func)
                            .and_then(|r| self.returned(r, args, None, depth))
                        {
                            Some(t) => out.extend(t),
                            None => self.lost.set(true),
                        },
                        _ => self.lost.set(true),
                    }
                }
            }
        }
        for (_, args) in &self.bags.moves {
            let lends = args.iter().any(|a| match a {
                Operand::Copy(p) | Operand::Move(p) if is_mut_ptr(self.body, p) => {
                    matches!(p.ty(self.body.locals()).ok().map(|t| t.kind()),
                        Some(TyKind::RigidTy(RigidTy::Ref(_, i, _))) if bag_content(i) == Some(q))
                        && self
                            .targets(p.local, &path_of_place(p), depth + 1)
                            .iter()
                            .any(|t| t.local == local && t.path.is_empty())
                }
                _ => false,
            });
            if lends {
                out.extend(self.level_sources(args, q, depth));
            }
        }
        for (b, rv) in &self.bags.box_inits {
            if *b == local {
                match rv {
                    Rvalue::Aggregate(_, ops) => out.extend(self.level_sources(ops, q, depth)),
                    Rvalue::Use(op, _) => {
                        out.extend(self.level_sources(std::slice::from_ref(op), q, depth))
                    }
                    _ => self.lost.set(true),
                }
            }
        }
        self.bag_stack.borrow_mut().pop();
        out
    }
}

/// Does a value of type `t` hold a value of type `q` (itself, behind a pointer, an element, a
/// type argument)? A type not known (a parameter, an opaque type, a trait object) may.
fn mentions(t: Ty, q: Ty, depth: usize) -> bool {
    if t == q {
        return true;
    }
    match t.kind().rigid() {
        _ if depth > 6 => true,
        Some(RigidTy::Ref(_, i, _) | RigidTy::RawPtr(i, _)) => mentions(*i, q, depth + 1),
        Some(RigidTy::Array(e, _) | RigidTy::Slice(e)) => mentions(*e, q, depth + 1),
        Some(RigidTy::Tuple(ts)) => ts.iter().any(|t| mentions(*t, q, depth + 1)),
        Some(
            RigidTy::Adt(_, args)
            | RigidTy::Closure(_, args)
            | RigidTy::Coroutine(_, args)
            | RigidTy::CoroutineClosure(_, args),
        ) => args.0.iter().any(|a| {
            matches!(a, rustc_public::ty::GenericArgKind::Type(t) if mentions(*t, q, depth + 1))
        }),
        Some(RigidTy::Dynamic(..)) => true,
        None => true,
        _ => false,
    }
}

impl Pointees<'_> {
    /// What the `&mut` borrows a closure or a struct built in `local` holds point to (its
    /// captures, its fields), each with whether it points at one place.
    /// A closure this body builds into `local` (its only definition): its item, and each
    /// capture that is a `&mut` with what it points to.
    fn held_closure(&self, local: Local) -> Option<(rustc_public::DefId, Vec<Capture>)> {
        let [DefKind::Assign(Rvalue::Aggregate(kind, ops), _)] =
            self.direct.get(&local)?.as_slice()
        else {
            return None;
        };
        let AggregateKind::Closure(def, _) = kind else {
            return None;
        };
        let caps = ops
            .iter()
            .enumerate()
            .filter_map(|(i, op)| match op {
                Operand::Copy(q) | Operand::Move(q) if is_mut_ptr(self.body, q) => {
                    let t = self.targets(q.local, &path_of_place(q), 0);
                    let single = sole_target(&t);
                    Some((i, t, single))
                }
                _ => None,
            })
            .collect();
        Some((def.def_id(), caps))
    }

    /// `by_borrow`: the call takes it by `&mut` (one borrow of it is this call's).
    fn held(&self, local: Local, by_borrow: bool) -> Vec<(Vec<Target>, bool, Option<usize>)> {
        let mut out = Vec::new();
        // (a value of a type holding no `&mut`: nothing)
        if !self.mut_holding.contains(&local) {
            return out;
        }
        // (moved into a temporary for the call, `set1(w)`: the value it was moved from)
        let mut chain = vec![local];
        let mut src = local;
        while chain.len() < 8
            && let Some([DefKind::Assign(Rvalue::Use(Operand::Copy(q) | Operand::Move(q), _), _)]) =
                self.direct.get(&src).map(|d| d.as_slice())
            && q.projection.is_empty()
            && !chain.contains(&q.local)
        {
            src = q.local;
            chain.push(src);
        }
        // a value holding a `&mut` that this body does not build here (a parameter, a call's
        // result, a copy of another): what it points to is not followed
        let defs = self.direct.get(&src);
        let followed = |k: &DefKind| match k {
            DefKind::Assign(Rvalue::Aggregate(..), _) => true,
            DefKind::Call { func, .. } => self.returns_of(func).is_some(),
            _ => false,
        };
        if self.mut_holding.contains(&local) && defs.is_none_or(|d| !d.iter().all(|k| followed(k)))
        {
            self.lost.set(true);
        }
        // (one place only when the value is built once: `if c { W { r: &mut a } } else { W {
        // r: &mut b } }` holds either)
        let once = defs.is_some_and(|d| d.len() == 1);
        // a value with a part stored later (`h.r = &mut b`) or lent by `&mut` to another call
        // (`repoint(&mut h, ..)`): what it holds at the call is not only what it was built with
        let lends = |l: Local| {
            self.body
                .blocks
                .iter()
                .flat_map(|b| &b.statements)
                .filter(|st| {
                    matches!(&st.kind, StatementKind::Assign(
                        _,
                        Rvalue::Ref(_, rustc_public::mir::BorrowKind::Mut { .. }, q)
                        | Rvalue::AddressOf(rustc_public::mir::RawPtrKind::Mut, q),
                    ) if q.local == l
                        && !q.projection.iter().any(|e| matches!(e, ProjectionElem::Deref)))
                })
                .count()
        };
        let changed = chain.iter().any(|l| self.partly.contains(l))
            || lends(local) > usize::from(by_borrow)
            || chain[1..].iter().any(|&l| lends(l) > 0);
        if changed {
            self.lost.set(true);
        }
        for k in defs.into_iter().flatten() {
            // (a holder the program's function returned, `let w = wrap1(&mut a)`: its pointers,
            // per its summary)
            if let DefKind::Call { func, args } = k
                && let Some(r) = self.returns_of(func)
            {
                for (p, _) in &r.ptrs {
                    let Some(t) = self.returned(r, args, Some(p), 0) else {
                        self.lost.set(true);
                        continue;
                    };
                    let single = sole_target(&t) && once && r.once && !changed;
                    let field = match p.as_slice() {
                        [Step::Field(i)] => Some(*i),
                        _ => None,
                    };
                    out.push((t, single, field));
                }
            }
            if let DefKind::Assign(Rvalue::Aggregate(kind, ops), _) = k {
                // (where the borrow sits: a struct's field, a tuple's element)
                let fields = match kind {
                    AggregateKind::Tuple => true,
                    AggregateKind::Adt(def, ..) => def.kind().is_struct(),
                    _ => false,
                };
                for (i, op) in ops.iter().enumerate() {
                    if let Operand::Copy(q) | Operand::Move(q) = op
                        && is_mut_ptr(self.body, q)
                    {
                        let t = self.targets(q.local, &path_of_place(q), 0);
                        let single = sole_target(&t) && once && !changed;
                        out.push((t, single, fields.then_some(i)));
                    }
                }
            }
        }
        out
    }
}

/// What a closure (`did`) assigns through its capture `k`, a `&mut` (`|_| a = &SHA384`:
/// `*((*_1).k) = ..`, or `*(_1.k)` for a closure taking itself by value): the values' origins,
/// its own parameters not followed. `None` when it does more with the capture than assign
/// through it and read it: lends or moves it, writes a part of what it points to.
fn capture_writes(tcx: TyCtxt<'_>, did: rustc_public::DefId, k: usize) -> Option<Vec<Origin>> {
    let body = rustc_public::CrateItem(did).body()?;
    let mut inner = Origins::new(tcx, &body, Some(rustc_internal::internal(tcx, did)));
    inner.followed = true;
    let stmts = || {
        body.blocks.iter().enumerate().flat_map(|(bb, b)| {
            b.statements
                .iter()
                .enumerate()
                .map(move |(idx, st)| (bb, idx, st))
        })
    };
    // the locals holding a copy of the capture's pointer (`_6 = copy (*_1).k`), and how much of
    // a place's projection is that pointer (`(*_1).k`, `_1.k`, or such a local)
    let mut copies: HashSet<Local> = HashSet::new();
    let pointer = |q: &Place, copies: &HashSet<Local>| -> Option<usize> {
        if copies.contains(&q.local) {
            return Some(0);
        }
        if q.local != 1 {
            return None;
        }
        match q.projection.as_slice() {
            [ProjectionElem::Deref, ProjectionElem::Field(f, _), ..] if *f == k => Some(2),
            [ProjectionElem::Field(f, _), ..] if *f == k => Some(1),
            _ => None,
        }
    };
    let whole = |o: &Operand, copies: &HashSet<Local>| {
        matches!(o, Operand::Copy(q) | Operand::Move(q)
            if pointer(q, copies).is_some_and(|n| q.projection.len() == n))
    };
    loop {
        let before = copies.len();
        for (_, _, st) in stmts() {
            if let StatementKind::Assign(p, Rvalue::Use(o, _) | Rvalue::Cast(_, o, _)) = &st.kind
                && p.projection.is_empty()
                && whole(o, &copies)
            {
                copies.insert(p.local);
            }
            if let StatementKind::Assign(p, Rvalue::CopyForDeref(q)) = &st.kind
                && p.projection.is_empty()
                && pointer(q, &copies).is_some_and(|n| q.projection.len() == n)
            {
                copies.insert(p.local);
            }
        }
        if copies.len() == before {
            break;
        }
    }
    let mut values = Vec::new();
    for (bb, idx, st) in stmts() {
        let StatementKind::Assign(p, rv) = &st.kind else {
            continue;
        };
        if let Some(n) = pointer(p, &copies) {
            // a copy of the pointer itself (above); otherwise what it points to, whole: not a
            // part of it, nor the pointer re-pointed
            if p.projection.len() == n && copies.contains(&p.local) {
                continue;
            }
            if p.projection.len() != n + 1 || !matches!(p.projection[n], ProjectionElem::Deref) {
                return None;
            }
            let o = inner.rvalue(
                rv,
                st.source_info.span,
                &[],
                At { bb, idx },
                1,
                &mut HashSet::new(),
            );
            if !values.contains(&o) {
                values.push(o);
            }
        }
        match rv {
            Rvalue::Ref(_, rustc_public::mir::BorrowKind::Mut { .. }, q)
            | Rvalue::AddressOf(rustc_public::mir::RawPtrKind::Mut, q)
                if pointer(q, &copies).is_some() =>
            {
                return None;
            }
            // (the pointer copied somewhere other than a local: escapes)
            Rvalue::Use(o, _) | Rvalue::Cast(_, o, _)
                if whole(o, &copies) && !(p.projection.is_empty() && copies.contains(&p.local)) =>
            {
                return None;
            }
            Rvalue::Aggregate(_, ops) if ops.iter().any(|o| whole(o, &copies)) => return None,
            _ => {}
        }
    }
    for b in &body.blocks {
        if let TerminatorKind::Call { args, .. } = &b.terminator.kind
            && args.iter().any(|o| whole(o, &copies))
        {
            return None;
        }
    }
    Some(values)
}

/// A closure's capture that is a `&mut`: its index, what it points to, and whether that is
/// one place.
type Capture = (usize, Vec<Target>, bool);

/// Does a pointer with these targets point at one place? The aliases stand for the place they
/// point at, not for another one; a place found twice (a copy of a parameter's pointer, which
/// points where the parameter does) is one.
fn sole_target(targets: &[Target]) -> bool {
    let mut places = targets
        .iter()
        .filter(|t| !t.alias)
        .map(|t| (t.local, &t.path));
    places
        .next()
        .is_some_and(|first| places.all(|other| other == first))
}

/// The defining path of the function a call operand names.
fn callee_name(body: &Body, func: &Operand) -> Option<String> {
    match func.ty(body.locals()).ok()?.kind() {
        TyKind::RigidTy(RigidTy::FnDef(def, _)) => Some(def.name()),
        _ => None,
    }
}

/// Does a call that returns `&mut` into its argument borrow a part of it (an element, a
/// range other than `..`), rather than all of it (`as_mut`, `deref_mut`, `&mut buf[..]`)?
fn borrows_part(body: &Body, func: &Operand, args: &[Operand]) -> bool {
    let name = callee_name(body, func).unwrap_or_default();
    let method = name.rsplit("::").next().unwrap_or("");
    let elementwise = matches!(
        method,
        "index_mut"
            | "get_mut"
            | "get_unchecked_mut"
            | "first_mut"
            | "last_mut"
            | "split_first_mut"
            | "split_last_mut"
    );
    // the receiver is an array, a slice or a `Vec` (`Mutex::get_mut` is all of the value)
    let of_sequence = args
        .first()
        .and_then(|a| a.ty(body.locals()).ok())
        .is_some_and(|t| {
            let inner = match t.kind().rigid() {
                Some(RigidTy::Ref(_, i, _)) => i.kind(),
                _ => return false,
            };
            match inner.rigid() {
                Some(RigidTy::Array(..) | RigidTy::Slice(_)) => true,
                Some(RigidTy::Adt(d, _)) => d.name().ends_with("::Vec"),
                _ => false,
            }
        });
    // `&mut buf[..]` indexes with `RangeFull`: all of it
    let full = args.get(1).and_then(|a| a.ty(body.locals()).ok()).is_some_and(|t| {
        matches!(t.kind().rigid(), Some(RigidTy::Adt(d, _)) if d.name().ends_with("RangeFull"))
    });
    elementwise && of_sequence && !full
}

/// Does a call of a function outside the standard library return a borrow of something inside
/// its argument (`fn slot(&mut self) -> &mut &Digest { &mut self.alg }`): a part of it, not the
/// whole, when what it points to is of another type than the argument's?
fn borrows_inside(body: &Body, func: &Operand, args: &[Operand], result: Local) -> bool {
    let std = match func.ty(body.locals()).ok().map(|t| t.kind()) {
        Some(TyKind::RigidTy(RigidTy::FnDef(def, _))) => {
            matches!(def.krate().name.as_str(), "core" | "std" | "alloc")
        }
        _ => true,
    };
    let pointee = |t: Ty| match t.kind().rigid() {
        Some(RigidTy::Ref(_, i, _) | RigidTy::RawPtr(i, _)) => Some(*i),
        _ => None,
    };
    let Some(out) = pointee(body.locals()[result].ty) else {
        return false;
    };
    // (of any pointer argument: `second(0, &mut s)` borrows from its second)
    !std && args
        .iter()
        .filter_map(|a| a.ty(body.locals()).ok().and_then(pointee))
        .any(|inp| inp != out)
}

/// The argument local and the part of what it points to that `local` borrows, when every
/// assignment of it in `body` borrows the same (`&mut (*_1).alg`, a copy of such a local).
fn resolve(body: &Body, nargs: usize, local: Local, depth: usize) -> Option<(Local, Path)> {
    if depth > 8 {
        return None;
    }
    let arg = |l: Local| (1..=nargs).contains(&l);
    let mut found: Option<(Local, Path)> = None;
    for b in &body.blocks {
        for st in &b.statements {
            let StatementKind::Assign(lhs, rv) = &st.kind else {
                continue;
            };
            if lhs.local != local {
                continue;
            }
            if !lhs.projection.is_empty() {
                return None;
            }
            let p = match rv {
                Rvalue::Ref(_, _, q) | Rvalue::AddressOf(_, q) => {
                    let qp = path_of_place(q);
                    let (Some(Step::Deref), rest) = (qp.first(), qp.get(1..)?) else {
                        return None;
                    };
                    if rest.contains(&Step::Deref) {
                        return None;
                    }
                    if arg(q.local) {
                        (q.local, rest.to_vec())
                    } else {
                        let (l, mut base) = resolve(body, nargs, q.local, depth + 1)?;
                        base.extend(rest.iter().cloned());
                        (l, base)
                    }
                }
                Rvalue::Use(Operand::Copy(q) | Operand::Move(q), _) | Rvalue::CopyForDeref(q)
                    if q.projection.is_empty() && !arg(q.local) =>
                {
                    resolve(body, nargs, q.local, depth + 1)?
                }
                _ => return None,
            };
            if found.as_ref().is_some_and(|f| *f != p) {
                return None;
            }
            found = Some(p);
        }
        // a call's result assigned to the local: not known
        if let TerminatorKind::Call { destination, .. } = &b.terminator.kind
            && destination.local == local
        {
            return None;
        }
    }
    found
}

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

/// What the result of a function (`body`) holds of the borrows it was given (`fn wrap(x: &mut
/// T) -> W { W { r: x } }`, `fn slots(&mut self) -> (&mut A, &mut B)`, `Some(x)`, a holder
/// handed back): built in the body from them, each such pointer's place known. `None` when it may
/// hold another (made by a call, a part assigned later, a type not seen into).
pub(crate) fn returned_pointers(tcx: TyCtxt<'_>, body: &Body) -> Option<Returns> {
    // (a body with a type `rustc_public` cannot convert, an `async` closure's: not known)
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        returned_pointers_in(tcx, body)
    }))
    .unwrap_or_else(|e| {
        if !crate::async_closure(&e) {
            std::panic::resume_unwind(e)
        }
        None
    })
}

fn returned_pointers_in(tcx: TyCtxt<'_>, body: &Body) -> Option<Returns> {
    let locals = body.locals();
    let ret = rustc_public::mir::RETURN_LOCAL;
    if !holds_mut_borrow(tcx, rustc_internal::internal(tcx, locals[ret].ty), 0)
        || matches!(
            locals[ret].ty.kind().rigid(),
            Some(RigidTy::Ref(..) | RigidTy::RawPtr(..))
        )
    {
        return None;
    }
    let nargs = body.arg_locals().len();
    let arg = |l: Local| (1..=nargs).contains(&l);
    // a local's assignments, none of a part of it nor by a call
    let defs = |l: Local| -> Option<Vec<&Rvalue>> {
        let mut out = Vec::new();
        for b in &body.blocks {
            for st in &b.statements {
                if let StatementKind::Assign(p, rv) = &st.kind
                    && p.local == l
                {
                    if !p.projection.is_empty() {
                        return None;
                    }
                    out.push(rv);
                }
            }
            if let TerminatorKind::Call { destination, .. } = &b.terminator.kind
                && destination.local == l
            {
                return None;
            }
        }
        Some(out)
    };
    // where a pointer the body has points: an argument's own, one an argument holds, a borrow
    // into what an argument points to, through copies
    fn pointer<'b>(
        body: &'b Body,
        nargs: usize,
        defs: &dyn Fn(Local) -> Option<Vec<&'b Rvalue>>,
        q: &Place,
        depth: usize,
    ) -> Option<Returned> {
        let arg = |l: Local| (1..=nargs).contains(&l);
        let qp = path_of_place(q);
        if arg(q.local) {
            return match qp.as_slice() {
                [] => Some(Returned::Borrow(q.local - 1, Vec::new())),
                fs if fs.iter().all(|s| matches!(s, Step::Field(_))) => {
                    Some(Returned::Held(q.local - 1, qp))
                }
                _ => None,
            };
        }
        if !qp.is_empty() || depth > 8 {
            return None;
        }
        if let [Rvalue::Use(Operand::Copy(r) | Operand::Move(r), _)] = defs(q.local)?.as_slice() {
            return pointer(body, nargs, defs, &r.clone(), depth + 1);
        }
        resolve(body, nargs, q.local, 0).map(|(l, p)| Returned::Borrow(l - 1, p))
    }
    let holds = |t: Ty| holds_mut_borrow(tcx, rustc_internal::internal(tcx, t), 0);
    let mut out = Vec::new();
    let mut once = true;
    let mut work: Vec<(&Rvalue, usize)> = Vec::new();
    let top = defs(ret)?;
    once &= top.len() == 1;
    work.extend(top.into_iter().map(|rv| (rv, 0)));
    while let Some((rv, depth)) = work.pop() {
        if depth > 8 {
            return None;
        }
        match rv {
            Rvalue::Aggregate(kind, ops) => {
                let prefix = match kind {
                    AggregateKind::Tuple => Vec::new(),
                    AggregateKind::Adt(def, ..) if def.kind().is_struct() => Vec::new(),
                    AggregateKind::Adt(def, v, ..) if def.kind().is_enum() => {
                        vec![Step::Variant(variant_index(v))]
                    }
                    _ => return None,
                };
                for (i, op) in ops.iter().enumerate() {
                    let t = op.ty(locals).ok()?;
                    let mut at = prefix.clone();
                    at.push(Step::Field(i));
                    match (op, t.kind().rigid()) {
                        (
                            Operand::Copy(q) | Operand::Move(q),
                            Some(
                                RigidTy::Ref(_, _, Mutability::Mut)
                                | RigidTy::RawPtr(_, Mutability::Mut),
                            ),
                        ) => out.push((at, pointer(body, nargs, &defs, q, 0)?)),
                        _ if holds(t) => return None,
                        _ => {}
                    }
                }
            }
            Rvalue::Use(Operand::Copy(q) | Operand::Move(q), _) if q.projection.is_empty() => {
                if arg(q.local) {
                    // a holder given and handed back: its own pointers
                    let ty = rustc_internal::internal(tcx, locals[q.local].ty);
                    let fields = holder_paths(tcx, ty);
                    if fields.is_empty() {
                        return None;
                    }
                    for f in fields {
                        out.push((
                            vec![Step::Field(f)],
                            Returned::Held(q.local - 1, vec![Step::Field(f)]),
                        ));
                    }
                } else {
                    let ds = defs(q.local)?;
                    once &= ds.len() == 1;
                    work.extend(ds.into_iter().map(|rv| (rv, depth + 1)));
                }
            }
            _ => return None,
        }
    }
    Some(Returns { ptrs: out, once })
}

/// The summaries (`returned_pointers`) of the program's functions a body calls whose result
/// holds a borrow, by function.
fn callee_returns(tcx: TyCtxt<'_>, body: &Body) -> HashMap<rustc_public::DefId, Returns> {
    let mut out = HashMap::new();
    for b in &body.blocks {
        let TerminatorKind::Call { func, .. } = &b.terminator.kind else {
            continue;
        };
        let Some(TyKind::RigidTy(RigidTy::FnDef(def, _))) =
            func.ty(body.locals()).ok().map(|t| t.kind())
        else {
            continue;
        };
        if out.contains_key(&def.def_id())
            || matches!(def.krate().name.as_str(), "core" | "std" | "alloc")
        {
            continue;
        }
        // (a body `rustc_public` cannot convert, one with an `async` closure's type: none)
        let summary = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| def.body()))
            .ok()
            .flatten()
            .and_then(|callee| returned_pointers(tcx, &callee));
        if let Some(r) = summary {
            out.insert(def.def_id(), r);
        }
    }
    out
}

/// The argument a function returns a borrow into, and the part of what it points to, when every
/// return of its body borrows the same one (`fn slot(&mut self) -> &mut &Digest { &mut
/// self.alg }`: argument 0, `[Field(0)]`; `fn second(_n: u8, s: &mut U) -> .. { &mut s.other }`:
/// argument 1).
fn returned_part(caller: &Body, func: &Operand) -> Option<(usize, Path)> {
    let Some(TyKind::RigidTy(RigidTy::FnDef(def, _))) =
        func.ty(caller.locals()).ok().map(|t| t.kind())
    else {
        return None;
    };
    // (a body `rustc_public` cannot convert, one with an `async` closure's type: not known)
    let body = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| def.body()))
        .ok()
        .flatten()?;
    let nargs = body.arg_locals().len();
    resolve(&body, nargs, 0, 0)
        .filter(|(_, p)| {
            !p.is_empty()
                && p.iter()
                    .all(|s| matches!(s, Step::Field(_) | Step::Variant(_)))
        })
        .map(|(l, p)| (l - 1, p))
}

fn is_ptr(body: &Body, p: &Place) -> bool {
    matches!(
        p.ty(body.locals())
            .ok()
            .and_then(|t| t.kind().rigid().cloned()),
        Some(RigidTy::Ref(..) | RigidTy::RawPtr(..))
    )
}

fn is_mut_ptr(body: &Body, p: &Place) -> bool {
    // (a place whose own type `rustc_public` cannot convert, an `async` closure handed to a
    // call, is no pointer: converting it panics, `crate::has_unconvertible`; any other panic is
    // raised again)
    let kind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        p.ty(body.locals())
            .ok()
            .and_then(|t| t.kind().rigid().cloned())
    }))
    .unwrap_or_else(|e| {
        if !crate::async_closure(&e) {
            std::panic::resume_unwind(e)
        }
        None
    });
    matches!(
        kind,
        Some(RigidTy::Ref(_, _, Mutability::Mut) | RigidTy::RawPtr(_, Mutability::Mut))
    )
}

fn returns_mut_ref(body: &Body, dest: &Place) -> bool {
    is_mut_ptr(body, dest)
}

/// A method returning its own receiver (`&mut self -> &mut Self`, `hasher.update(d)`).
fn returns_receiver(body: &Body, dest: &Place, args: &[Operand]) -> bool {
    let (Ok(d), Some(Ok(a))) = (
        dest.ty(body.locals()),
        args.first().map(|a| a.ty(body.locals())),
    ) else {
        return false;
    };
    is_mut_ptr(body, dest) && d == a
}

/// Does the call's result hold a borrow (`ChunksMut<'_, u8>`, `(&mut [u8], &mut [u8])`)?
/// A standard-library container's method that stores its other arguments in it
/// (`std::collections::HashMap::<K, V, S, A>::insert`, `alloc::vec::Vec::<T, A>::push`).
fn std_store(callee: &str) -> bool {
    const TYPES: &[&str] = &[
        "Vec", "VecDeque", "HashMap", "BTreeMap", "HashSet", "BTreeSet",
    ];
    const METHODS: &[&str] = &["push", "push_back", "push_front", "insert"];
    let segs: Vec<&str> = callee.split("::").filter(|s| !s.starts_with('<')).collect();
    matches!(segs.first(), Some(&("std" | "alloc" | "core")))
        && matches!(segs.as_slice(), [.., ty, m] if TYPES.contains(ty) && METHODS.contains(m))
}

/// Does a value of the type hold a `&mut` (a field, an element, a type argument)?
fn holds_mut_borrow<'tcx>(tcx: TyCtxt<'tcx>, t: rustc_middle::ty::Ty<'tcx>, depth: usize) -> bool {
    use rustc_middle::ty::TyKind as K;
    use rustc_middle::ty::TypeVisitableExt;
    // (past the bound: any type with a borrowed lifetime may)
    if depth > 4 {
        return t.has_free_regions();
    }
    match t.kind() {
        // what a closure or a coroutine captures (`|| fill(&mut k)`)
        K::Closure(_, args) => {
            holds_mut_borrow(tcx, args.as_closure().tupled_upvars_ty(), depth + 1)
        }
        K::Coroutine(_, args) => {
            holds_mut_borrow(tcx, args.as_coroutine().tupled_upvars_ty(), depth + 1)
        }
        K::CoroutineClosure(_, args) => holds_mut_borrow(
            tcx,
            args.as_coroutine_closure().tupled_upvars_ty(),
            depth + 1,
        ),
        // a type parameter: any type, a `&mut` included
        K::Param(_) => true,
        K::Ref(_, _, rustc_middle::ty::Mutability::Mut)
        | K::RawPtr(_, rustc_middle::ty::Mutability::Mut) => true,
        K::Ref(_, inner, _) | K::Array(inner, _) | K::Slice(inner) => {
            holds_mut_borrow(tcx, *inner, depth + 1)
        }
        K::Tuple(ts) => ts.iter().any(|t| holds_mut_borrow(tcx, t, depth + 1)),
        // a trait object with a borrowed lifetime (`Box<dyn DerefMut<..> + 'a>`), an opaque type
        // (`impl FnMut + 'a`): what they hold is not known
        K::Dynamic(_, r) => !r.is_static(),
        K::Alias(..) => true,
        K::Adt(def, args) => {
            args.types().any(|t| holds_mut_borrow(tcx, t, depth + 1))
                || (args.regions().next().is_some()
                    && def.all_fields().any(|f| {
                        holds_mut_borrow(tcx, f.ty(tcx, args).skip_normalization(), depth + 1)
                    }))
        }
        _ => false,
    }
}

/// The fields where a value of type `t` holds a `&mut` (`[0]` of `W<'a> { slot: &'a mut T }`, of
/// `(&mut T, u8)`): a struct of the program without a destructor, or a tuple, with no type
/// parameter in it; one field deep.
pub(crate) fn holder_paths<'tcx>(tcx: TyCtxt<'tcx>, t: rustc_middle::ty::Ty<'tcx>) -> Vec<usize> {
    use rustc_middle::ty::TyKind as K;
    use rustc_middle::ty::TypeVisitableExt;
    let is_mut = |f: rustc_middle::ty::Ty<'tcx>| {
        matches!(f.kind(), K::Ref(_, _, rustc_middle::ty::Mutability::Mut))
    };
    if t.has_param() {
        return Vec::new();
    }
    match t.kind() {
        K::Adt(def, args) if def.is_struct() && def.did().is_local() && !def.has_dtor(tcx) => def
            .all_fields()
            .enumerate()
            .filter(|(_, f)| is_mut(f.ty(tcx, args).skip_normalization()))
            .map(|(i, _)| i)
            .collect(),
        K::Tuple(ts) => ts
            .iter()
            .enumerate()
            .filter(|(_, f)| is_mut(*f))
            .map(|(i, _)| i)
            .collect(),
        _ => Vec::new(),
    }
}

/// The fields where a parameter of type `t` holds a `&mut` (`holder_paths`): of its value, or
/// of the value behind it for a `&mut` (`fn write_hm(h: &mut H)`).
pub(crate) fn holder_of<'tcx>(tcx: TyCtxt<'tcx>, t: rustc_middle::ty::Ty<'tcx>) -> Vec<usize> {
    match t.kind() {
        rustc_middle::ty::TyKind::Ref(_, i, rustc_middle::ty::Mutability::Mut) => {
            holder_paths(tcx, *i)
        }
        _ => holder_paths(tcx, t),
    }
}

/// The path (`[f]`) at which a call's argument `k` holds the borrow at field `f`, when the callee
/// is a function of the program, not generic nor a trait's, whose parameter `k` holds a `&mut`
/// there (`holder_of`): its summary says what it writes through it (`ParamWrite::path`).
fn holder_param(
    tcx: TyCtxt<'_>,
    body: &Body,
    func: &Operand,
    k: usize,
    f: usize,
) -> Option<Vec<usize>> {
    let Some(TyKind::RigidTy(RigidTy::FnDef(def, _))) =
        func.ty(body.locals()).ok().map(|t| t.kind())
    else {
        return None;
    };
    let did = rustc_internal::internal(tcx, def.def_id());
    if !did.is_local()
        || tcx.trait_of_assoc(did).is_some()
        || tcx.trait_impl_of_assoc(did).is_some()
        || tcx.generics_of(did).requires_monomorphization(tcx)
    {
        return None;
    }
    let input = *tcx
        .fn_sig(did)
        .instantiate_identity()
        .skip_binder()
        .inputs()
        .get(k)?;
    holder_of(tcx, input).contains(&f).then(|| vec![f])
}

/// The types the `&mut` borrows a value of type `t` holds point to (`&D` of a `Vec<&mut &D>`,
/// `T` of a `W<'a> { r: &'a mut T }`, a closure's capture's); none when what it holds is not
/// known (a type parameter, an opaque type, a trait object with a borrowed lifetime).
fn mut_pointees<'tcx>(
    tcx: TyCtxt<'tcx>,
    t: rustc_middle::ty::Ty<'tcx>,
) -> Option<Vec<rustc_middle::ty::Ty<'tcx>>> {
    fn walk<'tcx>(
        tcx: TyCtxt<'tcx>,
        t: rustc_middle::ty::Ty<'tcx>,
        depth: usize,
        out: &mut Vec<rustc_middle::ty::Ty<'tcx>>,
    ) -> bool {
        use rustc_middle::ty::TyKind as K;
        if depth > 6 {
            return false;
        }
        match t.kind() {
            K::Ref(_, i, rustc_middle::ty::Mutability::Mut)
            | K::RawPtr(i, rustc_middle::ty::Mutability::Mut) => {
                out.push(*i);
                walk(tcx, *i, depth + 1, out)
            }
            K::Ref(_, i, _) | K::RawPtr(i, _) | K::Array(i, _) | K::Slice(i) => {
                walk(tcx, *i, depth + 1, out)
            }
            K::Tuple(ts) => ts.iter().all(|t| walk(tcx, t, depth + 1, out)),
            K::Closure(_, args) => walk(tcx, args.as_closure().tupled_upvars_ty(), depth + 1, out),
            K::Coroutine(_, args) => {
                walk(tcx, args.as_coroutine().tupled_upvars_ty(), depth + 1, out)
            }
            K::CoroutineClosure(_, args) => walk(
                tcx,
                args.as_coroutine_closure().tupled_upvars_ty(),
                depth + 1,
                out,
            ),
            K::Param(_) | K::Alias(..) => false,
            K::Dynamic(_, r) => r.is_static(),
            K::Adt(def, args) => {
                args.types().all(|x| walk(tcx, x, depth + 1, out))
                    && (args.regions().next().is_none()
                        || def.all_fields().all(|f| {
                            walk(tcx, f.ty(tcx, args).skip_normalization(), depth + 1, out)
                        }))
            }
            _ => true,
        }
    }
    let mut out = Vec::new();
    walk(tcx, t, 0, &mut out).then_some(out)
}

/// Standard-library methods taking a shared borrow of a cell and returning a guard through
/// which the cell's value is written (`*c.borrow_mut() = v`, `*m.lock().unwrap() = v`).
const WRITE_GUARDS: &[&str] = &[
    "RefCell::<T>::borrow_mut",
    "RefCell::<T>::try_borrow_mut",
    "Mutex::<T>::lock",
    "Mutex::<T>::try_lock",
    "RwLock::<T>::write",
    "RwLock::<T>::try_write",
    "UnsafeCell::<T>::get",
    "Cell::<T>::as_ptr",
];

/// Does a value of type `t` hold a cell (`UnsafeCell`, inside `Cell`, `RefCell`, `Mutex`,
/// `RwLock`, `OnceLock`, an atomic; a field's, an element's), not behind a pointer: what a
/// shared borrow of it reaches may change.
pub(crate) fn holds_cell<'tcx>(
    tcx: TyCtxt<'tcx>,
    t: rustc_middle::ty::Ty<'tcx>,
    depth: usize,
) -> bool {
    use rustc_middle::ty::TyKind as K;
    if depth > 6 {
        return false;
    }
    match t.kind() {
        K::Adt(def, _) if def.is_unsafe_cell() => true,
        K::Adt(def, args) => def
            .all_fields()
            .any(|f| holds_cell(tcx, f.ty(tcx, args).skip_normalization(), depth + 1)),
        K::Array(inner, _) | K::Slice(inner) => holds_cell(tcx, *inner, depth + 1),
        K::Tuple(ts) => ts.iter().any(|t| holds_cell(tcx, t, depth + 1)),
        _ => false,
    }
}

/// Can a value of type `container` hold a value of type `t` (itself, a field, a variant's field,
/// an element; not behind a pointer)?
fn type_contains<'tcx>(
    tcx: TyCtxt<'tcx>,
    container: rustc_middle::ty::Ty<'tcx>,
    t: rustc_middle::ty::Ty<'tcx>,
    depth: usize,
) -> bool {
    use rustc_middle::ty::TyKind as K;
    if tcx.erase_and_anonymize_regions(container) == tcx.erase_and_anonymize_regions(t) {
        return true;
    }
    if depth > 4 {
        return false;
    }
    match container.kind() {
        K::Adt(def, args) => def
            .all_fields()
            .any(|f| type_contains(tcx, f.ty(tcx, args).skip_normalization(), t, depth + 1)),
        K::Tuple(ts) => ts.iter().any(|c| type_contains(tcx, c, t, depth + 1)),
        K::Array(e, _) | K::Slice(e) => type_contains(tcx, *e, t, depth + 1),
        // a type parameter, an opaque type: anything
        K::Param(_) | K::Alias(..) => true,
        _ => false,
    }
}

/// Does a value of type `t` hold a `&mut` to a value of type `pointee` (a field, an element, a
/// type argument)?
fn holds_mut_of<'tcx>(
    tcx: TyCtxt<'tcx>,
    t: rustc_middle::ty::Ty<'tcx>,
    pointee: rustc_middle::ty::Ty<'tcx>,
    depth: usize,
) -> bool {
    use rustc_middle::ty::TyKind as K;
    if depth > 4 {
        return false;
    }
    match t.kind() {
        K::Ref(_, inner, rustc_middle::ty::Mutability::Mut)
        | K::RawPtr(inner, rustc_middle::ty::Mutability::Mut) => {
            tcx.erase_and_anonymize_regions(*inner) == tcx.erase_and_anonymize_regions(pointee)
                || holds_mut_of(tcx, *inner, pointee, depth + 1)
        }
        K::Ref(_, inner, _) | K::Array(inner, _) | K::Slice(inner) => {
            holds_mut_of(tcx, *inner, pointee, depth + 1)
        }
        K::Tuple(ts) => ts.iter().any(|x| holds_mut_of(tcx, x, pointee, depth + 1)),
        K::Adt(def, args) => {
            args.types()
                .any(|x| holds_mut_of(tcx, x, pointee, depth + 1))
                || (args.regions().next().is_some()
                    && def.all_fields().any(|f| {
                        holds_mut_of(
                            tcx,
                            f.ty(tcx, args).skip_normalization(),
                            pointee,
                            depth + 1,
                        )
                    }))
        }
        _ => false,
    }
}

fn holds_borrow(body: &Body, dest: &Place) -> bool {
    fn borrows(t: &Ty, depth: usize) -> bool {
        if depth > 3 {
            return false;
        }
        match t.kind().rigid() {
            Some(RigidTy::Ref(..)) => true,
            Some(RigidTy::Tuple(ts)) => ts.iter().any(|t| borrows(t, depth + 1)),
            Some(RigidTy::Adt(_, args)) => args.0.iter().any(|a| match a {
                rustc_public::ty::GenericArgKind::Lifetime(_) => true,
                rustc_public::ty::GenericArgKind::Type(t) => borrows(t, depth + 1),
                _ => false,
            }),
            _ => false,
        }
    }
    dest.ty(body.locals()).is_ok_and(|t| borrows(&t, 0))
}

/// Reaching definitions at block entries (forward may-analysis with kills).
fn reaching(
    body: &Body,
    defs: &[Def],
    by_local: &HashMap<Local, Vec<usize>>,
    nargs: usize,
) -> Vec<BitSet> {
    let n = body.blocks.len();
    let mut in_sets = vec![BitSet::new(defs.len()); n];
    let mut block_defs: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (i, d) in defs.iter().enumerate() {
        if !matches!(d.kind, DefKind::Entry) {
            block_defs[d.at.bb].push(i);
        }
    }
    for v in &mut block_defs {
        v.sort_by_key(|&i| defs[i].at.idx);
    }
    if n > 0 {
        for (i, d) in defs.iter().enumerate().take(nargs) {
            debug_assert!(matches!(d.kind, DefKind::Entry));
            in_sets[0].insert(i);
        }
    }
    // Each block's effect, applying its definitions in order, is `out = (in - kill) | gen`:
    // `kill` holds every definition one of them kills; `gen` those of its own definitions that
    // no later one in the block kills (a definition killed only by an earlier one is defined
    // again after it).
    let mut kill: Vec<Vec<usize>> = vec![Vec::new(); n];
    let mut gen_: Vec<Vec<usize>> = vec![Vec::new(); n];
    for b in 0..n {
        let here = &block_defs[b];
        for (j, &i) in here.iter().enumerate() {
            let d = &defs[i];
            for &e in by_local.get(&d.local).into_iter().flatten() {
                if e != i && kills(d, &defs[e]) {
                    kill[b].push(e);
                }
            }
            let later_kill = here[j + 1..]
                .iter()
                .any(|&l| l != i && defs[l].local == d.local && kills(&defs[l], d));
            if !later_kill {
                gen_[b].push(i);
            }
        }
        kill[b].sort_unstable();
        kill[b].dedup();
    }
    let succs: Vec<Vec<usize>> = body
        .blocks
        .iter()
        .map(|b| b.terminator.successors())
        .collect();
    // forward problem: blocks in order (MIR numbers them roughly in execution order), first in
    // first out
    let mut work: std::collections::VecDeque<usize> = (0..n).collect();
    let mut queued = vec![true; n];
    while let Some(b) = work.pop_front() {
        queued[b] = false;
        let mut out = in_sets[b].clone();
        for &e in &kill[b] {
            out.remove(e);
        }
        for &g in &gen_[b] {
            out.insert(g);
        }
        for &s in &succs[b] {
            if in_sets[s].union_with(&out) && !queued[s] {
                queued[s] = true;
                work.push_back(s);
            }
        }
    }
    in_sets
}

#[derive(Clone)]
struct BitSet(Vec<u64>);

impl BitSet {
    fn new(n: usize) -> Self {
        BitSet(vec![0; n.div_ceil(64)])
    }
    fn insert(&mut self, i: usize) {
        self.0[i / 64] |= 1 << (i % 64);
    }
    fn remove(&mut self, i: usize) {
        self.0[i / 64] &= !(1 << (i % 64));
    }
    fn contains(&self, i: usize) -> bool {
        self.0[i / 64] & (1 << (i % 64)) != 0
    }
    /// Adds `other`; true if anything changed.
    fn union_with(&mut self, other: &BitSet) -> bool {
        let mut changed = false;
        for (a, b) in self.0.iter_mut().zip(&other.0) {
            let n = *a | *b;
            changed |= n != *a;
            *a = n;
        }
        changed
    }
}

/// The discriminant of an enum's variant, as the integer it is.
impl Origins<'_, '_> {
    /// The variant a field-less enum's `Default::default()` returns, read from the impl's MIR
    /// (a derived `#[default]`, or `fn default() -> Self { Self::Argon2id }`).
    fn default_variant(
        &self,
        def: rustc_public::DefId,
        gargs: &rustc_public::ty::GenericArgs,
    ) -> Option<Origin> {
        use rustc_middle::mir::{
            AggregateKind as A, RETURN_PLACE, Rvalue as R, StatementKind as S,
        };
        let tcx = self.tcx;
        let did = rustc_internal::internal(tcx, def);
        if path_of(tcx, did) != "core::default::Default::default" {
            return None;
        }
        let gargs = rustc_internal::internal(tcx, gargs);
        let self_ty = gargs.first()?.as_type()?;
        let rustc_middle::ty::Adt(adt, _) = self_ty.kind() else {
            return None;
        };
        if !adt.is_enum() || adt.variants().iter().any(|v| !v.fields.is_empty()) {
            return None;
        }
        let env = rustc_middle::ty::TypingEnv::fully_monomorphized();
        let inst = rustc_middle::ty::Instance::try_resolve(tcx, env, did, gargs).ok()??;
        let id = inst.def_id();
        if !tcx.is_mir_available(id) {
            return None;
        }
        let body = tcx.optimized_mir(id);
        let mut found = None;
        for bb in body.basic_blocks.iter() {
            for st in &bb.statements {
                if let S::Assign(b) = &st.kind
                    && b.0.local == RETURN_PLACE
                    && let R::Aggregate(k, ops) = &b.1
                    && let A::Adt(_, v, ..) = **k
                    && ops.is_empty()
                {
                    if found.is_some_and(|f| f != v) {
                        return None;
                    }
                    found = Some(v);
                }
            }
        }
        let v = found?;
        Some(Origin::Unit {
            path: path_of(tcx, adt.variant(v).def_id),
            krate: tcx.crate_name(adt.did().krate).to_string(),
            value: discriminant(tcx, *adt, v),
            span: None,
            runs: None,
        })
    }
}

fn discriminant<'tcx>(
    tcx: TyCtxt<'tcx>,
    adt: rustc_middle::ty::AdtDef<'tcx>,
    idx: rustc_abi::VariantIdx,
) -> Option<i128> {
    use rustc_middle::ty::layout::IntegerExt;
    let d = adt.discriminant_for_variant(tcx, idx);
    match d.ty.kind() {
        rustc_middle::ty::Int(ity) => Some(
            rustc_abi::Integer::from_int_ty(&tcx, *ity)
                .size()
                .sign_extend(d.val),
        ),
        _ => i128::try_from(d.val).ok(),
    }
}

/// The statics and named consts a promoted or inline constant's body refers to.
fn named_in<'tcx>(
    tcx: TyCtxt<'tcx>,
    body: &rustc_middle::mir::Body<'tcx>,
    args: Option<GenericArgsRef<'tcx>>,
) -> Vec<DefId> {
    use rustc_middle::mir::visit::Visitor;
    struct V<'tcx> {
        tcx: TyCtxt<'tcx>,
        args: Option<GenericArgsRef<'tcx>>,
        out: Vec<DefId>,
    }
    impl<'tcx> Visitor<'tcx> for V<'tcx> {
        fn visit_const_operand(
            &mut self,
            c: &rustc_middle::mir::ConstOperand<'tcx>,
            _: rustc_middle::mir::Location,
        ) {
            for d in crate::statics::named_by_const(self.tcx, c, self.args) {
                if !self.out.contains(&d) {
                    self.out.push(d);
                }
            }
        }
    }
    let mut v = V {
        tcx,
        args,
        out: Vec::new(),
    };
    v.visit_body(body);
    v.out
}

/// The ADT a method belongs to: `Self` of a trait method (`Argon2` in
/// `<Argon2 as Default>::default`), the self type of an inherent impl.
pub(crate) fn self_adt_path<'tcx>(
    tcx: TyCtxt<'tcx>,
    did: DefId,
    args: rustc_middle::ty::GenericArgsRef<'tcx>,
) -> Option<String> {
    let ty = if tcx.trait_of_assoc(did).is_some() {
        args.first()?.as_type()?
    } else {
        tcx.type_of(tcx.impl_of_assoc(did)?).skip_binder()
    };
    match ty.kind() {
        rustc_middle::ty::Adt(adt, _) => Some(path_of(tcx, adt.did())),
        _ => None,
    }
}

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

/// Sets the crates whose generic items' instances are summarised (`SUMMARISED`).
pub(crate) fn set_summarised(crates: HashSet<rustc_span::def_id::CrateNum>) {
    SUMMARISED.with(|s| *s.borrow_mut() = crates);
}

/// The instances `body_name` named since the last call.
pub(crate) fn take_instances() -> Vec<(String, rustc_public::mir::mono::Instance)> {
    INSTANCES.with(|v| std::mem::take(&mut *v.borrow_mut()))
}

/// The name of the body a call runs as the links name it: an item's defining path
/// (`<app::Fast as app::Pick>::alg`), or, for an item of the program with generic parameters (a
/// generic function, a trait's default body, a generic impl's method, a closure inside one), of
/// this crate or another of the program's (`SUMMARISED`), the instance's
/// (`app::pick::<app::Fast>`, `<app::Legacy as app::Pick>::alg`), whose summaries the driver
/// records; `None` for a standard-library or stop crate's generic item, and for an instance
/// still generic.
pub(crate) fn body_name<'tcx>(
    tcx: TyCtxt<'tcx>,
    inst: rustc_middle::ty::Instance<'tcx>,
) -> Option<String> {
    use rustc_middle::ty::TypeVisitableExt;
    use rustc_middle::ty::print::{
        with_crate_prefix, with_no_trimmed_paths, with_no_visible_paths,
    };
    if !matches!(inst.def, rustc_middle::ty::InstanceKind::Item(_)) {
        return None;
    }
    let def = inst.def_id();
    if !tcx.generics_of(def).requires_monomorphization(tcx) {
        return Some(path_of(tcx, def));
    }
    let summarised = SUMMARISED.with(|s| s.borrow().contains(&def.krate));
    if !(def.is_local() || summarised) || inst.args.has_non_region_param() {
        return None;
    }
    // a closure: only inside a generic function, whose instance it depends on (one of a
    // monomorphic function is its item, as the per-item links have it)
    if tcx.is_closure_like(def)
        && !tcx
            .generics_of(tcx.typeck_root_def_id(def))
            .requires_monomorphization(tcx)
    {
        return Some(path_of(tcx, def));
    }
    let args = tcx.erase_and_anonymize_regions(inst.args);
    let p = with_crate_prefix!(with_no_visible_paths!(with_no_trimmed_paths!(
        tcx.def_path_str_with_args(def, args)
    )));
    let name = crate::local_crate_name(tcx, p);
    let inst = rustc_middle::ty::Instance::new_raw(def, args);
    INSTANCES.with(|v| {
        let mut v = v.borrow_mut();
        if !v.iter().any(|(n, _)| *n == name) {
            v.push((name.clone(), rustc_internal::stable(inst)));
        }
    });
    Some(name)
}

/// The body a call of `did` with `args` runs, when it is another than `did`'s item as the
/// links name it (`Origin::Call::runs`): a trait method's implementation for a known `Self` or
/// the default body, an instance of a generic function of this crate.
pub(crate) fn runs_of<'tcx>(
    tcx: TyCtxt<'tcx>,
    did: DefId,
    args: rustc_middle::ty::GenericArgsRef<'tcx>,
) -> Option<String> {
    use rustc_middle::ty::TypeVisitableExt;
    if args.has_non_region_param() || dyn_self(tcx, did, args).is_some() {
        return None;
    }
    if tcx.trait_of_assoc(did).is_none() && !tcx.generics_of(did).requires_monomorphization(tcx) {
        return None;
    }
    let env = rustc_middle::ty::TypingEnv::fully_monomorphized();
    let inst = rustc_middle::ty::Instance::try_resolve(tcx, env, did, args).ok()??;
    body_name(tcx, inst).filter(|n| *n != path_of(tcx, did))
}

/// The body a function item of `did` with `args` runs when it is named as a value or made a
/// pointer (`map(Pick::alg)`, `let f = pick::<Fast>`): as `runs_of`, and also a generic
/// function's instance when it is not a method.
fn item_runs<'tcx>(
    tcx: TyCtxt<'tcx>,
    did: DefId,
    args: rustc_middle::ty::GenericArgsRef<'tcx>,
) -> Option<String> {
    runs_of(tcx, did, args).or_else(|| {
        let env = rustc_middle::ty::TypingEnv::fully_monomorphized();
        rustc_middle::ty::Instance::try_resolve(tcx, env, did, args)
            .ok()
            .flatten()
            .and_then(|i| body_name(tcx, i))
            .filter(|n| *n != path_of(tcx, did))
    })
}

/// The function a call of `did` with `args` writes through, as `Links::writes` names it: a
/// trait method's call with a known `Self` type is its implementation's (`<Ctx as Up>::up`, or
/// the trait's default body for it), a generic function's of this crate its instance's
/// (`body_name`); one on a trait object or a type parameter stays the trait method's, with
/// `dyn <trait>` or `impl <trait>` (see `Origin::Written`), unless the place written is of a
/// known type (`let u: &mut dyn Up = &mut b; u.up()` writes `b`, a `B`: `<B as Up>::up`).
pub(crate) fn write_callee<'tcx>(
    tcx: TyCtxt<'tcx>,
    did: DefId,
    args: rustc_middle::ty::GenericArgsRef<'tcx>,
    place: Option<rustc_middle::ty::Ty<'tcx>>,
) -> (String, Option<String>) {
    use rustc_middle::ty::TypeVisitableExt;
    let env = rustc_middle::ty::TypingEnv::fully_monomorphized();
    let resolved = |args: rustc_middle::ty::GenericArgsRef<'tcx>| {
        if args.has_non_region_param() {
            return None;
        }
        let i = rustc_middle::ty::Instance::try_resolve(tcx, env, did, args).ok()??;
        body_name(tcx, i)
    };
    let Some(tr) = tcx.trait_of_assoc(did) else {
        return (resolved(args).unwrap_or_else(|| path_of(tcx, did)), None);
    };
    if let Some(d) = dyn_self(tcx, did, args) {
        // the object is a place of a known type: its implementation
        if let Some(t) = place
            && matches!(t.kind(), rustc_middle::ty::Adt(..))
            && !t.has_non_region_param()
        {
            let args = tcx.mk_args_from_iter(
                std::iter::once(rustc_middle::ty::GenericArg::from(t)).chain(args.iter().skip(1)),
            );
            if let Some(n) = resolved(args) {
                return (n, None);
            }
        }
        return (path_of(tcx, did), Some(d));
    }
    if let Some(n) = resolved(args) {
        return (n, None);
    }
    (
        path_of(tcx, did),
        Some(format!("impl {}", path_of(tcx, tr))),
    )
}

/// For a trait method called on a trait object (`s.alg()` with `s: &dyn Source`), `dyn` and
/// the object's trait (`dyn app::Source`): the call runs the implementation of a type coerced to
/// it (`Links::coercions`).
fn dyn_self<'tcx>(
    tcx: TyCtxt<'tcx>,
    did: DefId,
    args: rustc_middle::ty::GenericArgsRef<'tcx>,
) -> Option<String> {
    tcx.trait_of_assoc(did)?;
    match args.first()?.as_type()?.kind() {
        rustc_middle::ty::Dynamic(preds, ..) => {
            Some(format!("dyn {}", path_of(tcx, preds.principal_def_id()?)))
        }
        _ => None,
    }
}

/// Byte length of `n` elements of type `elem`, when the elements are bytes.
fn byte_len(elem: &Ty, n: Option<u64>) -> Option<u64> {
    matches!(
        elem.kind().rigid(),
        Some(RigidTy::Uint(UintTy::U8) | RigidTy::Int(IntTy::I8))
    )
    .then_some(n)
    .flatten()
}

/// Literal data in an allocated constant: its length in bytes (an array in place, or the
/// array, slice or `&str` a reference points to: `b"salt"`, `""`) and whether all its bytes are
/// zero (`&[0u8; 32]`). Not an integer (its value says that).
fn literal_data(a: &rustc_public::ty::Allocation, ty: &Ty) -> (Option<u64>, bool) {
    let zero = |bytes: &[Option<u8>]| !bytes.is_empty() && bytes.iter().all(|b| *b == Some(0));
    let pointee = || {
        a.provenance
            .ptrs
            .first()
            .and_then(|(_, p)| match GlobalAlloc::from(p.0) {
                GlobalAlloc::Memory(m) => Some(m),
                _ => None,
            })
    };
    match ty.kind().rigid() {
        Some(RigidTy::Array(..)) => (bytes_of_ty(ty), zero(&a.bytes)),
        Some(RigidTy::Ref(_, t, _)) => match t.kind().rigid() {
            Some(RigidTy::Array(..)) => {
                (bytes_of_ty(ty), pointee().is_some_and(|m| zero(&m.bytes)))
            }
            // a fat pointer: the data's address, then its length in elements
            Some(RigidTy::Str) | Some(RigidTy::Slice(_)) if a.bytes.len() == 16 => {
                let len = a.bytes[8..16]
                    .iter()
                    .rev()
                    .try_fold(0u64, |acc, b| b.map(|b| (acc << 8) | b as u64));
                let bytes_per = match t.kind().rigid() {
                    Some(RigidTy::Slice(e)) => byte_len(e, Some(1)),
                    _ => Some(1),
                };
                let len = len.zip(bytes_per).map(|(n, k)| n * k);
                let data_zero = len.is_some_and(|n| n > 0)
                    && pointee().is_some_and(|m| {
                        let n = len.unwrap_or(0) as usize;
                        m.bytes.len() >= n && zero(&m.bytes[..n])
                    });
                (len, data_zero)
            }
            _ => (None, false),
        },
        // an integer: its bytes (`vec![0u8; 32]`'s element)
        Some(RigidTy::Int(_) | RigidTy::Uint(_)) => (bytes_of_ty(ty), zero(&a.bytes)),
        _ => (bytes_of_ty(ty), false),
    }
}

/// The field indices of a path made of fields only (`.alg`, `.0.key`).
/// The fields leading to an element written (`.algorithms` of `v.algorithms[0]`: fields, then
/// a dereference or an element step, with an element step among the rest).
fn fields_to_element(steps: &[Step]) -> Option<Vec<usize>> {
    let n = steps
        .iter()
        .take_while(|s| matches!(s, Step::Field(_)))
        .count();
    let (fields, rest) = steps.split_at(n);
    (n > 0
        && rest
            .iter()
            .any(|s| matches!(s, Step::Elem | Step::Index(_))))
    .then(|| field_steps(fields))
    .flatten()
}

fn field_steps(steps: &[Step]) -> Option<Vec<usize>> {
    steps
        .iter()
        .map(|s| match s {
            Step::Field(f) => Some(*f),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()
        .filter(|v| !v.is_empty())
}

/// `[u8; N]`, `&[u8; N]`, `&mut [u8; N]`: N bytes.
fn bytes_of_ty(ty: &Ty) -> Option<u64> {
    match ty.kind().rigid()? {
        RigidTy::Array(t, n) => byte_len(t, n.eval_target_usize().ok()),
        RigidTy::Ref(_, t, _) | RigidTy::RawPtr(t, _) => match t.kind().rigid()? {
            RigidTy::Array(e, n) => byte_len(e, n.eval_target_usize().ok()),
            _ => None,
        },
        _ => None,
    }
}

/// `[T; N]`, `&[T; N]`, `&mut [T; N]`: N.
fn array_len_of_ty(ty: &Ty) -> Option<u64> {
    match ty.kind().rigid()? {
        RigidTy::Array(_, n) => n.eval_target_usize().ok(),
        RigidTy::Ref(_, t, _) | RigidTy::RawPtr(t, _) => match t.kind().rigid()? {
            RigidTy::Array(_, n) => n.eval_target_usize().ok(),
            _ => None,
        },
        _ => None,
    }
}
