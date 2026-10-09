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

use rcbom_facts::{Loc, Origin};
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
/// Alternatives, call arguments and aggregate parts kept per node.
const MAX_WIDTH: usize = 8;
/// Nodes per origin tree.
const MAX_NODES: usize = 400;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Step {
    Deref,
    Field(usize),
    Variant(usize),
    /// Some element or elements of an array or slice (`a[i]`, `a[2..]`, slice patterns): a
    /// part of it, not the whole.
    Elem,
}

type Path = Vec<Step>;

fn variant_index(v: &rustc_public::ty::VariantIdx) -> usize {
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
            // `a[i]`, `a[2..]`, slice patterns: some part of the array, whichever it is
            _ => {
                out.push(Step::Elem);
                break;
            }
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
    },
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
    /// Origins of the captures, when known (a closure followed from the place it is built).
    captures: Option<Vec<Origin>>,
    /// Captures looked up in the parent body, computed once.
    parent_captures: RefCell<Option<Option<Vec<Origin>>>>,
    nodes: Cell<usize>,
    /// For an instance body (a generic function's instance, a closure in the walk): the item
    /// it was instantiated from and the instance's generic arguments. The instance body has its
    /// named constants evaluated away (`&ECDSA_P256_SHA256_ASN1` is a bare pointer there); the
    /// item's MIR, at the same span, still names them.
    item: Option<(DefId, GenericArgsRef<'tcx>)>,
    /// The item MIR's unevaluated constants by span (`None`: several share the span).
    item_consts: OnceCell<HashMap<rustc_span::Span, Option<Uneval<'tcx>>>>,
}

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
            captures: None,
            parent_captures: RefCell::new(None),
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
        self.flow.get_or_init(|| Flow::new(self.body))
    }
}

impl Flow {
    fn new(body: &Body) -> Self {
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
        let ptr = Pointees {
            body,
            direct: &direct,
        };
        let mut extra = Vec::new();
        for (place, at, kind) in &pending {
            let path = path_of_place(place);
            if let Some(i) = path.iter().position(|s| *s == Step::Deref) {
                // `*r = x`, `(*r).f = x`: defines what `r` points to (weakly), and the place
                // through `r` for reads that go through it
                // with a single possible target the write certainly lands there (a strong
                // update); otherwise it may (weak)
                let targets = ptr.targets(place.local, &path[..i], 0);
                let single = sole_target(&targets);
                for (t, tp) in targets {
                    let mut p = tp;
                    p.extend_from_slice(&path[i + 1..]);
                    extra.push((t, p, *at, clone_kind(kind), single));
                }
            }
            if let DefKind::Call { func, args } = kind {
                // out-parameters, unless the call only hands out a borrow into its argument
                // (`index_mut`, `as_mut`, `deref_mut`): the caller writes through the result
                if !returns_mut_ref(body, place) {
                    for a in args {
                        if let Operand::Copy(p) | Operand::Move(p) = a
                            && is_mut_ptr(body, p)
                        {
                            let targets = ptr.targets(p.local, &path_of_place(p), 0);
                            let single = sole_target(&targets);
                            for (t, tp) in targets {
                                extra.push((
                                    t,
                                    tp,
                                    *at,
                                    DefKind::OutParam {
                                        func: func.clone(),
                                        args: args.clone(),
                                    },
                                    single,
                                ));
                            }
                        }
                    }
                }
            }
        }
        // a write to an element (`key[31] = 1`, through `&mut key[3]`, or a fill of
        // `&mut key[..16]`) changes part of the array: it neither overwrites the whole nor
        // replaces its initialization
        let partial = |path: &[Step]| path.contains(&Step::Elem);
        for (place, at, kind) in pending {
            let path = path_of_place(&place);
            let strong = !path.contains(&Step::Deref) && !partial(&path);
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
        for (local, path, at, kind, single) in extra {
            let out_param = matches!(kind, DefKind::OutParam { .. });
            let init = is_init(body, &kind) && !partial(&path);
            // through a reference: certain only with a single target; an out-parameter call
            // may or may not write, so it never overwrites
            let strong = single && !out_param && !partial(&path);
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
        let outer = Origins::new(self.tcx, &body, Some(parent));
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

    /// Length of the array behind an argument (`&mut [0u8; 32]` passed as `&mut [u8]`), found
    /// in the types along the def chain.
    pub(crate) fn array_len(&self, op: &Operand) -> Option<u64> {
        self.len_of_operand(op, 0)
    }

    fn len_of_operand(&self, op: &Operand, depth: usize) -> Option<u64> {
        if depth > MAX_DEPTH {
            return None;
        }
        let ty = op.ty(self.body.locals()).ok()?;
        if let Some(n) = array_len_of_ty(&ty) {
            return Some(n);
        }
        match op {
            Operand::Copy(p) | Operand::Move(p) if p.projection.is_empty() => {
                self.len_of_local(p.local, depth + 1)
            }
            _ => None,
        }
    }

    fn len_of_local(&self, l: Local, depth: usize) -> Option<u64> {
        if depth > MAX_DEPTH {
            return None;
        }
        if let Some(n) = array_len_of_ty(&self.body.locals()[l].ty) {
            return Some(n);
        }
        self.flow().by_local.get(&l)?.iter().find_map(|&i| {
            let d = &self.flow().defs[i];
            if !d.path.is_empty() {
                return None;
            }
            match &d.kind {
                DefKind::Assign(Rvalue::Use(op, _), _)
                | DefKind::Assign(Rvalue::Cast(_, op, _), _) => self.len_of_operand(op, depth + 1),
                DefKind::Assign(Rvalue::Ref(_, _, p), _)
                | DefKind::Assign(Rvalue::AddressOf(_, p), _)
                | DefKind::Assign(Rvalue::Reborrow(_, _, p), _)
                | DefKind::Assign(Rvalue::CopyForDeref(p), _) => {
                    self.len_of_local(p.local, depth + 1)
                }
                _ => None,
            }
        })
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
        let key = (local, path.clone(), at);
        if !seen.insert(key.clone()) {
            return Origin::Unknown; // a loop: the other definitions say where it starts
        }
        let defs = self.reaching_at(local, at);
        // definitions of the place, or of a whole it is part of: it is one of these
        let mut alts: Vec<Origin> = Vec::new();
        // writes to a part of it (`key[31] = 1`, `cfg.key = ..`): it is also made of these
        let mut parts: Vec<Origin> = Vec::new();
        for &i in &defs {
            let d = &self.flow().defs[i];
            let (list, rest) = if is_prefix(&d.path, &path) {
                if self.shadowed(i, &defs, &path, at) {
                    continue;
                }
                (&mut alts, path[d.path.len()..].to_vec())
            } else if is_prefix(&path, &d.path) {
                (&mut parts, Vec::new())
            } else {
                continue;
            };
            let o = self.def_origin(d, &rest, depth, seen);
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

    /// Is definition `i`, of a whole that contains `path`, overwritten for `path` before the
    /// read at `at`: does a definition of a more specific place covering `path` (`c.key =
    /// [8; 32]` after `c = Cfg { key: env_key(), .. }`) lie on every way from `i` to `at`?
    fn shadowed(&self, i: usize, defs: &[usize], path: &[Step], at: At) -> bool {
        let d = &self.flow().defs[i];
        defs.iter().any(|&j| {
            let e = &self.flow().defs[j];
            j != i
                && e.strong
                && e.path.len() > d.path.len()
                && is_prefix(&d.path, &e.path)
                && is_prefix(&e.path, path)
                && self.always_through(d, e.at, at)
        })
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
            DefKind::Call { func, args } | DefKind::OutParam { func, args } => {
                self.call(func, args, d.at, depth, seen)
            }
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
        let (callee, krate, self_ty) = match func.ty(self.body.locals()).ok().map(|t| t.kind()) {
            Some(TyKind::RigidTy(RigidTy::FnDef(def, gargs))) => {
                let did = rustc_internal::internal(self.tcx, def.def_id());
                let gargs = rustc_internal::internal(self.tcx, gargs);
                (
                    path_of(self.tcx, did),
                    self.tcx.crate_name(did.krate).to_string(),
                    self_adt_path(self.tcx, did, gargs),
                )
            }
            // a pointer to a function reified here (`let h: fn(..) = digest; h(..)`)
            _ => match self.callee_through_pointer(func) {
                Some((def, gargs, _)) => {
                    let did = rustc_internal::internal(self.tcx, def.def_id());
                    let gargs = rustc_internal::internal(self.tcx, gargs);
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
        // the position the scanner gives this call's site
        let span = self
            .callee_span_at(func, at)
            .or_else(|| self.callee_through_pointer(func).map(|(_, _, s)| s))
            .map(|s| crate::locate_stable(self.tcx, s).0)
            .filter(|l| l.line > 0);
        Origin::Call {
            callee,
            krate,
            self_ty,
            args: out,
            span,
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
            Rvalue::Use(op, _) | Rvalue::Cast(_, op, _) => self.operand(op, at, depth, seen),
            // a reference stands for what it points to; reading through it continues there
            Rvalue::Ref(_, _, q) | Rvalue::AddressOf(_, q) | Rvalue::Reborrow(_, _, q) => {
                let mut p = path_of_place(q);
                p.extend_from_slice(rest.strip_prefix(&[Step::Deref]).unwrap_or(&[]));
                self.place(q.local, p, at, depth, seen)
            }
            // `[0u8; 12]`
            Rvalue::Repeat(op, n) => match op {
                Operand::Constant(c) => Origin::Const {
                    value: None,
                    len: byte_len(&c.const_.ty(), n.eval_target_usize().ok()),
                    span: Some(self.loc(span)),
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
                _ => self.operand(op, at, depth, seen),
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
                }
            }
            AggregateKind::Tuple if ops.is_empty() => Origin::Unknown,
            _ if !ops.is_empty() && ops.iter().all(|o| matches!(o, Operand::Constant(_))) => {
                let len = match kind {
                    AggregateKind::Array(t) => byte_len(t, Some(ops.len() as u64)),
                    _ => None,
                };
                Origin::Const {
                    value: None,
                    len,
                    span: Some(self.loc(span)),
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
                    _ if matches!(rest.first(), Some(Step::Elem)) => Origin::Any(parts),
                    // the value itself: made of all of them (`[user, b"pepper"].concat()`)
                    _ => Origin::All(parts),
                }
            }
        }
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
        let mut inner = Origins::new(self.tcx, &body, Some(did));
        inner.followed = true;
        inner.captures = captures;
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
        let ret = match alts.len() {
            0 => Origin::Unknown,
            1 => alts.pop().unwrap(),
            _ => Origin::Any(alts),
        };
        Origin::Call {
            callee: "<closure>".into(),
            krate: String::new(),
            self_ty: None,
            args: vec![ret],
            span: None,
        }
    }

    /// An argument read before any assignment: a parameter, or a capture of a closure or
    /// coroutine.
    fn entry_origin(&self, local: Local, rest: &[Step], depth: usize) -> Origin {
        match self.kind {
            BodyKind::Fn if self.followed => Origin::Unknown,
            BodyKind::Fn => Origin::Param { index: local - 1 },
            BodyKind::Closure | BodyKind::Coroutine if local == 1 => {
                // captures: `(*_1).k` (by reference), `_1.k` (by value), `(*_1.0).k` (pinned)
                let k = match (self.kind, rest) {
                    (BodyKind::Coroutine, [Step::Field(0), Step::Deref, Step::Field(k), ..]) => {
                        Some(*k)
                    }
                    (BodyKind::Closure, [Step::Deref, Step::Field(k), ..])
                    | (BodyKind::Closure, [Step::Field(k), ..]) => Some(*k),
                    _ => None,
                };
                match k.and_then(|k| self.capture(k, depth)) {
                    Some(o) => o,
                    None => Origin::Unknown,
                }
            }
            // a coroutine's other argument is its resume value
            BodyKind::Coroutine => Origin::Unknown,
            BodyKind::Closure if self.followed => Origin::Unknown,
            BodyKind::Closure => Origin::Param { index: local - 2 },
        }
    }

    fn capture(&self, k: usize, depth: usize) -> Option<Origin> {
        if let Some(c) = &self.captures {
            return c.get(k).cloned();
        }
        if self.followed {
            return None;
        }
        if self.parent_captures.borrow().is_none() {
            let found = self.captures_from_parent(depth);
            *self.parent_captures.borrow_mut() = Some(found);
        }
        self.parent_captures
            .borrow()
            .as_ref()
            .unwrap()
            .as_ref()
            .and_then(|c| c.get(k).cloned())
    }

    /// The operands of the aggregate that builds this closure (or coroutine) in its parent's
    /// body, as origins there: a captured key is what the parent put in.
    fn captures_from_parent(&self, depth: usize) -> Option<Vec<Origin>> {
        let did = self.def?;
        if depth >= MAX_DEPTH {
            return None;
        }
        let parent = self.tcx.parent(did);
        let body = rustc_public::CrateItem(rustc_internal::stable(parent)).body()?;
        let outer = Origins::new(self.tcx, &body, Some(parent));
        let mut caps: Option<Vec<Vec<Origin>>> = None;
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
                let c = caps.get_or_insert_with(|| vec![Vec::new(); ops.len()]);
                for (k, o) in ops.iter().enumerate() {
                    let x = outer.operand(o, at, depth + 1, &mut HashSet::new());
                    if let Some(v) = c.get_mut(k)
                        && !v.contains(&x)
                    {
                        v.push(x);
                    }
                }
            }
        }
        caps.map(|c| {
            c.into_iter()
                .map(|mut v| match v.len() {
                    0 => Origin::Unknown,
                    1 => v.pop().unwrap(),
                    _ => Origin::Any(v),
                })
                .collect()
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
            Some(RigidTy::FnDef(def, _)) => {
                let did = rustc_internal::internal(self.tcx, def.def_id());
                return Origin::Unit {
                    path: path_of(self.tcx, did),
                    krate: self.tcx.crate_name(did.krate).to_string(),
                    value: None,
                };
            }
            Some(RigidTy::Tuple(ts)) if ts.is_empty() => return Origin::Unknown,
            _ => {}
        }
        if let Some(unit) = self.unit_value(&ty) {
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
                // `&STATIC`: a pointer to a static allocation
                let mut statics = Vec::new();
                for (_, prov) in &a.provenance.ptrs {
                    if let GlobalAlloc::Static(s) = GlobalAlloc::from(prov.0) {
                        let did = rustc_internal::internal(self.tcx, s.def_id());
                        let o = Origin::Data {
                            def: def_ref_internal(self.tcx, did),
                            value: None,
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
                Origin::Const {
                    value,
                    len: bytes_of_ty(&ty),
                    span,
                }
            }
            // `&CONST`, `&[42u8; 32]`, `const { &SHA256 }`: what the promoted or inline
            // constant names, else literal data of this function
            ConstantKind::Unevaluated(u) => self
                .unevaluated(
                    (
                        rustc_internal::internal(self.tcx, u.def.def_id()),
                        rustc_internal::internal(self.tcx, &u.args),
                        u.promoted.map(rustc_middle::mir::Promoted::from_u32),
                    ),
                    &ty,
                    None,
                    int_ty,
                )
                .unwrap_or(Origin::Const {
                    value: None,
                    len: bytes_of_ty(&ty),
                    span,
                }),
            _ => Origin::Const {
                value: None,
                len: bytes_of_ty(&ty),
                span,
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
            None => vec![crate::statics::resolve_const(
                tcx,
                did,
                uargs,
                self.inst_args(),
            )],
        };
        let evaluate = || {
            if args.has_non_region_param() {
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
        };
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
            })
            .collect();
        data.dedup();
        match data.len() {
            0 => None,
            1 => data.pop(),
            _ => Some(Origin::Any(data)),
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
        DefKind::OutParam { func, args } => DefKind::OutParam {
            func: func.clone(),
            args: args.clone(),
        },
    }
}

fn is_prefix(a: &[Step], b: &[Step]) -> bool {
    b.len() >= a.len() && b[..a.len()] == *a
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

/// What a pointer-typed place may point to, from the definitions that took the address.
struct Pointees<'a> {
    body: &'a Body,
    direct: &'a HashMap<Local, Vec<&'a DefKind>>,
}

impl Pointees<'_> {
    /// Places that `local.path` (a reference or raw pointer) points to.
    fn targets(&self, local: Local, path: &[Step], depth: usize) -> Vec<(Local, Path)> {
        if depth > 6 || !path.is_empty() {
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
                    if let Some(i) = qp.iter().position(|s| *s == Step::Deref) {
                        for (t, mut tp) in self.targets(q.local, &qp[..i], depth + 1) {
                            tp.extend_from_slice(&qp[i + 1..]);
                            out.push((t, tp));
                        }
                    }
                    out.push((q.local, qp));
                }
                DefKind::Assign(Rvalue::Use(Operand::Copy(q) | Operand::Move(q), _), _)
                | DefKind::Assign(Rvalue::Cast(_, Operand::Copy(q) | Operand::Move(q), _), _) => {
                    out.extend(self.targets(q.local, &path_of_place(q), depth + 1))
                }
                // `index_mut(&mut buf, ..)`, `as_mut()`: a borrow into the argument
                DefKind::Call { args, .. } => {
                    for a in args {
                        if let Operand::Copy(q) | Operand::Move(q) = a
                            && is_mut_ptr(self.body, q)
                        {
                            out.extend(self.targets(q.local, &path_of_place(q), depth + 1));
                        }
                    }
                }
                _ => {}
            }
        }
        out
    }
}

/// Does a pointer with these targets point at one place? The targets also list the references
/// a reborrow went through (`_7` behind `_6 = &mut (*_7)`, with a `Deref` path), which stand for
/// the place they point at, not for another place.
fn sole_target(targets: &[(Local, Path)]) -> bool {
    targets
        .iter()
        .filter(|(_, p)| !p.contains(&Step::Deref))
        .count()
        == 1
}

fn is_mut_ptr(body: &Body, p: &Place) -> bool {
    matches!(
        p.ty(body.locals())
            .ok()
            .and_then(|t| t.kind().rigid().cloned()),
        Some(RigidTy::Ref(_, _, Mutability::Mut) | RigidTy::RawPtr(_, Mutability::Mut))
    )
}

fn returns_mut_ref(body: &Body, dest: &Place) -> bool {
    is_mut_ptr(body, dest)
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

/// Byte length of `n` elements of type `elem`, when the elements are bytes.
fn byte_len(elem: &Ty, n: Option<u64>) -> Option<u64> {
    matches!(
        elem.kind().rigid(),
        Some(RigidTy::Uint(UintTy::U8) | RigidTy::Int(IntTy::I8))
    )
    .then_some(n)
    .flatten()
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
