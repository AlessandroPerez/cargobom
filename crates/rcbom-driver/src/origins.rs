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
            } => {
                out.push(Step::Index(*offset as usize));
                break;
            }
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
        /// The argument that points at the place (`None`: a value holding a pointer to it).
        index: Option<usize>,
    },
    /// The place was mutably borrowed by this call, which returned a value holding the borrow
    /// (`key.chunks_mut(16)`, `split_at_mut`): later writes go through that value.
    Through {
        func: Operand,
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
            Flow::new(self.body, self.kind == BodyKind::Coroutine, &|f| {
                self.local_fn(f)
            })
        })
    }
}

impl Flow {
    /// `local_fn`: is a callee a function of the crate (whose writes through `&mut` its links
    /// summarize, the value before included where it may not write)?
    fn new(body: &Body, coroutine: bool, local_fn: &dyn Fn(&Operand) -> bool) -> Self {
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
        // (place, path, at, kind, single target, written by the call as its receiver)
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
                        let single = sole_target(&targets);
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
            let through = !returns_mut_ref(body, place)
                && holds_borrow(body, place)
                && !callee_name(body, func).is_some_and(|c| std_store(&c));
            // a call that writes the whole buffer it is given (`rng.fill_bytes(nonce)`,
            // `read_exact(buf)`): what was there before is gone
            let whole = fills_whole(body, func);
            for (k, a) in args.iter().enumerate() {
                // a closure or a struct handed over (by value or `&mut`) that holds a `&mut` to
                // a place (`|| rng.fill_bytes(&mut k1)` called, `fill_out(Out { buf: &mut k2 })`):
                // the call may write that place through it
                if !through && let Operand::Copy(p) | Operand::Move(p) = a {
                    let holders: Vec<Local> = if is_mut_ptr(body, p) {
                        ptr.targets(p.local, &path_of_place(p), 0)
                            .into_iter()
                            .filter(|t| t.path.is_empty())
                            .map(|t| t.local)
                            .collect()
                    } else if p.projection.is_empty() {
                        vec![p.local]
                    } else {
                        Vec::new()
                    };
                    for h in holders {
                        for (targets, single) in ptr.held(h) {
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
                                    },
                                    single,
                                    false,
                                ));
                            }
                        }
                    }
                }
                if let Operand::Copy(p) | Operand::Move(p) = a
                    && is_mut_ptr(body, p)
                {
                    let targets = ptr.targets(p.local, &path_of_place(p), 0);
                    let single = sole_target(&targets);
                    for Target {
                        local: t, path: tp, ..
                    } in targets
                    {
                        if through {
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
                                },
                                single,
                                k == 0 || whole || local_fn(func),
                            ));
                        }
                    }
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
                        }
                        ty = field.ty(tcx, args).skip_norm_wip();
                        variant = None;
                    }
                    rustc_middle::ty::Tuple(ts) => match ts.get(*f) {
                        Some(t) => ty = *t,
                        None => break,
                    },
                    _ => break,
                },
                Step::Elem | Step::Index(_) => match ty.builtin_index() {
                    Some(t) => ty = t,
                    None => break,
                },
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
            // a write to a field of it (`h.alg = ..`, `set_slot(&mut c.alg)`): which field
            if part && let Some(fields) = field_steps(&d.path[path.len()..]) {
                let strong = d.strong && self.part_always_after(&defs, i, &path, at);
                o = Origin::Set {
                    path: fields,
                    value: Box::new(o),
                    strong,
                };
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
        let args = args
            .iter()
            .take(MAX_WIDTH)
            .map(|a| self.operand(a, d.at, depth + 1, seen))
            .collect();
        let gargs = match func.ty(self.body.locals()).ok().map(|t| t.kind()) {
            Some(TyKind::RigidTy(RigidTy::FnDef(_, g))) => rustc_internal::internal(self.tcx, g),
            _ => return None,
        };
        let (callee, self_ty) = write_callee(self.tcx, did, gargs);
        Some(Origin::Written {
            callee,
            index: *index,
            args,
            self_ty,
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
        let (callee, krate, self_ty) = match func.ty(self.body.locals()).ok().map(|t| t.kind()) {
            Some(TyKind::RigidTy(RigidTy::FnDef(def, gargs))) => {
                let did = rustc_internal::internal(self.tcx, def.def_id());
                let gargs = rustc_internal::internal(self.tcx, gargs);
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
                    span: None,
                }
            }
            AggregateKind::Tuple if ops.is_empty() => Origin::Unknown,
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
            _ if !ops.is_empty() && ops.iter().all(|o| matches!(o, Operand::Constant(_))) => {
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
            Some(RigidTy::FnDef(def, _)) => {
                let did = rustc_internal::internal(self.tcx, def.def_id());
                return Origin::Unit {
                    path: path_of(self.tcx, did),
                    krate: self.tcx.crate_name(did.krate).to_string(),
                    value: None,
                    span: Some(self.loc(c.span)),
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
                self.unevaluated(uneval, &ty, None, int_ty)
                    .unwrap_or_else(|| {
                        // a promoted literal (`&[0; 32]` in an item body): its data, as an
                        // instance body has it evaluated
                        let (len, zero) = uneval
                            .2
                            .and_then(|_| self.evaluate(uneval))
                            .and_then(|v| {
                                let c: rustc_public::ty::MirConst =
                                    rustc_internal::stable(rustc_middle::mir::Const::Val(
                                        v,
                                        rustc_internal::internal(self.tcx, ty),
                                    ));
                                match c.kind() {
                                    ConstantKind::Allocated(a) => Some(literal_data(a, &ty)),
                                    _ => None,
                                }
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
        DefKind::OutParam { func, args, index } => DefKind::OutParam {
            func: func.clone(),
            args: args.clone(),
            index: *index,
        },
        DefKind::Through { func } => DefKind::Through { func: func.clone() },
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
        };
    }
    ty
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
        .any(|s| matches!(s, Step::Elem | Step::Index(_)))
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
    /// The boxes a box `local.path` is the same allocation as: itself, and, for a copy of a
    /// box read through a reference (`_28 = copy (*_4)`), the box the reference points to.
    fn same_box(&self, local: Local, path: Path, depth: usize) -> Vec<(Local, Path)> {
        let mut out = vec![(local, path.clone())];
        if depth > 6 || !path.is_empty() {
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
                    if !partial(&qp) {
                        qp.push(Step::Deref);
                        out.push(Target {
                            local: q.local,
                            path: qp,
                            alias: false,
                        });
                    }
                }
                // `index_mut(&mut buf, ..)`, `as_mut()`: a borrow into the argument, all of it
                // (`as_mut`, `deref_mut`, `&mut buf[..]`) or a part (`&mut buf[..16]`,
                // `get_mut(i)`)
                DefKind::Call { func, args } => {
                    let part = borrows_part(self.body, func, args);
                    for a in args {
                        if let Operand::Copy(q) | Operand::Move(q) = a
                            && is_mut_ptr(self.body, q)
                        {
                            for mut t in self.targets(q.local, &path_of_place(q), depth + 1) {
                                if part && !partial(&t.path) {
                                    t.path.push(Step::Elem);
                                }
                                out.push(t);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        out
    }
}

impl Pointees<'_> {
    /// What the `&mut` borrows a closure or a struct built in `local` holds point to (its
    /// captures, its fields), each with whether it points at one place.
    fn held(&self, local: Local) -> Vec<(Vec<Target>, bool)> {
        let mut out = Vec::new();
        for k in self.direct.get(&local).into_iter().flatten() {
            if let DefKind::Assign(Rvalue::Aggregate(_, ops), _) = k {
                for op in ops {
                    if let Operand::Copy(q) | Operand::Move(q) = op
                        && is_mut_ptr(self.body, q)
                    {
                        let t = self.targets(q.local, &path_of_place(q), 0);
                        let single = sole_target(&t);
                        out.push((t, single));
                    }
                }
            }
        }
        out
    }
}

/// Does a pointer with these targets point at one place? The aliases stand for the place they
/// point at, not for another one.
fn sole_target(targets: &[Target]) -> bool {
    targets.iter().filter(|t| !t.alias).count() == 1
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

/// The function a call of `did` with `args` writes through, as `Links::writes` names it: a
/// trait method's call with a known `Self` type is its implementation's (`<Ctx as Up>::up`, or
/// the trait's default body); one on a trait object or a type parameter stays the trait
/// method's, with `dyn <trait>` or `impl <trait>` (see `Origin::Written`).
pub(crate) fn write_callee<'tcx>(
    tcx: TyCtxt<'tcx>,
    did: DefId,
    args: rustc_middle::ty::GenericArgsRef<'tcx>,
) -> (String, Option<String>) {
    let Some(tr) = tcx.trait_of_assoc(did) else {
        return (path_of(tcx, did), None);
    };
    if let Some(d) = dyn_self(tcx, did, args) {
        return (path_of(tcx, did), Some(d));
    }
    if !rustc_middle::ty::TypeVisitableExt::has_non_region_param(&args) {
        let env = rustc_middle::ty::TypingEnv::fully_monomorphized();
        if let Ok(Some(i)) = rustc_middle::ty::Instance::try_resolve(tcx, env, did, args)
            && matches!(i.def, rustc_middle::ty::InstanceKind::Item(_))
        {
            return (path_of(tcx, i.def_id()), None);
        }
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

/// `[u8; N]`, `&[u8; N]`, `&mut [u8; N]`: N bytes.
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
