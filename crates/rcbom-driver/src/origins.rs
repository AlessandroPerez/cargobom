//! Intraprocedural origins of call arguments: where the value passed to a crypto API comes
//! from, as a bounded tree over the body's def-use chains.
//!
//! `UnboundKey::new(&AES_256_GCM, &secret.as_bytes()[..32])` gives, for argument 1, a chain of
//! calls (`Index::index`, `str::as_bytes`) down to `std::env::var`; for the nonce of
//! `Nonce::assume_unique_for_key([0u8; 12])` a 12-byte constant. The tree is knowledge-base
//! agnostic: deciding that `env::var` is external input or `thread_rng` a CSPRNG happens in the
//! analysis, which also sees through standard-library plumbing.
//!
//! Locals are tracked whole (a write to a field counts as a definition of the local), and
//! every definition of a local is kept, so the result over-approximates the possible origins.

use std::collections::{HashMap, HashSet};

use rcbom_facts::{Loc, Origin};
use rustc_middle::ty::TyCtxt;
use rustc_public::mir::alloc::GlobalAlloc;
use rustc_public::mir::{
    Body, BorrowKind, Local, Mutability, Operand, RawPtrKind, Rvalue, StatementKind, TerminatorKind,
};
use rustc_public::ty::{ConstantKind, RigidTy, Span, Ty, TyKind};
use rustc_public::{CrateDef, rustc_internal};

use crate::{def_ref_internal, locate};

const MAX_DEPTH: usize = 6;
const MAX_ALTERNATIVES: usize = 4;

enum Def {
    Assign(Rvalue, Span),
    Call {
        func: Operand,
        args: Vec<Operand>,
    },
    /// The local was passed by `&mut` to this call, which may have written it
    /// (`OsRng.fill_bytes(&mut nonce)`, `pbkdf2_hmac(.., &mut out)`).
    OutParam {
        func: Operand,
        args: Vec<Operand>,
    },
}

pub(crate) struct Origins<'a, 'tcx> {
    tcx: TyCtxt<'tcx>,
    body: &'a Body,
    defs: HashMap<Local, Vec<Def>>,
    args: usize,
    /// Inside a closure body followed from its caller: its own parameters are not the
    /// caller's, and closures are followed one level only.
    in_closure: bool,
    /// The call whose arguments are being traced: it does not define its own arguments
    /// (`RsaPrivateKey::new(&mut rng, 2048)` writes `rng`, but `rng` comes from before).
    current: std::cell::RefCell<Option<(Operand, Vec<Operand>)>>,
}

impl<'a, 'tcx> Origins<'a, 'tcx> {
    pub(crate) fn new(tcx: TyCtxt<'tcx>, body: &'a Body) -> Self {
        let mut defs: HashMap<Local, Vec<Def>> = HashMap::new();
        for bb in &body.blocks {
            for s in &bb.statements {
                if let StatementKind::Assign(place, rv) = &s.kind {
                    defs.entry(place.local)
                        .or_default()
                        .push(Def::Assign(rv.clone(), s.source_info.span));
                }
            }
            if let TerminatorKind::Call {
                func,
                args,
                destination,
                ..
            } = &bb.terminator.kind
            {
                defs.entry(destination.local).or_default().push(Def::Call {
                    func: func.clone(),
                    args: args.clone(),
                });
            }
        }
        // writes through `&mut` arguments: `let mut nonce = [0u8; 12]; rng.fill_bytes(&mut
        // nonce)` defines `nonce` by the call, not only by the zero initialization
        let mut out_params: Vec<(Local, Def)> = Vec::new();
        for bb in &body.blocks {
            if let TerminatorKind::Call { func, args, .. } = &bb.terminator.kind {
                for a in args {
                    let (Operand::Copy(p) | Operand::Move(p)) = a else {
                        continue;
                    };
                    for target in mut_borrowed(&defs, p.local, 0) {
                        out_params.push((
                            target,
                            Def::OutParam {
                                func: func.clone(),
                                args: args.clone(),
                            },
                        ));
                    }
                }
            }
        }
        for (l, d) in out_params {
            defs.entry(l).or_default().push(d);
        }
        let args = body.arg_locals().len();
        Origins {
            tcx,
            body,
            defs,
            args,
            in_closure: false,
            current: std::cell::RefCell::new(None),
        }
    }

    /// Origin of argument `op` of the call `func(args)`.
    pub(crate) fn of_arg(&self, op: &Operand, func: &Operand, args: &[Operand]) -> Origin {
        *self.current.borrow_mut() = Some((func.clone(), args.to_vec()));
        let o = self.operand(op, 0, &mut HashSet::new());
        *self.current.borrow_mut() = None;
        o
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
        if let Some(n) = array_len_of_ty(&self.body.locals()[l].ty) {
            return Some(n);
        }
        let defs = self.defs.get(&l)?;
        defs.iter().find_map(|d| match d {
            Def::Assign(Rvalue::Use(op, _), _) | Def::Assign(Rvalue::Cast(_, op, _), _) => {
                self.len_of_operand(op, depth + 1)
            }
            Def::Assign(Rvalue::Ref(_, _, p), _)
            | Def::Assign(Rvalue::AddressOf(_, p), _)
            | Def::Assign(Rvalue::CopyForDeref(p), _) => self.len_of_local(p.local, depth + 1),
            _ => None,
        })
    }

    fn operand(&self, op: &Operand, depth: usize, seen: &mut HashSet<Local>) -> Origin {
        match op {
            // `unwrap_or_else(|_| "fallback".to_string())`: a closure defined here is followed
            // one level, to what it returns
            Operand::Constant(c) if !self.in_closure => match c.const_.ty().kind().rigid() {
                Some(RigidTy::Closure(def, _)) => match def.body() {
                    Some(body) => {
                        let mut inner = Origins::new(self.tcx, &body);
                        inner.in_closure = true;
                        let ret = inner.local(
                            rustc_public::mir::RETURN_LOCAL,
                            depth + 1,
                            &mut HashSet::new(),
                        );
                        Origin::Call {
                            callee: "<closure>".into(),
                            krate: String::new(),
                            args: vec![ret],
                        }
                    }
                    None => Origin::Unknown,
                },
                _ => self.constant(c),
            },
            Operand::Constant(c) => self.constant(c),
            Operand::Copy(p) | Operand::Move(p) => self.local(p.local, depth, seen),
            _ => Origin::Unknown,
        }
    }

    fn constant(&self, c: &rustc_public::mir::ConstOperand) -> Origin {
        // a closure or fn item passed as a value is code, not data
        if matches!(
            c.const_.ty().kind().rigid(),
            Some(RigidTy::Closure(..) | RigidTy::FnDef(..))
        ) {
            return Origin::Unknown;
        }
        let span = Some(self.loc(c.span));
        match c.const_.kind() {
            ConstantKind::Allocated(a) => {
                // `&STATIC`: a pointer to a static allocation
                for (_, prov) in &a.provenance.ptrs {
                    if let GlobalAlloc::Static(s) = GlobalAlloc::from(prov.0) {
                        let did = rustc_internal::internal(self.tcx, s.def_id());
                        return Origin::Data {
                            def: def_ref_internal(self.tcx, did),
                        };
                    }
                }
                let ty = c.const_.ty();
                let value = match ty.kind().rigid() {
                    Some(RigidTy::Uint(_)) => {
                        a.read_uint().ok().and_then(|v| i128::try_from(v).ok())
                    }
                    Some(RigidTy::Int(_)) => a.read_int().ok(),
                    _ => None,
                };
                Origin::Const {
                    value,
                    len: array_len_of_ty(&ty),
                    span,
                }
            }
            // a promoted constant (`&[42u8; 32]`) is literal data of the enclosing fn
            ConstantKind::Unevaluated(u) if u.promoted.is_some() => Origin::Const {
                value: None,
                len: array_len_of_ty(&c.const_.ty()),
                span,
            },
            // a named const (aws-lc-rs algorithms) not yet evaluated
            ConstantKind::Unevaluated(u) => {
                let did = rustc_internal::internal(self.tcx, u.def.def_id());
                Origin::Data {
                    def: def_ref_internal(self.tcx, did),
                }
            }
            _ => Origin::Const {
                value: None,
                len: array_len_of_ty(&c.const_.ty()),
                span,
            },
        }
    }

    fn local(&self, l: Local, depth: usize, seen: &mut HashSet<Local>) -> Origin {
        if (1..=self.args).contains(&l) {
            if self.in_closure {
                return Origin::Unknown;
            }
            return Origin::Param { index: l - 1 };
        }
        if depth > MAX_DEPTH || !seen.insert(l) {
            return Origin::Unknown;
        }
        let Some(defs) = self.defs.get(&l) else {
            return Origin::Unknown;
        };
        // a buffer initialized with a constant and then filled by a call: the constant is only
        // the initialization
        let current = self.current.borrow().clone();
        let is_current = |d: &Def| match (d, &current) {
            (Def::OutParam { func, args }, Some((f, a))) => func == f && args == a,
            _ => false,
        };
        let filled = defs
            .iter()
            .any(|d| matches!(d, Def::OutParam { .. }) && !is_current(d));
        let mut alts: Vec<Origin> = Vec::new();
        for d in defs.iter() {
            if is_current(d) || (filled && is_constant_init(d)) {
                continue;
            }
            let o = self.def(d, depth, seen);
            if !alts.contains(&o) {
                alts.push(o);
            }
            if alts.len() >= MAX_ALTERNATIVES {
                break;
            }
        }
        seen.remove(&l);
        if alts.len() == 1 {
            alts.pop().unwrap()
        } else {
            Origin::Any(alts)
        }
    }

    fn def(&self, d: &Def, depth: usize, seen: &mut HashSet<Local>) -> Origin {
        match d {
            Def::Assign(rv, span) => match rv {
                Rvalue::Use(op, _) | Rvalue::Cast(_, op, _) => self.operand(op, depth + 1, seen),
                Rvalue::Ref(_, _, p)
                | Rvalue::AddressOf(_, p)
                | Rvalue::CopyForDeref(p)
                | Rvalue::Reborrow(_, _, p) => self.local(p.local, depth + 1, seen),
                // `[0u8; 12]`
                Rvalue::Repeat(op, n) => match op {
                    Operand::Constant(_) => Origin::Const {
                        value: None,
                        len: n.eval_target_usize().ok(),
                        span: Some(self.loc(*span)),
                    },
                    _ => self.operand(op, depth + 1, seen),
                },
                // `[1, 2, 3]`, a struct literal: constant if every part is
                Rvalue::Aggregate(_, ops) => {
                    if ops.iter().all(|o| matches!(o, Operand::Constant(_))) {
                        Origin::Const {
                            value: None,
                            len: Some(ops.len() as u64),
                            span: Some(self.loc(*span)),
                        }
                    } else {
                        let parts: Vec<Origin> = ops
                            .iter()
                            .take(MAX_ALTERNATIVES)
                            .map(|o| self.operand(o, depth + 1, seen))
                            .collect();
                        if parts.len() == 1 {
                            parts.into_iter().next().unwrap()
                        } else {
                            Origin::Any(parts)
                        }
                    }
                }
                _ => Origin::Unknown,
            },
            Def::Call { func, args } | Def::OutParam { func, args } => {
                let (callee, krate) = match func.ty(self.body.locals()).ok().map(|t| t.kind()) {
                    Some(TyKind::RigidTy(RigidTy::FnDef(def, _))) => (def.name(), def.krate().name),
                    _ => ("<indirect>".to_string(), String::new()),
                };
                Origin::Call {
                    callee,
                    krate,
                    args: args
                        .iter()
                        .take(MAX_ALTERNATIVES)
                        .map(|a| self.operand(a, depth + 1, seen))
                        .collect(),
                }
            }
        }
    }

    fn loc(&self, span: Span) -> Loc {
        locate(self.tcx, rustc_internal::internal(self.tcx, span)).0
    }
}

/// Locals whose mutable borrow `l` is (through reborrows and casts).
fn mut_borrowed(defs: &HashMap<Local, Vec<Def>>, l: Local, depth: usize) -> Vec<Local> {
    if depth > 4 {
        return Vec::new();
    }
    let mut out = Vec::new();
    for d in defs.get(&l).into_iter().flatten() {
        match d {
            Def::Assign(Rvalue::Ref(_, BorrowKind::Mut { .. }, p), _)
            | Def::Assign(Rvalue::AddressOf(RawPtrKind::Mut, p), _)
            | Def::Assign(Rvalue::Reborrow(_, Mutability::Mut, p), _) => {
                // `&mut *x` reborrows what `x` borrows
                if p.projection.is_empty() {
                    out.push(p.local);
                } else {
                    out.extend(mut_borrowed(defs, p.local, depth + 1));
                    out.push(p.local);
                }
            }
            Def::Assign(Rvalue::Use(Operand::Copy(p) | Operand::Move(p), _), _)
            | Def::Assign(Rvalue::Cast(_, Operand::Copy(p) | Operand::Move(p), _), _) => {
                out.extend(mut_borrowed(defs, p.local, depth + 1))
            }
            _ => {}
        }
    }
    out
}

fn is_constant_init(d: &Def) -> bool {
    match d {
        Def::Assign(Rvalue::Repeat(Operand::Constant(_), _), _)
        | Def::Assign(Rvalue::Use(Operand::Constant(_), _), _) => true,
        Def::Assign(Rvalue::Aggregate(_, ops), _) => {
            ops.iter().all(|o| matches!(o, Operand::Constant(_)))
        }
        _ => false,
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
