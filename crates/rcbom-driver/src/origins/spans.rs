//! Where a call's callee, a pointer's function or a closure is named, and the lengths of arrays
//! read.

use super::*;

impl<'a, 'tcx> Origins<'a, 'tcx> {
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

    pub(super) fn callee_span_at(&self, func: &Operand, at: At) -> Option<Span> {
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
    pub(super) fn fn_item_span(
        &self,
        local: Local,
        path: &[Step],
        at: At,
        depth: usize,
    ) -> Option<Span> {
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

    pub(super) fn rvalue_fn_span(
        &self,
        rv: &Rvalue,
        rest: &[Step],
        at: At,
        depth: usize,
    ) -> Option<Span> {
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
    pub(super) fn capture_fn_span(
        &self,
        local: Local,
        rest: &[Step],
        depth: usize,
    ) -> Option<Span> {
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

    pub(super) fn len_of_operand(&self, op: &Operand, at: At, depth: usize) -> Option<u64> {
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
    pub(super) fn len_of_local(&self, l: Local, at: At, depth: usize) -> Option<u64> {
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

    pub(super) fn loc(&self, span: Span) -> Loc {
        locate(self.tcx, rustc_internal::internal(self.tcx, span)).0
    }
}
