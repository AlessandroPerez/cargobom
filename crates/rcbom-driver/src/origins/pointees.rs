//! What pointers point to (`Pointees`): reborrows, holders, containers of pointers, returned
//! borrows.

use super::*;

/// Is `q` a box's pointer (`b.0`, its `Unique`, or a field further in): how many fields from
/// the box `b` (as `Origins::box_pointer`, from the stable types).
pub(super) fn box_field(body: &Body, q: &Place) -> Option<usize> {
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
impl Pointees<'_> {
    /// Targets reached through a pointer held in a place (`*v[0] = x` on a `Vec<&mut T>`: the
    /// element's pointer, `(v, [Elem, Deref])`): where that pointer points, as far as followed
    /// (not followed: `lost`). An argument's (`*(*_1).0`, a closure's capture) stays as it is.
    pub(super) fn through_held(&self, targets: Vec<Target>) -> Vec<Target> {
        self.through_held_at(targets, 0)
    }

    /// One more place looked at by the current search; false past `MAX_SEARCH`.
    pub(super) fn step(&self) -> bool {
        self.steps.set(self.steps.get() + 1);
        self.steps.get() <= MAX_SEARCH
    }

    pub(super) fn through_held_at(&self, targets: Vec<Target>, depth: usize) -> Vec<Target> {
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
    pub(super) fn same_box(&self, local: Local, path: Path, depth: usize) -> Vec<(Local, Path)> {
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
    pub(super) fn targets(&self, local: Local, path: &[Step], depth: usize) -> Vec<Target> {
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
        // a pointer whose own place the body lends by `&mut` (`repoint(&mut r, ..)`,
        // `mem::swap(&mut r, &mut s)`, `mem::replace(&mut r, ..)`): what the loan makes it point
        // to is no definition here, not followed
        if self.repointed.contains(&local) {
            self.lost.set(true);
            return Vec::new();
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
    pub(super) fn field_targets(&self, local: Local, path: &[Step], depth: usize) -> Vec<Target> {
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
            } else if matches!(path.last(), Some(Step::Field(_)))
                && path
                    .iter()
                    .all(|s| matches!(s, Step::Field(_) | Step::Variant(_)))
            {
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
pub(super) fn holds_mut_arg(t: Ty, depth: usize) -> bool {
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
/// The pointer type a standard-library container of pointers holds: `&mut T` of `Vec<&mut T>`,
/// `Option<&mut T>`, `Box<&mut T>`, `[&mut T; 2]`, `vec::IntoIter<&mut T>`, `iter::Once<&mut T>`,
/// `Box<MaybeUninit<[&mut T; 1]>>` (`vec![..]`'s allocation); none when it holds another
/// borrow besides.
pub(super) fn bag_content(t: Ty) -> Option<Ty> {
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
pub(super) fn risky(t: Ty, p: Ty) -> bool {
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
pub(super) fn holds_dyn(t: Ty, depth: usize) -> bool {
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
/// Is the callee one of `MOVES`, or of `MOVES_OF` for a container?
pub(super) fn moves_only(body: &Body, func: &Operand) -> bool {
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
pub(super) fn closed_bags(body: &Body) -> Bags {
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
pub(super) fn closed_bags_in(body: &Body) -> Bags {
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
    pub(super) fn bag(&self, local: Local) -> Option<Ty> {
        bag_content(self.body.locals()[local].ty).filter(|c| self.bags.closed.contains(c))
    }

    /// What a call's result holds of the borrows it is given (`returned_pointers`).
    pub(super) fn returns_of(&self, func: &Operand) -> Option<&Returns> {
        match func.ty(self.body.locals()).ok()?.kind() {
            TyKind::RigidTy(RigidTy::FnDef(def, _)) => self.returns.get(&def.def_id()),
            _ => None,
        }
    }

    /// The places the pointers a call's result holds at `at` point to (all of them for `None`),
    /// per its function's summary `r`: into what an argument points to, or where a pointer an
    /// argument holds points. `None` when the summary has none there, or an argument is not a
    /// place.
    pub(super) fn returned(
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
    pub(super) fn taken_from_bag(&self, func: &Operand, local: Local) -> bool {
        let t = self.body.locals()[local].ty;
        moves_only(self.body, func)
            && (self.bags.closed.contains(&t)
                || matches!(t.kind().rigid(),
                    Some(RigidTy::Ref(_, i, _)) if self.bags.closed.contains(i)))
    }

    /// Is `local` a box of pointers whose contents are followed?
    pub(super) fn boxed(&self, local: Local) -> bool {
        self.bag(local).is_some()
            && matches!(self.body.locals()[local].ty.kind().rigid(),
                Some(RigidTy::Adt(def, _)) if def.name().rsplit("::").next() == Some("Box"))
    }

    /// For an argument of a `moves_only` call: is it a pointer of a closed type or a container of
    /// them (stored or handed on, written through by nothing), or a borrow of such a container?
    pub(super) fn moved(&self, p: &Place) -> (bool, bool) {
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
    pub(super) fn level_sources(&self, args: &[Operand], q: Ty, depth: usize) -> Vec<Target> {
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
    pub(super) fn bag_targets(&self, local: Local, depth: usize) -> Vec<Target> {
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
            // a parameter (`fn opt_set(o: Option<&mut T>)`): what its `Some` pointed to on entry
            None if (1..=self.nargs).contains(&local) && self.options.contains(&local) => {
                out.push(Target {
                    local,
                    path: vec![Step::Variant(1), Step::Field(0), Step::Deref],
                    alias: false,
                })
            }
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
pub(super) fn mentions(t: Ty, q: Ty, depth: usize) -> bool {
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
    pub(super) fn held_closure(&self, local: Local) -> Option<(rustc_public::DefId, Vec<Capture>)> {
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

    /// The local whose value place `p` holds: itself, or for a part (`o.w`) of a value this
    /// body builds once by a struct or tuple literal (`Outer13 { w: W13 { .. } }`) and neither
    /// lends nor stores into, the local the literal moved or copied there.
    pub(super) fn part_source(&self, p: &Place) -> Option<Local> {
        let mut l = p.local;
        for e in &p.projection {
            let ProjectionElem::Field(i, _) = e else {
                return None;
            };
            if self.partly.contains(&l) || self.lent_locals.contains(&l) {
                return None;
            }
            let [DefKind::Assign(Rvalue::Aggregate(kind, ops), _)] =
                self.direct.get(&l)?.as_slice()
            else {
                return None;
            };
            if !matches!(kind, AggregateKind::Tuple)
                && !matches!(kind, AggregateKind::Adt(def, ..) if def.kind().is_struct())
            {
                return None;
            }
            match ops.get(*i) {
                Some(Operand::Copy(q) | Operand::Move(q)) if q.projection.is_empty() => l = q.local,
                _ => return None,
            }
        }
        Some(l)
    }

    /// `by_borrow`: the call takes it by `&mut` (one borrow of it is this call's).
    pub(super) fn held(
        &self,
        local: Local,
        by_borrow: bool,
    ) -> Vec<(Vec<Target>, bool, Option<usize>)> {
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
            && let Some(l) = self.part_source(q)
            && !chain.contains(&l)
        {
            src = l;
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
                // (where the borrow sits: a struct's field, a tuple's element, `Some`'s)
                let fields = match kind {
                    AggregateKind::Tuple => true,
                    AggregateKind::Adt(def, v, ..) => {
                        def.kind().is_struct()
                            || (variant_index(v) == 1 && self.options.contains(&src))
                    }
                    _ => false,
                };
                for (i, op) in ops.iter().enumerate() {
                    if let Operand::Copy(q) | Operand::Move(q) = op
                        && is_mut_ptr(self.body, q)
                    {
                        let t = self.targets(q.local, &path_of_place(q), 0);
                        let single = sole_target(&t) && once && !changed;
                        out.push((t, single, fields.then_some(i)));
                    } else if let Operand::Copy(q) | Operand::Move(q) = op
                        && self.mut_holding.contains(&q.local)
                    {
                        // a holder inside it (`Outer { w: W { r: &mut a } }`, `Some(w)`, `(w, 0)`,
                        // `[w1, w2]`): a summary describes the fields of the value handed over,
                        // not what they hold, so what it points to is not followed
                        self.lost.set(true);
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
pub(super) fn capture_writes(
    tcx: TyCtxt<'_>,
    did: rustc_public::DefId,
    k: usize,
) -> Option<Vec<Origin>> {
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
/// Does a pointer with these targets point at one place? The aliases stand for the place they
/// point at, not for another one; a place found twice (a copy of a parameter's pointer, which
/// points where the parameter does) is one.
pub(super) fn sole_target(targets: &[Target]) -> bool {
    let mut places = targets
        .iter()
        .filter(|t| !t.alias)
        .map(|t| (t.local, &t.path));
    places
        .next()
        .is_some_and(|first| places.all(|other| other == first))
}
/// Does a call that returns `&mut` into its argument borrow a part of it (an element, a
/// range other than `..`), rather than all of it (`as_mut`, `deref_mut`, `&mut buf[..]`)?
pub(super) fn borrows_part(body: &Body, func: &Operand, args: &[Operand]) -> bool {
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
pub(super) fn borrows_inside(body: &Body, func: &Operand, args: &[Operand], result: Local) -> bool {
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
pub(super) fn resolve(
    body: &Body,
    nargs: usize,
    local: Local,
    depth: usize,
) -> Option<(Local, Path)> {
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
pub(super) fn returned_pointers_in(tcx: TyCtxt<'_>, body: &Body) -> Option<Returns> {
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
                        let steps = holder_steps(tcx, ty, f);
                        out.push((steps.clone(), Returned::Held(q.local - 1, steps)));
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
pub(super) fn callee_returns(
    tcx: TyCtxt<'_>,
    body: &Body,
) -> HashMap<rustc_public::DefId, Returns> {
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
pub(super) fn returned_part(caller: &Body, func: &Operand) -> Option<(usize, Path)> {
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
/// The pointers whose own place the body lends by `&mut` (or `&raw mut`) where the loan may
/// change it: handed on, stored, copied, lent again or written through (`repoint(&mut r, ..)`,
/// `mem::swap(&mut r, &mut s)`, `*l = &mut y`). Not a loan only read through (`f(&mut r)` with
/// `f` taking `&mut T`, coerced to `f(&mut *r)`: `_5 = &mut _1; _6 = copy (*_5)`), nor a closure's
/// capture of a variable it only writes through (`MutBorrowKind::ClosureCapture`).
pub(super) fn repointed(body: &Body) -> HashSet<Local> {
    use rustc_public::mir::visit::{Location, PlaceContext};
    use rustc_public::mir::{MirVisitor, VarDebugInfo};
    let mut out = HashSet::new();
    // the local holding each loan: the pointer lent
    let mut loans: HashMap<Local, Local> = HashMap::new();
    for st in body.blocks.iter().flat_map(|b| &b.statements) {
        let StatementKind::Assign(lhs, rv) = &st.kind else {
            continue;
        };
        let q = match rv {
            Rvalue::Ref(_, BorrowKind::Mut { kind }, q)
                if *kind != MutBorrowKind::ClosureCapture =>
            {
                q
            }
            Rvalue::AddressOf(rustc_public::mir::RawPtrKind::Mut, q) => q,
            _ => continue,
        };
        if !q.projection.is_empty() || !is_ptr(body, q) {
            continue;
        }
        if lhs.projection.is_empty() {
            loans.insert(lhs.local, q.local);
        } else {
            out.insert(q.local);
        }
    }
    struct V<'a> {
        loans: &'a HashMap<Local, Local>,
        out: &'a mut HashSet<Local>,
    }
    impl MirVisitor for V<'_> {
        fn visit_rvalue(&mut self, rv: &Rvalue, loc: Location) {
            // the loan lent itself (`&mut _5`)
            if let Rvalue::Ref(_, _, q) | Rvalue::AddressOf(_, q) | Rvalue::Reborrow(_, _, q) = rv
                && q.projection.is_empty()
                && let Some(p) = self.loans.get(&q.local)
            {
                self.out.insert(*p);
            }
            self.super_rvalue(rv, loc);
        }
        fn visit_place(&mut self, place: &Place, ptx: PlaceContext, _: Location) {
            let Some(p) = self.loans.get(&place.local) else {
                return;
            };
            let kept = match place.projection.as_slice() {
                // the loan's local defined (lent, above)
                [] => ptx.is_mutating(),
                // the pointer read through the loan (`copy (*_5)`), not written nor lent again
                [ProjectionElem::Deref] => !ptx.is_mutating(),
                // what the pointer points to
                [ProjectionElem::Deref, ProjectionElem::Deref, ..] => true,
                _ => false,
            };
            if !kept {
                self.out.insert(*p);
            }
        }
        // (a debugger's name for it is no use)
        fn visit_var_debug_info(&mut self, _: &VarDebugInfo) {}
    }
    if !loans.is_empty() {
        V {
            loans: &loans,
            out: &mut out,
        }
        .visit_body(body);
    }
    out
}
pub(super) fn is_ptr(body: &Body, p: &Place) -> bool {
    matches!(
        p.ty(body.locals())
            .ok()
            .and_then(|t| t.kind().rigid().cloned()),
        Some(RigidTy::Ref(..) | RigidTy::RawPtr(..))
    )
}
pub(super) fn is_mut_ptr(body: &Body, p: &Place) -> bool {
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
pub(super) fn returns_mut_ref(body: &Body, dest: &Place) -> bool {
    is_mut_ptr(body, dest)
}
/// A method returning its own receiver (`&mut self -> &mut Self`, `hasher.update(d)`).
pub(super) fn returns_receiver(body: &Body, dest: &Place, args: &[Operand]) -> bool {
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
pub(super) fn std_store(callee: &str) -> bool {
    const TYPES: &[&str] = &[
        "Vec", "VecDeque", "HashMap", "BTreeMap", "HashSet", "BTreeSet",
    ];
    const METHODS: &[&str] = &["push", "push_back", "push_front", "insert"];
    let segs: Vec<&str> = callee.split("::").filter(|s| !s.starts_with('<')).collect();
    matches!(segs.first(), Some(&("std" | "alloc" | "core")))
        && matches!(segs.as_slice(), [.., ty, m] if TYPES.contains(ty) && METHODS.contains(m))
}
/// The types the `&mut` borrows a value of type `t` holds point to (`&D` of a `Vec<&mut &D>`,
/// `T` of a `W<'a> { r: &'a mut T }`, a closure's capture's); none when what it holds is not
/// known (a type parameter, an opaque type, a trait object with a borrowed lifetime).
pub(super) fn mut_pointees<'tcx>(
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
pub(super) fn holds_borrow(body: &Body, dest: &Place) -> bool {
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
