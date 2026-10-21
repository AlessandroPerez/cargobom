//! Definitions and where they reach (`Flow`): writes, through pointers and calls, and the cells
//! whose aliases escape.

use super::*;

impl Flow {
    /// `local_fn`: is a callee a function of the crate (whose writes through `&mut` its links
    /// summarize, the value before included where it may not write)?
    pub(super) fn new<'tcx>(
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
            options: body
                .locals()
                .iter()
                .enumerate()
                .filter(|(_, l)| option_holder(tcx, internal(l.ty)))
                .map(|(i, _)| i)
                .collect(),
            // (all of it or a part of it, `&mut s.f`; not a place reached through a pointer, nor a
            // closure's capture of a variable it only writes through, `s.n = 1` on `s: &mut S` in
            // an edition 2015 closure, which cannot change the variable itself)
            lent_locals: body
                .blocks
                .iter()
                .flat_map(|b| &b.statements)
                .filter_map(|st| match &st.kind {
                    StatementKind::Assign(_, Rvalue::Ref(_, BorrowKind::Mut { kind }, q))
                        if *kind != MutBorrowKind::ClosureCapture
                            && !q
                                .projection
                                .iter()
                                .any(|e| matches!(e, ProjectionElem::Deref)) =>
                    {
                        Some(q.local)
                    }
                    StatementKind::Assign(
                        _,
                        Rvalue::AddressOf(rustc_public::mir::RawPtrKind::Mut, q),
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
            repointed: repointed(body),
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
                        let (whole, parts): (Vec<Target>, Vec<Target>) = ptr
                            .targets(p.local, &path_of_place(p), 0)
                            .into_iter()
                            .partition(|t| t.path.is_empty());
                        // a part of a value lent (`set_ref(&mut o.w)`, by fields and elements,
                        // not what another pointer points to) that holds a `&mut`: what it
                        // points to is not followed, a write through it lands where such
                        // borrows point
                        if parts.iter().any(|t| {
                            !t.path.contains(&Step::Deref)
                                && mut_holder(internal(body.locals()[t.local].ty), &t.path)
                        }) {
                            match pointee(p).and_then(|t| mut_pointees(tcx, t)) {
                                Some(ts) => lost_at.extend(ts.into_iter().map(|t| (*at, Some(t)))),
                                None => lost_at.push((*at, None)),
                            }
                        }
                        whole.into_iter().map(|t| t.local).collect()
                    } else if let Some(h) = ptr.part_source(p) {
                        // (or a part of one built here, `set13(o.w)`: the value put there)
                        vec![h]
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
                // function may write through; so may a standard-library function, `swap`,
                // `take`, `OnceCell::set`, a guard written through later, unless it only reads
                // the cell, `CELL_READS`: the modelled writes are above)
                if let Operand::Copy(p) | Operand::Move(p) = a
                    && (is_mut_ptr(body, p)
                        || (cell_ptr(p)
                            && (!std_callee || !CELL_READS.iter().any(|g| name.ends_with(g)))))
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
        let open_cells = open_cells(tcx, body, &ptr);
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
            open_cells,
        }
    }
}
pub(super) fn clone_kind(k: &DefKind) -> DefKind {
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
/// Does a write to `def` (a place with an unknown part, `Step::Part`) overlap the read of
/// `read` beyond their common prefix: the function whose borrow points there.
pub(super) fn part_overlap(def: &[Step], read: &[Step]) -> Option<String> {
    let j = def.iter().zip(read).take_while(|(a, b)| a.same(b)).count();
    match (def.get(j), read.get(j)) {
        (Some(Step::Part(f)), Some(_)) => Some(f.clone()),
        _ => None,
    }
}
/// Does a write through a value holding a borrow (`DefKind::Through`, recorded at some element
/// `Elem` of the place) overlap a read of a field of that place (`s.a`)?
pub(super) fn through_overlap(def: &[Step], read: &[Step]) -> bool {
    let j = def.iter().zip(read).take_while(|(a, b)| a.same(b)).count();
    matches!(
        (def.get(j), read.get(j)),
        (Some(Step::Elem), Some(Step::Field(_) | Step::Variant(_)))
    )
}
pub(super) fn is_prefix(a: &[Step], b: &[Step]) -> bool {
    b.len() >= a.len() && a.iter().zip(b).all(|(x, y)| x.same(y))
}
/// A definition building one variant of an enum (`Pick::A(x)`), read as another
/// (`[Variant(B), Field(0)]`).
pub(super) fn other_variant(d: &DefKind, rest: &[Step]) -> bool {
    matches!(
        (d, rest.first()),
        (DefKind::Assign(Rvalue::Aggregate(AggregateKind::Adt(_, v, ..), _), _), Some(Step::Variant(w)))
            if variant_index(v) != *w
    )
}
/// A part of the place, not all of it: an element.
pub(super) fn partial(path: &[Step]) -> bool {
    path.iter()
        .any(|s| matches!(s, Step::Elem | Step::Index(_) | Step::Part(_)))
}
/// Does `d` end `e`? An assignment overwrites the place and its parts; a call that fills the
/// place through `&mut` (`rng.fill_bytes(&mut nonce)`) replaces its initialization
/// (`let mut nonce = [0u8; 12]`), while a constant written after the fill stays.
pub(super) fn kills(d: &Def, e: &Def) -> bool {
    d.local == e.local
        && is_prefix(&d.path, &e.path)
        && (d.strong || (matches!(d.kind, DefKind::OutParam { .. }) && d.sole && e.init))
}
/// An initialization rather than a value: a constant, or a standard-library constructor taking
/// only constants (`String::new()`, `Vec::with_capacity(32)`, `Default::default()`).
pub(super) fn is_init(body: &Body, d: &DefKind) -> bool {
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
pub(super) fn is_constant_init(d: &DefKind) -> bool {
    match d {
        DefKind::Assign(Rvalue::Repeat(Operand::Constant(_), _), _)
        | DefKind::Assign(Rvalue::Use(Operand::Constant(_), _), _) => true,
        DefKind::Assign(Rvalue::Aggregate(_, ops), _) => {
            ops.iter().all(|o| matches!(o, Operand::Constant(_)))
        }
        _ => false,
    }
}
/// The locals whose cells (`reaches_cell`) may change through an alias the body's definitions
/// do not follow. Aliases are borrows of them and what is copied, cast or returned from them (a
/// call given one may return one: an `Rc` clone, a `deref`, an accessor). Such an alias may only
/// go to a standard-library function that reads (`CELL_READS`), to a call whose pointer argument
/// is resolved to its place where the cell is in it (a write there is a definition, or the
/// callee's summary), or to another alias. Anywhere else (into a value: a struct, a closure's
/// capture, a coroutine; a cast: a trait object; a store through a pointer or into a part; a call
/// given a cell only behind a pointer, or an alias it cannot resolve; inline assembly) the cell
/// may be written where nothing records it, whenever: every read of it is also the unknown.
pub(super) fn open_cells<'tcx>(tcx: TyCtxt<'tcx>, body: &Body, ptr: &Pointees) -> HashSet<Local> {
    let internal = |t: Ty| rustc_internal::internal(tcx, t);
    let n = body.locals().len();
    let cells: Vec<bool> = (0..n)
        .map(|l| reaches_cell(tcx, internal(body.locals()[l].ty), 0))
        .collect();
    if !cells.iter().any(|c| *c) {
        return HashSet::new();
    }
    fn find(parent: &mut [usize], mut x: usize) -> usize {
        while parent[x] != x {
            parent[x] = parent[parent[x]];
            x = parent[x];
        }
        x
    }
    fn union(parent: &mut [usize], a: usize, b: usize) {
        let (a, b) = (find(parent, a), find(parent, b));
        if a != b {
            parent[a] = b;
        }
    }
    let place_of = |o: &Operand| match o {
        Operand::Copy(p) | Operand::Move(p) => Some(p.clone()),
        _ => None,
    };
    let ty_of = |p: &Place| walk_ty(tcx, internal(body.locals()[p.local].ty), &path_of_place(p));
    // first, the aliases: what a borrow, copy, cast or call result of a cell's place is
    let mut parent: Vec<usize> = (0..n).collect();
    for block in &body.blocks {
        for st in &block.statements {
            let StatementKind::Assign(lhs, rv) = &st.kind else {
                continue;
            };
            let from = match rv {
                Rvalue::Ref(_, _, q) | Rvalue::AddressOf(_, q) | Rvalue::CopyForDeref(q) => {
                    Some(q.clone())
                }
                Rvalue::Use(o, _) | Rvalue::Cast(_, o, _) => place_of(o),
                _ => None,
            };
            if let Some(q) = from
                && lhs.projection.is_empty()
                && cells[q.local]
            {
                union(&mut parent, lhs.local, q.local);
            }
        }
        // (not a guard a lock or a `RefCell` hands out: a write through it is the call's own,
        // `Through` at the call)
        if let TerminatorKind::Call {
            func,
            args,
            destination,
            ..
        } = &block.terminator.kind
            && destination.projection.is_empty()
            && reaches_cell(tcx, ty_of(destination), 0)
            && !callee_name(body, func).is_some_and(|n| GUARDS.iter().any(|g| n.ends_with(g)))
        {
            for q in args.iter().filter_map(place_of) {
                if cells[q.local] {
                    union(&mut parent, destination.local, q.local);
                }
            }
        }
    }
    let mut has_cell = vec![false; n];
    for (l, _) in cells.iter().enumerate().filter(|(_, c)| **c) {
        let r = find(&mut parent, l);
        has_cell[r] = true;
    }
    let in_cell = |parent: &mut [usize], l: Local| {
        let r = find(parent, l);
        has_cell[r]
    };
    // then where the aliases go (the pointer search's state is the scan's: kept as it was)
    let saved = (ptr.lost.get(), ptr.cut.get(), ptr.cur_at.get());
    let mut open: HashSet<usize> = HashSet::new();
    for (bb, block) in body.blocks.iter().enumerate() {
        for st in &block.statements {
            let StatementKind::Assign(lhs, rv) = &st.kind else {
                continue;
            };
            let used: Vec<Place> = match rv {
                Rvalue::Ref(_, _, q) | Rvalue::AddressOf(_, q) | Rvalue::CopyForDeref(q) => {
                    vec![q.clone()]
                }
                Rvalue::Use(o, _) => place_of(o).into_iter().collect(),
                Rvalue::Cast(_, o, _) => {
                    // a cast of one: a trait object, a raw pointer
                    if let Some(q) = place_of(o)
                        && in_cell(&mut parent, q.local)
                    {
                        open.insert(find(&mut parent, q.local));
                    }
                    Vec::new()
                }
                Rvalue::Aggregate(_, ops) => {
                    for q in ops.iter().filter_map(place_of) {
                        if in_cell(&mut parent, q.local) {
                            open.insert(find(&mut parent, q.local));
                        }
                    }
                    Vec::new()
                }
                _ => Vec::new(),
            };
            // stored into a part or through a pointer
            if !lhs.projection.is_empty() {
                for q in used {
                    if in_cell(&mut parent, q.local) {
                        open.insert(find(&mut parent, q.local));
                    }
                }
            }
        }
        match &block.terminator.kind {
            TerminatorKind::Call { func, args, .. } => {
                let name = callee_name(body, func).unwrap_or_default();
                let std_callee = ["core::", "std::", "alloc::"]
                    .iter()
                    .any(|c| name.starts_with(c));
                if std_callee && CELL_READS.iter().any(|g| name.ends_with(g)) {
                    continue;
                }
                for q in args.iter().filter_map(place_of) {
                    if !in_cell(&mut parent, q.local) {
                        continue;
                    }
                    // a pointer to a place the cell is in, resolved: the call's write is a
                    // definition there (modelled, or the callee's summary, or the unknown)
                    let inline = match ty_of(&q).kind() {
                        rustc_middle::ty::TyKind::Ref(_, i, _)
                        | rustc_middle::ty::TyKind::RawPtr(i, _) => cell_inline(tcx, *i),
                        _ => false,
                    };
                    // (a parameter's pointer: what the callers pass, as the summary says)
                    let param =
                        q.projection.is_empty() && (1..=body.arg_locals().len()).contains(&q.local);
                    let resolved = inline
                        && (param || {
                            ptr.lost.set(false);
                            ptr.cut.set(false);
                            ptr.cur_at.set(Some(At {
                                bb,
                                idx: block.statements.len(),
                            }));
                            let t = ptr.targets(q.local, &path_of_place(&q), 0);
                            !t.is_empty() && !ptr.lost.get() && !ptr.cut.get()
                        });
                    if !resolved {
                        open.insert(find(&mut parent, q.local));
                    }
                }
            }
            TerminatorKind::InlineAsm { .. } => {
                for (l, _) in cells.iter().enumerate().filter(|(_, c)| **c) {
                    open.insert(find(&mut parent, l));
                }
            }
            _ => {}
        }
    }
    ptr.lost.set(saved.0);
    ptr.cut.set(saved.1);
    ptr.cur_at.set(saved.2);
    let out: HashSet<Local> = (0..n)
        .filter(|&l| cells[l] && open.contains(&find(&mut parent, l)))
        .collect();
    if std::env::var_os("RCBOM_DEBUG_CELLS").is_some() && !out.is_empty() {
        let mut v: Vec<_> = out.iter().copied().collect();
        v.sort();
        let tys: Vec<String> = v
            .iter()
            .map(|l| format!("_{l}: {}", internal(body.locals()[*l].ty)))
            .collect();
        eprintln!(
            "rcbom-driver: open cells {:?}: {}",
            body.span,
            tys.join(", ")
        );
    }
    out
}
/// Reaching definitions at block entries (forward may-analysis with kills).
pub(super) fn reaching(
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
impl BitSet {
    pub(super) fn new(n: usize) -> Self {
        BitSet(vec![0; n.div_ceil(64)])
    }
    pub(super) fn insert(&mut self, i: usize) {
        self.0[i / 64] |= 1 << (i % 64);
    }
    pub(super) fn remove(&mut self, i: usize) {
        self.0[i / 64] &= !(1 << (i % 64));
    }
    pub(super) fn contains(&self, i: usize) -> bool {
        self.0[i / 64] & (1 << (i % 64)) != 0
    }
    /// Adds `other`; true if anything changed.
    pub(super) fn union_with(&mut self, other: &BitSet) -> bool {
        let mut changed = false;
        for (a, b) in self.0.iter_mut().zip(&other.0) {
            let n = *a | *b;
            changed |= n != *a;
            *a = n;
        }
        changed
    }
}
