//! The value of a place, an operand or an rvalue at a point: its definitions, their parts, calls,
//! aggregates, closures.

use super::*;

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

    pub(super) fn at_returns(&self, local: Local, rest: &[Step]) -> Origin {
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
    pub(super) fn read_fields(
        &self,
        ty: rustc_middle::ty::Ty<'tcx>,
        rest: &[Step],
        o: Origin,
    ) -> Origin {
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
                        } else if variant == Some(0)
                            && crate::path_of(tcx, adt.did()) == "core::result::Result"
                        {
                            // the value of a `Result` (`Ok(a) => a` in a match): its `Ok` side,
                            // which a constant's data does not say
                            o = Origin::Call {
                                callee: "core::result::Result::<T, E>::unwrap".to_string(),
                                krate: "core".to_string(),
                                self_ty: Some("core::result::Result".to_string()),
                                args: vec![o],
                                span: None,
                                runs: None,
                                pointer: None,
                                fed: None,
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
                            // an element of a tuple (held by a static or a constant, `PAIRS[i].0`,
                            // `NEST.0.1`: what its initializer puts there; a call's, a
                            // parameter's: the analysis projects it or says it does not)
                            o = Origin::Field {
                                adt: rcbom_facts::TUPLE.to_string(),
                                field: *f,
                                base: Box::new(o),
                                args: None,
                            };
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
    pub(super) fn local_ty(&self, local: Local) -> rustc_middle::ty::Ty<'tcx> {
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

    /// Definitions of `local` that reach the point `at`.
    pub(super) fn reaching_at(&self, local: Local, at: At) -> Vec<usize> {
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

    pub(super) fn budget(&self) -> bool {
        self.nodes.set(self.nodes.get() + 1);
        self.nodes.get() <= MAX_NODES
    }

    pub(super) fn operand(
        &self,
        op: &Operand,
        at: At,
        depth: usize,
        seen: &mut HashSet<Key>,
    ) -> Origin {
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

    pub(super) fn place(
        &self,
        local: Local,
        path: Path,
        at: At,
        depth: usize,
        seen: &mut HashSet<Key>,
    ) -> Origin {
        // past the query's budget nothing is followed, places either: reads of places that
        // reach operands only further down (a value before each write through a raw pointer,
        // `width(l, r)` in a loop) would recompute the same definitions without bound
        if path.len() > MAX_PATH || self.nodes.get() > MAX_NODES {
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
                // is of a part (`a.alg`): which part it wrote is not known, so not its value
                // either, only that this part may have changed (an unnamed part: a cut or lost
                // write, its own origin says so)
                let o = if f.is_empty() {
                    self.def_origin(d, &[], depth, seen)
                } else {
                    Origin::Through { callee: f }
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
        // a cell (in the value, or in what it owns) whose borrow escaped where its writes are
        // not followed (`open_cells`): what it holds may have been changed through that alias
        // (not one read through a borrow: the place it points to is its own)
        if self.flow().open_cells.contains(&local)
            && owns_cell(self.tcx, walk_ty(self.tcx, self.local_ty(local), &path))
            && !(0..path.len()).any(|i| {
                path[i] == Step::Deref
                    && matches!(
                        walk_ty(self.tcx, self.local_ty(local), &path[..i]).kind(),
                        rustc_middle::ty::TyKind::Ref(..) | rustc_middle::ty::TyKind::RawPtr(..)
                    )
            })
        {
            let o = Origin::Through {
                callee: format!(
                    "{} what a cell holds once a borrow of it went where its writes are not \
                     followed",
                    rcbom_facts::NOT_FOLLOWED
                ),
            };
            if !alts.contains(&o) {
                alts.push(o);
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
    pub(super) fn element_write(&self) -> Origin {
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
    pub(super) fn local_fn(&self, func: &Operand) -> bool {
        matches!(func.ty(self.body.locals()).ok().map(|t| t.kind()),
            Some(TyKind::RigidTy(RigidTy::FnDef(def, _)))
                if rustc_internal::internal(self.tcx, def.def_id()).is_local())
    }

    /// What a call of a function of the program (`d`, an out-parameter definition) writes
    /// through the argument pointing at the place: `Written`, which the links resolve to the
    /// values the function stores there. `None` for another crate's function, whose result
    /// stands for what it writes (`rng.fill_bytes(&mut c.key)`, `v.push(x)`).
    pub(super) fn written(&self, d: &Def, depth: usize, seen: &mut HashSet<Key>) -> Option<Origin> {
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
    pub(super) fn part_always_after(
        &self,
        defs: &[usize],
        j: usize,
        path: &[Step],
        at: At,
    ) -> bool {
        let e = &self.flow().defs[j];
        defs.iter()
            .map(|&i| &self.flow().defs[i])
            .filter(|d| is_prefix(&d.path, path))
            .all(|d| self.always_through(d, e.at, at))
    }

    /// Is definition `i`, of a whole that contains `path`, overwritten for `path` before the
    /// read at `at`: does a definition of a more specific place covering `path` (`c.key =
    /// [8; 32]` after `c = Cfg { key: env_key(), .. }`) lie on every way from `i` to `at`?
    pub(super) fn shadowed(&self, i: usize, defs: &[usize], path: &[Step], at: At) -> bool {
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
    pub(super) fn part_init(&self, d: &Def, rest: &[Step]) -> bool {
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
    pub(super) fn always_through(&self, d: &Def, via: At, to: At) -> bool {
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

    pub(super) fn def_origin(
        &self,
        d: &Def,
        rest: &[Step],
        depth: usize,
        seen: &mut HashSet<Key>,
    ) -> Origin {
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

    pub(super) fn call(
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

    pub(super) fn rvalue(
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
    pub(super) fn box_pointer(&self, q: &Place) -> Option<usize> {
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

    /// A value built of parts read whole: each part's value at its position (`Set`).
    pub(super) fn parts_at(
        &self,
        ops: &[Operand],
        at: At,
        depth: usize,
        seen: &mut HashSet<Key>,
    ) -> Origin {
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

    #[allow(clippy::too_many_arguments)]
    pub(super) fn aggregate(
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
                self.parts_at(ops, at, depth, seen)
            }
            // (and a tuple's elements at their positions: `(Algorithm::HS512, secret)` put in a
            // map and read back as `.0`; not literal data, below)
            AggregateKind::Tuple
                if rest.is_empty()
                    && ops.len() > 1
                    && !ops.iter().all(|o| {
                        matches!(o, Operand::Constant(_))
                            && matches!(self.operand(o, at, depth + 1, seen), Origin::Const { .. })
                    }) =>
            {
                self.parts_at(ops, at, depth, seen)
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
    pub(super) fn constant_part(
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
    pub(super) fn program_struct(&self, def: rustc_public::DefId) -> bool {
        let did = rustc_internal::internal(self.tcx, def);
        self.tcx.adt_def(did).is_struct()
            && !matches!(
                self.tcx.crate_name(did.krate).as_str(),
                "core" | "std" | "alloc"
            )
    }

    /// A closure's return value, with its captures' origins when the caller knows them.
    pub(super) fn follow_closure(
        &self,
        did: DefId,
        captures: Option<Vec<Origin>>,
        depth: usize,
    ) -> Origin {
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
    pub(super) fn entry_origin(&self, local: Local, rest: &[Step], depth: usize) -> Origin {
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

    pub(super) fn capture(&self, k: usize, tail: &[Step], depth: usize) -> Option<Origin> {
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
    pub(super) fn captures_from_parent(
        &self,
        k: usize,
        tail: &[Step],
        depth: usize,
    ) -> Option<Origin> {
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
}
