//! The walk from the entry points: reachable instances, statics and coercions (`Walker`, `Edges`).

use super::*;

/// Roots of the walk in a workspace member: `main`; for a library, its exported monomorphic
/// functions and exported statics; in any crate, what the linker keeps whatever calls it
/// (`#[no_mangle]`, `#[export_name]` functions, `#[used]` statics). Last, a library's generic
/// functions its users can call (not walked: only a caller has their type arguments).
#[allow(clippy::type_complexity)]
pub(super) fn roots(
    cx: &Cx<'_>,
) -> (
    Vec<Instance>,
    Vec<rustc_span::def_id::DefId>,
    Vec<rustc_span::def_id::DefId>,
) {
    use rustc_middle::middle::codegen_fn_attrs::CodegenFnAttrFlags as F;
    let tcx = cx.tcx;
    let vis = tcx.effective_visibilities(());
    let is_bin = rustc_public::entry_fn().is_some();
    let mut fns = Vec::new();
    if let Some(entry) = rustc_public::entry_fn()
        && let Ok(i) = Instance::try_from(entry)
    {
        fns.push(i);
    }
    for item in rustc_public::all_local_items() {
        if !matches!(item.kind(), ItemKind::Fn)
            || !item.has_body()
            || item.requires_monomorphization()
        {
            continue;
        }
        let did = rustc_internal::internal(tcx, item.def_id());
        let exported = !is_bin && did.as_local().is_some_and(|l| vis.is_exported(l));
        if (exported || tcx.codegen_fn_attrs(did).contains_extern_indicator())
            && let Ok(i) = Instance::try_from(item)
            && !fns.contains(&i)
        {
            fns.push(i);
        }
    }
    // a library: the non-generic functions its exported generic or inline functions call
    // (`pub fn hash(d: impl AsRef<[u8]>)` calling a private `fn inner(d: &[u8])`), which
    // every user of the library runs and rustc exports for them (`reachable_set`), and those
    // generic functions themselves
    let mut generic = Vec::new();
    if !is_bin {
        let reachable = tcx.reachable_set(());
        let mut extra: Vec<rustc_span::def_id::DefId> = tcx
            .hir_body_owners()
            .filter(|l| reachable.contains(l))
            .map(|l| l.to_def_id())
            .filter(|d| {
                matches!(
                    tcx.def_kind(*d),
                    rustc_hir::def::DefKind::Fn | rustc_hir::def::DefKind::AssocFn
                )
            })
            .collect();
        extra.sort_by_key(|d| def_hash(tcx, *d));
        for did in extra {
            let item = rustc_public::CrateItem(rustc_internal::stable(did));
            if !item.has_body() {
                continue;
            }
            if item.requires_monomorphization() {
                generic.push(did);
            } else if let Ok(i) = Instance::try_from(item)
                && !fns.contains(&i)
            {
                fns.push(i);
            }
        }
    }
    let mut statics = Vec::new();
    for did in tcx.hir_body_owners().map(|d| d.to_def_id()) {
        if !matches!(tcx.def_kind(did), rustc_hir::def::DefKind::Static { .. })
            || tcx.is_foreign_item(did)
        {
            continue;
        }
        let attrs = tcx.codegen_fn_attrs(did);
        let exported = !is_bin && did.as_local().is_some_and(|l| vis.is_exported(l));
        if exported
            || attrs.contains_extern_indicator()
            || attrs.flags.intersects(F::USED_COMPILER | F::USED_LINKER)
        {
            statics.push(did);
        }
    }
    (fns, statics, generic)
}
impl<'a, 'tcx> Walker<'a, 'tcx> {
    pub(super) fn new(cx: &'a mut Cx<'tcx>) -> Self {
        let limit = std::env::var("RCBOM_MAX_INSTANCES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(200_000);
        Walker {
            cx,
            queue: VecDeque::new(),
            seen: HashSet::new(),
            usage_seen: HashSet::new(),
            usage_statics: HashSet::new(),
            crates: BTreeSet::new(),
            parent: HashMap::new(),
            statics: BTreeSet::new(),
            static_refs: Vec::new(),
            static_seen: HashSet::new(),
            sites: Vec::new(),
            fns: Vec::new(),
            paths: Vec::new(),
            coercions: BTreeMap::new(),
            limit,
        }
    }

    pub(super) fn run(
        &mut self,
        roots: Vec<Instance>,
        static_roots: Vec<rustc_span::def_id::DefId>,
    ) -> Reach {
        for root in roots {
            self.enqueue(root, None);
        }
        for s in static_roots {
            self.reach_static(s);
        }
        let mut truncated = false;
        let mut usage_complete = true;
        while let Some((inst, usage)) = self.queue.pop_front() {
            if self.seen.len() > self.limit {
                truncated = true;
                break;
            }
            if usage && self.usage_seen.len() > self.limit {
                usage_complete = false;
                continue;
            }
            if catch_unwind(AssertUnwindSafe(|| self.visit(inst, usage))).is_err() {
                self.cx.errors += 1;
            }
        }
        let mut statics: Vec<DefRef> = std::mem::take(&mut self.static_refs);
        statics.sort_by(|a, b| a.id.cmp(&b.id));
        statics.dedup_by(|a, b| a.id == b.id);
        let mut fns = std::mem::take(&mut self.fns);
        fns.sort();
        fns.dedup();
        let mut paths = std::mem::take(&mut self.paths);
        paths.sort();
        paths.dedup();
        let tcx = self.cx.tcx;
        let crates = self
            .crates
            .iter()
            .filter(|c| !self.cx.local.contains(c))
            .map(|c| crate_ref(tcx, c.as_def_id()))
            .collect();
        Reach {
            instances: self.seen.len(),
            truncated,
            statics,
            fns,
            paths,
            crates,
            crates_complete: !truncated && usage_complete,
            points_to: None,
        }
    }

    pub(super) fn enqueue(
        &mut self,
        inst: Instance,
        from: Option<(Instance, Loc, Option<String>)>,
    ) {
        if matches!(
            inst.kind,
            InstanceKind::Virtual { .. } | InstanceKind::Intrinsic | InstanceKind::LlvmIntrinsic
        ) {
            return;
        }
        if self.seen.insert(inst) {
            if let Some(f) = from {
                self.parent.insert(inst, f);
            }
            self.queue.push_back((inst, false));
        }
    }

    /// Enqueues an instance a stop crate's code calls, walked for usage only: standard-library
    /// code only when instantiated with other crates' types (`Iterator::map` over its closure).
    pub(super) fn enqueue_usage(&mut self, inst: Instance) {
        if matches!(
            inst.kind,
            InstanceKind::Virtual { .. } | InstanceKind::Intrinsic | InstanceKind::LlvmIntrinsic
        ) || self.seen.contains(&inst)
        {
            return;
        }
        let tcx = self.cx.tcx;
        let i = rustc_internal::internal(tcx, inst);
        let std_crate =
            |did: rustc_span::def_id::DefId| self.cx.is_std(tcx.crate_name(did.krate).as_str());
        if std_crate(i.def_id())
            && !i.args.iter().any(|a| {
                a.walk().any(|g| {
                    g.as_type().is_some_and(|t| match t.kind() {
                        rustc_middle::ty::Adt(adt, _) => !std_crate(adt.did()),
                        rustc_middle::ty::Closure(d, _)
                        | rustc_middle::ty::Coroutine(d, _)
                        | rustc_middle::ty::FnDef(d, _) => !std_crate(*d),
                        _ => false,
                    })
                })
            })
        {
            return;
        }
        if self.usage_seen.insert(inst) {
            self.queue.push_back((inst, true));
        }
    }

    /// A static a stop crate's code refers to: the functions its value points at run too.
    pub(super) fn usage_static(&mut self, did: rustc_span::def_id::DefId) {
        let tcx = self.cx.tcx;
        if !self.usage_statics.insert(did) || tcx.is_foreign_item(did) {
            return;
        }
        self.crates.insert(did.krate);
        let Ok(s) = rustc_public::mir::mono::StaticDef::try_from(rustc_public::CrateItem(
            rustc_internal::stable(did),
        )) else {
            return;
        };
        let Some(a) = catch_unwind(AssertUnwindSafe(|| s.eval_initializer().ok()))
            .ok()
            .flatten()
        else {
            return;
        };
        let mut found = Vec::new();
        let mut nested = Vec::new();
        alloc_callees(tcx, &a, &mut found, &mut nested, &mut Vec::new(), 0);
        for i in found {
            self.enqueue_usage(i);
        }
        for n in nested {
            self.usage_static(rustc_internal::internal(tcx, n.def_id()));
        }
    }

    pub(super) fn via(&self, inst: Instance) -> Vec<ViaStep> {
        let mut out = Vec::new();
        let mut cur = inst;
        while let Some((p, loc, text)) = self.parent.get(&cur) {
            // only generic instantiations need the chain to explain their arguments
            if cur.args().0.is_empty() || out.len() >= 4 {
                break;
            }
            out.push(ViaStep {
                caller: instance_name(self.cx.tcx, p),
                span: loc.clone(),
                text: text.clone(),
            });
            cur = *p;
        }
        out
    }

    /// Code outside the stop crates and the standard library, or standard-library code
    /// instantiated with such code (`Iterator::map` over the user's closure): what a stop crate
    /// calls back.
    pub(super) fn calls_back(&self, callee: &Instance) -> bool {
        let tcx = self.cx.tcx;
        // a stop crate's own dependencies are its implementation (curve25519-dalek under
        // ed25519-dalek), not code it calls back
        let foreign = |did: rustc_span::def_id::DefId| {
            let k = tcx.crate_name(did.krate).to_string();
            !self.cx.stop_crate(did.krate) && !self.cx.is_std(&k) && !self.cx.impl_crate(did.krate)
        };
        let i = rustc_internal::internal(tcx, callee);
        if foreign(i.def_id()) {
            return true;
        }
        // a stop-crate or std function instantiated with user code (ring's `agree_ephemeral`
        // hands the user's closure to its internal `agree_ephemeral_`)
        i.args.iter().any(|a| {
            a.walk().any(|g| {
                g.as_type().is_some_and(|t| match t.kind() {
                    rustc_middle::ty::Adt(adt, _) => foreign(adt.did()),
                    rustc_middle::ty::Closure(d, _)
                    | rustc_middle::ty::Coroutine(d, _)
                    | rustc_middle::ty::FnDef(d, _) => foreign(*d),
                    _ => false,
                })
            })
        })
    }

    /// `usage`: walked only to learn which crates run (code a stop crate calls).
    pub(super) fn visit(&mut self, inst: Instance, usage: bool) {
        let did = rustc_internal::internal(self.cx.tcx, inst.def.def_id());
        self.crates.insert(did.krate);
        // Not `inst.has_body()`: in this rustc_public it asks about the instance's *def*, which
        // for a shim (`<closure as FnOnce>::call_once` behind a `dyn FnOnce`, as in every
        // `thread::spawn`) is a trait method without a body. `body()` checks the instance.
        let Some(body) = inst.body().map(|b| live_body(self.cx.tcx, &b)) else {
            return;
        };
        let mut edges = Edges {
            tcx: self.cx.tcx,
            body: &body,
            found: Vec::new(),
            coerced: Vec::new(),
            cur: None,
            unconvertible: has_unconvertible(self.cx.tcx, &body),
            errors: 0,
            dest: None,
        };
        edges.visit_body(&body);
        self.cx.errors += edges.errors;
        for (c, span, in_const) in std::mem::take(&mut edges.coerced) {
            // a vtable in a named constant's value (`KP.alg()` with `const KP: &dyn Konst =
            // &K1`): the coercion is written at the constant's item
            let tcx = self.cx.tcx;
            let item = in_const
                .then(|| const_item_at(tcx, did, rustc_internal::internal(tcx, span)))
                .flatten();
            let at = match item {
                Some(k) => locate(tcx, tcx.def_span(k)).0,
                None => locate_stable(tcx, span).0,
            };
            self.coerced(c, (at.line > 0).then_some(at), false);
        }
        // RCBOM_DEBUG_WALK=<substring>: print the edges out of matching instances
        let debug = std::env::var("RCBOM_DEBUG_WALK")
            .ok()
            .filter(|d| inst.name().contains(d.as_str()));
        if debug.is_some() {
            eprintln!("rcbom-walk: {} ({:?})", inst.name(), inst.kind);
        }
        let stop = self.cx.stop_crate(did.krate);
        if !usage
            && !stop
            && let Some(p) = self.cx.pta.as_mut()
        {
            p.add_body(self.cx.tcx, inst, &body);
        }
        // a shim's body is the compiler's (a `dyn` method behind a function pointer, drop glue,
        // `<closure as FnOnce>::call_once`): what it calls is walked, but none of it is code
        // written at the span it carries (the trait method's declaration)
        let shim = matches!(inst.kind, InstanceKind::Shim);
        if usage {
            let mut v = AllocStatics(Vec::new());
            v.visit_body(&body);
            for s in v.0 {
                self.usage_static(rustc_internal::internal(self.cx.tcx, s.def_id()));
            }
        } else if !stop && !shim {
            let owner = fn_owner(self.cx, &inst);
            self.fns.push(owner.id.clone());
            self.paths.push(path_of(self.cx.tcx, did));
            // an instance whose summaries the links record under its own name (a trait's
            // default body for a type, `<app::Legacy as app::Pick>::alg`)
            if let Some(n) =
                origins::body_name(self.cx.tcx, rustc_internal::internal(self.cx.tcx, inst))
                && n != path_of(self.cx.tcx, did)
            {
                self.paths.push(n);
            }
            let item = matches!(inst.kind, InstanceKind::Item);
            if item {
                // a generic fn's per-item sites are owned by its def-path hash
                self.fns.push(def_hash(self.cx.tcx, did));
            }
            let via = self.via(inst);
            // A monomorphic function is scanned in its item body, as the per-item scan does:
            // the types are the same, and the instance body has its named consts evaluated away
            // (`SSH_ED25519_RECIPIENT_KEY_LABEL` would read as a literal). The statics it
            // reaches are still taken from the instance body, where a const pointing at a static
            // has become that pointer.
            let generic =
                item && rustc_public::CrateItem(inst.def.def_id()).requires_monomorphization();
            let item_body = (item && !generic)
                .then(|| rustc_public::CrateItem(inst.def.def_id()).body())
                .flatten()
                .map(|b| live_body(self.cx.tcx, &b));
            let mut sites = Vec::new();
            let scanned = item_body.as_ref().unwrap_or(&body);
            // A generic instance (or a closure) must be scanned in its instance body, where the
            // types are concrete; its constants are named in the item's MIR at the same span.
            let inst_args = rustc_internal::internal(self.cx.tcx, inst).args;
            let lookup = (item && generic).then_some((did, inst_args));
            let mut sc = Scanner::new(
                self.cx,
                scanned,
                Some(did),
                owner.clone(),
                Tier::Reachable,
                via.clone(),
                &mut sites,
                lookup,
            );
            sc.visit_body(scanned);
            let mut statics = std::mem::take(&mut sc.statics);
            if item_body.is_some() {
                let mut v = AllocStatics(Vec::new());
                v.visit_body(&body);
                statics = v.0;
            }
            if item {
                let args = rustc_internal::internal(self.cx.tcx, inst).args;
                sites.extend(statics::fn_data_sites(
                    self.cx,
                    did,
                    Some(args),
                    &owner,
                    Tier::Reachable,
                    &via,
                ));
            }
            self.sites.extend(sites);
            for s in statics {
                self.reach_static(rustc_internal::internal(self.cx.tcx, s.def_id()));
            }
        }
        for (callee, span) in edges.found {
            if debug.is_some() {
                eprintln!("rcbom-walk:   -> {} ({:?})", callee.name(), callee.kind);
            }
            // inside an algorithm implementation, only what it calls back into is walked; the
            // rest for usage only
            if (usage || stop) && !(stop && self.calls_back(&callee)) {
                self.enqueue_usage(callee);
                continue;
            }
            let loc = locate_stable(self.cx.tcx, span).0;
            // the text of the function named at the call (`decrypt::aes_ctr::<Aes128Ctr>`: the
            // span is the callee's); none for a call through a value (the span is the call's)
            let internal = rustc_internal::internal(self.cx.tcx, span);
            let text = callee_span(self.cx.tcx, internal)
                .is_none()
                .then(|| span_text(self.cx.tcx, internal))
                .flatten();
            self.enqueue(callee, Some((inst, loc, text)));
        }
    }

    /// A type is coerced to a trait object at `at` (in a function's body, a constant's or a
    /// static's item; `in_static`: the static's value).
    pub(super) fn coerced(
        &mut self,
        (trait_path, ty, methods): Coerced,
        at: Option<Loc>,
        in_static: bool,
    ) {
        self.coercions
            .entry((trait_path, ty))
            .or_insert((at, in_static, methods));
    }

    /// A static is reached: remember it, and walk the function pointers and vtables in its
    /// value (rustls keeps its providers as `&dyn` objects inside statics).
    pub(super) fn reach_static(&mut self, did: rustc_span::def_id::DefId) {
        let tcx = self.cx.tcx;
        let r = def_ref_internal(tcx, did);
        if !self.static_seen.insert(r.id.clone()) {
            return;
        }
        self.statics.insert(r.id.clone());
        if self.cx.static_interesting(did) {
            self.static_refs.push(r);
        }
        if tcx.is_foreign_item(did) {
            return;
        }
        let s = match rustc_public::mir::mono::StaticDef::try_from(rustc_public::CrateItem(
            rustc_internal::stable(did),
        )) {
            Ok(s) => s,
            Err(_) => return,
        };
        let Some(a) = catch_unwind(AssertUnwindSafe(|| s.eval_initializer().ok()))
            .ok()
            .flatten()
        else {
            return;
        };
        let mut found = Vec::new();
        let mut nested = Vec::new();
        let mut coerced = Vec::new();
        alloc_callees(tcx, &a, &mut found, &mut nested, &mut coerced, 0);
        let at = locate(tcx, tcx.def_span(did)).0;
        for c in coerced {
            self.coerced(c, (at.line > 0).then(|| at.clone()), true);
        }
        for i in found {
            self.enqueue(i, None);
        }
        for n in nested {
            self.reach_static(rustc_internal::internal(tcx, n.def_id()));
        }
    }
}
impl MirVisitor for AllocStatics {
    fn visit_const_operand(&mut self, c: &ConstOperand, loc: Location) {
        if let ConstantKind::Allocated(a) = c.const_.kind() {
            alloc_statics(a, &mut self.0, &mut HashSet::new(), 0);
        }
        self.super_const_operand(c, loc);
    }
}
/// Is `local` used anywhere in `body` but where it is assigned whole, its storage marked or it
/// is dropped (a closure built and never called, passed on, stored or returned is not)?
pub(super) fn local_used(body: &Body, local: rustc_public::mir::Local) -> bool {
    struct Uses {
        local: rustc_public::mir::Local,
        used: bool,
    }
    impl MirVisitor for Uses {
        fn visit_statement(&mut self, stmt: &rustc_public::mir::Statement, loc: Location) {
            match &stmt.kind {
                StatementKind::StorageLive(_)
                | StatementKind::StorageDead(_)
                | StatementKind::FakeRead(..)
                | StatementKind::PlaceMention(_)
                | StatementKind::AscribeUserType { .. } => {}
                StatementKind::Assign(p, rv)
                    if p.local == self.local && p.projection.is_empty() =>
                {
                    self.visit_rvalue(rv, loc)
                }
                _ => self.super_statement(stmt, loc),
            }
        }
        fn visit_terminator(&mut self, term: &Terminator, loc: Location) {
            match &term.kind {
                TerminatorKind::Drop { place, .. } if place.local == self.local => {}
                _ => self.super_terminator(term, loc),
            }
        }
        fn visit_local(
            &mut self,
            local: &rustc_public::mir::Local,
            _: rustc_public::mir::visit::PlaceContext,
            _: Location,
        ) {
            self.used |= *local == self.local;
        }
        // (a debugger's name for it, `_never`, is no use)
        fn visit_var_debug_info(&mut self, _: &rustc_public::mir::VarDebugInfo) {}
    }
    if local == rustc_public::mir::RETURN_LOCAL {
        return true;
    }
    let mut u = Uses { local, used: false };
    u.visit_body(body);
    u.used
}
impl MirVisitor for Edges<'_, '_> {
    fn visit_statement(&mut self, stmt: &rustc_public::mir::Statement, loc: Location) {
        self.cur = Some(stmt.source_info.span);
        self.dest = match &stmt.kind {
            StatementKind::Assign(p, _) if p.projection.is_empty() => Some(p.local),
            _ => None,
        };
        self.super_statement(stmt, loc);
    }

    // a type `rustc_public` cannot convert (an `async` closure's) loses one edge, not the
    // instance's others; any other panic is a bug, counted
    fn visit_terminator(&mut self, term: &Terminator, loc: Location) {
        let r = catch_unwind(AssertUnwindSafe(|| self.edges_of_terminator(term, loc)));
        self.errors += usize::from(r.is_err_and(|e| !self.unconvertible && !async_closure(&e)));
    }

    fn visit_rvalue(&mut self, rv: &Rvalue, loc: Location) {
        let r = catch_unwind(AssertUnwindSafe(|| self.edges_of_rvalue(rv, loc)));
        self.errors += usize::from(r.is_err_and(|e| !self.unconvertible && !async_closure(&e)));
    }

    fn visit_const_operand(&mut self, c: &ConstOperand, loc: Location) {
        let r = catch_unwind(AssertUnwindSafe(|| self.edges_of_const(c, loc)));
        self.errors += usize::from(r.is_err_and(|e| !self.unconvertible && !async_closure(&e)));
    }
}
impl Edges<'_, '_> {
    pub(super) fn edges_of_terminator(&mut self, term: &Terminator, loc: Location) {
        self.cur = Some(term.source_info.span);
        match &term.kind {
            TerminatorKind::Call { func, .. } => {
                if let Ok(ty) = func.ty(self.body.locals())
                    && let Some(RigidTy::FnDef(def, args)) = ty.kind().rigid()
                    && let Ok(i) = Instance::resolve(*def, args)
                {
                    let span = match func {
                        Operand::Constant(c) => c.span,
                        _ => term.source_info.span,
                    };
                    self.found.push((i, span));
                }
            }
            TerminatorKind::Drop { place, .. } => {
                if let Ok(ty) = place.ty(self.body.locals()) {
                    let i = Instance::resolve_drop_in_place(ty);
                    if !i.is_empty_shim() {
                        self.found.push((i, term.source_info.span));
                    }
                }
            }
            _ => {}
        }
        self.super_terminator(term, loc);
    }

    pub(super) fn edges_of_rvalue(&mut self, rv: &Rvalue, loc: Location) {
        // a closure or coroutine built here: its body runs when it is called or polled, by
        // the code it is handed to or returned to (a library's `pub async fn`, a returned
        // `impl Fn`); built here, it is reachable from here
        if let Rvalue::Aggregate(kind, _) = rv {
            let built = match kind {
                rustc_public::mir::AggregateKind::Closure(def, args) => Some((def.def_id(), args)),
                rustc_public::mir::AggregateKind::Coroutine(def, args) => {
                    Some((def.def_id(), args))
                }
                rustc_public::mir::AggregateKind::CoroutineClosure(def, args) => {
                    Some((def.def_id(), args))
                }
                _ => None,
            };
            // (a closure built and never used, `let _never = || ..;`: not run from here)
            let unused = matches!(kind, rustc_public::mir::AggregateKind::Closure(..))
                && self.dest.is_some_and(|d| !local_used(self.body, d));
            if let Some((def, args)) = built
                && !unused
            {
                let did = rustc_internal::internal(self.tcx, def);
                let iargs = rustc_internal::internal(self.tcx, args);
                if !iargs.has_non_region_param() {
                    let i = rustc_middle::ty::Instance::new_raw(did, iargs);
                    let span = self.cur.unwrap_or(self.body.span);
                    self.found.push((rustc_internal::stable(i), span));
                }
            }
        }
        if let Rvalue::Cast(kind, op, target) = rv {
            let span = self.cur.unwrap_or(self.body.span);
            if let Ok(src) = op.ty(self.body.locals()) {
                match kind {
                    CastKind::PointerCoercion(PointerCoercion::ReifyFnPointer(_)) => {
                        if let Some(RigidTy::FnDef(def, args)) = src.kind().rigid()
                            && let Ok(i) = Instance::resolve_for_fn_ptr(*def, args)
                        {
                            self.found.push((i, span));
                        }
                    }
                    CastKind::PointerCoercion(PointerCoercion::ClosureFnPointer(_)) => {
                        if let Some(RigidTy::Closure(def, args)) = src.kind().rigid()
                            && let Ok(i) =
                                Instance::resolve_closure(*def, args, ClosureKind::FnOnce)
                        {
                            self.found.push((i, span));
                        }
                    }
                    CastKind::PointerCoercion(PointerCoercion::Unsize) => {
                        if let Some((concrete, dynamic)) = unsize_tails(&src, target) {
                            let c = rustc_internal::internal(self.tcx, concrete);
                            if let rustc_middle::ty::Dynamic(preds, ..) =
                                rustc_internal::internal(self.tcx, dynamic).kind()
                                && let Some(c) = coercion(self.tcx, c, preds)
                            {
                                self.coerced.push((c, span, false));
                            }
                            for i in vtable_methods(self.tcx, concrete, dynamic) {
                                self.found.push((i, span));
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        self.super_rvalue(rv, loc);
    }

    pub(super) fn edges_of_const(&mut self, c: &ConstOperand, loc: Location) {
        if let ConstantKind::Allocated(a) = c.const_.kind() {
            let mut found = Vec::new();
            let mut coerced = Vec::new();
            alloc_callees(self.tcx, a, &mut found, &mut Vec::new(), &mut coerced, 0);
            self.found.extend(found.into_iter().map(|i| (i, c.span)));
            self.coerced
                .extend(coerced.into_iter().map(|x| (x, c.span, true)));
        }
        self.super_const_operand(c, loc);
    }
}
/// Function pointers and vtables inside a constant's memory; statics are reported separately.
pub(super) fn alloc_callees(
    tcx: TyCtxt<'_>,
    a: &Allocation,
    found: &mut Vec<Instance>,
    statics: &mut Vec<rustc_public::mir::mono::StaticDef>,
    coerced: &mut Vec<Coerced>,
    depth: usize,
) {
    if depth > 8 {
        return;
    }
    for (_, prov) in &a.provenance.ptrs {
        match GlobalAlloc::from(prov.0) {
            GlobalAlloc::Function(i) => found.push(i),
            GlobalAlloc::Memory(m) => alloc_callees(tcx, &m, found, statics, coerced, depth + 1),
            GlobalAlloc::Static(s) => statics.push(s),
            GlobalAlloc::VTable(..) => {
                let id = rustc_internal::internal(tcx, prov.0);
                if let rustc_middle::mir::interpret::GlobalAlloc::VTable(ty, preds) =
                    tcx.global_alloc(id)
                {
                    // as for an unsizing coercion: the methods and the type's drop glue
                    coerced.extend(coercion(tcx, ty, preds));
                    found.extend(vtable_methods_internal(tcx, ty, preds));
                    found.push(Instance::resolve_drop_in_place(rustc_internal::stable(ty)));
                }
            }
            GlobalAlloc::TypeId { .. } => {}
        }
    }
}
/// For an unsizing coercion `P<T> -> P<dyn Trait>`, the pair `(T, dyn Trait)`.
pub(super) fn unsize_tails(src: &Ty, dst: &Ty) -> Option<(Ty, Ty)> {
    let (s, d) = (src.kind(), dst.kind());
    let (s, d) = (s.rigid()?, d.rigid()?);
    match (s, d) {
        (_, RigidTy::Dynamic(..)) => Some((*src, *dst)),
        (
            RigidTy::Ref(_, a, _) | RigidTy::RawPtr(a, _),
            RigidTy::Ref(_, b, _) | RigidTy::RawPtr(b, _),
        ) => unsize_tails(a, b),
        (RigidTy::Adt(da, aa), RigidTy::Adt(db, ab)) if da == db => aa
            .0
            .iter()
            .zip(ab.0.iter())
            .find_map(|(x, y)| match (x, y) {
                (GenericArgKind::Type(x), GenericArgKind::Type(y)) if x != y => unsize_tails(x, y),
                _ => None,
            }),
        _ => None,
    }
}
/// A coercion of `concrete` to a trait object with predicates `preds`: the trait's path, the
/// type's (an ADT's defining path with its type arguments, `app::W<app::A>`; `dyn` and the
/// trait of another trait object; any other type as rustc prints it), and for each method of
/// the object the body it runs for the type (`origins::body_name`).
pub(super) fn coercion<'tcx>(
    tcx: TyCtxt<'tcx>,
    concrete: rustc_middle::ty::Ty<'tcx>,
    preds: &'tcx rustc_middle::ty::List<rustc_middle::ty::PolyExistentialPredicate<'tcx>>,
) -> Option<Coerced> {
    let t = path_of(tcx, preds.principal_def_id()?);
    let ty = match concrete.kind() {
        rustc_middle::ty::Adt(adt, _) => {
            type_name(tcx, concrete).unwrap_or_else(|| path_of(tcx, adt.did()))
        }
        // an upcast (`&dyn Sub` to `&dyn Super`): the types coerced to `Sub`; none for the
        // same trait (a reborrow)
        rustc_middle::ty::Dynamic(p, ..) => {
            let sub = path_of(tcx, p.principal_def_id()?);
            if sub == t {
                return None;
            }
            format!("dyn {sub}")
        }
        _ => concrete.to_string(),
    };
    // each method of the vtable: the trait's item it is, and the body it runs
    let methods = if concrete.is_trait() {
        Vec::new()
    } else {
        let principal = preds.principal()?;
        let trait_ref = principal.with_self_ty(tcx, concrete);
        let trait_ref = tcx.instantiate_bound_regions_with_erased(trait_ref);
        tcx.vtable_entries(trait_ref)
            .iter()
            .filter_map(|e| match e {
                rustc_middle::ty::VtblEntry::Method(i) => Some(*i),
                _ => None,
            })
            .filter_map(|i| {
                let d = i.def_id();
                let item = if tcx.trait_of_assoc(d).is_some() {
                    d
                } else {
                    tcx.trait_item_of(d)?
                };
                Some((
                    path_of(tcx, item),
                    crate::origins::body_name(tcx, i)?,
                    crate::links::method_sig(tcx, i.def_id(), i.args),
                ))
            })
            .collect()
    };
    Some((t, ty, methods))
}
/// The named constant a body's constant operand at `span` is (`KP` in `KP.alg()`), read from
/// the item's MIR, where it is not evaluated away.
pub(super) fn const_item_at(
    tcx: TyCtxt<'_>,
    did: rustc_span::def_id::DefId,
    span: rustc_span::Span,
) -> Option<rustc_span::def_id::DefId> {
    use rustc_middle::mir::visit::Visitor;
    struct V {
        span: rustc_span::Span,
        out: Option<rustc_span::def_id::DefId>,
    }
    impl<'tcx> Visitor<'tcx> for V {
        fn visit_const_operand(
            &mut self,
            c: &rustc_middle::mir::ConstOperand<'tcx>,
            _: rustc_middle::mir::Location,
        ) {
            if c.span == self.span
                && let rustc_middle::mir::Const::Unevaluated(uv, _) = c.const_
                && uv.promoted.is_none()
            {
                self.out = Some(uv.def);
            }
        }
    }
    if !tcx.is_mir_available(did) || tcx.is_closure_like(did) && !did.is_local() {
        return None;
    }
    let mut v = V { span, out: None };
    v.visit_body(tcx.optimized_mir(did));
    v.out
}
pub(super) fn vtable_methods(tcx: TyCtxt<'_>, concrete: Ty, dynamic: Ty) -> Vec<Instance> {
    let c = rustc_internal::internal(tcx, concrete);
    let d = rustc_internal::internal(tcx, dynamic);
    let mut out = Vec::new();
    if let rustc_middle::ty::Dynamic(preds, ..) = d.kind() {
        out = vtable_methods_internal(tcx, c, preds);
    }
    out.push(Instance::resolve_drop_in_place(concrete));
    out
}
pub(super) fn vtable_methods_internal<'tcx>(
    tcx: TyCtxt<'tcx>,
    concrete: rustc_middle::ty::Ty<'tcx>,
    preds: &'tcx rustc_middle::ty::List<rustc_middle::ty::PolyExistentialPredicate<'tcx>>,
) -> Vec<Instance> {
    let Some(principal) = preds.principal() else {
        return Vec::new();
    };
    let trait_ref = principal.with_self_ty(tcx, concrete);
    let trait_ref = tcx.instantiate_bound_regions_with_erased(trait_ref);
    tcx.vtable_entries(trait_ref)
        .iter()
        .filter_map(|e| match e {
            rustc_middle::ty::VtblEntry::Method(i) => Some(rustc_internal::stable(*i)),
            _ => None,
        })
        .collect()
}
