//! The per-item scan: the sites a body or an initializer names (`Scanner`).

use super::*;

/// Statics an allocation points at, following plain memory but not into other statics.
pub(super) fn alloc_statics(
    a: &Allocation,
    out: &mut Vec<rustc_public::mir::mono::StaticDef>,
    seen: &mut HashSet<rustc_public::mir::alloc::AllocId>,
    depth: usize,
) {
    if depth > 8 {
        return;
    }
    for (_, prov) in &a.provenance.ptrs {
        if !seen.insert(prov.0) {
            continue;
        }
        match GlobalAlloc::from(prov.0) {
            GlobalAlloc::Static(s) => out.push(s),
            GlobalAlloc::Memory(m) => alloc_statics(&m, out, seen, depth + 1),
            _ => {}
        }
    }
}
/// Is a caught panic `rustc_public`'s for an `async` closure's type, which it cannot convert
/// yet ("FIXME(async_closures)"), wherever the type sits (a capture's field, a callee's
/// generic argument)?
pub(crate) fn async_closure(e: &Box<dyn std::any::Any + Send>) -> bool {
    let msg = e
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| e.downcast_ref::<&str>().copied())
        .unwrap_or("");
    msg.contains("FIXME(async_closures)")
}
/// Does a local of `body` have a type `rustc_public` cannot convert yet? An `async` closure's
/// (`CoroutineClosure`): converting it panics ("FIXME(async_closures): Lower these to SMIR").
/// Reading a statement or call that involves one is a known limit of the interface, not a bug.
pub(crate) fn has_unconvertible(tcx: TyCtxt<'_>, body: &Body) -> bool {
    let unconvertible = |ty: rustc_public::ty::Ty| {
        rustc_internal::internal(tcx, ty).walk().any(|g| {
            g.as_type()
                .is_some_and(|t| matches!(t.kind(), rustc_middle::ty::CoroutineClosure(..)))
        })
    };
    // in a local's type, or in a callee's generic arguments (`apply::<{async closure}>`)
    body.locals().iter().any(|l| unconvertible(l.ty))
        || body.blocks.iter().any(|b| match &b.terminator.kind {
            rustc_public::mir::TerminatorKind::Call { func, .. } => {
                func.ty(body.locals()).is_ok_and(unconvertible)
            }
            _ => false,
        })
}
impl<'a, 'tcx> Scanner<'a, 'tcx> {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        cx: &'a mut Cx<'tcx>,
        body: &'a Body,
        def: Option<rustc_span::def_id::DefId>,
        owner: Owner,
        tier: Tier,
        via: Vec<ViaStep>,
        out: &'a mut Vec<Site>,
        item: Option<(
            rustc_span::def_id::DefId,
            rustc_middle::ty::GenericArgsRef<'tcx>,
        )>,
    ) -> Self {
        let mut origins = origins::Origins::new(cx.tcx, body, def);
        if let Some((item, args)) = item {
            origins = origins.with_item(item, args);
        }
        let unconvertible = has_unconvertible(cx.tcx, body);
        Scanner {
            cx,
            body,
            owner,
            tier,
            via,
            out,
            statics: Vec::new(),
            origins,
            unconvertible,
            def,
            lib_generic: false,
        }
    }

    pub(super) fn push_internal(&mut self, mut internal: rustc_span::Span, target: Target) {
        // code a derive generates with an input token's span (`quote_spanned!` at a field's
        // name): the derive's, not the field's
        if !internal.from_expansion()
            && let Some(did) = self.def
            && let Some(call) = derive_site(self.cx.tcx, did)
        {
            internal = call;
        }
        let text = span_text(self.cx.tcx, internal);
        let line_text = line_text(self.cx.tcx, internal);
        let (span, expansion) = locate(self.cx.tcx, internal);
        if span.line == 0 {
            // compiler-generated code (shims), and operands an optimization rebuilt, have no
            // source position
            if std::env::var_os("RCBOM_DEBUG").is_some() {
                eprintln!(
                    "rcbom-driver: site without a position dropped in {}: {:?}",
                    self.owner.name, target
                );
            }
            return;
        }
        self.out.push(Site {
            tier: self.tier,
            owner: self.owner.clone(),
            span,
            text,
            line_text,
            expansion,
            target,
            via: self.via.clone(),
        });
    }

    /// A call through a pointer or a trait object of a function: at its callee, with where the
    /// pointer comes from; an unknown pointer when that is not known or the call has no callee
    /// to place it at (the analysis takes it as a call of any function made a pointer).
    pub(super) fn push_pointer(
        &mut self,
        origin: Origin,
        const_args: Vec<Option<i128>>,
        arg_origins: Vec<Origin>,
        arg_lens: Vec<Option<u64>>,
        sig: Option<String>,
        term: &Terminator,
    ) {
        let tcx = self.cx.tcx;
        let at = rustc_internal::internal(tcx, term.source_info.span);
        let (call, origin) = match callee_span(tcx, at) {
            Some(call) if !matches!(origin, Origin::Truncated) => (call, origin),
            Some(call) => (call, Origin::Unknown),
            None => (at, Origin::Unknown),
        };
        self.push_internal(
            call,
            Target::Pointer {
                origin,
                const_args,
                arg_origins,
                arg_lens,
                sig,
            },
        );
    }

    /// Is a call (or a function used as a value) of `def::<args>` a crypto fact?
    pub(super) fn interesting(&self, def: &rustc_public::ty::FnDef, args: &GenericArgs) -> bool {
        let tcx = self.cx.tcx;
        let did = rustc_internal::internal(tcx, def.def_id());
        let iargs = rustc_internal::internal(tcx, args);
        // not monomorphic (`<A as KeyInit>::new_from_slice`, `Hkdf::<<Kdf as Kdf>::Hash>`):
        // the walk sees the instances; in a library's generic function its users can call,
        // which only they instantiate, a call into a KB crate is kept with its types as
        // parameters (`Sha256::digest::<impl AsRef<[u8]>>`, `v.shuffle::<R>(rng)`)
        if iargs.has_non_region_param() || iargs.has_aliases() {
            return self.lib_generic && self.cx.kb_crate(did.krate);
        }
        let krate = tcx.crate_name(did.krate).to_string();
        if self.cx.kb_crate(did.krate) {
            return true;
        }
        let trees = arg_trees(tcx, &args.0, 0);
        if !trees.iter().any(|t| tree_mentions(t, self.cx)) {
            return false;
        }
        if self.cx.is_std(&krate) {
            // `Result::unwrap`, `Vec::push`, `Clone::clone`, drop glue: the standard library
            // handling a crypto value is not a use of it. Constructors and conversions the
            // crypto type implements are: `<Argon2 as Default>::default()`,
            // `StaticSecret::from([7u8; 32])`, `SigningKey::try_from(bytes)`, `bytes.into()`;
            // so is data written into it through its `io::Write` impl (`h.write_all(data)`,
            // `io::copy(&mut file, &mut h)` hashing a file)
            let Some(tr) = tcx.trait_of_assoc(did) else {
                return path_of(tcx, did).ends_with("io::copy::copy")
                    && matches!(trees.get(1), Some(TyTree::Adt { krate, .. }) if self.cx.kb_ref(krate));
            };
            let name = tcx.get_diagnostic_name(tr).map(|s| s.to_string());
            let constructed = match name.as_deref() {
                Some("Default" | "From" | "TryFrom" | "FromStr" | "IoWrite") => trees.first(),
                // `Into<T>`: `Self` is the source, `T` the crypto type
                Some("Into" | "TryInto") => trees.get(1),
                _ => None,
            };
            return matches!(
                constructed,
                Some(TyTree::Adt { krate, .. }) if self.cx.kb_ref(krate)
            );
        }
        // another crate's generic function with a crypto type as argument: a crypto fact only
        // if that parameter is bounded by a trait of a KB crate (`fn seal<A: Aead>`), not a
        // container (`Mutex::new(cipher)`)
        kb_bounded(tcx, did, iargs, &|c| self.cx.kb_crate(c))
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn record_call(
        &mut self,
        def: &rustc_public::ty::FnDef,
        args: &GenericArgs,
        span: Span,
        call: Option<(&[Operand], &Terminator)>,
    ) {
        let internal = rustc_internal::internal(self.cx.tcx, span);
        self.record_call_at(def, args, internal, call, None);
    }

    /// `record_call` at a compiler span; `through`: where the function a pointer call calls was
    /// named.
    pub(super) fn record_call_at(
        &mut self,
        def: &rustc_public::ty::FnDef,
        args: &GenericArgs,
        span: rustc_span::Span,
        call: Option<(&[Operand], &Terminator)>,
        through: Option<Loc>,
    ) {
        let tcx = self.cx.tcx;
        let did = rustc_internal::internal(tcx, def.def_id());
        let callee = def_ref_internal(tcx, did);
        let method = strip_generics(&callee.path)
            .rsplit("::")
            .next()
            .unwrap_or_default()
            .to_string();
        let (mut self_ty, mut own) = split_self(tcx, def.def_id(), args);
        // `bytes.into()` constructs its target: the crypto type is the one the call is about
        if let Some(tr) = tcx.trait_of_assoc(did)
            && matches!(
                tcx.get_diagnostic_name(tr)
                    .map(|s| s.to_string())
                    .as_deref(),
                Some("Into" | "TryInto")
            )
            && !own.is_empty()
        {
            self_ty = Some(own.remove(0));
        }
        // `io::copy(&mut reader, &mut h)` writes into its writer: the crypto type it is about
        if self_ty.is_none() && own.len() == 2 && path_of(tcx, did).ends_with("io::copy::copy") {
            self_ty = Some(own.remove(1));
        }
        let (const_args, arg_origins, arg_lens) = match call {
            Some((call_args, term)) => self.call_values(call_args, term),
            None => (Vec::new(), Vec::new(), Vec::new()),
        };
        self.push_internal(
            span,
            Target::Call {
                callee,
                method,
                self_ty,
                args: own,
                const_args,
                arg_origins,
                arg_lens,
                through,
                value: call.is_none(),
            },
        );
    }

    /// The value arguments of a call: integer constants, origins, array lengths.
    #[allow(clippy::type_complexity)]
    pub(super) fn call_values(
        &self,
        call_args: &[Operand],
        term: &Terminator,
    ) -> (Vec<Option<i128>>, Vec<Origin>, Vec<Option<u64>>) {
        let origins: Vec<Origin> = call_args
            .iter()
            .map(|a| self.origins.of_arg(a, term))
            .collect();
        let consts = call_args
            .iter()
            .zip(&origins)
            .map(|(a, o)| {
                const_int(a).or(match o {
                    Origin::Const { value, .. }
                    | Origin::Data { value, .. }
                    | Origin::Unit { value, .. } => *value,
                    _ => None,
                })
            })
            .collect();
        let lens = call_args
            .iter()
            .map(|a| self.origins.array_len(a, term))
            .collect();
        (consts, origins, lens)
    }

    /// A call of function `def` held in a pointer or a place, named at `named`: the operation
    /// runs at the call (cited at its callee expression); the function was named where it was
    /// made the value. At the naming when the call has no callee expression in source.
    pub(super) fn record_through(
        &mut self,
        def: &rustc_public::ty::FnDef,
        args: &GenericArgs,
        named: Span,
        call_args: &[Operand],
        term: &Terminator,
    ) {
        let tcx = self.cx.tcx;
        let named = rustc_internal::internal(tcx, named);
        let call = callee_span(tcx, rustc_internal::internal(tcx, term.source_info.span));
        let through = Some(locate(tcx, named).0).filter(|l| l.line != 0);
        match (call, through) {
            (Some(call), Some(t)) => {
                self.record_call_at(def, args, call, Some((call_args, term)), Some(t))
            }
            _ => self.record_call_at(def, args, named, Some((call_args, term)), None),
        }
    }

    /// A KB function used as a value (`iter.map(Sha256::digest)`, `let h: fn(..) = digest`):
    /// recorded where it is named (`Call::value`).
    pub(super) fn function_value(&mut self, op: &Operand) {
        if let Operand::Constant(c) = op
            && let Some(RigidTy::FnDef(def, args)) = c.const_.ty().kind().rigid()
            && self.interesting(def, args)
        {
            self.record_call(def, args, c.span, None);
        }
    }
}
/// The callee expression of a call written in source (`h` of `h(x)`, `(h.f)` of `(h.f)(x)`,
/// `get()` of `get()(x)`, `fs[0]` of `fs[0](x)`): what precedes the argument list, the last
/// parenthesised group of the call's text; `None` when the call is not written as one (a
/// macro's, an operator's).
pub(crate) fn callee_span(tcx: TyCtxt<'_>, call: rustc_span::Span) -> Option<rustc_span::Span> {
    if call.from_expansion() {
        return None;
    }
    let text = tcx.sess.source_map().span_to_snippet(call).ok()?;
    let len = args_start(&text)?;
    let callee = text[..len].trim_end();
    if callee.is_empty() {
        return None;
    }
    Some(call.with_hi(call.lo() + rustc_span::BytePos(callee.len() as u32)))
}
/// Where the last top-level parenthesised group of `text` starts, when it ends the text:
/// brackets inside string and character literals do not count.
pub(super) fn args_start(text: &str) -> Option<usize> {
    let b = text.as_bytes();
    let (mut depth, mut i, mut last, mut closed_at) = (0usize, 0usize, None, None);
    while i < b.len() {
        match b[i] {
            b'"' => {
                i += 1;
                while i < b.len() && b[i] != b'"' {
                    i += if b[i] == b'\\' { 2 } else { 1 };
                }
            }
            // a character literal (`'('`, `'\''`), not a lifetime (`'a`)
            b'\'' if b.get(i + 2) == Some(&b'\'') => i += 2,
            b'\'' if b.get(i + 1) == Some(&b'\\') => {
                // past the backslash and the escaped character
                i += 3;
                while i < b.len() && b[i] != b'\'' {
                    i += 1;
                }
            }
            b'(' | b'[' | b'{' => {
                if depth == 0 && b[i] == b'(' {
                    last = Some(i);
                }
                depth += 1;
            }
            b')' | b']' | b'}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    closed_at = Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    let end = text.trim_end().len().checked_sub(1)?;
    (depth == 0 && closed_at == Some(end) && b[end] == b')').then_some(last?)
}
/// The body without the blocks no execution reaches: those behind a branch on a constant
/// (`if cfg!(debug_assertions)` is `if false` in a release build, which MIR level 0 keeps).
/// Their statements are dropped and their terminators made `unreachable`.
pub(super) fn live_body(
    tcx: TyCtxt<'_>,
    body: &rustc_public::mir::Body,
) -> rustc_public::mir::Body {
    let n = body.blocks.len();
    let mut live = vec![false; n];
    let mut work = vec![0usize];
    while let Some(b) = work.pop() {
        if b >= n || live[b] {
            continue;
        }
        live[b] = true;
        let block = &body.blocks[b];
        match &block.terminator.kind {
            TerminatorKind::SwitchInt { discr, targets } => match switch_value(tcx, block, discr) {
                Some(v) => work.push(
                    targets
                        .branches()
                        .find(|(x, _)| *x == v)
                        .map(|(_, t)| t)
                        .unwrap_or(targets.otherwise()),
                ),
                None => work.extend(block.terminator.successors()),
            },
            _ => work.extend(block.terminator.successors()),
        }
    }
    let mut out = body.clone();
    for (b, l) in live.iter().enumerate() {
        if !l {
            out.blocks[b].statements.clear();
            out.blocks[b].terminator.kind = TerminatorKind::Unreachable;
        }
    }
    out
}
/// The value a block switches on, when it is a constant: given directly, or assigned to the
/// switched local earlier in the block (`_3 = const false; switchInt(move _3)`).
pub(super) fn switch_value(
    tcx: TyCtxt<'_>,
    block: &rustc_public::mir::BasicBlock,
    discr: &Operand,
) -> Option<u128> {
    let c = match discr {
        Operand::Constant(c) => c.clone(),
        Operand::Copy(p) | Operand::Move(p) if p.projection.is_empty() => {
            let rv = block.statements.iter().rev().find_map(|s| match &s.kind {
                rustc_public::mir::StatementKind::Assign(q, rv)
                    if q.local == p.local && q.projection.is_empty() =>
                {
                    Some(rv)
                }
                _ => None,
            })?;
            match rv {
                Rvalue::Use(Operand::Constant(c), _) => c.clone(),
                // `match MODE` with `const MODE: Mode = Mode::Fast`: the discriminant of the
                // variant the constant the block gave the matched local holds
                Rvalue::Discriminant(q) if q.projection.is_empty() => {
                    let c = block.statements.iter().rev().find_map(|s| match &s.kind {
                        rustc_public::mir::StatementKind::Assign(r, rv)
                            if r.local == q.local && r.projection.is_empty() =>
                        {
                            Some(rv)
                        }
                        _ => None,
                    })?;
                    let Rvalue::Use(Operand::Constant(c), _) = c else {
                        return None;
                    };
                    let k = rustc_internal::internal(tcx, &c.const_);
                    return statics::enum_discriminant(tcx, &k).map(|v| v.to_bits_unchecked());
                }
                _ => return None,
            }
        }
        _ => return None,
    };
    match c.const_.kind() {
        ConstantKind::Allocated(a) => a.read_uint().ok(),
        // a named constant (`if FLAG`), evaluated when it does not depend on generics
        ConstantKind::Unevaluated(_) => {
            use rustc_middle::ty::TypeVisitableExt;
            let k = rustc_internal::internal(tcx, &c.const_);
            if k.ty().has_non_region_param() || !statics::evaluable_const(tcx, &k, None) {
                return None;
            }
            k.try_eval_bits(tcx, rustc_middle::ty::TypingEnv::fully_monomorphized())
        }
        _ => None,
    }
}
pub(super) fn strip_generics(path: &str) -> String {
    let mut out = String::new();
    let mut depth = 0usize;
    for ch in path.chars() {
        match ch {
            '<' => depth += 1,
            '>' => depth = depth.saturating_sub(1),
            _ if depth == 0 => out.push(ch),
            _ => {}
        }
    }
    out.replace("::::", "::")
}
/// Does a generic argument that names a KB type stand for a parameter bounded by a trait of
/// a KB crate?
pub(super) fn kb_bounded<'tcx>(
    tcx: TyCtxt<'tcx>,
    did: rustc_span::def_id::DefId,
    args: rustc_middle::ty::GenericArgsRef<'tcx>,
    kb: &dyn Fn(rustc_span::def_id::CrateNum) -> bool,
) -> bool {
    let clauses = tcx.clauses_of(did).instantiate_identity(tcx);
    clauses.clauses.into_iter().any(|c| {
        let Some(tc) = c.skip_norm_wip().as_trait_clause() else {
            return false;
        };
        let tc = tc.skip_binder();
        if !kb(tc.def_id().krate) {
            return false;
        }
        let rustc_middle::ty::Param(p) = tc.self_ty().kind() else {
            return false;
        };
        args.get(p.index as usize)
            .and_then(|a| a.as_type())
            .is_some_and(|t| {
                t.walk().any(|g| {
                    g.as_type().is_some_and(|t| match t.kind() {
                        rustc_middle::ty::Adt(adt, _) => kb(adt.did().krate),
                        _ => false,
                    })
                })
            })
    })
}
impl MirVisitor for Scanner<'_, '_> {
    // a panic loses the call, rvalue or constant it was raised in, not the function: an
    // `async` closure's type is lost this way (`has_unconvertible`); any other panic is a bug,
    // counted as one
    fn visit_terminator(&mut self, term: &Terminator, loc: Location) {
        let r = catch_unwind(AssertUnwindSafe(|| self.scan_terminator(term, loc)));
        self.caught(r.err(), "a call");
    }

    fn visit_rvalue(&mut self, rv: &Rvalue, loc: Location) {
        let r = catch_unwind(AssertUnwindSafe(|| self.scan_rvalue(rv, loc)));
        self.caught(r.err(), "a value");
    }

    fn visit_const_operand(&mut self, c: &ConstOperand, loc: Location) {
        let r = catch_unwind(AssertUnwindSafe(|| self.scan_const(c, loc)));
        self.caught(r.err(), "a constant");
    }
}
impl Scanner<'_, '_> {
    pub(super) fn caught(&mut self, panic: Option<Box<dyn std::any::Any + Send>>, what: &str) {
        let Some(e) = panic else {
            return;
        };
        let unconvertible = self.unconvertible || async_closure(&e);
        if !unconvertible {
            self.cx.errors += 1;
        }
        if std::env::var_os("RCBOM_DEBUG").is_some() {
            eprintln!(
                "rcbom-driver: {what} in {} could not be read{}",
                self.owner.name,
                if unconvertible {
                    " (an async closure's type, which rustc_public cannot convert)"
                } else {
                    ""
                }
            );
        }
    }
}
/// A call of `Fn::call`, `FnMut::call_mut` or `FnOnce::call_once` on a trait object (`dyn
/// Fn(..)`, behind a reference or a `Box`).
pub(super) fn dyn_fn_call(
    tcx: TyCtxt<'_>,
    def: &rustc_public::ty::FnDef,
    args: &rustc_public::ty::GenericArgs,
) -> bool {
    fn dynamic(t: &Ty, depth: usize) -> bool {
        match t.kind().rigid() {
            Some(RigidTy::Dynamic(..)) => true,
            Some(RigidTy::Ref(_, t, _)) if depth < 4 => dynamic(t, depth + 1),
            Some(RigidTy::Adt(adt, a)) if depth < 4 && adt.is_box() => match a.0.first() {
                Some(GenericArgKind::Type(t)) => dynamic(t, depth + 1),
                _ => false,
            },
            _ => false,
        }
    }
    let did = rustc_internal::internal(tcx, def.def_id());
    let path = path_of(tcx, did);
    matches!(
        path.as_str(),
        "core::ops::function::Fn::call"
            | "core::ops::function::FnMut::call_mut"
            | "core::ops::function::FnOnce::call_once"
    ) && matches!(args.0.first(), Some(GenericArgKind::Type(t)) if dynamic(t, 0))
}
/// The operands a tuple argument was built from (`(a, b)` passed to `Fn::call`), when the body
/// builds it in one statement.
pub(super) fn untuple(body: &Body, tuple: &Operand) -> Option<Vec<Operand>> {
    let (Operand::Copy(p) | Operand::Move(p)) = tuple else {
        return None;
    };
    if !p.projection.is_empty() {
        return None;
    }
    body.blocks
        .iter()
        .flat_map(|b| &b.statements)
        .find_map(|st| match &st.kind {
            StatementKind::Assign(lhs, Rvalue::Aggregate(AggregateKind::Tuple, ops))
                if lhs.local == p.local && lhs.projection.is_empty() =>
            {
                Some(ops.clone())
            }
            _ => None,
        })
}
impl Scanner<'_, '_> {
    pub(super) fn scan_terminator(&mut self, term: &Terminator, loc: Location) {
        if let TerminatorKind::Call {
            func,
            args: call_args,
            ..
        } = &term.kind
        {
            if let Ok(ty) = func.ty(self.body.locals())
                && let Some(RigidTy::FnDef(def, args)) = ty.kind().rigid()
                && self.interesting(def, args)
            {
                match func {
                    // the callee path's own span (`UnboundKey::new`, `.encrypt`), not the whole
                    // call expression
                    Operand::Constant(c) => {
                        self.record_call(def, args, c.span, Some((call_args, term)))
                    }
                    // a function item held in a place (`let f = Sha256::digest; f(d)`): the call
                    // runs at its callee expression; the function was named where the place got
                    // it
                    _ => match self.origins.callee_name_span(func, term) {
                        Some(named) => self.record_through(def, args, named, call_args, term),
                        None => {
                            if std::env::var_os("RCBOM_DEBUG").is_some() {
                                eprintln!(
                                    "rcbom-driver: call of {} without a position for its callee \
                                     dropped in {}",
                                    def.name(),
                                    self.owner.name
                                );
                            }
                        }
                    },
                }
            } else if let Some((def, args, named)) = self.origins.callee_through_pointer(func)
                && self.interesting(&def, &args)
            {
                // a call through a pointer to a KB function reified here (`h(&SHA256, d)`)
                self.record_through(&def, &args, named, call_args, term);
            } else if let Ok(ty) = func.ty(self.body.locals())
                && matches!(ty.kind().rigid(), Some(RigidTy::FnPtr(..)))
            {
                // a pointer whose function is named elsewhere (`(h.f)(..)`, a parameter, a
                // returned pointer): where it comes from, for the analysis to follow to the
                // functions named as values
                // (one whose pointer is not known, or without a callee to place it at, too: a
                // call that may run any function made a pointer)
                let origin = self.origins.of_arg(func, term);
                let (const_args, arg_origins, arg_lens) = self.call_values(call_args, term);
                let tcx = self.cx.tcx;
                let sig = links::pointer_sig(tcx, rustc_internal::internal(tcx, ty)).map(|s| s.1);
                self.push_pointer(origin, const_args, arg_origins, arg_lens, sig, term);
            } else if let Ok(ty) = func.ty(self.body.locals())
                && let Some(RigidTy::FnDef(def, args)) = ty.kind().rigid()
                && dyn_fn_call(self.cx.tcx, def, args)
                && let [recv, tuple] = call_args.as_slice()
            {
                // a call through a closure or function boxed as a trait object (`b(&SHA1, d)`
                // with `b: Box<dyn Fn(..)>`): as through a pointer, the object's origin and the
                // call's own arguments (not known when the tuple is not built here)
                let origin = self.origins.of_arg(recv, term);
                let (const_args, arg_origins, arg_lens) = match untuple(self.body, tuple) {
                    Some(untupled) => self.call_values(&untupled, term),
                    None => {
                        let n = match tuple
                            .ty(self.body.locals())
                            .ok()
                            .and_then(|t| t.kind().rigid().cloned())
                        {
                            Some(RigidTy::Tuple(ts)) => ts.len(),
                            _ => 0,
                        };
                        (vec![None; n], vec![Origin::Unknown; n], vec![None; n])
                    }
                };
                let tcx = self.cx.tcx;
                let sig = match args.0.first() {
                    Some(GenericArgKind::Type(t)) => {
                        let mut t = rustc_internal::internal(tcx, *t);
                        while let rustc_middle::ty::Ref(_, i, _) = *t.kind() {
                            t = i;
                        }
                        if t.is_box() {
                            t = t.boxed_ty().unwrap_or(t);
                        }
                        links::pointer_sig(tcx, t).map(|s| s.1)
                    }
                    _ => None,
                };
                self.push_pointer(origin, const_args, arg_origins, arg_lens, sig, term);
            }
            for a in call_args {
                self.function_value(a);
            }
        }
        self.super_terminator(term, loc);
    }

    /// Functions named as values inside the item's promoted constants (`run(&Holder { f:
    /// digest::digest })`): where they are named, as `scan_rvalue` records it in a body (the
    /// body itself only holds the promoted constant).
    pub(super) fn promoted_values(&mut self, did: rustc_span::def_id::DefId) {
        let tcx = self.cx.tcx;
        if !tcx.is_mir_available(did) || tcx.is_closure_like(did) && !did.is_local() {
            return;
        }
        for p in tcx.promoted_mir(did).iter() {
            let pb: Body = rustc_internal::stable(p);
            for block in &pb.blocks {
                for st in &block.statements {
                    match &st.kind {
                        StatementKind::Assign(
                            _,
                            Rvalue::Cast(
                                CastKind::PointerCoercion(PointerCoercion::ReifyFnPointer(_)),
                                op,
                                _,
                            )
                            | Rvalue::Use(op, _),
                        ) => self.function_value(op),
                        StatementKind::Assign(_, Rvalue::Aggregate(_, ops)) => {
                            for op in ops {
                                self.function_value(op);
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    pub(super) fn scan_rvalue(&mut self, rv: &Rvalue, loc: Location) {
        match rv {
            // a function made a pointer, or kept as a value in a struct, a tuple, an array or a
            // local (`Some(blake3::hash)`, `Holder { f: Aes256Gcm::new_from_slice }`): it is
            // named here, whatever calls it later
            Rvalue::Cast(CastKind::PointerCoercion(PointerCoercion::ReifyFnPointer(_)), op, _)
            | Rvalue::Use(op, _) => self.function_value(op),
            Rvalue::Aggregate(_, ops) => {
                for op in ops {
                    self.function_value(op);
                }
            }
            _ => {}
        }
        self.super_rvalue(rv, loc);
    }

    pub(super) fn scan_const(&mut self, c: &ConstOperand, loc: Location) {
        if let ConstantKind::Allocated(a) = c.const_.kind() {
            alloc_statics(a, &mut self.statics, &mut HashSet::new(), 0);
        }
        self.super_const_operand(c, loc);
    }
}
