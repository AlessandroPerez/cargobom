//! Constants: their evaluated data, promoted constants, enum values and literal data.

use super::*;

impl<'a, 'tcx> Origins<'a, 'tcx> {
    pub(super) fn constant(&self, c: &rustc_public::mir::ConstOperand, depth: usize) -> Origin {
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
    pub(super) fn unevaluated(
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
    pub(super) fn promoted_origin(
        &self,
        did: DefId,
        p: rustc_middle::mir::Promoted,
    ) -> Option<Origin> {
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
    pub(super) fn evaluate(
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
    pub(super) fn item_zero(&self, did: DefId) -> bool {
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
    pub(super) fn fieldless_enum(&self, ty: &Ty) -> bool {
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
    pub(super) fn enum_elements(
        &self,
        a: &rustc_public::ty::Allocation,
        ty: &Ty,
    ) -> Option<Origin> {
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
    pub(super) fn unit_value(&self, ty: &Ty) -> Option<Origin> {
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
}
/// The discriminant of an enum's variant, as the integer it is.
impl Origins<'_, '_> {
    /// The variant a field-less enum's `Default::default()` returns, read from the impl's MIR
    /// (a derived `#[default]`, or `fn default() -> Self { Self::Argon2id }`).
    pub(super) fn default_variant(
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
pub(super) fn discriminant<'tcx>(
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
pub(super) fn named_in<'tcx>(
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
/// Byte length of `n` elements of type `elem`, when the elements are bytes.
pub(super) fn byte_len(elem: &Ty, n: Option<u64>) -> Option<u64> {
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
pub(super) fn literal_data(a: &rustc_public::ty::Allocation, ty: &Ty) -> (Option<u64>, bool) {
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
/// `[u8; N]`, `&[u8; N]`, `&mut [u8; N]`: N bytes.
pub(super) fn bytes_of_ty(ty: &Ty) -> Option<u64> {
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
pub(super) fn array_len_of_ty(ty: &Ty) -> Option<u64> {
    match ty.kind().rigid()? {
        RigidTy::Array(_, n) => n.eval_target_usize().ok(),
        RigidTy::Ref(_, t, _) | RigidTy::RawPtr(t, _) => match t.kind().rigid()? {
            RigidTy::Array(_, n) => n.eval_target_usize().ok(),
            _ => None,
        },
        _ => None,
    }
}
