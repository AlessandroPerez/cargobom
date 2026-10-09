//! Value flow across the functions of a crate (`rcbom_facts::Links`), for the values that can
//! carry an algorithm or a key: those whose type involves a knowledge-base crate's type
//! (`&'static ring::aead::Algorithm`, `ring::hmac::Key`, `&dyn VerificationAlgorithm`).
//!
//! An argument's origin ends at the function boundary (a parameter), at a call's result, or at
//! a static. The analysis continues from there with these records, flow- and
//! context-insensitively: a field holds any value the crate stores in it, a parameter any
//! argument a caller passes, a call's result anything the function returns, a mutable static
//! anything its initializer or a write puts in it.

use std::collections::HashSet;

use rcbom_facts::{FieldStore, Links, LocalCall, Origin, Returned, StaticValue};
use rustc_middle::ty::{Ty, TypeVisitableExt};
use rustc_public::mir::{
    AggregateKind, Body, ProjectionElem, Rvalue, StatementKind, TerminatorKind,
};
use rustc_public::{CrateDef, rustc_internal};
use rustc_span::def_id::DefId;

use crate::origins::{Origins, Step};
use crate::{Cx, def_ref_internal, path_of};

/// Can a value of this type carry an algorithm or a key: does it name a knowledge-base
/// crate's type (or trait object)?
pub(crate) fn carries(cx: &Cx<'_>, ty: Ty<'_>) -> bool {
    ty.walk().any(|g| {
        g.as_type().is_some_and(|t| match t.kind() {
            rustc_middle::ty::Adt(adt, _) => cx.kb_crate(adt.did().krate),
            rustc_middle::ty::Dynamic(preds, ..) => preds
                .principal_def_id()
                .is_some_and(|d| cx.kb_crate(d.krate)),
            rustc_middle::ty::Foreign(d) => cx.kb_crate(d.krate),
            _ => false,
        })
    })
}

/// The parts of a value of type `ty` that can carry an algorithm or a key: the value itself
/// (no fields), and the fields of the structs it holds, three levels deep
/// (`Aes128GcmAead(AeadAlgorithm(&'static aead::Algorithm))`: field 0, and its field 0), for
/// the structs of the crates whose code is analysed (not the standard library's, nor the
/// stop crates'). Each with the steps that read it from the value (through references and
/// boxes). Tuples are not fields of their own (as `Origin::Field` has them).
pub(crate) fn carrying_parts<'tcx>(cx: &Cx<'tcx>, ty: Ty<'tcx>) -> Vec<(Vec<usize>, Vec<Step>)> {
    let mut out = Vec::new();
    parts(cx, ty, &mut Vec::new(), &mut Vec::new(), 0, &mut out);
    out
}

fn parts<'tcx>(
    cx: &Cx<'tcx>,
    ty: Ty<'tcx>,
    fields: &mut Vec<usize>,
    steps: &mut Vec<Step>,
    depth: usize,
    out: &mut Vec<(Vec<usize>, Vec<Step>)>,
) {
    const MAX_PARTS: usize = 8;
    const MAX_DEPTH: usize = 3;
    if out.len() >= MAX_PARTS {
        return;
    }
    let tcx = cx.tcx;
    // what a reference or a box points to
    let pointee = match ty.kind() {
        rustc_middle::ty::Ref(_, t, _) => Some(*t),
        _ if ty.is_box() => Some(ty.expect_boxed_ty()),
        _ => None,
    };
    if let Some(t) = pointee
        && depth < MAX_DEPTH
    {
        steps.push(Step::Deref);
        parts(cx, t, fields, steps, depth + 1, out);
        steps.pop();
        return;
    }
    let whole = carries(cx, ty);
    if whole {
        out.push((fields.clone(), steps.clone()));
    }
    if depth >= MAX_DEPTH {
        return;
    }
    match ty.kind() {
        rustc_middle::ty::Tuple(ts) if !whole => {
            for (i, t) in ts.iter().enumerate() {
                steps.push(Step::Field(i));
                parts(cx, t, fields, steps, depth + 1, out);
                steps.pop();
            }
        }
        rustc_middle::ty::Adt(adt, args)
            if adt.is_struct()
                && !cx.is_std(tcx.crate_name(adt.did().krate).as_str())
                && !cx.stop_crate(adt.did().krate) =>
        {
            for (i, f) in adt.non_enum_variant().fields.iter().enumerate() {
                fields.push(i);
                steps.push(Step::Field(i));
                parts(
                    cx,
                    f.ty(tcx, args).skip_norm_wip(),
                    fields,
                    steps,
                    depth + 1,
                    out,
                );
                steps.pop();
                fields.pop();
            }
        }
        _ => {}
    }
}

/// Origins that say nothing: not worth a record.
fn empty(o: &Origin) -> bool {
    matches!(o, Origin::Unknown | Origin::Truncated)
}

/// A struct of the program's (not the standard library's, whose fields `Origin::Field` does not
/// name) whose fields a store or a read names.
fn named_struct<'tcx>(cx: &Cx<'tcx>, ty: Ty<'tcx>) -> Option<rustc_middle::ty::AdtDef<'tcx>> {
    match ty.kind() {
        rustc_middle::ty::Adt(adt, _)
            if adt.is_struct() && !cx.is_std(cx.tcx.crate_name(adt.did().krate).as_str()) =>
        {
            Some(*adt)
        }
        _ => None,
    }
}

/// The links of one body: of function `did` (`func` true), of a static's initializer, or of a
/// promoted constant of either.
pub(crate) fn body_links(cx: &Cx<'_>, body: &Body, did: DefId, func: bool, out: &mut Links) {
    // a stop crate's code is not analysed: its functions are what the knowledge base names
    // (`hmac::Key::new` is a constructor, not a function whose returns are followed)
    if cx.stop_crate(did.krate) {
        return;
    }
    let tcx = cx.tcx;
    let origins = Origins::new(tcx, body, Some(did));
    let locals = body.locals();
    // a fill through `&mut` can only reach a mutable static the body names
    let fills_static = names_mutable_static(cx, body);
    let static_init = !func && matches!(tcx.def_kind(did), rustc_hir::def::DefKind::Static { .. });
    // whose parameters the values recorded name
    let here = if func {
        path_of(tcx, did)
    } else {
        String::new()
    };
    for (bb, block) in body.blocks.iter().enumerate() {
        for (idx, stmt) in block.statements.iter().enumerate() {
            let StatementKind::Assign(place, rv) = &stmt.kind else {
                continue;
            };
            // `S { f: v }`: what each part of `v` that can carry an algorithm or a key is
            if let Rvalue::Aggregate(AggregateKind::Adt(def, variant, args, ..), ops) = rv {
                let adt_did = rustc_internal::internal(tcx, def.def_id());
                let adt = tcx.adt_def(adt_did);
                if !adt.is_struct() || cx.is_std(tcx.crate_name(adt_did.krate).as_str()) {
                    continue;
                }
                let iargs = rustc_internal::internal(tcx, args);
                let v = adt.variant(rustc_abi::VariantIdx::from_usize(
                    crate::origins::variant_index(variant),
                ));
                for (f, op) in ops.iter().enumerate() {
                    let Some(field) = v.fields.get(rustc_abi::FieldIdx::from_usize(f)) else {
                        continue;
                    };
                    for (inner, steps) in carrying_parts(cx, field.ty(tcx, iargs).skip_norm_wip()) {
                        let value = origins.operand_part_at(op, &steps, bb, idx);
                        if !empty(&value) {
                            let mut path = vec![f];
                            path.extend(inner);
                            out.fields.push(FieldStore {
                                adt: path_of(tcx, adt_did),
                                path,
                                value,
                                func: here.clone(),
                                via_ref: false,
                            });
                        }
                    }
                }
                continue;
            }
            // `x.f = v`, `x.a.f = v`, `self.f = v`: a store in each struct along the fields
            if matches!(
                place.projection.last(),
                Some(ProjectionElem::Field(..) | ProjectionElem::Deref)
            ) {
                field_assign(
                    cx,
                    &origins,
                    place,
                    rv,
                    stmt.source_info.span,
                    (bb, idx),
                    &here,
                    out,
                );
            }
        }
        let term = &block.terminator;
        let TerminatorKind::Call {
            func: callee, args, ..
        } = &term.kind
        else {
            continue;
        };
        let Ok(fty) = callee.ty(locals) else { continue };
        let fty = rustc_internal::internal(tcx, fty);
        let rustc_middle::ty::FnDef(cdid, cargs) = *fty.kind() else {
            continue;
        };
        let idx = block.statements.len();
        let method = tcx.item_name(cdid);
        let method = method.as_str();
        let krate = tcx.crate_name(cdid.krate).to_string();
        // what a static holds at run time: `OnceLock::set(&S, v)`, `S.get_or_init(|| v)`,
        // `LazyLock::new(|| v)` in `S`'s initializer
        if matches!(
            method,
            "set" | "get_or_init" | "get_or_try_init" | "try_insert"
        ) {
            let cpath = path_of(tcx, cdid);
            if (cpath.contains("OnceLock") || cpath.contains("OnceCell"))
                && let (Some(s), Some(v)) = (args.first(), args.get(1))
                && let Origin::Data { def, .. } = origins.operand_at(s, bb, idx)
            {
                let value = origins.closure_value(v, bb, idx);
                push_static(out, def, value);
            }
        }
        if static_init
            && method == "new"
            && path_of(tcx, cdid).contains("Lazy")
            && let Some(f) = args.first()
        {
            let value = origins.closure_value(f, bb, idx);
            push_static(out, def_ref_internal(tcx, did), value);
        }
        // a call that fills a static through `&mut` (`rng.fill_bytes(&mut SK)` on a
        // `static mut`): kept for the statics marked mutable (`mutable_statics`)
        if fills_static {
            for a in args {
                let mutable = a
                    .ty(locals)
                    .ok()
                    .is_some_and(|t| rustc_internal::internal(tcx, t).is_mutable_ptr());
                if mutable && let Origin::Data { def, .. } = origins.operand_at(a, bb, idx) {
                    let call = Origin::Call {
                        callee: path_of(tcx, cdid),
                        krate: krate.clone(),
                        self_ty: None,
                        args: args
                            .iter()
                            .map(|a| origins.operand_at(a, bb, idx))
                            .collect(),
                        span: None,
                    };
                    push_static(out, def, call);
                }
            }
        }
        // a call of a function whose code is analysed (not the standard library's, nor a stop
        // crate's), passing values that can carry an algorithm or a key
        if cx.stop_crate(cdid.krate) || cx.is_std(&krate) || cargs.has_non_region_param() {
            continue;
        }
        let relevant: Vec<bool> = args
            .iter()
            .map(|a| {
                a.ty(locals).ok().is_some_and(|t| {
                    !carrying_parts(cx, rustc_internal::internal(tcx, t)).is_empty()
                })
            })
            .collect();
        if relevant.iter().any(|r| *r) {
            let args: Vec<Origin> = args
                .iter()
                .zip(&relevant)
                .map(|(a, r)| {
                    if *r {
                        origins.operand_at(a, bb, idx)
                    } else {
                        Origin::Unknown
                    }
                })
                .collect();
            out.calls.push(LocalCall {
                callee: path_of(tcx, cdid),
                caller: here.clone(),
                args,
            });
        }
    }
    // what a function returns, and each part of it that can carry an algorithm or a key
    if func {
        let ret = rustc_internal::internal(tcx, body.locals()[rustc_public::mir::RETURN_LOCAL].ty);
        for (path, steps) in carrying_parts(cx, ret) {
            let value = origins.returned_part(&steps);
            if !empty(&value) {
                out.returns.push(Returned {
                    func: here.clone(),
                    path,
                    value,
                });
            }
        }
    }
}

/// `x.a.f = v`: a store of `v` (or of each part of it that can carry an algorithm or a key) in
/// `f` of `x.a`'s struct, and in `a.f` of `x`'s. A struct reached through a reference
/// (`self.f = v` in a `&mut self` method) may be a part of another one: marked `via_ref`.
#[allow(clippy::too_many_arguments)]
fn field_assign(
    cx: &Cx<'_>,
    origins: &Origins<'_, '_>,
    place: &rustc_public::mir::Place,
    rv: &Rvalue,
    span: rustc_public::ty::Span,
    (bb, idx): (usize, usize),
    here: &str,
    out: &mut Links,
) {
    let tcx = cx.tcx;
    // nothing to record unless what is written can carry an algorithm or a key
    let Ok(written) = place.ty(origins.body().locals()) else {
        return;
    };
    if carrying_parts(cx, rustc_internal::internal(tcx, written)).is_empty() {
        return;
    }
    let proj = &place.projection;
    // the trailing fields and dereferences
    let mut start = proj.len();
    while start > 0
        && matches!(
            proj[start - 1],
            ProjectionElem::Field(..) | ProjectionElem::Deref
        )
    {
        start -= 1;
    }
    let base = rustc_public::mir::Place {
        local: place.local,
        projection: proj[..start].to_vec(),
    };
    let Ok(ty) = base.ty(origins.body().locals()) else {
        return;
    };
    let mut ty = rustc_internal::internal(tcx, ty);
    // the structs along the way: (struct, fields from it, reached through a reference)
    let mut chains: Vec<(String, Vec<usize>, bool)> = Vec::new();
    let mut behind_ref = start > 0;
    for e in &proj[start..] {
        match e {
            ProjectionElem::Deref => {
                let Some(t) = ty.builtin_deref(true) else {
                    return;
                };
                ty = t;
                behind_ref = true;
            }
            ProjectionElem::Field(f, _) => {
                if let Some(adt) = named_struct(cx, ty) {
                    chains.push((path_of(tcx, adt.did()), Vec::new(), behind_ref));
                    for c in &mut chains {
                        c.1.push(*f);
                    }
                }
                ty = match ty.kind() {
                    rustc_middle::ty::Adt(adt, args) if adt.is_struct() => {
                        match adt
                            .non_enum_variant()
                            .fields
                            .get(rustc_abi::FieldIdx::from_usize(*f))
                        {
                            Some(fd) => fd.ty(tcx, args).skip_norm_wip(),
                            None => return,
                        }
                    }
                    rustc_middle::ty::Tuple(ts) => match ts.get(*f) {
                        Some(t) => *t,
                        None => return,
                    },
                    _ => return,
                };
                behind_ref = false;
            }
            _ => return,
        }
    }
    // `*p = S { .. }`: a whole struct written through a reference
    if behind_ref && let Some(adt) = named_struct(cx, ty) {
        chains.push((path_of(tcx, adt.did()), Vec::new(), true));
    }
    if chains.is_empty() {
        return;
    }
    for (inner, steps) in carrying_parts(cx, ty) {
        let value = origins.rvalue_part_at(rv, span, &steps, bb, idx);
        if empty(&value) {
            continue;
        }
        for (adt, fields, via_ref) in &chains {
            let mut path = fields.clone();
            path.extend(inner.iter().copied());
            if path.is_empty() {
                continue;
            }
            out.fields.push(FieldStore {
                adt: adt.clone(),
                path,
                value: value.clone(),
                func: here.to_string(),
                via_ref: *via_ref,
            });
        }
    }
}

/// The links of the promoted constants item `did` uses: a static's `&KxGroup {
/// agreement_algorithm: &agreement::X25519, .. }` is one, as is a function's `&Hash(&SHA256)`.
pub(crate) fn promoted_links(cx: &Cx<'_>, did: DefId, out: &mut Links) {
    let tcx = cx.tcx;
    if cx.stop_crate(did.krate) {
        return;
    }
    // only a promoted constant that builds a struct stores anything
    let builds_struct = |b: &rustc_middle::mir::Body<'_>| {
        b.basic_blocks.iter().any(|bb| {
            bb.statements.iter().any(|st| {
                matches!(
                    &st.kind,
                    rustc_middle::mir::StatementKind::Assign(a)
                        if matches!(&a.1, rustc_middle::mir::Rvalue::Aggregate(k, _)
                            if matches!(**k, rustc_middle::mir::AggregateKind::Adt(..)))
                )
            })
        })
    };
    if !tcx.promoted_mir(did).iter().any(builds_struct) {
        return;
    }
    for p in crate::statics::used_promoted(tcx, did) {
        if !builds_struct(&tcx.promoted_mir(did)[p]) {
            continue;
        }
        let body: Body = rustc_internal::stable(&tcx.promoted_mir(did)[p]);
        body_links(cx, &body, did, false, out);
    }
}

fn push_static(out: &mut Links, def: rcbom_facts::DefRef, value: Origin) {
    if empty(&value) {
        return;
    }
    match out.statics.iter_mut().find(|s| s.def.id == def.id) {
        Some(s) => {
            if !s.values.contains(&value) {
                s.values.push(value);
            }
        }
        None => out.statics.push(StaticValue {
            def,
            mutable: false,
            values: vec![value],
        }),
    }
}

/// The statics of this crate whose contents change at run time and can carry an algorithm or
/// a key (`static mut`, `LazyLock`, `OnceLock`, locks, cells): marked mutable, with the values
/// recorded for them.
pub(crate) fn mutable_statics(cx: &Cx<'_>, out: &mut Links) {
    let tcx = cx.tcx;
    let mut defs: Vec<DefId> = mutable_static_defs(cx).iter().copied().collect();
    defs.sort_by_key(|d| path_of(tcx, *d));
    for did in defs {
        let def = def_ref_internal(tcx, did);
        match out.statics.iter_mut().find(|s| s.def.id == def.id) {
            Some(s) => s.mutable = true,
            None => out.statics.push(StaticValue {
                def,
                mutable: true,
                values: Vec::new(),
            }),
        }
    }
}

/// The statics of this crate whose contents change at run time and can hold key material.
pub(crate) fn mutable_static_defs<'a>(cx: &'a Cx<'_>) -> &'a HashSet<DefId> {
    cx.mutable_statics.get_or_init(|| {
        cx.tcx
            .hir_body_owners()
            .map(|d| d.to_def_id())
            .filter(|&did| mutable_static(cx, did))
            .collect()
    })
}

/// Is `did` a static whose contents change at run time and can hold key material: a
/// `static mut`, or a type with interior mutability (`LazyLock`, `OnceLock`, a lock, a cell)?
fn mutable_static(cx: &Cx<'_>, did: DefId) -> bool {
    let tcx = cx.tcx;
    if !matches!(tcx.def_kind(did), rustc_hir::def::DefKind::Static { .. })
        || tcx.is_foreign_item(did)
    {
        return false;
    }
    let ty = tcx.type_of(did).instantiate_identity().skip_norm_wip();
    (tcx.static_mutability(did) == Some(rustc_middle::mir::Mutability::Mut)
        || !ty.is_freeze(tcx, rustc_middle::ty::TypingEnv::fully_monomorphized()))
        && carries_or_bytes(cx, ty)
}

/// Does `body` name a mutable static (a constant pointing at one, of any crate)?
fn names_mutable_static(cx: &Cx<'_>, body: &Body) -> bool {
    use rustc_public::mir::MirVisitor;
    struct V<'a, 'tcx> {
        cx: &'a Cx<'tcx>,
        found: bool,
    }
    impl MirVisitor for V<'_, '_> {
        fn visit_const_operand(
            &mut self,
            c: &rustc_public::mir::ConstOperand,
            _: rustc_public::mir::visit::Location,
        ) {
            if let rustc_public::ty::ConstantKind::Allocated(a) = c.const_.kind() {
                for (_, prov) in &a.provenance.ptrs {
                    if let rustc_public::mir::alloc::GlobalAlloc::Static(st) =
                        rustc_public::mir::alloc::GlobalAlloc::from(prov.0)
                        && mutable_static(
                            self.cx,
                            rustc_internal::internal(self.cx.tcx, st.def_id()),
                        )
                    {
                        self.found = true;
                    }
                }
            }
        }
    }
    let mut v = V { cx, found: false };
    v.visit_body(body);
    v.found
}

/// A static that can hold key material: a knowledge-base type, or bytes (`[u8; 32]`,
/// `Vec<u8>`, `String`) behind any wrapper (`LazyLock<Vec<u8>>`, `Mutex<[u8; 32]>`), or an
/// integer (a nonce counter).
fn carries_or_bytes(cx: &Cx<'_>, ty: Ty<'_>) -> bool {
    carries(cx, ty)
        || ty.walk().any(|g| {
            g.as_type().is_some_and(|t| {
                matches!(
                    t.kind(),
                    rustc_middle::ty::Uint(_) | rustc_middle::ty::Int(_) | rustc_middle::ty::Str
                )
            })
        })
}
