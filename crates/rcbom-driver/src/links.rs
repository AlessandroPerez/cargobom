//! Value flow across the functions of a crate (`rcbom_facts::Links`), for the values that can
//! carry an algorithm or a key: those whose type involves a knowledge-base crate's type
//! (`&'static ring::aead::Algorithm`, `ring::hmac::Key`, `&dyn VerificationAlgorithm`).
//!
//! An argument's origin ends at the function boundary (a parameter), at a call's result, or at
//! a static. The analysis continues from there with these records, flow- and
//! context-insensitively: a field holds any value the crate stores in it, a parameter any
//! argument a caller passes, a call's result anything the function returns, a mutable static
//! anything its initializer or a write puts in it.

use std::collections::{HashMap, HashSet};

use rcbom_facts::{FieldStore, Links, LocalCall, Origin, ParamWrite, Returned, StaticValue};
use rustc_middle::ty::{Ty, TypeVisitableExt};
use rustc_public::mir::{
    AggregateKind, Body, Operand, ProjectionElem, Rvalue, StatementKind, TerminatorKind,
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
/// promoted constant of either; `instance`: the body is that instance's of a generic function
/// (`origins::body_name`), whose summaries (returns, writes, calls) are recorded under its name.
pub(crate) fn body_links(
    cx: &Cx<'_>,
    body: &Body,
    did: DefId,
    func: bool,
    instance: Option<&str>,
    out: &mut Links,
) {
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
    let const_init = !func
        && matches!(
            tcx.def_kind(did),
            rustc_hir::def::DefKind::Const | rustc_hir::def::DefKind::AssocConst
        );
    // whose parameters the values recorded name; a static's initializer names its static (a
    // value stored there reaches a call only if the static is reachable)
    let here = if let Some(name) = instance {
        name.to_string()
    } else if func {
        path_of(tcx, did)
    } else if static_init {
        rcbom_facts::static_owner(&path_of(tcx, did), &def_ref_internal(tcx, did).id)
    } else if const_init {
        rcbom_facts::const_owner(&path_of(tcx, did), &def_ref_internal(tcx, did).id)
    } else {
        String::new()
    };
    let borrows = field_borrows(tcx, body);
    // a body with an `async` closure's type cannot have its values read (`rustc_public` cannot
    // convert the type): the reads below that only this round's records need are skipped there
    let readable = !crate::has_unconvertible(tcx, body);
    // in a static's or a constant's initializer, the path from the value to each tuple built
    // into it (`_2 = (a, b); _0 = (move _2, c)`: `_2` at `[0]`); an array's elements are at
    // the array's path
    let mut prefix: HashMap<rustc_public::mir::Local, Vec<usize>> = HashMap::new();
    if static_init || const_init {
        prefix.insert(rustc_public::mir::RETURN_LOCAL, Vec::new());
        loop {
            let before = prefix.len();
            for st in body.blocks.iter().flat_map(|b| &b.statements) {
                if let StatementKind::Assign(p, Rvalue::Aggregate(kind, ops)) = &st.kind
                    && p.projection.is_empty()
                    && let Some(pre) = prefix.get(&p.local).cloned()
                {
                    for (i, op) in ops.iter().enumerate() {
                        if let Operand::Copy(q) | Operand::Move(q) = op
                            && q.projection.is_empty()
                            && !prefix.contains_key(&q.local)
                        {
                            let mut at = pre.clone();
                            if matches!(kind, AggregateKind::Tuple) {
                                at.push(i);
                            } else if !matches!(kind, AggregateKind::Array(_)) {
                                continue;
                            }
                            prefix.insert(q.local, at);
                        }
                    }
                }
            }
            if prefix.len() == before {
                break;
            }
        }
    }
    // the ids of the mutable statics of this crate
    let mutable_ids: HashSet<String> = if fills_static {
        mutable_static_defs(cx)
            .iter()
            .map(|d| def_ref_internal(tcx, *d).id)
            .collect()
    } else {
        HashSet::new()
    };
    // the `&mut` parameters of a function (not a closure's): what each points to when the
    // function returns is recorded whole below
    // (or a shared borrow of a value holding a cell, `set(c: &Cell<T>)`, written through it;
    // a lock's also by the stores through its guard, below)
    let cell_param = |l: &rustc_public::mir::LocalDecl| {
        matches!(rustc_internal::internal(tcx, l.ty).kind(),
            rustc_middle::ty::Ref(_, inner, rustc_middle::ty::Mutability::Not)
                if crate::origins::holds_cell(tcx, *inner, 0))
    };
    let (mut_params, cell_params): (Vec<usize>, Vec<usize>) = if func && !tcx.is_closure_like(did) {
        let args = body.arg_locals();
        let cells: Vec<usize> = (0..args.len()).filter(|&i| cell_param(&args[i])).collect();
        let all = (0..args.len())
            .filter(|&i| {
                matches!(
                    args[i].ty.kind().rigid(),
                    Some(rustc_public::ty::RigidTy::Ref(
                        _,
                        _,
                        rustc_public::mir::Mutability::Mut
                    ))
                ) || cells.contains(&i)
            })
            .collect();
        (all, cells)
    } else {
        (Vec::new(), Vec::new())
    };
    // (a parameter the lock rules below read: not a `&mut` one, whose value at the returns is
    // recorded whole)
    let by_guard = |i: &usize| !mut_params.contains(i) || cell_params.contains(i);
    for (bb, block) in body.blocks.iter().enumerate() {
        for (idx, stmt) in block.statements.iter().enumerate() {
            let StatementKind::Assign(place, rv) = &stmt.kind else {
                continue;
            };
            // `S { f: v }`, `E::V(v)`: what each part of `v` that can carry an algorithm or a key
            // is, in the struct or in the enum's variant (`KeyPairKind::Ec(kp)`), as
            // `Origin::Field` names them
            // `(&SHA256, &SHA1)` in a static's or a constant's initializer: what each element
            // is, as a field of the tuple (read as such from that static only)
            // (a tuple inside it, `((&SHA256, &SHA1), &SHA512)`, at its path from the value:
            // `[0, 1]`; an array's elements are not told apart)
            // a constant in it (`[BASE, Cfg { .. }]`, `(BASE, 0)`): the constant's fields, as
            // that constant stores them
            if let Rvalue::Aggregate(kind @ (AggregateKind::Tuple | AggregateKind::Array(_)), ops) =
                rv
                && (static_init || const_init)
                && place.projection.is_empty()
            {
                let tuple = matches!(kind, AggregateKind::Tuple);
                let pre = prefix.get(&place.local).cloned().unwrap_or_default();
                let mut store = |adt: String, path: Vec<usize>, value: Origin| {
                    let s = FieldStore {
                        adt,
                        path,
                        value,
                        func: here.clone(),
                        via_ref: false,
                        args: None,
                    };
                    if !empty(&s.value) && !out.fields.contains(&s) {
                        out.fields.push(s);
                    }
                };
                for (f, op) in ops.iter().enumerate() {
                    let mut at = pre.clone();
                    at.push(f);
                    if tuple {
                        store(
                            rcbom_facts::TUPLE.to_string(),
                            at.clone(),
                            origins.operand_part_at(op, &[], bb, idx),
                        );
                    }
                    if !tuple && !matches!(op, Operand::Constant(_)) {
                        continue;
                    }
                    let Ok(ty) = op.ty(locals) else { continue };
                    let ty = rustc_internal::internal(tcx, ty);
                    for (inner, steps) in carrying_parts(cx, ty) {
                        if inner.is_empty() {
                            continue;
                        }
                        let value = origins.operand_part_at(op, &steps, bb, idx);
                        if tuple {
                            let mut path = at.clone();
                            path.extend(inner);
                            store(rcbom_facts::TUPLE.to_string(), path, value);
                        } else if let rustc_middle::ty::Adt(adt, _) = ty.peel_refs().kind()
                            && adt.is_struct()
                        {
                            store(path_of(tcx, adt.did()), inner, value);
                        }
                    }
                }
                if tuple {
                    continue;
                }
            }
            if let Rvalue::Aggregate(AggregateKind::Adt(def, variant, args, ..), ops) = rv {
                let adt_did = rustc_internal::internal(tcx, def.def_id());
                let adt = tcx.adt_def(adt_did);
                if adt.is_union() || cx.is_std(tcx.crate_name(adt_did.krate).as_str()) {
                    continue;
                }
                let iargs = rustc_internal::internal(tcx, args);
                let v = adt.variant(rustc_abi::VariantIdx::from_usize(
                    crate::origins::variant_index(variant),
                ));
                let named = if adt.is_enum() { v.def_id } else { adt_did };
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
                                adt: path_of(tcx, named),
                                path,
                                value,
                                func: here.clone(),
                                via_ref: false,
                                args: crate::adt_args(tcx, iargs),
                            });
                        }
                    }
                }
                continue;
            }
            // `ALG2 = v` on a `static mut`, `*ALG.write().unwrap() = v` through a lock's guard:
            // a value the static holds at run time
            if fills_static && matches!(place.projection.first(), Some(ProjectionElem::Deref)) {
                let base = rustc_public::mir::Place {
                    local: place.local,
                    projection: Vec::new(),
                };
                let ptr = origins.operand_at(&rustc_public::mir::Operand::Copy(base), bb, idx);
                if let Some(def) = static_behind(&ptr) {
                    let mut value = origins.rvalue_part_at(rv, stmt.source_info.span, &[], bb, idx);
                    // into a field of it (`CFG.lock().unwrap().h = v`): that field
                    let fields: Option<Vec<usize>> = place.projection[1..]
                        .iter()
                        .map(|e| match e {
                            ProjectionElem::Field(f, _) => Some(*f),
                            _ => None,
                        })
                        .collect();
                    match fields {
                        Some(f) if !f.is_empty() => {
                            value = Origin::Set {
                                path: f,
                                value: Box::new(value),
                                strong: false,
                            }
                        }
                        Some(_) => {}
                        None => value = Origin::Unknown,
                    }
                    push_static(out, def, value, &here);
                }
            }
            // `m.lock().unwrap().h = v` into a field through a lock the function is given (`fn
            // set_cfg(m: &Mutex<Cfg>)`; the whole value: below): what it writes there, for the
            // callers passing a static
            if func
                && readable
                && matches!(place.projection.first(), Some(ProjectionElem::Deref))
                && place.projection.len() > 1
            {
                let base = rustc_public::mir::Place {
                    local: place.local,
                    projection: Vec::new(),
                };
                let ptr = origins.operand_at(&rustc_public::mir::Operand::Copy(base), bb, idx);
                if let Some(index) = param_behind(&ptr)
                    && by_guard(&index)
                    && !matches!(ptr, Origin::Param { .. })
                {
                    let mut value = origins.rvalue_part_at(rv, stmt.source_info.span, &[], bb, idx);
                    let fields: Option<Vec<usize>> = place.projection[1..]
                        .iter()
                        .map(|e| match e {
                            ProjectionElem::Field(f, _) => Some(*f),
                            _ => None,
                        })
                        .collect();
                    match fields {
                        Some(f) if !f.is_empty() => {
                            value = Origin::Set {
                                path: f,
                                value: Box::new(value),
                                strong: false,
                            }
                        }
                        Some(_) => {}
                        None => value = Origin::Unknown,
                    }
                    let w = ParamWrite {
                        func: here.clone(),
                        index,
                        value,
                        path: Vec::new(),
                    };
                    if !empty(&w.value) && !out.writes.contains(&w) {
                        out.writes.push(w);
                    }
                }
            }
            let span = stmt.source_info.span;
            let value = |steps: &[Step]| origins.rvalue_part_at(rv, span, steps, bb, idx);
            // `x.f = v`, `x.a.f = v`, `self.f = v`, `x.a[0] = v`: a store in each struct along
            // the fields
            if matches!(
                place.projection.last(),
                Some(
                    ProjectionElem::Field(..)
                        | ProjectionElem::Deref
                        | ProjectionElem::Index(_)
                        | ProjectionElem::ConstantIndex { .. }
                )
            ) {
                field_store(cx, &origins, place, &value, &here, out);
            }
            // `let r = &mut c.alg; *r = v`: a store in the field borrowed
            if matches!(place.projection.first(), Some(ProjectionElem::Deref)) {
                for b in borrows.get(&place.local).into_iter().flatten() {
                    let mut p = b.clone();
                    p.projection.extend_from_slice(&place.projection[1..]);
                    field_store(cx, &origins, &p, &value, &here, out);
                }
            }
            // `*l.write().unwrap() = v` on a parameter's lock: what the function writes
            // through it (through a `&mut` parameter: its value at the returns, below)
            if func && matches!(place.projection.as_slice(), [ProjectionElem::Deref]) {
                let base = rustc_public::mir::Place {
                    local: place.local,
                    projection: Vec::new(),
                };
                let ptr = origins.operand_at(&rustc_public::mir::Operand::Copy(base), bb, idx);
                if let Some(index) = param_behind(&ptr)
                    && by_guard(&index)
                {
                    let v = value(&[]);
                    if !empty(&v) {
                        let w = ParamWrite {
                            func: here.clone(),
                            index,
                            value: v,
                            path: Vec::new(),
                        };
                        if !out.writes.contains(&w) {
                            out.writes.push(w);
                        }
                    }
                }
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
        // a call through a function pointer the body made of one of the program's functions or
        // closures (`let f: fn(..) = hash_with; f(&SHA512, d)`): a call of that function
        if let rustc_middle::ty::FnPtr(..) = fty.kind()
            && let rustc_public::mir::Operand::Copy(p) | rustc_public::mir::Operand::Move(p) =
                callee
            && p.projection.is_empty()
            && let Some(target) = fn_ptr_target(tcx, body, p.local)
            && !cx.stop_crate(target.krate)
            && !cx.is_std(tcx.crate_name(target.krate).as_str())
        {
            let idx = block.statements.len();
            let cargs_o: Vec<Origin> = args
                .iter()
                .map(|a| origins.operand_at(a, bb, idx))
                .collect();
            if cargs_o.iter().any(|o| !empty(o)) {
                out.calls.push(LocalCall {
                    callee: path_of(tcx, target),
                    caller: here.clone(),
                    args: cargs_o,
                });
            }
            continue;
        }
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
                push_static(out, def, value, &here);
            }
        }
        if static_init
            && method == "new"
            && path_of(tcx, cdid).contains("Lazy")
            && let Some(f) = args.first()
        {
            let value = origins.closure_value(f, bb, idx);
            push_static(out, def_ref_internal(tcx, did), value, "");
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
                        runs: None,
                        pointer: None,
                        fed: None,
                    };
                    push_static(out, def, call, &here);
                }
            }
        }
        // a call that writes through `&mut` into a field (`mem::replace(&mut c.alg, v)`,
        // `c.v.push(v)`, `opt.replace(v)`, the program's `set_slot(&mut c.alg)`) or into a
        // static (the program's `set_alg(&ALG, v)`): a store of what it writes there
        let std_call = cx.is_std(&krate);
        let program = !std_call && !cx.stop_crate(cdid.krate);
        for (i, a) in args.iter().enumerate() {
            let Ok(aty) = a.ty(locals) else { continue };
            let aty = rustc_internal::internal(tcx, aty);
            let written = if std_call && i == 0 && WRITERS.contains(&method) {
                let rest: Vec<Origin> = args[1..]
                    .iter()
                    .map(|a| origins.operand_at(a, bb, idx))
                    .filter(|o| !empty(o))
                    .collect();
                match rest.len() {
                    0 => None,
                    1 => rest.into_iter().next(),
                    _ => Some(Origin::Any(rest)),
                }
            } else if program && writable(tcx, aty) && carries(cx, aty) {
                let (callee, self_ty) =
                    crate::origins::write_callee(tcx, cdid, cargs.skip_binder(), None);
                Some(Origin::Written {
                    callee,
                    index: i,
                    args: args
                        .iter()
                        .map(|a| origins.operand_at(a, bb, idx))
                        .collect(),
                    self_ty,
                    place_ty: None,
                    path: Vec::new(),
                })
            } else {
                None
            };
            let Some(w) = written else { continue };
            if let rustc_public::mir::Operand::Copy(p) | rustc_public::mir::Operand::Move(p) = a
                && p.projection.is_empty()
            {
                let value = |steps: &[Step]| {
                    if steps.iter().all(|s| matches!(s, Step::Deref)) {
                        w.clone()
                    } else {
                        Origin::Unknown
                    }
                };
                for b in borrows.get(&p.local).into_iter().flatten() {
                    field_store(cx, &origins, b, &value, &here, out);
                }
            }
            // a static written by the program's function, or by a writer of the standard
            // library (`TA.set(v)` on a `thread_local!` cell)
            if (program || (std_call && i == 0))
                && let Some(def) = static_behind(&origins.operand_at(a, bb, idx))
            {
                push_static(out, def, w.clone(), &here);
            }
        }
        // `lazy_static!`: its `Lazy::get(&LAZY, __static_ref_initialize)` puts what the
        // function returns in the static
        if method == "get"
            && krate == "lazy_static"
            && let (Some(s), Some(f)) = (args.first(), args.get(1))
            && let Origin::Data { def, .. } = origins.operand_at(s, bb, idx)
        {
            push_static(out, def, origins.closure_value(f, bb, idx), "");
        }
        // a call of a closure of this crate (`f(&SHA512, d)` is `Fn::call(&f, (&SHA512, d))`):
        // its parameters receive the tuple's elements, numbered from its first declared one
        // (as `Origin::Param` numbers them in a closure's body)
        if matches!(method, "call" | "call_mut" | "call_once")
            && cx.is_std(&krate)
            && let (Some(f), Some(tuple)) = (args.first(), args.get(1))
            && let Ok(fty) = f.ty(locals)
            && let rustc_middle::ty::Closure(cl, _) =
                *rustc_internal::internal(tcx, fty).peel_refs().kind()
            && cl.is_local()
            && let Ok(tty) = tuple.ty(locals)
            && let rustc_middle::ty::Tuple(ts) = *rustc_internal::internal(tcx, tty).kind()
        {
            let mut cargs_o = Vec::new();
            for (i, t) in ts.iter().enumerate() {
                cargs_o.push(if carrying_parts(cx, t).is_empty() {
                    Origin::Unknown
                } else {
                    origins.operand_part_at(tuple, &[Step::Field(i)], bb, idx)
                });
            }
            if cargs_o.iter().any(|o| !empty(o)) {
                out.calls.push(LocalCall {
                    callee: path_of(tcx, cl),
                    caller: here.clone(),
                    args: cargs_o,
                });
            }
            continue;
        }
        // a call of a function whose code is analysed (not the standard library's, nor a stop
        // crate's), passing values that can carry an algorithm or a key
        if cx.stop_crate(cdid.krate) || cx.is_std(&krate) || cargs.has_non_region_param() {
            continue;
        }
        // a lock static handed to a function of the program (`set_cfg(&CFG)`), or what its
        // guard points to (`CFG.lock().unwrap().set(v)`): what the function writes through it
        // is a value the static holds at run time, stored by that function (named the writer:
        // it is reached when some caller is, which may pass another static)
        if fills_static && readable {
            let all: Vec<Origin> = args
                .iter()
                .map(|a| origins.operand_at(a, bb, idx))
                .collect();
            let callee = crate::origins::runs_of(tcx, cdid, cargs.skip_binder())
                .unwrap_or_else(|| path_of(tcx, cdid));
            for (k, a) in all.iter().enumerate() {
                if let Some(def) = static_behind(a)
                    && mutable_ids.contains(&def.id)
                {
                    push_static(
                        out,
                        def,
                        Origin::Written {
                            callee: callee.clone(),
                            index: k,
                            args: all.clone(),
                            self_ty: None,
                            place_ty: None,
                            path: Vec::new(),
                        },
                        &callee,
                    );
                }
            }
        }
        let relevant: Vec<bool> = args
            .iter()
            .map(|a| {
                a.ty(locals).ok().is_some_and(|t| {
                    !carrying_parts(cx, rustc_internal::internal(tcx, t)).is_empty()
                })
            })
            .collect();
        // between the program's own functions, with no argument that can carry an algorithm
        // (`decode_token(&args)`): kept apart, for whether a value depends on the input
        if !relevant.iter().any(|r| *r)
            && !args.is_empty()
            && cx.is_program(rustc_span::def_id::LOCAL_CRATE)
            && cx.is_program(cdid.krate)
        {
            out.arg_calls.push(LocalCall {
                callee: path_of(tcx, cdid),
                caller: here.clone(),
                args: args
                    .iter()
                    .map(|a| origins.operand_at(a, bb, idx))
                    .collect(),
            });
        }
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
            // also of the body it runs (an implementation for a known `Self`, an instance of
            // a generic function), whose parameters its summaries name
            if let Some(runs) = crate::origins::runs_of(tcx, cdid, cargs.skip_binder()) {
                out.calls.push(LocalCall {
                    callee: runs,
                    caller: here.clone(),
                    args: args.clone(),
                });
            }
            out.calls.push(LocalCall {
                callee: path_of(tcx, cdid),
                caller: here.clone(),
                args,
            });
        }
    }
    // a static whose contents change at run time starts with its initializer's value (a
    // `static mut`'s, a lock's), unless it starts empty (`OnceLock`) or its value is the
    // closure a `LazyLock` runs (recorded above)
    if static_init && mutable_static(cx, did) {
        let ty = tcx.type_of(did).instantiate_identity().skip_norm_wip();
        let lazy = matches!(ty.kind(), rustc_middle::ty::Adt(adt, _)
            if re_lazy(&path_of(tcx, adt.did())));
        // the initializer itself, not one of its promoted constants
        let ret = rustc_internal::internal(tcx, body.locals()[rustc_public::mir::RETURN_LOCAL].ty);
        if !lazy && tcx.erase_and_anonymize_regions(ret) == tcx.erase_and_anonymize_regions(ty) {
            push_static(
                out,
                def_ref_internal(tcx, did),
                origins.returned_part(&[]),
                "",
            );
        }
    } else if const_init
        && tcx.item_name(did).as_str().contains("INTERNAL_INIT")
        && let Some(key) = tcx.opt_parent(did)
        && mutable_static_defs(cx).contains(&key)
    {
        // a `thread_local!` key's `const { .. }` initializer (`TA::__RUST_STD_INTERNAL_INIT`):
        // the value the key starts with (not a struct's: a key's struct is read through a
        // closure whose field read is not followed, `TA.with_borrow(|c| c.h)`, and its fields
        // are what the program stores in them)
        fn has_set(o: &Origin) -> bool {
            match o {
                Origin::Set { .. } => true,
                Origin::All(v) | Origin::Any(v) => v.iter().any(has_set),
                Origin::Call { args, .. } => args.iter().any(has_set),
                _ => false,
            }
        }
        let value = origins.returned_part(&[]);
        if !has_set(&value) {
            push_static(out, def_ref_internal(tcx, key), value, "");
        }
    } else if static_init || const_init {
        // a static holding a function pointer (`static MY: HashFn = my`, `static B: &HashFn =
        // &A`): its value, for the calls through it
        let ty = tcx.type_of(did).instantiate_identity().skip_norm_wip();
        let ret = rustc_internal::internal(tcx, body.locals()[rustc_public::mir::RETURN_LOCAL].ty);
        if tcx.erase_and_anonymize_regions(ret) == tcx.erase_and_anonymize_regions(ty) {
            let value = origins.returned_part(&[]);
            // or another static or constant, or a reference to one (`static REF: &Cfg =
            // &FIX`, `const ALIAS: Cfg = BASE`), or what a `const fn` of the crate returns
            // (`static MADE: Cfg = make()`): a field read of it is that one's
            let local_call = matches!(&value, Origin::Call { krate, .. }
                if *krate == tcx.crate_name(rustc_span::def_id::LOCAL_CRATE).as_str());
            // (or a table of references to statics or constants, `[&S1, &S2]`, `&[&C1, &C2]`: a
            // field read of an element is that field of any of them)
            let ref_table = matches!(&value, Origin::All(v) | Origin::Any(v)
                if !v.is_empty() && v.iter().all(|e| matches!(e, Origin::Data { .. })));
            if holds_fn_ptr(tcx, ty, 0)
                || matches!(value, Origin::Data { .. })
                || local_call
                || ref_table
            {
                push_static(out, def_ref_internal(tcx, did), value, "");
            }
        }
    }
    // what a `&mut` parameter points to at the returns (`set_slot(slot)`: `*slot = &SHA512`;
    // `upgrade(&mut self)`: the value on entry with `alg` set), when the function writes it:
    // a caller's `Written` resolves to it, the entry value standing for the caller's own
    // a `&mut` parameter the body points elsewhere (`if c { slot = other }; *slot = v`): what
    // the place it pointed to on entry holds at the returns is not followed, nor what the
    // other parameters' places hold (one of them may be written through it)
    // (or lends the parameter itself as `&mut`: `mem::swap(&mut slot, &mut other)`)
    // (a result whose borrows its callers follow, `returned_pointers`)
    let returns_followed = crate::origins::returned_pointers(tcx, body).is_some();
    let redirect = |index: usize| -> (bool, bool) {
        let stmts = || body.blocks.iter().flat_map(|b| &b.statements);
        // the locals holding a copy of the parameter's pointer (`let s = slot;`), its own first
        let mut copies: HashSet<rustc_public::mir::Local> = HashSet::from([index + 1]);
        loop {
            let before = copies.len();
            for st in stmts() {
                // (or a reborrow of it: `&mut (*slot)`, as a struct literal's field or a
                // field assignment takes it)
                if let StatementKind::Assign(p, rv) = &st.kind
                    && p.projection.is_empty()
                    && match rv {
                        Rvalue::Use(Operand::Copy(q) | Operand::Move(q), _) => {
                            q.projection.is_empty() && copies.contains(&q.local)
                        }
                        Rvalue::Ref(_, rustc_public::mir::BorrowKind::Mut { .. }, q) => {
                            matches!(
                                q.projection.as_slice(),
                                [rustc_public::mir::ProjectionElem::Deref]
                            ) && copies.contains(&q.local)
                        }
                        _ => false,
                    }
                {
                    copies.insert(p.local);
                }
            }
            if copies.len() == before {
                break;
            }
        }
        let copy =
            |q: &rustc_public::mir::Place| q.projection.is_empty() && copies.contains(&q.local);
        let repointed = stmts().any(|st| match &st.kind {
            StatementKind::Assign(p, rv) => {
                (p.local == index + 1 && p.projection.is_empty())
                    || matches!(rv, Rvalue::Ref(_, rustc_public::mir::BorrowKind::Mut { .. }, q)
                        | Rvalue::AddressOf(rustc_public::mir::RawPtrKind::Mut, q) if copy(q))
            }
            _ => false,
        });
        // (moved into a closure, or into the value the function returns: written through
        // where the body does not see; moved into a value it uses itself, `let (s, _o) = (slot,
        // other)`, `p.a = slot`: followed, or lost, by the body's own pointer search)
        // (or returned itself, `fn id(s: &mut T) -> &mut T { s }`, or stored through another
        // pointer, `(*o).r = slot`: written through outside the body)
        // (into a result its callers follow, `returned_pointers`: written through there, by
        // them; a caller that does not keeps it not followed)
        let outside = |p: &rustc_public::mir::Place| {
            (p.local == rustc_public::mir::RETURN_LOCAL && !returns_followed)
                || p.projection
                    .iter()
                    .any(|e| matches!(e, rustc_public::mir::ProjectionElem::Deref))
        };
        let escapes = stmts().any(|st| match &st.kind {
            StatementKind::Assign(p, Rvalue::Aggregate(kind, ops)) => {
                (matches!(
                    kind,
                    AggregateKind::Closure(..) | AggregateKind::Coroutine(..)
                ) || outside(p))
                    && ops
                        .iter()
                        .any(|o| matches!(o, Operand::Copy(q) | Operand::Move(q) if copy(q)))
            }
            StatementKind::Assign(
                p,
                Rvalue::Use(Operand::Copy(q) | Operand::Move(q), _)
                | Rvalue::Cast(_, Operand::Copy(q) | Operand::Move(q), _),
            ) => outside(p) && copy(q),
            _ => false,
        });
        (repointed, escapes)
    };
    // a parameter the body points elsewhere taints them all; one that escapes, only itself
    let any_repointed = mut_params.iter().any(|&i| redirect(i).0);
    for &index in &mut_params {
        let entry = Origin::Param { index, owner: None };
        let value = if any_repointed || redirect(index).1 {
            Origin::Any(vec![entry.clone(), Origin::Unknown])
        } else {
            // a recursive call writing the same place (`rec(slot, n - 1)`) leaves what this
            // summary says, or the value before: the value before stands for it
            unrecurse(origins.written_through(index), &here)
        };
        // (an `Unknown` too: written in a way not followed, not left as it was)
        if value != entry {
            let w = ParamWrite {
                func: here.clone(),
                index,
                value,
                path: Vec::new(),
            };
            if !out.writes.contains(&w) {
                out.writes.push(w);
            }
        }
    }
    // what it writes through a borrow a parameter holds, by field (`fn wset(w: W) { *w.slot = v
    // }`, `fn write_hm(h: &mut H) { *h.r = v }`: `origins::holder_of`, the fields its callers
    // follow): what is behind it at the returns; through a holder the body uses otherwise (hands
    // on whole, re-points or lends a field), not followed
    let mut holders = false;
    if func && !tcx.is_closure_like(did) {
        for (index, decl) in body.arg_locals().iter().enumerate() {
            let ty = rustc_internal::internal(tcx, decl.ty);
            let fields = crate::origins::holder_of(tcx, ty);
            if fields.is_empty() {
                continue;
            }
            holders = true;
            let behind = matches!(
                ty.kind(),
                rustc_middle::ty::Ref(_, _, rustc_middle::ty::Mutability::Mut)
            );
            let kept = holder_kept(body, index + 1, behind, &fields);
            let entry = Origin::Param { index, owner: None };
            for f in fields {
                let value = if kept {
                    let mut path = if behind {
                        vec![Step::Deref]
                    } else {
                        Vec::new()
                    };
                    path.extend(crate::origins::holder_steps(tcx, ty, f));
                    path.push(Step::Deref);
                    unrecurse(origins.behind_at_returns(index + 1, &path), &here)
                } else {
                    Origin::Any(vec![entry.clone(), Origin::Unknown])
                };
                if value != entry {
                    let w = ParamWrite {
                        func: here.clone(),
                        index,
                        value,
                        path: vec![f],
                    };
                    if !out.writes.contains(&w) {
                        out.writes.push(w);
                    }
                }
            }
        }
    }
    // one taking a `&mut` (or a holder of one) that writes nothing through it (`fn up(&mut
    // self) {}`): summarised all the same, so its callers' values are left as they were
    if (!mut_params.is_empty() || holders)
        && !out.writes.iter().any(|w| w.func == here)
        && !out.summarised.contains(&here)
    {
        out.summarised.push(here.clone());
    }
    // what a function returns, and each part of it that can carry an algorithm or a key; a
    // method implementing a trait's also as `<trait method> for <Self>`, the name its calls
    // have (`ExternalError::_err` on a `Result`: `rcgen::error::ExternalError::_err for
    // core::result::Result`)
    if func {
        let ret = rustc_internal::internal(tcx, body.locals()[rustc_public::mir::RETURN_LOCAL].ty);
        let mut names = vec![here.clone()];
        if instance.is_none()
            && let Some(item) = tcx.trait_item_of(did)
            && let Some(self_ty) = crate::origins::self_adt_path(
                tcx,
                did,
                rustc_middle::ty::GenericArgs::identity_for_item(tcx, did),
            )
        {
            names.push(rcbom_facts::impl_key(&path_of(tcx, item), &self_ty));
        }
        let mut parts = carrying_parts(cx, ret);
        // a generic function's result may be of any type: kept whole (`fn _err(self) ->
        // Result<T, Error>`, a plain wrapper)
        if parts.is_empty() && ret.has_non_region_param() {
            parts.push((Vec::new(), Vec::new()));
        }
        for (path, steps) in parts {
            let value = origins.returned_part(&steps);
            if !empty(&value) {
                for func in &names {
                    out.returns.push(Returned {
                        func: func.clone(),
                        path: path.clone(),
                        value: value.clone(),
                    });
                }
            }
        }
    }
}

/// The summaries of the instances of generic functions the crate's summaries name
/// (`origins::body_name`), and of those theirs name, up to a bound: what each returns, writes
/// through its `&mut` parameters and passes to the functions it calls, under the instance's
/// name. The stores into fields and statics are the generic body's.
pub(crate) fn instance_links(cx: &Cx<'_>, out: &mut Links) {
    const MAX_INSTANCES: usize = 4096;
    let mut done = HashSet::new();
    // the generic items (and closures in them) whose instances were summarised, and those one
    // of whose instances was cut: the calls an item's own body records (for no type in
    // particular: a trait method's call whose body is not known) are said by the instances
    let mut summarised: HashSet<DefId> = HashSet::new();
    let mut cut_items: HashSet<DefId> = HashSet::new();
    // the instances named but not summarised (past the bound, or whose analysis panicked):
    // a summary that is missing is a cut
    let cut = |name: String, out: &mut Links| {
        if !out.truncated.contains(&name) {
            out.truncated.push(name);
        }
    };
    loop {
        let todo = crate::origins::take_instances();
        if todo.is_empty() {
            break;
        }
        for (name, inst) in todo {
            if done.contains(&name) {
                continue;
            }
            let did = rustc_internal::internal(cx.tcx, inst.def.def_id());
            if done.len() >= MAX_INSTANCES {
                cut_items.insert(did);
                cut(name, out);
                continue;
            }
            done.insert(name.clone());
            if cx.stop_crate(did.krate) {
                continue;
            }
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut l = Links::default();
                if let Some(body) = inst.body() {
                    body_links(cx, &body, did, true, Some(&name), &mut l);
                }
                l.fields.clear();
                l.statics.clear();
                l
            }));
            match r {
                Ok(l) => {
                    summarised.insert(did);
                    out.merge(l)
                }
                Err(_) => {
                    cut_items.insert(did);
                    cut(name, out)
                }
            }
        }
    }
    let items: HashSet<String> = summarised
        .difference(&cut_items)
        .map(|d| path_of(cx.tcx, *d))
        .collect();
    out.calls.retain(|c| !items.contains(&c.caller));
}

/// `x.a.f = v`: a store of `v` (or of each part of it that can carry an algorithm or a key) in
/// `f` of `x.a`'s struct, and in `a.f` of `x`'s; `x.a[0] = v` stores an element of `a`. A
/// struct reached through a reference (`self.f = v` in a `&mut self` method) may be a part of
/// another one: marked `via_ref`. `value` gives the origin of each part written, by the steps
/// that read it from the value.
fn field_store(
    cx: &Cx<'_>,
    origins: &Origins<'_, '_>,
    place: &rustc_public::mir::Place,
    value: &dyn Fn(&[Step]) -> Origin,
    here: &str,
    out: &mut Links,
) {
    let tcx = cx.tcx;
    let proj = &place.projection;
    // an element of an array or slice field (`m.a[0] = v`) is stored in the field
    let mut end = proj.len();
    while end > 0
        && matches!(
            proj[end - 1],
            ProjectionElem::Index(_)
                | ProjectionElem::ConstantIndex { .. }
                | ProjectionElem::Subslice { .. }
        )
    {
        end -= 1;
    }
    let field_place = rustc_public::mir::Place {
        local: place.local,
        projection: proj[..end].to_vec(),
    };
    // nothing to record unless what is written can carry an algorithm or a key
    let Ok(written) = place.ty(origins.body().locals()) else {
        return;
    };
    if carrying_parts(cx, rustc_internal::internal(tcx, written)).is_empty() {
        return;
    }
    let proj = &field_place.projection;
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
    // the structs along the way: (struct, its type arguments, fields from it, reached through
    // a reference)
    let mut chains: Vec<(String, Option<String>, Vec<usize>, bool)> = Vec::new();
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
                    let args = match ty.kind() {
                        rustc_middle::ty::Adt(_, a) => crate::adt_args(tcx, a),
                        _ => None,
                    };
                    chains.push((path_of(tcx, adt.did()), args, Vec::new(), behind_ref));
                    for c in &mut chains {
                        c.2.push(*f);
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
    if behind_ref
        && end == place.projection.len()
        && let Some(adt) = named_struct(cx, ty)
    {
        let args = match ty.kind() {
            rustc_middle::ty::Adt(_, a) => crate::adt_args(tcx, a),
            _ => None,
        };
        chains.push((path_of(tcx, adt.did()), args, Vec::new(), true));
    }
    if chains.is_empty() {
        return;
    }
    // the parts of what is written: of the element for an element
    let written = rustc_internal::internal(tcx, written);
    for (inner, steps) in carrying_parts(cx, written) {
        let value = value(&steps);
        if empty(&value) {
            continue;
        }
        for (adt, args, fields, via_ref) in &chains {
            let mut path = fields.clone();
            if end == place.projection.len() {
                path.extend(inner.iter().copied());
            }
            if path.is_empty() {
                continue;
            }
            let store = FieldStore {
                adt: adt.clone(),
                path,
                value: value.clone(),
                func: here.to_string(),
                via_ref: *via_ref,
                args: args.clone(),
            };
            if !out.fields.contains(&store) {
                out.fields.push(store);
            }
        }
    }
}

/// The function or closure a function-pointer local was made from (`_5 = hash_with as fn(..)
/// (ReifyFnPointer)`, a closure's `ClosureFnPointer`, through copies), when that is all it is.
fn fn_ptr_target(
    tcx: rustc_middle::ty::TyCtxt<'_>,
    body: &Body,
    local: rustc_public::mir::Local,
) -> Option<DefId> {
    let mut local = local;
    for _ in 0..4 {
        let defs: Vec<&Rvalue> = body
            .blocks
            .iter()
            .flat_map(|b| &b.statements)
            .filter_map(|st| match &st.kind {
                StatementKind::Assign(p, rv) if p.local == local && p.projection.is_empty() => {
                    Some(rv)
                }
                _ => None,
            })
            .collect();
        let [rv] = defs.as_slice() else { return None };
        match rv {
            Rvalue::Cast(_, rustc_public::mir::Operand::Constant(c), _) => {
                let ty = rustc_internal::internal(tcx, c.const_.ty());
                return match *ty.kind() {
                    rustc_middle::ty::FnDef(d, _) | rustc_middle::ty::Closure(d, _) => Some(d),
                    _ => None,
                };
            }
            Rvalue::Use(
                rustc_public::mir::Operand::Copy(q) | rustc_public::mir::Operand::Move(q),
                _,
            ) if q.projection.is_empty() => {
                local = q.local;
            }
            _ => return None,
        }
    }
    None
}

/// `o` with each write by a recursive call of `here` (`Written { callee: here }`) replaced by
/// the value before that call: the summary being made is what the call leaves, beside it.
fn unrecurse(o: Origin, here: &str) -> Origin {
    let go = |v: Vec<Origin>| v.into_iter().map(|a| unrecurse(a, here)).collect();
    match o {
        Origin::Written {
            callee,
            index,
            args,
            ..
        } if callee == here => args
            .get(index)
            .cloned()
            .map(|a| unrecurse(a, here))
            .unwrap_or(Origin::Unknown),
        Origin::Written {
            callee,
            index,
            args,
            self_ty,
            place_ty,
            path,
        } => Origin::Written {
            callee,
            index,
            args: go(args),
            self_ty,
            place_ty,
            path,
        },
        Origin::Any(v) => Origin::Any(go(v)),
        Origin::All(v) => Origin::All(go(v)),
        Origin::Set {
            path,
            value,
            strong,
        } => Origin::Set {
            path,
            value: Box::new(unrecurse(*value, here)),
            strong,
        },
        other => other,
    }
}

/// Standard-library methods that write their other arguments into what their first one
/// borrows mutably (`mem::replace(&mut c.alg, v)`, `c.v.push(v)`, `opt.replace(v)`).
const WRITERS: &[&str] = &[
    "replace",
    "swap",
    "push",
    "push_back",
    "push_front",
    "insert",
    "get_or_insert",
    "extend",
    "extend_from_slice",
    "append",
    "set",
    "clone_from",
];

/// A pointer through which a callee can write: `&mut T`, `*mut T`, or `&T` of a type with
/// interior mutability (a lock, a cell).
fn writable<'tcx>(tcx: rustc_middle::ty::TyCtxt<'tcx>, ty: Ty<'tcx>) -> bool {
    match ty.kind() {
        rustc_middle::ty::Ref(_, t, m) | rustc_middle::ty::RawPtr(t, m) => {
            m.is_mut()
                || (!t.has_non_region_param()
                    && !t.is_freeze(tcx, rustc_middle::ty::TypingEnv::fully_monomorphized()))
        }
        _ => false,
    }
}

/// The places a local mutably borrows a field of (`let r = &mut c.alg;`, the temporary of
/// `set_slot(&mut c.alg)`, through reborrows `&mut *r`): a write through it is a store in the
/// field.
fn field_borrows(
    tcx: rustc_middle::ty::TyCtxt<'_>,
    body: &Body,
) -> HashMap<rustc_public::mir::Local, Vec<rustc_public::mir::Place>> {
    // every borrow by a local
    let mut refs: HashMap<rustc_public::mir::Local, Vec<rustc_public::mir::Place>> = HashMap::new();
    for block in &body.blocks {
        for stmt in &block.statements {
            let StatementKind::Assign(place, rv) = &stmt.kind else {
                continue;
            };
            let (Rvalue::Ref(_, _, q) | Rvalue::Reborrow(_, _, q) | Rvalue::AddressOf(_, q)) = rv
            else {
                continue;
            };
            let ty = rustc_internal::internal(tcx, body.locals()[place.local].ty);
            let mutable = matches!(ty.kind(),
                rustc_middle::ty::Ref(_, _, m) | rustc_middle::ty::RawPtr(_, m) if m.is_mut());
            if place.projection.is_empty() && mutable {
                let v = refs.entry(place.local).or_default();
                if !v.contains(q) {
                    v.push(q.clone());
                }
            }
        }
    }
    // a reborrow (`&mut *r`) borrows what `r` does
    let resolve = |q: &rustc_public::mir::Place| -> Vec<rustc_public::mir::Place> {
        let mut out = Vec::new();
        let mut work = vec![(q.clone(), 0)];
        while let Some((q, depth)) = work.pop() {
            match q.projection.first() {
                Some(ProjectionElem::Deref) if depth < 8 && refs.contains_key(&q.local) => {
                    for b in &refs[&q.local] {
                        let mut p = b.clone();
                        p.projection.extend_from_slice(&q.projection[1..]);
                        work.push((p, depth + 1));
                    }
                }
                _ => {
                    if q.projection
                        .iter()
                        .any(|e| matches!(e, ProjectionElem::Field(..)))
                        && !out.contains(&q)
                    {
                        out.push(q);
                    }
                }
            }
        }
        out
    };
    refs.iter()
        .map(|(l, qs)| (*l, qs.iter().flat_map(&resolve).collect::<Vec<_>>()))
        .filter(|(_, v)| !v.is_empty())
        .collect()
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
        body_links(cx, &body, did, false, None, out);
    }
}

/// Cells whose value is set later or computed on first use: `OnceLock`, `OnceCell`, `LazyLock`,
/// `LazyCell`, once_cell's `Lazy`.
fn re_lazy(path: &str) -> bool {
    let last = path.rsplit("::").next().unwrap_or(path);
    matches!(
        last,
        "OnceLock" | "OnceCell" | "LazyLock" | "LazyCell" | "Lazy" | "OnceBox"
    )
}

/// The parameter a pointer written through leads to: itself (`*slot = v`), or a lock's guard
/// or a cell's reference of it (`*l.write().unwrap() = v`).
fn param_behind(o: &Origin) -> Option<usize> {
    let mut o = o;
    loop {
        match o {
            Origin::Param { index, owner: None } => return Some(*index),
            Origin::Call {
                callee,
                krate,
                args,
                ..
            } if matches!(krate.as_str(), "core" | "std" | "alloc")
                && THROUGH.iter().any(|t| callee.ends_with(t)) =>
            {
                o = args.first()?;
            }
            _ => return None,
        }
    }
}

/// The std calls a pointer is reached through from what it points into: a lock's guard, a
/// cell's reference.
const THROUGH: &[&str] = &[
    "::deref_mut",
    "::deref",
    "::unwrap",
    "::expect",
    "::write",
    "::lock",
    "::borrow_mut",
    "::get_mut",
    "::as_mut",
];

/// The static a pointer written through leads to: its address (`static mut`), or a lock's
/// guard or a cell's reference of it (`ALG.write().unwrap()`, `deref_mut`).
fn static_behind(o: &Origin) -> Option<rcbom_facts::DefRef> {
    let mut o = o;
    loop {
        match o {
            Origin::Data { def, .. } => return Some(def.clone()),
            Origin::Call {
                callee,
                krate,
                args,
                ..
            } if matches!(krate.as_str(), "core" | "std" | "alloc")
                && THROUGH.iter().any(|t| callee.ends_with(t)) =>
            {
                o = args.first()?;
            }
            _ => return None,
        }
    }
}

/// Does a value of `ty` hold a function pointer (in a reference, an array, a tuple, a struct's
/// field)?
fn holds_fn_ptr<'tcx>(tcx: rustc_middle::ty::TyCtxt<'tcx>, ty: Ty<'tcx>, depth: usize) -> bool {
    use rustc_middle::ty::TyKind as K;
    if depth > 4 {
        return false;
    }
    match ty.kind() {
        K::FnPtr(..) => true,
        K::Ref(_, t, _) | K::RawPtr(t, _) | K::Array(t, _) | K::Slice(t) => {
            holds_fn_ptr(tcx, *t, depth + 1)
        }
        K::Tuple(ts) => ts.iter().any(|t| holds_fn_ptr(tcx, t, depth + 1)),
        K::Adt(adt, args) => adt
            .all_fields()
            .any(|f| holds_fn_ptr(tcx, f.ty(tcx, args).skip_norm_wip(), depth + 1)),
        _ => false,
    }
}

/// A value static `def` holds: its initializer's (`writer` empty), or one function `writer`
/// puts there at run time.
fn push_static(out: &mut Links, def: rcbom_facts::DefRef, value: Origin, writer: &str) {
    if empty(&value) {
        return;
    }
    let i = match out.statics.iter().position(|s| s.def.id == def.id) {
        Some(i) => i,
        None => {
            out.statics.push(StaticValue {
                def,
                mutable: false,
                values: Vec::new(),
                writers: Vec::new(),
            });
            out.statics.len() - 1
        }
    };
    let s = &mut out.statics[i];
    if !writer.is_empty() && !s.writers.contains(&(writer.to_string(), value.clone())) {
        s.writers.push((writer.to_string(), value.clone()));
    }
    if !s.values.contains(&value) {
        s.values.push(value);
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
                def: def.clone(),
                mutable: true,
                values: Vec::new(),
                writers: Vec::new(),
            }),
        }
        // a `thread_local!` key starts with what its initializer function returns (`static TA:
        // Cell<..> = Cell::new(&SHA256)` makes `TA::__rust_std_internal_init_fn`)
        let ty = tcx.type_of(did).instantiate_identity().skip_norm_wip();
        if local_key(cx, ty) {
            for f in tcx.hir_body_owners().map(|d| d.to_def_id()) {
                if matches!(tcx.def_kind(f), rustc_hir::def::DefKind::Fn)
                    && tcx.opt_parent(f) == Some(did)
                    && tcx.item_name(f).as_str().contains("init")
                {
                    push_static(
                        out,
                        def.clone(),
                        Origin::Call {
                            callee: path_of(tcx, f),
                            krate: tcx.crate_name(f.krate).to_string(),
                            self_ty: None,
                            args: Vec::new(),
                            span: None,
                            runs: None,
                            pointer: None,
                            fed: None,
                        },
                        "",
                    );
                }
            }
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
    match tcx.def_kind(did) {
        rustc_hir::def::DefKind::Static { .. } if !tcx.is_foreign_item(did) => {
            let ty = tcx.type_of(did).instantiate_identity().skip_norm_wip();
            (tcx.static_mutability(did) == Some(rustc_middle::mir::Mutability::Mut)
                || !ty.is_freeze(tcx, rustc_middle::ty::TypingEnv::fully_monomorphized())
                || local_key(cx, ty))
                && carries_or_bytes(cx, ty)
        }
        rustc_hir::def::DefKind::Const if !tcx.generics_of(did).requires_monomorphization(tcx) => {
            let ty = tcx.type_of(did).instantiate_identity().skip_norm_wip();
            local_key(cx, ty) && carries_or_bytes(cx, ty)
        }
        _ => false,
    }
}

/// A `thread_local!` key over a cell (`TA.set(v)`): each thread's value changes.
fn local_key<'tcx>(cx: &Cx<'tcx>, ty: Ty<'tcx>) -> bool {
    let tcx = cx.tcx;
    match ty.kind() {
        rustc_middle::ty::Adt(adt, args)
            if path_of(tcx, adt.did()).ends_with("LocalKey")
                && cx.is_std(tcx.crate_name(adt.did().krate).as_str()) =>
        {
            args.types().next().is_some_and(|t| {
                !t.has_non_region_param()
                    && !t.is_freeze(tcx, rustc_middle::ty::TypingEnv::fully_monomorphized())
            })
        }
        _ => false,
    }
}

/// Does the body use parameter `local`, a value holding `&mut`s at `fields` (behind it when
/// `behind`), only through its fields: reading those pointers (copied, moved, reborrowed) and
/// writing or reading through them (`*w.slot = v`), and its other fields; not handing it on
/// whole, nor assigning or borrowing one of those pointers?
fn holder_kept(
    body: &Body,
    local: rustc_public::mir::Local,
    behind: bool,
    fields: &[usize],
) -> bool {
    use rustc_public::mir::MirVisitor;
    use rustc_public::mir::visit::{Location, PlaceContext};
    struct V<'a> {
        local: rustc_public::mir::Local,
        behind: bool,
        fields: &'a [usize],
        kept: bool,
    }
    impl MirVisitor for V<'_> {
        fn visit_place(
            &mut self,
            place: &rustc_public::mir::Place,
            ptx: PlaceContext,
            _: Location,
        ) {
            if place.local != self.local {
                return;
            }
            let rest = match (self.behind, place.projection.as_slice()) {
                (false, p) => p,
                (true, [ProjectionElem::Deref, p @ ..]) => p,
                _ => {
                    self.kept = false;
                    return;
                }
            };
            match rest {
                // one of the pointers (`Some`'s, of an `Option`): not assigned nor borrowed
                // itself
                [ProjectionElem::Field(f, _), tail @ ..]
                | [
                    ProjectionElem::Downcast(_),
                    ProjectionElem::Field(f, _),
                    tail @ ..,
                ] if self.fields.contains(f) => {
                    if tail.is_empty() && ptx.is_mutating() {
                        self.kept = false;
                    }
                }
                [ProjectionElem::Field(..), ..] => {}
                _ => self.kept = false,
            }
        }
        // (a debugger's name for it is no use)
        fn visit_var_debug_info(&mut self, _: &rustc_public::mir::VarDebugInfo) {}
        // (nor which variant it is, `if let Some(s) = o`)
        fn visit_rvalue(&mut self, rv: &Rvalue, loc: Location) {
            if let Rvalue::Discriminant(p) = rv
                && p.local == self.local
            {
                return;
            }
            self.super_rvalue(rv, loc)
        }
    }
    let mut v = V {
        local,
        behind,
        fields,
        kept: true,
    };
    v.visit_body(body);
    // (nor one of the pointers, or a copy of it, moved into a closure, the value returned, or a
    // place through a pointer: written through where the body does not see)
    let stmts = || body.blocks.iter().flat_map(|b| &b.statements);
    let pointer = |q: &rustc_public::mir::Place| match (behind, q.projection.as_slice()) {
        (false, [ProjectionElem::Field(f, _)])
        | (false, [ProjectionElem::Downcast(_), ProjectionElem::Field(f, _)])
        | (true, [ProjectionElem::Deref, ProjectionElem::Field(f, _)])
        | (
            true,
            [
                ProjectionElem::Deref,
                ProjectionElem::Downcast(_),
                ProjectionElem::Field(f, _),
            ],
        ) => q.local == local && fields.contains(f),
        _ => false,
    };
    let mut copies: HashSet<rustc_public::mir::Local> = HashSet::new();
    loop {
        let before = copies.len();
        for st in stmts() {
            if let StatementKind::Assign(p, rv) = &st.kind
                && p.projection.is_empty()
                && match rv {
                    Rvalue::Use(Operand::Copy(q) | Operand::Move(q), _)
                    | Rvalue::CopyForDeref(q) => {
                        pointer(q) || (q.projection.is_empty() && copies.contains(&q.local))
                    }
                    Rvalue::Ref(_, rustc_public::mir::BorrowKind::Mut { .. }, q) => {
                        matches!(q.projection.last(), Some(ProjectionElem::Deref)) && {
                            let mut base = q.clone();
                            base.projection.pop();
                            pointer(&base)
                                || (base.projection.is_empty() && copies.contains(&base.local))
                        }
                    }
                    _ => false,
                }
            {
                copies.insert(p.local);
            }
        }
        if copies.len() == before {
            break;
        }
    }
    let held = |o: &Operand| {
        matches!(o, Operand::Copy(q) | Operand::Move(q)
            if pointer(q) || (q.projection.is_empty() && copies.contains(&q.local)))
    };
    let outside = |p: &rustc_public::mir::Place| {
        p.local == rustc_public::mir::RETURN_LOCAL
            || p.projection
                .iter()
                .any(|e| matches!(e, ProjectionElem::Deref))
    };
    let escapes = stmts().any(|st| match &st.kind {
        StatementKind::Assign(p, Rvalue::Aggregate(kind, ops)) => {
            (matches!(
                kind,
                AggregateKind::Closure(..)
                    | AggregateKind::Coroutine(..)
                    | AggregateKind::CoroutineClosure(..)
            ) || outside(p))
                && ops.iter().any(held)
        }
        StatementKind::Assign(p, Rvalue::Use(o, _) | Rvalue::Cast(_, o, _)) => {
            outside(p) && held(o)
        }
        _ => false,
    });
    v.kept && !escapes
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
fn carries_or_bytes<'tcx>(cx: &Cx<'tcx>, ty: Ty<'tcx>) -> bool {
    carries(cx, ty)
        // a struct of the program held in a lock (`Mutex<Cfg>` with `Cfg { h: &Digest }`)
        || ty.walk().any(|g| {
            g.as_type()
                .is_some_and(|t| t != ty && !carrying_parts(cx, t).is_empty())
        })
        || ty.walk().any(|g| {
            g.as_type().is_some_and(|t| {
                matches!(
                    t.kind(),
                    rustc_middle::ty::Uint(_) | rustc_middle::ty::Int(_) | rustc_middle::ty::Str
                )
            })
        })
}
