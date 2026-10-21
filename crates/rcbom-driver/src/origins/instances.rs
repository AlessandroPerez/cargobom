//! Instances and the bodies calls run: their names, summaries and the instances named.

use super::*;

/// The defining path of the function a call operand names.
pub(super) fn callee_name(body: &Body, func: &Operand) -> Option<String> {
    match func.ty(body.locals()).ok()?.kind() {
        TyKind::RigidTy(RigidTy::FnDef(def, _)) => Some(def.name()),
        _ => None,
    }
}
/// Sets the crates whose generic items' instances are summarised (`SUMMARISED`).
pub(crate) fn set_summarised(crates: HashSet<rustc_span::def_id::CrateNum>) {
    SUMMARISED.with(|s| *s.borrow_mut() = crates);
}
/// The instances `body_name` named since the last call.
pub(crate) fn take_instances() -> Vec<(String, rustc_public::mir::mono::Instance)> {
    INSTANCES.with(|v| std::mem::take(&mut *v.borrow_mut()))
}
/// The name of the body a call runs as the links name it: an item's defining path
/// (`<app::Fast as app::Pick>::alg`), or, for an item of the program with generic parameters (a
/// generic function, a trait's default body, a generic impl's method, a closure inside one), of
/// this crate or another of the program's (`SUMMARISED`), the instance's
/// (`app::pick::<app::Fast>`, `<app::Legacy as app::Pick>::alg`), whose summaries the driver
/// records; `None` for a standard-library or stop crate's generic item, and for an instance
/// still generic.
pub(crate) fn body_name<'tcx>(
    tcx: TyCtxt<'tcx>,
    inst: rustc_middle::ty::Instance<'tcx>,
) -> Option<String> {
    use rustc_middle::ty::TypeVisitableExt;
    use rustc_middle::ty::print::{
        with_crate_prefix, with_no_trimmed_paths, with_no_visible_paths,
    };
    if !matches!(inst.def, rustc_middle::ty::InstanceKind::Item(_)) {
        return None;
    }
    let def = inst.def_id();
    if !tcx.generics_of(def).requires_monomorphization(tcx) {
        return Some(path_of(tcx, def));
    }
    let summarised = SUMMARISED.with(|s| s.borrow().contains(&def.krate));
    if !(def.is_local() || summarised) || inst.args.has_non_region_param() {
        return None;
    }
    // a closure: only inside a generic function, whose instance it depends on (one of a
    // monomorphic function is its item, as the per-item links have it)
    if tcx.is_closure_like(def)
        && !tcx
            .generics_of(tcx.typeck_root_def_id(def))
            .requires_monomorphization(tcx)
    {
        return Some(path_of(tcx, def));
    }
    let args = tcx.erase_and_anonymize_regions(inst.args);
    let p = with_crate_prefix!(with_no_visible_paths!(with_no_trimmed_paths!(
        tcx.def_path_str_with_args(def, args)
    )));
    let name = crate::local_crate_name(tcx, p);
    let inst = rustc_middle::ty::Instance::new_raw(def, args);
    INSTANCES.with(|v| {
        let mut v = v.borrow_mut();
        if !v.iter().any(|(n, _)| *n == name) {
            v.push((name.clone(), rustc_internal::stable(inst)));
        }
    });
    Some(name)
}
/// The body a call of `did` with `args` runs, when it is another than `did`'s item as the
/// links name it (`Origin::Call::runs`): a trait method's implementation for a known `Self` or
/// the default body, an instance of a generic function of this crate.
pub(crate) fn runs_of<'tcx>(
    tcx: TyCtxt<'tcx>,
    did: DefId,
    args: rustc_middle::ty::GenericArgsRef<'tcx>,
) -> Option<String> {
    use rustc_middle::ty::TypeVisitableExt;
    if args.has_non_region_param() || dyn_self(tcx, did, args).is_some() {
        return None;
    }
    if tcx.trait_of_assoc(did).is_none() && !tcx.generics_of(did).requires_monomorphization(tcx) {
        return None;
    }
    let env = rustc_middle::ty::TypingEnv::fully_monomorphized();
    let inst = rustc_middle::ty::Instance::try_resolve(tcx, env, did, args).ok()??;
    body_name(tcx, inst).filter(|n| *n != path_of(tcx, did))
}
/// The body a function item of `did` with `args` runs when it is named as a value or made a
/// pointer (`map(Pick::alg)`, `let f = pick::<Fast>`): as `runs_of`, and also a generic
/// function's instance when it is not a method.
pub(super) fn item_runs<'tcx>(
    tcx: TyCtxt<'tcx>,
    did: DefId,
    args: rustc_middle::ty::GenericArgsRef<'tcx>,
) -> Option<String> {
    runs_of(tcx, did, args).or_else(|| {
        let env = rustc_middle::ty::TypingEnv::fully_monomorphized();
        rustc_middle::ty::Instance::try_resolve(tcx, env, did, args)
            .ok()
            .flatten()
            .and_then(|i| body_name(tcx, i))
            .filter(|n| *n != path_of(tcx, did))
    })
}
/// The function a call of `did` with `args` writes through, as `Links::writes` names it: a
/// trait method's call with a known `Self` type is its implementation's (`<Ctx as Up>::up`, or
/// the trait's default body for it), a generic function's of this crate its instance's
/// (`body_name`); one on a trait object or a type parameter stays the trait method's, with
/// `dyn <trait>` or `impl <trait>` (see `Origin::Written`), unless the place written is of a
/// known type (`let u: &mut dyn Up = &mut b; u.up()` writes `b`, a `B`: `<B as Up>::up`).
pub(crate) fn write_callee<'tcx>(
    tcx: TyCtxt<'tcx>,
    did: DefId,
    args: rustc_middle::ty::GenericArgsRef<'tcx>,
    place: Option<rustc_middle::ty::Ty<'tcx>>,
) -> (String, Option<String>) {
    use rustc_middle::ty::TypeVisitableExt;
    let env = rustc_middle::ty::TypingEnv::fully_monomorphized();
    let resolved = |args: rustc_middle::ty::GenericArgsRef<'tcx>| {
        if args.has_non_region_param() {
            return None;
        }
        let i = rustc_middle::ty::Instance::try_resolve(tcx, env, did, args).ok()??;
        body_name(tcx, i)
    };
    let Some(tr) = tcx.trait_of_assoc(did) else {
        return (resolved(args).unwrap_or_else(|| path_of(tcx, did)), None);
    };
    if let Some(d) = dyn_self(tcx, did, args) {
        // the object is a place of a known type: its implementation
        if let Some(t) = place
            && matches!(t.kind(), rustc_middle::ty::Adt(..))
            && !t.has_non_region_param()
        {
            let args = tcx.mk_args_from_iter(
                std::iter::once(rustc_middle::ty::GenericArg::from(t)).chain(args.iter().skip(1)),
            );
            if let Some(n) = resolved(args) {
                return (n, None);
            }
        }
        return (path_of(tcx, did), Some(d));
    }
    if let Some(n) = resolved(args) {
        return (n, None);
    }
    (
        path_of(tcx, did),
        Some(format!("impl {}", path_of(tcx, tr))),
    )
}
