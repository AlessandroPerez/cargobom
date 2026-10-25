//! Type tests: what a type holds (a `&mut`, a cell), holders, parameters and fields of types.

use super::*;

/// `ty` followed along `path` (fields, derefs, elements), as far as it goes.
pub(super) fn walk_ty<'tcx>(
    tcx: TyCtxt<'tcx>,
    ty: rustc_middle::ty::Ty<'tcx>,
    path: &[Step],
) -> rustc_middle::ty::Ty<'tcx> {
    let mut ty = ty;
    let mut variant = None;
    for step in path {
        ty = match step {
            Step::Deref => match ty.builtin_deref(true) {
                Some(t) => t,
                None => return ty,
            },
            Step::Variant(v) => {
                variant = Some(*v);
                continue;
            }
            Step::Field(f) => match ty.kind() {
                rustc_middle::ty::Adt(adt, args) => {
                    let v = match (adt.is_enum(), variant.take()) {
                        (true, Some(v)) => adt.variant(rustc_abi::VariantIdx::from_usize(v)),
                        (true, None) => return ty,
                        _ => adt.non_enum_variant(),
                    };
                    match v.fields.get(rustc_abi::FieldIdx::from_usize(*f)) {
                        Some(field) => field.ty(tcx, args).skip_norm_wip(),
                        None => return ty,
                    }
                }
                rustc_middle::ty::Tuple(ts) => match ts.get(*f) {
                    Some(t) => *t,
                    None => return ty,
                },
                _ => return ty,
            },
            Step::Elem | Step::Index(_) => match ty.builtin_index() {
                Some(t) => t,
                None => return ty,
            },
            Step::Part(_) => return ty,
        };
    }
    ty
}
/// The knowledge base's `[semantics]` for the driver (`RCBOM_SEMANTICS`, one `key=a,b` per
/// line): `fills`, the random fills that write a whole buffer; `generators`, how random
/// generators' type names end.
static SEMANTICS: std::sync::LazyLock<HashMap<String, Vec<String>>> =
    std::sync::LazyLock::new(|| {
        std::env::var("RCBOM_SEMANTICS")
            .unwrap_or_default()
            .lines()
            .filter_map(|l| l.split_once('='))
            .map(|(k, v)| {
                let vs = v.split(',').filter(|x| !x.is_empty()).map(str::to_string);
                (k.to_string(), vs.collect())
            })
            .collect()
    });
fn semantics(key: &str) -> &'static [String] {
    SEMANTICS.get(key).map_or(&[], Vec::as_slice)
}
/// Is the local a random generator (`ThreadRng`, `OsRng`, `StdRng`, `ChaCha20Rng`)?
pub(super) fn is_rng(body: &Body, local: Local) -> bool {
    match body.locals()[local].ty.kind() {
        TyKind::RigidTy(RigidTy::Adt(def, _)) => {
            let name = def.name();
            semantics("generators")
                .iter()
                .any(|s| name.ends_with(s.as_str()))
        }
        _ => false,
    }
}
/// Calls that write every byte of the buffers they are given by `&mut`, or fail: random
/// fills (`fills`: `RngCore::fill_bytes`, `Rng::fill`, `getrandom`), `Read::read_exact` and the
/// slice's own (`copy_from_slice`, `fill`).
pub(super) fn fills_whole(body: &Body, func: &Operand) -> bool {
    let Some(TyKind::RigidTy(RigidTy::FnDef(def, _))) =
        func.ty(body.locals()).ok().map(|t| t.kind())
    else {
        return false;
    };
    let name = def.name();
    let last = name.rsplit("::").next().unwrap_or(&name);
    matches!(
        last,
        "read_exact" | "copy_from_slice" | "clone_from_slice" | "fill"
    ) || semantics("fills").iter().any(|f| f == last)
}
/// Does a value of the type hold a `&mut` (a field, an element, a type argument)?
pub(super) fn holds_mut_borrow<'tcx>(
    tcx: TyCtxt<'tcx>,
    t: rustc_middle::ty::Ty<'tcx>,
    depth: usize,
) -> bool {
    use rustc_middle::ty::TyKind as K;
    use rustc_middle::ty::TypeVisitableExt;
    // (past the bound: any type with a borrowed lifetime may)
    if depth > 4 {
        return t.has_free_regions();
    }
    match t.kind() {
        // what a closure or a coroutine captures (`|| fill(&mut k)`)
        K::Closure(_, args) => {
            holds_mut_borrow(tcx, args.as_closure().tupled_upvars_ty(), depth + 1)
        }
        K::Coroutine(_, args) => {
            holds_mut_borrow(tcx, args.as_coroutine().tupled_upvars_ty(), depth + 1)
        }
        K::CoroutineClosure(_, args) => holds_mut_borrow(
            tcx,
            args.as_coroutine_closure().tupled_upvars_ty(),
            depth + 1,
        ),
        // a type parameter: any type, a `&mut` included
        K::Param(_) => true,
        K::Ref(_, _, rustc_middle::ty::Mutability::Mut)
        | K::RawPtr(_, rustc_middle::ty::Mutability::Mut) => true,
        K::Ref(_, inner, _) | K::Array(inner, _) | K::Slice(inner) => {
            holds_mut_borrow(tcx, *inner, depth + 1)
        }
        K::Tuple(ts) => ts.iter().any(|t| holds_mut_borrow(tcx, t, depth + 1)),
        // a trait object with a borrowed lifetime (`Box<dyn DerefMut<..> + 'a>`), an opaque type
        // (`impl FnMut + 'a`): what they hold is not known
        K::Dynamic(_, r) => !r.is_static(),
        K::Alias(..) => true,
        K::Adt(def, args) => {
            args.types().any(|t| holds_mut_borrow(tcx, t, depth + 1))
                || (args.regions().next().is_some()
                    && def.all_fields().any(|f| {
                        holds_mut_borrow(tcx, f.ty(tcx, args).skip_normalization(), depth + 1)
                    }))
        }
        _ => false,
    }
}
/// The fields where a value of type `t` holds a `&mut` (`[0]` of `W<'a> { slot: &'a mut T }`, of
/// `(&mut T, u8)`, of `Some` in `Option<&mut T>`: `holder_steps`): a struct of the program
/// without a destructor, a tuple or an `Option`, with no type parameter in it; one field deep.
pub(crate) fn holder_paths<'tcx>(tcx: TyCtxt<'tcx>, t: rustc_middle::ty::Ty<'tcx>) -> Vec<usize> {
    use rustc_middle::ty::TyKind as K;
    use rustc_middle::ty::TypeVisitableExt;
    let is_mut = |f: rustc_middle::ty::Ty<'tcx>| {
        matches!(f.kind(), K::Ref(_, _, rustc_middle::ty::Mutability::Mut))
    };
    if t.has_param() {
        return Vec::new();
    }
    match t.kind() {
        K::Adt(def, args) if def.is_struct() && def.did().is_local() && !def.has_dtor(tcx) => def
            .all_fields()
            .enumerate()
            .filter(|(_, f)| is_mut(f.ty(tcx, args).skip_normalization()))
            .map(|(i, _)| i)
            .collect(),
        K::Tuple(ts) => ts
            .iter()
            .enumerate()
            .filter(|(_, f)| is_mut(*f))
            .map(|(i, _)| i)
            .collect(),
        K::Adt(..) if option_holder(tcx, t) => vec![0],
        _ => Vec::new(),
    }
}
/// Is `t` an `Option<&mut T>` (`T` with no type parameter)?
pub(super) fn option_holder<'tcx>(tcx: TyCtxt<'tcx>, t: rustc_middle::ty::Ty<'tcx>) -> bool {
    use rustc_middle::ty::TypeVisitableExt;
    matches!(t.kind(), rustc_middle::ty::TyKind::Adt(def, args)
        if tcx.is_diagnostic_item(rustc_span::sym::Option, def.did())
            && matches!(args.type_at(0).kind(),
                rustc_middle::ty::TyKind::Ref(_, _, rustc_middle::ty::Mutability::Mut)))
        && !t.has_param()
}
/// The steps from a holder of type `t` (behind a `&mut` or not, `holder_of`) to its pointer at
/// field `f`: the field, or `Some`'s (variant 1 of `Option`).
pub(crate) fn holder_steps<'tcx>(
    tcx: TyCtxt<'tcx>,
    t: rustc_middle::ty::Ty<'tcx>,
    f: usize,
) -> Vec<Step> {
    let t = match t.kind() {
        rustc_middle::ty::TyKind::Ref(_, i, rustc_middle::ty::Mutability::Mut) => *i,
        _ => t,
    };
    match t.kind() {
        rustc_middle::ty::TyKind::Adt(def, _)
            if tcx.is_diagnostic_item(rustc_span::sym::Option, def.did()) =>
        {
            vec![Step::Variant(1), Step::Field(f)]
        }
        _ => vec![Step::Field(f)],
    }
}
/// The fields where a parameter of type `t` holds a `&mut` (`holder_paths`): of its value, or
/// of the value behind it for a `&mut` (`fn write_hm(h: &mut H)`).
pub(crate) fn holder_of<'tcx>(tcx: TyCtxt<'tcx>, t: rustc_middle::ty::Ty<'tcx>) -> Vec<usize> {
    match t.kind() {
        rustc_middle::ty::TyKind::Ref(_, i, rustc_middle::ty::Mutability::Mut) => {
            holder_paths(tcx, *i)
        }
        _ => holder_paths(tcx, t),
    }
}
/// The path (`[f]`) at which a call's argument `k` holds the borrow at field `f`, when the callee
/// is a function of the program, not generic nor a trait's, whose parameter `k` holds a `&mut`
/// there (`holder_of`): its summary says what it writes through it (`ParamWrite::path`).
pub(super) fn holder_param(
    tcx: TyCtxt<'_>,
    body: &Body,
    func: &Operand,
    k: usize,
    f: usize,
) -> Option<Vec<usize>> {
    let Some(TyKind::RigidTy(RigidTy::FnDef(def, _))) =
        func.ty(body.locals()).ok().map(|t| t.kind())
    else {
        return None;
    };
    let did = rustc_internal::internal(tcx, def.def_id());
    if !did.is_local()
        || tcx.trait_of_assoc(did).is_some()
        || tcx.trait_impl_of_assoc(did).is_some()
        || tcx.generics_of(did).requires_monomorphization(tcx)
    {
        return None;
    }
    let input = *tcx
        .fn_sig(did)
        .instantiate_identity()
        .skip_binder()
        .inputs()
        .get(k)?;
    holder_of(tcx, input).contains(&f).then(|| vec![f])
}
/// Does a value of type `t` hold a cell (`UnsafeCell`, inside `Cell`, `RefCell`, `Mutex`,
/// `RwLock`, `OnceLock`, an atomic; a field's, an element's), not behind a pointer: what a
/// shared borrow of it reaches may change.
pub(crate) fn holds_cell<'tcx>(
    tcx: TyCtxt<'tcx>,
    t: rustc_middle::ty::Ty<'tcx>,
    depth: usize,
) -> bool {
    use rustc_middle::ty::TyKind as K;
    if depth > 6 {
        return false;
    }
    match t.kind() {
        K::Adt(def, _) if def.is_unsafe_cell() => true,
        K::Adt(def, args) => def
            .all_fields()
            .any(|f| holds_cell(tcx, f.ty(tcx, args).skip_normalization(), depth + 1)),
        K::Array(inner, _) | K::Slice(inner) => holds_cell(tcx, *inner, depth + 1),
        K::Tuple(ts) => ts.iter().any(|t| holds_cell(tcx, t, depth + 1)),
        _ => false,
    }
}
/// Can a value of type `t` reach a cell that holds more than a plain number (`Cell<&Algorithm>`,
/// a `RefCell`'s, a lock's or a `OnceLock`'s value; not a reference count or an atomic integer),
/// in itself or through pointers (`Rc<RefCell<..>>`, `Box<Cell<..>>`, `&Cell<..>`, a `Vec` of
/// cells)?
pub(crate) fn reaches_cell<'tcx>(
    tcx: TyCtxt<'tcx>,
    t: rustc_middle::ty::Ty<'tcx>,
    depth: usize,
) -> bool {
    cell_in(tcx, t, depth, Through::All)
}
/// The same, not behind a borrow: in the value itself or in what it owns (a `Box`, an `Rc`, a
/// `Vec`, whose pointers are raw). A borrow's value is an address, which no alias changes.
pub(super) fn owns_cell<'tcx>(tcx: TyCtxt<'tcx>, t: rustc_middle::ty::Ty<'tcx>) -> bool {
    cell_in(tcx, t, 0, Through::Owned)
}
/// The same, not behind any pointer (the cell is in the value itself).
pub(super) fn cell_inline<'tcx>(tcx: TyCtxt<'tcx>, t: rustc_middle::ty::Ty<'tcx>) -> bool {
    cell_in(tcx, t, 0, Through::None)
}
pub(super) fn cell_in<'tcx>(
    tcx: TyCtxt<'tcx>,
    t: rustc_middle::ty::Ty<'tcx>,
    depth: usize,
    through: Through,
) -> bool {
    use rustc_middle::ty::TyKind as K;
    if depth > 10 {
        return false;
    }
    match t.kind() {
        K::Adt(def, args) if def.is_unsafe_cell() => not_plain(tcx, args.type_at(0), 0),
        // (`Vec<T>` names its elements only in a marker)
        K::Adt(def, args) if def.is_phantom_data() => {
            through != Through::None && cell_in(tcx, args.type_at(0), depth + 1, through)
        }
        K::Adt(def, args) => def.all_fields().any(|f| {
            cell_in(
                tcx,
                f.ty(tcx, args).skip_normalization(),
                depth + 1,
                through,
            )
        }),
        K::RawPtr(i, _) => through != Through::None && cell_in(tcx, *i, depth + 1, through),
        K::Ref(_, i, _) => through == Through::All && cell_in(tcx, *i, depth + 1, through),
        K::Array(i, _) | K::Slice(i) => cell_in(tcx, *i, depth + 1, through),
        K::Tuple(ts) => ts.iter().any(|t| cell_in(tcx, t, depth + 1, through)),
        _ => false,
    }
}
/// Does a value of type `t` hold more than numbers (a reference, a pointer, a type parameter)?
pub(super) fn not_plain<'tcx>(
    tcx: TyCtxt<'tcx>,
    t: rustc_middle::ty::Ty<'tcx>,
    depth: usize,
) -> bool {
    use rustc_middle::ty::TyKind as K;
    if depth > 6 {
        return true;
    }
    // (an atomic's storage is a projection, `<usize as AtomicPrimitive>::Storage`)
    let t = if matches!(t.kind(), K::Alias(..)) {
        match tcx.try_normalize_erasing_regions(
            rustc_middle::ty::TypingEnv::fully_monomorphized(),
            rustc_middle::ty::Unnormalized::new_wip(t),
        ) {
            Ok(n) => n,
            Err(_) => return true,
        }
    } else {
        t
    };
    match t.kind() {
        K::Bool | K::Char | K::Int(_) | K::Uint(_) | K::Float(_) | K::Never => false,
        K::Adt(def, _) if def.is_phantom_data() => false,
        K::Adt(def, args) => def
            .all_fields()
            .any(|f| not_plain(tcx, f.ty(tcx, args).skip_normalization(), depth + 1)),
        K::Array(i, _) | K::Slice(i) => not_plain(tcx, *i, depth + 1),
        K::Tuple(ts) => ts.iter().any(|t| not_plain(tcx, t, depth + 1)),
        _ => true,
    }
}
/// Can a value of type `container` hold a value of type `t` (itself, a field, a variant's field,
/// an element; not behind a pointer)?
pub(super) fn type_contains<'tcx>(
    tcx: TyCtxt<'tcx>,
    container: rustc_middle::ty::Ty<'tcx>,
    t: rustc_middle::ty::Ty<'tcx>,
    depth: usize,
) -> bool {
    use rustc_middle::ty::TyKind as K;
    if tcx.erase_and_anonymize_regions(container) == tcx.erase_and_anonymize_regions(t) {
        return true;
    }
    if depth > 4 {
        return false;
    }
    match container.kind() {
        K::Adt(def, args) => def
            .all_fields()
            .any(|f| type_contains(tcx, f.ty(tcx, args).skip_normalization(), t, depth + 1)),
        K::Tuple(ts) => ts.iter().any(|c| type_contains(tcx, c, t, depth + 1)),
        K::Array(e, _) | K::Slice(e) => type_contains(tcx, *e, t, depth + 1),
        // a type parameter, an opaque type: anything
        K::Param(_) | K::Alias(..) => true,
        _ => false,
    }
}
/// Does a value of type `t` hold a `&mut` to a value of type `pointee` (a field, an element, a
/// type argument)?
pub(super) fn holds_mut_of<'tcx>(
    tcx: TyCtxt<'tcx>,
    t: rustc_middle::ty::Ty<'tcx>,
    pointee: rustc_middle::ty::Ty<'tcx>,
    depth: usize,
) -> bool {
    use rustc_middle::ty::TyKind as K;
    if depth > 4 {
        return false;
    }
    match t.kind() {
        K::Ref(_, inner, rustc_middle::ty::Mutability::Mut)
        | K::RawPtr(inner, rustc_middle::ty::Mutability::Mut) => {
            tcx.erase_and_anonymize_regions(*inner) == tcx.erase_and_anonymize_regions(pointee)
                || holds_mut_of(tcx, *inner, pointee, depth + 1)
        }
        K::Ref(_, inner, _) | K::Array(inner, _) | K::Slice(inner) => {
            holds_mut_of(tcx, *inner, pointee, depth + 1)
        }
        K::Tuple(ts) => ts.iter().any(|x| holds_mut_of(tcx, x, pointee, depth + 1)),
        K::Adt(def, args) => {
            args.types()
                .any(|x| holds_mut_of(tcx, x, pointee, depth + 1))
                || (args.regions().next().is_some()
                    && def.all_fields().any(|f| {
                        holds_mut_of(
                            tcx,
                            f.ty(tcx, args).skip_normalization(),
                            pointee,
                            depth + 1,
                        )
                    }))
        }
        _ => false,
    }
}
/// The ADT a method belongs to: `Self` of a trait method (`Argon2` in
/// `<Argon2 as Default>::default`), the self type of an inherent impl.
pub(crate) fn self_adt_path<'tcx>(
    tcx: TyCtxt<'tcx>,
    did: DefId,
    args: rustc_middle::ty::GenericArgsRef<'tcx>,
) -> Option<String> {
    let ty = if tcx.trait_of_assoc(did).is_some() {
        args.first()?.as_type()?
    } else {
        tcx.type_of(tcx.impl_of_assoc(did)?).skip_binder()
    };
    match ty.kind() {
        rustc_middle::ty::Adt(adt, _) => Some(path_of(tcx, adt.did())),
        _ => None,
    }
}
/// For a trait method called on a trait object (`s.alg()` with `s: &dyn Source`), `dyn` and
/// the object's trait (`dyn app::Source`): the call runs the implementation of a type coerced to
/// it (`Links::coercions`).
pub(super) fn dyn_self<'tcx>(
    tcx: TyCtxt<'tcx>,
    did: DefId,
    args: rustc_middle::ty::GenericArgsRef<'tcx>,
) -> Option<String> {
    tcx.trait_of_assoc(did)?;
    match args.first()?.as_type()?.kind() {
        rustc_middle::ty::Dynamic(preds, ..) => {
            Some(format!("dyn {}", path_of(tcx, preds.principal_def_id()?)))
        }
        _ => None,
    }
}
/// The field indices of a path made of fields only (`.alg`, `.0.key`).
/// The fields leading to an element written (`.algorithms` of `v.algorithms[0]`: fields, then
/// a dereference or an element step, with an element step among the rest).
pub(super) fn fields_to_element(steps: &[Step]) -> Option<Vec<usize>> {
    let n = steps
        .iter()
        .take_while(|s| matches!(s, Step::Field(_)))
        .count();
    let (fields, rest) = steps.split_at(n);
    (n > 0
        && rest
            .iter()
            .any(|s| matches!(s, Step::Elem | Step::Index(_))))
    .then(|| field_steps(fields))
    .flatten()
}
pub(super) fn field_steps(steps: &[Step]) -> Option<Vec<usize>> {
    steps
        .iter()
        .map(|s| match s {
            Step::Field(f) => Some(*f),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()
        .filter(|v| !v.is_empty())
}
