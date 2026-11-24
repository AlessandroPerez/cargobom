//! Names, defining paths, positions and type trees of the items the facts cite.

use super::*;

/// A type's kind, read without the panic `rustc_public` has for the type of an `async` closure
/// (`CoroutineClosure`: "FIXME(async_closures): Lower these to SMIR"): that one is built here,
/// from the compiler's own type. Every reading of a type's kind in this crate goes through it:
/// a caught panic would lose what was being read with it (a coercion to a trait object of a
/// type holding such a closure, and the methods the object runs).
pub(crate) trait KindOf {
    fn kind_of(&self) -> TyKind;
}
impl KindOf for Ty {
    #[allow(clippy::disallowed_methods)]
    fn kind_of(&self) -> TyKind {
        rustc_middle::ty::tls::with(|tcx| match rustc_internal::internal(tcx, *self).kind() {
            rustc_middle::ty::CoroutineClosure(def, args) => {
                TyKind::RigidTy(RigidTy::CoroutineClosure(
                    rustc_public::ty::CoroutineClosureDef(rustc_internal::stable(*def)),
                    GenericArgs(
                        args.iter()
                            .map(|a| rustc_internal::stable(a.kind()))
                            .collect(),
                    ),
                ))
            }
            _ => self.kind(),
        })
    }
}
pub(crate) fn crate_ref(tcx: TyCtxt<'_>, did: rustc_span::def_id::DefId) -> CrateRef {
    CrateRef {
        name: tcx.crate_name(did.krate).to_string(),
        stable_id: format!("{:016x}", tcx.stable_crate_id(did.krate).as_u64()),
    }
}
pub(crate) fn def_ref_internal(tcx: TyCtxt<'_>, did: rustc_span::def_id::DefId) -> DefRef {
    DefRef {
        krate: crate_ref(tcx, did),
        path: path_of(tcx, did),
        id: def_hash(tcx, did),
    }
}
/// The defining path of an item, crate first: the same whichever crate prints it, and not
/// through re-exports (`crypto_common::KeyInit::new_from_slice`, not
/// `aes_gcm::KeyInit::new_from_slice` in one crate and `chacha20poly1305::KeyInit::..` in
/// another).
pub(crate) fn path_of(tcx: TyCtxt<'_>, did: rustc_span::def_id::DefId) -> String {
    use rustc_middle::ty::print::{
        with_crate_prefix, with_no_trimmed_paths, with_no_visible_paths,
    };
    let p = with_crate_prefix!(with_no_visible_paths!(with_no_trimmed_paths!(
        tcx.def_path_str(did)
    )));
    local_crate_name(tcx, p)
}
/// The crate's own structs, enums and unions that implement one of `traits` (defining paths),
/// by path, with those traits: read from the crate's impls (`impl Error for PError`).
pub(crate) fn implementors(
    tcx: TyCtxt<'_>,
    traits: &[String],
) -> std::collections::BTreeMap<String, Vec<String>> {
    let mut out: std::collections::BTreeMap<String, Vec<String>> = Default::default();
    if traits.is_empty() {
        return out;
    }
    for (&tr, impls) in tcx.all_local_trait_impls(()) {
        let name = path_of(tcx, tr);
        if !traits.contains(&name) {
            continue;
        }
        for &i in impls {
            if let Some(adt) = tcx.type_of(i).skip_binder().ty_adt_def()
                && adt.did().is_local()
            {
                out.entry(path_of(tcx, adt.did()))
                    .or_default()
                    .push(name.clone());
            }
        }
    }
    for v in out.values_mut() {
        v.sort();
        v.dedup();
    }
    out
}
/// An instance's path with its generic arguments, printed the same way as `path_of`.
pub(crate) fn instance_name(tcx: TyCtxt<'_>, inst: &Instance) -> String {
    use rustc_middle::ty::print::{
        with_crate_prefix, with_no_trimmed_paths, with_no_visible_paths,
    };
    let i = rustc_internal::internal(tcx, inst);
    let p = with_crate_prefix!(with_no_visible_paths!(with_no_trimmed_paths!(
        tcx.def_path_str_with_args(i.def_id(), i.args)
    )));
    local_crate_name(tcx, p)
}
/// A struct's type arguments, printed as `path_of` prints paths, regions erased: `None` when it
/// has none, or when they are not known yet (a generic function's own parameters).
pub(crate) fn adt_args<'tcx>(
    tcx: TyCtxt<'tcx>,
    args: rustc_middle::ty::GenericArgsRef<'tcx>,
) -> Option<String> {
    use rustc_middle::ty::print::{
        with_crate_prefix, with_no_trimmed_paths, with_no_visible_paths,
    };
    let tys: Vec<_> = args.types().collect();
    if tys.is_empty() || args.has_non_region_param() {
        return None;
    }
    let p = tys
        .iter()
        .map(|t| {
            let t = tcx.erase_and_anonymize_regions(*t);
            with_crate_prefix!(with_no_visible_paths!(with_no_trimmed_paths!(format!(
                "{t}"
            ))))
        })
        .collect::<Vec<_>>()
        .join(", ");
    Some(local_crate_name(tcx, p))
}
/// `crate::` (how rustc prints the local crate under `with_crate_prefix!`) as the crate's name:
/// `<crate::AesSealer as crate::Sealer>::seal` is `<micro::AesSealer as micro::Sealer>::seal`.
pub(crate) fn local_crate_name(tcx: TyCtxt<'_>, p: String) -> String {
    let name = tcx.crate_name(rustc_span::def_id::LOCAL_CRATE);
    let mut out = String::with_capacity(p.len());
    let mut rest = p.as_str();
    while let Some(i) = rest.find("crate::") {
        let boundary = rest[..i]
            .chars()
            .next_back()
            .is_none_or(|c| !(c.is_alphanumeric() || c == '_'));
        out.push_str(&rest[..i]);
        out.push_str(if boundary { name.as_str() } else { "crate" });
        out.push_str("::");
        rest = &rest[i + "crate::".len()..];
    }
    out.push_str(rest);
    unraw(&out)
}
/// A path without raw-identifier prefixes: rustc prints rand's `gen` as `r#gen` when compiling
/// a crate of edition 2024, where it is a keyword, and as `gen` from rand's own crate; one
/// function, one path.
pub(super) fn unraw(p: &str) -> String {
    let b = p.as_bytes();
    let mut out = String::with_capacity(p.len());
    let mut i = 0;
    while i < b.len() {
        let starts = i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_');
        if starts
            && b[i] == b'r'
            && b.get(i + 1) == Some(&b'#')
            && b.get(i + 2)
                .is_some_and(|c| c.is_ascii_alphabetic() || *c == b'_')
        {
            i += 2;
            continue;
        }
        let c = p[i..].chars().next().unwrap_or_default();
        out.push(c);
        i += c.len_utf8();
    }
    out
}
pub(super) fn owner_id_of(s: &Site) -> String {
    s.owner.id.clone()
}
pub(super) fn fn_owner(cx: &Cx<'_>, inst: &Instance) -> Owner {
    let did = rustc_internal::internal(cx.tcx, inst.def.def_id());
    Owner {
        kind: OwnerKind::Fn,
        name: instance_name(cx.tcx, inst),
        id: inst.mangled_name(),
        krate: crate_ref(cx.tcx, did),
        path: path_of(cx.tcx, did),
    }
}
pub(super) fn fn_owner_item(cx: &Cx<'_>, item: &rustc_public::CrateItem) -> Owner {
    let did = rustc_internal::internal(cx.tcx, item.def_id());
    Owner {
        kind: OwnerKind::Fn,
        name: path_of(cx.tcx, did),
        id: def_hash(cx.tcx, did),
        krate: crate_ref(cx.tcx, did),
        path: path_of(cx.tcx, did),
    }
}
/// The def-path hash as 32 hex digits; the first 16 are the crate's `StableCrateId`.
pub(crate) fn def_hash(tcx: TyCtxt<'_>, did: rustc_span::def_id::DefId) -> String {
    let (a, b) = tcx.def_path_hash(did).0.split();
    format!("{:016x}{:016x}", a.as_u64(), b.as_u64())
}
/// The source text of a span on one line outside macros: what an occurrence names.
pub(crate) fn span_text(tcx: TyCtxt<'_>, span: rustc_span::Span) -> Option<String> {
    if span.from_expansion() {
        return None;
    }
    let t = tcx.sess.source_map().span_to_snippet(span).ok()?;
    (!t.is_empty() && !t.contains('\n') && t.chars().count() <= 120).then_some(t)
}
/// The source line of a span's position (`locate`: the outermost macro call site for code
/// from a macro), trimmed.
pub(crate) fn line_text(tcx: TyCtxt<'_>, span: rustc_span::Span) -> Option<String> {
    let at = if span.from_expansion() {
        span.source_callsite()
    } else {
        span
    };
    let sm = tcx.sess.source_map();
    let line = sm
        .span_to_snippet(sm.span_extend_to_line(at.shrink_to_lo()))
        .ok()?;
    let line = line.trim();
    (!line.is_empty()).then(|| line.to_string())
}
/// For a function a derive generated (its definition is in the derive's expansion), a span of
/// that expansion to cite its code at: the derive's (`locate` then tags it `[derive ..]`).
pub(crate) fn derive_site(
    tcx: TyCtxt<'_>,
    did: rustc_span::def_id::DefId,
) -> Option<rustc_span::Span> {
    use rustc_span::hygiene::{ExpnKind, MacroKind as K};
    let ds = tcx.def_span(did);
    if !ds.from_expansion() {
        return None;
    }
    let mut expn = ds.ctxt().outer_expn_data();
    while expn.call_site.from_expansion() {
        expn = expn.call_site.ctxt().outer_expn_data();
    }
    matches!(expn.kind, ExpnKind::Macro(K::Derive, _)).then_some(ds)
}
/// Source position of a span; code from a macro is attributed to the outermost call site in
/// the user's source, with the position inside the macro kept as `Expansion`.
pub(crate) fn locate(tcx: TyCtxt<'_>, span: rustc_span::Span) -> (Loc, Option<Expansion>) {
    if span.from_expansion() {
        let call = span.source_callsite();
        // the outermost expansion is the one whose call site is in the user's source:
        // `vec![..]` inside `hash_all!(..)` is reported as `hash_all!`
        let mut expn = span.ctxt().outer_expn_data();
        while expn.call_site.from_expansion() {
            expn = expn.call_site.ctxt().outer_expn_data();
        }
        use rustc_span::hygiene::{ExpnKind, MacroKind as K};
        let (kind, macro_name) = match expn.kind {
            ExpnKind::Macro(K::Bang, name) => (MacroKind::Bang, name.to_string()),
            // code a derive or an attribute generates is attributed to that attribute
            ExpnKind::Macro(K::Derive, name) => (MacroKind::Derive, name.to_string()),
            ExpnKind::Macro(K::Attr, name) => (MacroKind::Attr, name.to_string()),
            // desugarings (`?`, `for`, `async`): the call site is ordinary code
            _ => (MacroKind::Desugaring, String::new()),
        };
        let exp = Expansion {
            kind,
            macro_name,
            def_site: raw_loc(tcx, span),
            steps: expansion_steps(tcx, span),
            text: span_head(tcx, span, 120),
            mark: span_mark(tcx, span),
        };
        (raw_loc(tcx, call), Some(exp))
    } else {
        (raw_loc(tcx, span), None)
    }
}
/// The span of the path naming item `did`, where the compiler ran it from an earlier writing of
/// a macro's fragment (`rcbom_facts::fragment_path`): from the fragment's writing the path
/// starts with. Any other span as it is.
pub(crate) fn named_span(
    tcx: TyCtxt<'_>,
    span: rustc_span::Span,
    did: rustc_span::def_id::DefId,
) -> rustc_span::Span {
    if !span.from_expansion() {
        return span;
    }
    let Some(name) = tcx.opt_item_name(did) else {
        return span;
    };
    let Ok(text) = tcx.sess.source_map().span_to_snippet(span) else {
        return span;
    };
    match rcbom_facts::fragment_path(&text, name.as_str()) {
        Some(at) => span.with_lo(span.lo() + rustc_span::BytePos(at as u32)),
        None => span,
    }
}
/// Where a piece of code is, for a place no name in the text holds (a coercion): the code
/// itself, or for a macro's code the invocation in the source that writes it (`locate`'s
/// position), with how it starts there and the fingerprint of its line at its column.
pub(crate) fn place(tcx: TyCtxt<'_>, span: rustc_span::Span) -> crate::Place {
    let s = if span.from_expansion() {
        span.source_callsite()
    } else {
        span
    };
    (raw_loc(tcx, s), span_head(tcx, s, 120), span_mark(tcx, s))
}
/// The start of a span's source text where it is written (inside a macro's definition, for a
/// macro's code): its first line, to `max` characters.
pub(crate) fn span_head(tcx: TyCtxt<'_>, span: rustc_span::Span, max: usize) -> Option<String> {
    let t = tcx.sess.source_map().span_to_snippet(span).ok()?;
    let h: String = t.lines().next()?.chars().take(max).collect();
    (!h.trim().is_empty()).then_some(h)
}
/// The fingerprint of a span's start in its source line, where it is written
/// (`rcbom_facts::line_mark`).
pub(crate) fn span_mark(tcx: TyCtxt<'_>, span: rustc_span::Span) -> Option<String> {
    if span.is_dummy() {
        return None;
    }
    let sm = tcx.sess.source_map();
    let line = sm
        .span_to_snippet(sm.span_extend_to_line(span.shrink_to_lo()))
        .ok()?;
    let (_, _, col, _, _) = sm.span_to_location_info(span);
    Some(rcbom_facts::line_mark(&line, col.saturating_sub(1)))
}
/// Every expansion a span is in, innermost first, as the compiler records them.
fn expansion_steps(tcx: TyCtxt<'_>, span: rustc_span::Span) -> Vec<rcbom_facts::ExpansionStep> {
    if !span.from_expansion() {
        return Vec::new();
    }
    steps_from(tcx, span.ctxt().outer_expn_data())
}
/// An expansion and those it is in, innermost first.
fn steps_from(
    tcx: TyCtxt<'_>,
    first: rustc_span::hygiene::ExpnData,
) -> Vec<rcbom_facts::ExpansionStep> {
    use rcbom_facts::{Rewrite as R, StepKind};
    use rustc_span::hygiene::{DesugaringKind as D, ExpnKind, MacroKind as K};
    let mut out = Vec::new();
    let mut next = Some(first);
    while let Some(expn) = next.take()
        && out.len() < 64
    {
        let (kind, name) = match expn.kind {
            ExpnKind::Root => break,
            ExpnKind::Macro(K::Bang, name) => (StepKind::Bang, name.to_string()),
            ExpnKind::Macro(K::Attr, name) => (StepKind::Attr, name.to_string()),
            ExpnKind::Macro(K::Derive, name) => (StepKind::Derive, name.to_string()),
            ExpnKind::AstPass(_) => (StepKind::Pass, String::new()),
            // (no arm for the rest: a rewrite a later toolchain adds does not build here)
            ExpnKind::Desugaring(d) => (
                StepKind::Rewrite(match d {
                    D::QuestionMark => R::QuestionMark,
                    D::TryBlock => R::TryBlock,
                    D::YeetExpr => R::Yeet,
                    D::OpaqueTy => R::OpaqueTy,
                    D::Async => R::Async,
                    D::Await => R::Await,
                    D::ForLoop => R::ForLoop,
                    D::WhileLoop => R::WhileLoop,
                    D::BoundModifier => R::BoundModifier,
                    D::Contract => R::Contract,
                    D::PatTyRange => R::PatTyRange,
                    D::FormatLiteral { .. } => R::FormatLiteral,
                    D::RangeExpr => R::RangeExpr,
                }),
                String::new(),
            ),
        };
        out.push(rcbom_facts::ExpansionStep {
            kind,
            name,
            call: raw_loc(tcx, expn.call_site),
            def: raw_loc(tcx, expn.def_site),
            mark: span_mark(tcx, expn.call_site),
        });
        if expn.call_site.from_expansion() {
            next = Some(expn.call_site.ctxt().outer_expn_data());
        }
    }
    out
}
/// The expansion that defines an item, as the compiler records it; the root's for one the
/// source writes. Of another crate's items, the metadata keeps it for modules, types, traits
/// and impls only: an item in one of those a macro defines is that macro's. One in none of
/// those (a free function a macro writes, `implement_aead!(aes128_seal, ..)`: its name is the
/// invocation's, and reads as the source's) is the macro's whose expansion its header is
/// written in.
fn defining_expansion(
    tcx: TyCtxt<'_>,
    did: rustc_span::def_id::DefId,
) -> rustc_span::hygiene::ExpnId {
    use rustc_hir::def::DefKind as K;
    let root = rustc_span::hygiene::ExpnId::root();
    if did.is_local() {
        return tcx.expn_that_defined(did);
    }
    let mut d = did;
    while !d.is_crate_root() {
        if matches!(
            tcx.def_kind(d),
            K::Mod | K::Struct | K::Union | K::Enum | K::Trait | K::Impl { .. }
        ) {
            let e = tcx.expn_that_defined(d);
            if e != root {
                return e;
            }
        }
        match tcx.opt_parent(d) {
            Some(p) => d = p,
            None => break,
        }
    }
    // (past what the compiler rewrites, an `async fn`'s body: the macro such code is in)
    let mut own = tcx.def_span(did).ctxt().outer_expn();
    while own != root
        && !matches!(
            own.expn_data().kind,
            rustc_span::hygiene::ExpnKind::Macro(..)
        )
    {
        own = own.expn_data().call_site.ctxt().outer_expn();
    }
    own
}
/// Where the source names an item: its identifier; for a closure or an `async` block, where it
/// is written. An item a macro defines is so whatever spans its tokens have (a procedural macro
/// gives its code the spans of what it was made from: `#[async_trait]`'s `async move { .. }`
/// block has the span of the `async` of the `async fn` it rewrites; a `macro_rules!` writing
/// `fn $name() { .. }` has the invocation's `$name`): with the expansions that define it, as
/// the compiler records them of the definition.
pub(crate) fn item_at(
    tcx: TyCtxt<'_>,
    did: rustc_span::def_id::DefId,
    body: Option<rustc_span::Span>,
) -> Option<rcbom_facts::ItemAt> {
    let ident = tcx.def_ident_span(did);
    let span = ident.unwrap_or_else(|| tcx.def_span(did));
    if span.is_dummy() {
        return None;
    }
    let (name, mut expansion) = locate(tcx, span);
    let defined = defining_expansion(tcx, did);
    if expansion.is_none() && defined != rustc_span::hygiene::ExpnId::root() {
        let steps = steps_from(tcx, defined.expn_data());
        // (a module an invocation declares out of line, `cfg_rt! { mod task; }`, is defined
        // in that expansion with all its file holds, and the macro writes none of it: an item
        // named in another file than the expansions' invocations and definitions is the
        // source's, as its file writes it)
        let file = raw_loc(tcx, span).file;
        let written = steps
            .iter()
            .any(|s| s.call.file == file || s.def.file == file);
        if let Some(last) = steps.last().filter(|_| written) {
            let kind = match last.kind {
                rcbom_facts::StepKind::Bang => MacroKind::Bang,
                rcbom_facts::StepKind::Derive => MacroKind::Derive,
                rcbom_facts::StepKind::Attr => MacroKind::Attr,
                rcbom_facts::StepKind::Rewrite(_) | rcbom_facts::StepKind::Pass => {
                    MacroKind::Desugaring
                }
            };
            expansion = Some(Expansion {
                kind,
                macro_name: last.name.clone(),
                def_site: raw_loc(tcx, span),
                steps,
                text: span_head(tcx, span, 120),
                mark: span_mark(tcx, span),
            });
        }
    }
    // (the item whole, for one the source writes: its body's span, or for one of this crate,
    // its source's)
    let body = body
        .or_else(|| did.as_local().map(|l| tcx.source_span(l)))
        .filter(|b| expansion.is_none() && !b.is_dummy() && !b.from_expansion())
        .map(|b| raw_loc(tcx, b));
    // (an item with no identifier: how it starts and its line's fingerprint say where it is)
    let read = ident.is_none() && expansion.is_none();
    (name.line != 0).then_some(rcbom_facts::ItemAt {
        text: span_head(tcx, span, 120).filter(|_| read),
        mark: span_mark(tcx, span).filter(|_| read),
        name,
        expansion,
        body,
    })
}
pub(super) fn raw_loc(tcx: TyCtxt<'_>, span: rustc_span::Span) -> Loc {
    // no position at all (a call the compiler generated, in the standard library's MIR): not
    // the first line of whatever file is first in the source map
    if span.is_dummy() {
        return Loc {
            file: String::new(),
            line: 0,
            col: 0,
            end_line: 0,
            end_col: 0,
        };
    }
    let sm = tcx.sess.source_map();
    let (_, line, col, end_line, end_col) = sm.span_to_location_info(span);
    let mut file = sm
        .span_to_filename(span)
        .prefer_local_unconditionally()
        .to_string();
    // The standard library's sources by rustc's own name for them (`/rustc/<commit>/library/..`,
    // as in its panic messages), not by where rust-src is installed on this machine, so that
    // the CBOM is the same on every machine and names no local directory. rustc itself maps
    // that name to the installed rust-src when it reads a crate's metadata, and keeps only the
    // local path.
    let rust_src = tcx.sess.opts.sysroot.path().join("lib/rustlib/src/rust");
    if let Ok(rest) = Path::new(&file).strip_prefix(&rust_src)
        && let Some(base) = virtual_rust_src(tcx)
    {
        file = format!("{base}/{}", rest.display());
    }
    Loc {
        file,
        line,
        col,
        end_line,
        end_col,
    }
}
/// `/rustc/<commit>`, the directory rustc names the standard library's sources by, from the
/// toolchain's own `rustc -vV`; asked once, when first needed.
pub(super) fn virtual_rust_src(tcx: TyCtxt<'_>) -> Option<&'static str> {
    static BASE: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    BASE.get_or_init(|| {
        let rustc = tcx.sess.opts.sysroot.path().join("bin").join("rustc");
        let out = std::process::Command::new(rustc).arg("-vV").output().ok()?;
        let text = String::from_utf8(out.stdout).ok()?;
        let hash = text
            .lines()
            .find_map(|l| l.strip_prefix("commit-hash: "))?
            .trim();
        (hash != "unknown").then(|| format!("/rustc/{hash}"))
    })
    .as_deref()
}
pub(crate) fn locate_stable(tcx: TyCtxt<'_>, span: Span) -> (Loc, Option<Expansion>) {
    locate(tcx, rustc_internal::internal(tcx, span))
}
pub(crate) fn ty_tree(tcx: TyCtxt<'_>, ty: &Ty, depth: usize) -> TyTree {
    if depth > 16 {
        return TyTree::Other("…".into());
    }
    match ty.kind_of() {
        TyKind::RigidTy(r) => match r {
            RigidTy::Adt(def, args) => {
                let did = rustc_internal::internal(tcx, def.def_id());
                TyTree::Adt {
                    krate: crate_ref(tcx, did),
                    path: path_of(tcx, did),
                    args: arg_trees(tcx, &args.0, depth + 1),
                }
            }
            RigidTy::Ref(_, t, _) | RigidTy::RawPtr(t, _) => {
                TyTree::Ref(Box::new(ty_tree(tcx, &t, depth + 1)))
            }
            RigidTy::Slice(t) => TyTree::Slice(Box::new(ty_tree(tcx, &t, depth + 1))),
            RigidTy::Array(t, n) => TyTree::Array(
                Box::new(ty_tree(tcx, &t, depth + 1)),
                n.eval_target_usize().ok(),
            ),
            RigidTy::Tuple(ts) => {
                TyTree::Tuple(ts.iter().map(|t| ty_tree(tcx, t, depth + 1)).collect())
            }
            RigidTy::Dynamic(preds, _) => TyTree::Dyn(
                preds
                    .iter()
                    .filter_map(|p| match &p.value {
                        // (by its defining path, as coercions and call sites name traits:
                        // `sha2::digest::DynDigest` is `digest::digest::DynDigest`)
                        rustc_public::ty::ExistentialPredicate::Trait(t) => {
                            Some(path_of(tcx, rustc_internal::internal(tcx, t.def_id.0)))
                        }
                        _ => None,
                    })
                    .collect(),
            ),
            _ => TyTree::Other(format!("{ty}")),
        },
        TyKind::Param(p) => TyTree::Param(p.name),
        // `<Kdf as kdf::Kdf>::HashImpl`: a projection is not monomorphic either
        TyKind::Alias(..) => TyTree::Param(format!("{ty}")),
        _ => TyTree::Other(format!("{ty}")),
    }
}
pub(super) fn arg_trees(tcx: TyCtxt<'_>, args: &[GenericArgKind], depth: usize) -> Vec<TyTree> {
    args.iter()
        .filter_map(|a| match a {
            GenericArgKind::Type(t) => Some(ty_tree(tcx, t, depth)),
            GenericArgKind::Const(c) => Some(TyTree::Const(c.eval_target_usize().ok())),
            GenericArgKind::Lifetime(_) => None,
        })
        .collect()
}
/// Splits a method's generic arguments into the type it belongs to and its own arguments:
/// `Self` of a trait method, or the instantiated self type of an inherent impl.
pub(super) fn split_self(
    tcx: TyCtxt<'_>,
    def: rustc_public::DefId,
    args: &rustc_public::ty::GenericArgs,
) -> (Option<TyTree>, Vec<TyTree>) {
    let did = rustc_internal::internal(tcx, def);
    if tcx.trait_of_assoc(did).is_some() {
        if let Some(GenericArgKind::Type(t)) = args.0.first() {
            return (Some(ty_tree(tcx, t, 0)), arg_trees(tcx, &args.0[1..], 0));
        }
    } else if let Some(impl_id) = tcx.impl_of_assoc(did) {
        let n = tcx.generics_of(impl_id).count().min(args.0.len());
        let internal_args = rustc_internal::internal(tcx, args);
        let impl_args = tcx.mk_args(&internal_args[..n]);
        let self_ty = tcx.type_of(impl_id).instantiate(tcx, impl_args);
        let self_ty = tcx
            .normalize_erasing_regions(rustc_middle::ty::TypingEnv::fully_monomorphized(), self_ty);
        let self_ty: Ty = rustc_internal::stable(self_ty);
        return (
            Some(ty_tree(tcx, &self_ty, 0)),
            arg_trees(tcx, &args.0[n..], 0),
        );
    }
    (None, arg_trees(tcx, &args.0, 0))
}
/// The struct or enum a resolved function is a function of: the self type of its impl with
/// the instance's arguments (`SipHasher13` for `<SipHasher13 as Hasher>::write`), `Self` of a
/// trait's own method.
pub(crate) fn self_tree<'tcx>(
    tcx: TyCtxt<'tcx>,
    did: rustc_span::def_id::DefId,
    args: rustc_middle::ty::GenericArgsRef<'tcx>,
) -> Option<TyTree> {
    use rustc_middle::ty::TypeVisitableExt;
    let ty = if tcx.trait_of_assoc(did).is_some() {
        args.first()?.as_type()?
    } else {
        let impl_id = tcx.impl_of_assoc(did)?;
        let n = tcx.generics_of(impl_id).count().min(args.len());
        let impl_args = tcx.mk_args(&args[..n]);
        let ty = tcx.type_of(impl_id).instantiate(tcx, impl_args);
        if impl_args.has_non_region_param() || impl_args.has_aliases() {
            ty.skip_norm_wip()
        } else {
            tcx.normalize_erasing_regions(rustc_middle::ty::TypingEnv::fully_monomorphized(), ty)
        }
    };
    if !matches!(ty.kind(), rustc_middle::ty::Adt(..)) {
        return None;
    }
    let ty: Ty = rustc_internal::stable(ty);
    Some(ty_tree(tcx, &ty, 0))
}
/// The value of an integer constant argument (`2048`, `1_000`); `None` for anything else.
pub(crate) fn const_int(op: &Operand) -> Option<i128> {
    let Operand::Constant(c) = op else {
        return None;
    };
    let ConstantKind::Allocated(a) = c.const_.kind() else {
        return None;
    };
    match c.const_.ty().kind_of().rigid()? {
        RigidTy::Uint(_) => a.read_uint().ok().and_then(|v| i128::try_from(v).ok()),
        RigidTy::Int(_) => a.read_int().ok(),
        _ => None,
    }
}
pub(super) fn tree_mentions(t: &TyTree, cx: &Cx<'_>) -> bool {
    match t {
        TyTree::Adt { krate, args, .. } => {
            cx.kb_ref(krate) || args.iter().any(|a| tree_mentions(a, cx))
        }
        TyTree::Ref(t) | TyTree::Slice(t) | TyTree::Array(t, _) => tree_mentions(t, cx),
        TyTree::Tuple(ts) => ts.iter().any(|a| tree_mentions(a, cx)),
        _ => false,
    }
}
/// An ADT as coercions name it: its defining path with its type arguments (`app::W<app::A>`);
/// `None` for another type, or one still generic.
pub(crate) fn type_name<'tcx>(tcx: TyCtxt<'tcx>, ty: rustc_middle::ty::Ty<'tcx>) -> Option<String> {
    use rustc_middle::ty::TypeVisitableExt;
    match ty.kind() {
        rustc_middle::ty::Adt(adt, args) if !args.has_non_region_param() => {
            Some(match adt_args(tcx, args) {
                Some(a) => format!("{}<{a}>", path_of(tcx, adt.did())),
                None => path_of(tcx, adt.did()),
            })
        }
        _ => None,
    }
}
