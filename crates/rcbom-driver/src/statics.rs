//! Named data items in MIR: statics and consts, read through `rustc_middle`.
//!
//! `rustc_public` gives values, and values lose names, in two ways:
//! - rustls builds `TLS13_AES_256_GCM_SHA384` from `hkdf::HKDF_SHA384` *by value*, so the
//!   evaluated allocation holds a copy and no pointer to the ring static;
//! - aws-lc-rs defines its algorithms as `pub const`, which are copied wherever they are used and
//!   never get an allocation of their own.
//!
//! The MIR before evaluation still names both, with spans: `mir_for_ctfe` of a static or const,
//! `optimized_mir` of a function, and the promoted constants of each (`&aead::AES_256_GCM` is a
//! promoted constant holding `const aead::AES_256_GCM`). Every static and const site comes from
//! here, for the per-item scan and for the walk alike: in an instance body all constants are
//! evaluated, and a static found inside the value of `Self::ALG` would get the span of
//! `Self::ALG`. The walk reads the definition's MIR instead and resolves its generic constants
//! (`<T as Tr>::ALG`) with the instance's arguments.

use std::collections::HashSet;

use rcbom_facts::{DataEdge, Owner, OwnerKind, Site, Target, Tier, ViaStep};
use rustc_hir::def::DefKind;
use rustc_middle::mir::interpret::{AllocId, GlobalAlloc, Scalar};
use rustc_middle::mir::visit::Visitor;
use rustc_middle::mir::{self, ConstValue};
use rustc_middle::ty::{self, GenericArgsRef, TyCtxt, TypeVisitableExt, TypingEnv};
use rustc_span::def_id::DefId;

use crate::{Cx, crate_ref, def_ref_internal, locate, path_of};

/// A named data item a body refers to, with the span that names it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Named {
    Static(DefId),
    Const(DefId),
}

/// Sites owned by the local statics and consts (associated consts included): what their
/// initializers name. These are the edges of the data graph the analysis closes over. Also
/// returns the edges only evaluation shows (a static built by a `const fn`).
pub(crate) fn local_data_sites(cx: &mut Cx<'_>) -> (Vec<Site>, Vec<DataEdge>) {
    let tcx = cx.tcx;
    let mut out = Vec::new();
    let mut edges = Vec::new();
    for did in tcx.hir_body_owners().map(|d| d.to_def_id()) {
        if !matches!(
            tcx.def_kind(did),
            DefKind::Static { .. } | DefKind::Const | DefKind::AssocConst
        ) || tcx.is_foreign_item(did)
            || !tcx.is_mir_available(did)
        {
            continue;
        }
        let owner = Owner {
            kind: OwnerKind::Static,
            name: path_of(tcx, did),
            id: crate::def_hash(tcx, did),
            krate: crate_ref(tcx, did),
        };
        let found = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut v = Refs::new(tcx, None);
            v.visit_body(tcx.mir_for_ctfe(did));
            for p in tcx.promoted_mir(did).iter() {
                v.visit_body(p);
            }
            v.found
        }));
        let Ok(found) = found else {
            cx.errors += 1;
            continue;
        };
        let mut named: HashSet<DefId> = HashSet::new();
        // Every edge is kept, whatever the crate: rustls's SUPPORTED_SIG_ALGS reaches ring's
        // descriptors only through rustls-webpki statics.
        for (n, span) in found {
            named.insert(match n {
                Named::Static(d) | Named::Const(d) => d,
            });
            if let Some(s) = site(tcx, &owner, n, span, did, Tier::Present, &[]) {
                out.push(s);
            }
        }
        // `static T: Table = make_table();`: the pointers are only in the evaluated value
        if matches!(tcx.def_kind(did), DefKind::Static { .. })
            && let Ok(alloc) = tcx.eval_static_initializer(did)
        {
            let mut statics = Vec::new();
            for (_, prov) in alloc.inner().provenance().ptrs().iter() {
                statics_in(tcx, prov.alloc_id(), &mut statics, &mut HashSet::new(), 0);
            }
            for s in statics {
                if s != did && named.insert(s) {
                    edges.push(DataEdge {
                        owner: owner.clone(),
                        target: def_ref_internal(tcx, s),
                    });
                }
            }
        }
    }
    (out, edges)
}

/// Statics and consts a function names in its own body and promoted constants. For an
/// instance (`args`), generic constants are resolved with its arguments.
pub(crate) fn fn_data_sites<'tcx>(
    cx: &mut Cx<'tcx>,
    did: DefId,
    args: Option<GenericArgsRef<'tcx>>,
    owner: &Owner,
    tier: Tier,
    via: &[ViaStep],
) -> Vec<Site> {
    let tcx = cx.tcx;
    if !tcx.is_mir_available(did) {
        return Vec::new();
    }
    let found = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut v = Refs::new(tcx, args);
        v.visit_body(tcx.optimized_mir(did));
        for p in tcx.promoted_mir(did).iter() {
            v.visit_body(p);
        }
        v.found
    }));
    let Ok(found) = found else {
        cx.errors += 1;
        return Vec::new();
    };
    let mut out = Vec::new();
    for (named, span) in found {
        // local data, data of knowledge-base crates, and statics leading to them
        let keep = match named {
            Named::Static(d) => {
                d.is_local()
                    || cx.kb_crates.contains(tcx.crate_name(d.krate).as_str())
                    || cx.static_interesting(d)
            }
            Named::Const(d) => {
                d.is_local() || cx.kb_crates.contains(tcx.crate_name(d.krate).as_str())
            }
        };
        if keep && let Some(s) = site(tcx, owner, named, span, did, tier, via) {
            out.push(s);
        }
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn site(
    tcx: TyCtxt<'_>,
    owner: &Owner,
    named: Named,
    span: rustc_span::Span,
    self_did: DefId,
    tier: Tier,
    via: &[ViaStep],
) -> Option<Site> {
    let (target_did, is_const) = match named {
        Named::Static(d) => (d, false),
        Named::Const(d) => (d, true),
    };
    if target_did == self_did {
        return None;
    }
    let def = def_ref_internal(tcx, target_did);
    let text = crate::span_text(tcx, span);
    let line_text = crate::line_text(tcx, span);
    let (span, expansion) = locate(tcx, span);
    if span.line == 0 {
        return None;
    }
    Some(Site {
        tier,
        owner: owner.clone(),
        span,
        text,
        line_text,
        expansion,
        target: if is_const {
            Target::Const { def }
        } else {
            Target::Static { def }
        },
        via: via.to_vec(),
    })
}

/// Statics and consts named by constants in a MIR body, with the span that names them.
struct Refs<'tcx> {
    tcx: TyCtxt<'tcx>,
    /// The instance's generic arguments, to resolve `<T as Tr>::ALG`.
    args: Option<GenericArgsRef<'tcx>>,
    found: Vec<(Named, rustc_span::Span)>,
    depth: usize,
}

impl<'tcx> Refs<'tcx> {
    fn new(tcx: TyCtxt<'tcx>, args: Option<GenericArgsRef<'tcx>>) -> Self {
        Refs {
            tcx,
            args,
            found: Vec::new(),
            depth: 0,
        }
    }
}

impl<'tcx> Visitor<'tcx> for Refs<'tcx> {
    fn visit_const_operand(&mut self, c: &mir::ConstOperand<'tcx>, _: mir::Location) {
        match c.const_ {
            mir::Const::Unevaluated(uv, _) if uv.promoted.is_none() => {
                match self.tcx.def_kind(uv.def) {
                    // `const { &SHA512 }`: its contents, at their own positions. The body is
                    // written in the constant's own generics, which `uv.args` maps to ours.
                    DefKind::AnonConst if self.depth < 4 => {
                        let args = match self.args {
                            Some(a) => ty::EarlyBinder::bind(self.tcx, uv.args)
                                .instantiate(self.tcx, a)
                                .skip_norm_wip(),
                            None => uv.args,
                        };
                        match ctfe_mir(self.tcx, uv.def) {
                            Ok(body) => {
                                let mut inner = Refs::new(self.tcx, Some(args));
                                inner.depth = self.depth + 1;
                                inner.visit_body(body);
                                for p in self.tcx.promoted_mir(uv.def).iter() {
                                    inner.visit_body(p);
                                }
                                self.found.extend(inner.found);
                            }
                            Err((value, ty)) => self.found.extend(
                                statics_of_value(self.tcx, value, ty)
                                    .into_iter()
                                    .map(|s| (Named::Static(s), c.span)),
                            ),
                        }
                    }
                    // `const aead::AES_256_GCM` (aws-lc-rs), `Self::ALG`, `<T as Tr>::ALG`
                    DefKind::Const | DefKind::AssocConst => {
                        let def = resolve_const(self.tcx, uv.def, uv.args, self.args);
                        self.found.push((Named::Const(def), c.span));
                    }
                    _ => {}
                }
            }
            _ => {
                let mut statics = Vec::new();
                for id in alloc_ids(&c.const_) {
                    statics_in(self.tcx, id, &mut statics, &mut HashSet::new(), 0);
                }
                self.found
                    .extend(statics.into_iter().map(|s| (Named::Static(s), c.span)));
            }
        }
    }
}

/// The const item a (possibly generic) constant refers to: an associated const resolves to
/// the impl's item once the instance's arguments are known.
fn resolve_const<'tcx>(
    tcx: TyCtxt<'tcx>,
    def: DefId,
    uv_args: GenericArgsRef<'tcx>,
    inst_args: Option<GenericArgsRef<'tcx>>,
) -> DefId {
    if !matches!(tcx.def_kind(def), DefKind::AssocConst) {
        return def;
    }
    let args = match inst_args {
        Some(a) => ty::EarlyBinder::bind(tcx, uv_args)
            .instantiate(tcx, a)
            .skip_norm_wip(),
        None => uv_args,
    };
    if args.has_non_region_param() {
        return def;
    }
    let env = TypingEnv::fully_monomorphized();
    let args = tcx.normalize_erasing_regions(env, ty::Unnormalized::new_wip(args));
    match ty::Instance::try_resolve(tcx, env, def, args) {
        Ok(Some(i)) => i.def_id(),
        _ => def,
    }
}

/// The MIR const evaluation runs for a constant, or, for a constant of a dependency whose value
/// needed no evaluation (an enum discriminant, a literal), that value: rustc then encodes
/// neither its MIR nor its promoted constants, and asking for them panics inside the query.
pub(crate) fn ctfe_mir<'tcx>(
    tcx: TyCtxt<'tcx>,
    def: DefId,
) -> Result<&'tcx mir::Body<'tcx>, (ConstValue, ty::Ty<'tcx>)> {
    match (def.is_local(), tcx.trivial_const(def)) {
        (false, Some(v)) => Err(v),
        _ => Ok(tcx.mir_for_ctfe(def)),
    }
}

/// The statics a constant value points at, through any depth of allocations.
pub(crate) fn statics_of_value<'tcx>(
    tcx: TyCtxt<'tcx>,
    value: ConstValue,
    ty: ty::Ty<'tcx>,
) -> Vec<DefId> {
    let mut statics = Vec::new();
    for id in alloc_ids(&mir::Const::Val(value, ty)) {
        statics_in(tcx, id, &mut statics, &mut HashSet::new(), 0);
    }
    statics
}

fn alloc_ids(c: &mir::Const<'_>) -> Vec<AllocId> {
    match c {
        mir::Const::Val(ConstValue::Scalar(Scalar::Ptr(p, _)), _) => {
            vec![p.provenance.alloc_id()]
        }
        mir::Const::Val(ConstValue::Slice { alloc_id, .. }, _) => vec![*alloc_id],
        mir::Const::Val(ConstValue::Indirect { alloc_id, .. }, _) => vec![*alloc_id],
        _ => Vec::new(),
    }
}

/// The statics and named consts one constant operand names (for argument origins): a
/// pointer's static, a named const, and through an inline const its contents.
pub(crate) fn named_by_const<'tcx>(tcx: TyCtxt<'tcx>, c: &mir::ConstOperand<'tcx>) -> Vec<DefId> {
    let mut v = Refs::new(tcx, None);
    v.visit_const_operand(
        c,
        mir::Location {
            block: mir::START_BLOCK,
            statement_index: 0,
        },
    );
    v.found
        .into_iter()
        .map(|(n, _)| match n {
            Named::Static(d) | Named::Const(d) => d,
        })
        .collect()
}

pub(crate) fn statics_in(
    tcx: TyCtxt<'_>,
    id: AllocId,
    out: &mut Vec<DefId>,
    seen: &mut HashSet<AllocId>,
    depth: usize,
) {
    if depth > 8 || !seen.insert(id) {
        return;
    }
    match tcx.global_alloc(id) {
        GlobalAlloc::Static(def) => {
            if !out.contains(&def) {
                out.push(def)
            }
        }
        GlobalAlloc::Memory(m) => {
            for (_, prov) in m.inner().provenance().ptrs().iter() {
                statics_in(tcx, prov.alloc_id(), out, seen, depth + 1);
            }
        }
        _ => {}
    }
}
