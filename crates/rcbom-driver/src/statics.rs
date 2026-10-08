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
//! promoted constant holding `const aead::AES_256_GCM`). `rustc_public` exposes none of
//! `mir_for_ctfe`, `promoted_mir` or unevaluated consts in monomorphic bodies.

use std::collections::HashSet;

use rcbom_facts::{Owner, OwnerKind, Site, Target, Tier};
use rustc_hir::def::DefKind;
use rustc_middle::mir::interpret::{AllocId, GlobalAlloc, Scalar};
use rustc_middle::mir::visit::Visitor;
use rustc_middle::mir::{self, ConstValue};
use rustc_middle::ty::TyCtxt;
use rustc_span::def_id::DefId;

use crate::{Cx, crate_ref, def_ref_internal, locate};

/// A named data item a body refers to.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Named {
    Static(DefId),
    Const(DefId),
}

/// Sites owned by the local statics and consts: what their initializers name. These are the
/// edges of the data graph the analysis closes over.
pub(crate) fn local_data_sites(cx: &mut Cx<'_>) -> Vec<Site> {
    let tcx = cx.tcx;
    let mut out = Vec::new();
    for did in tcx.hir_body_owners().map(|d| d.to_def_id()) {
        if !matches!(tcx.def_kind(did), DefKind::Static { .. } | DefKind::Const)
            || tcx.is_foreign_item(did)
            || !tcx.is_mir_available(did)
        {
            continue;
        }
        let owner = Owner {
            kind: OwnerKind::Static,
            name: rustc_middle::ty::print::with_no_trimmed_paths!(tcx.def_path_str(did)),
            id: tcx.def_path_hash(did).0.to_hex(),
            krate: crate_ref(tcx, did),
        };
        let found = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut v = Refs {
                tcx,
                found: Vec::new(),
            };
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
        // Every edge is kept, whatever the crate: rustls's SUPPORTED_SIG_ALGS reaches ring's
        // descriptors only through rustls-webpki statics.
        for (named, span) in found {
            if let Some(s) = site(tcx, cx, &owner, named, span, did, true) {
                out.push(s);
            }
        }
    }
    out
}

/// Statics and consts a function names in its own body and promoted constants. Calls are
/// found by the `rustc_public` scanner; this adds the names that evaluation erases.
pub(crate) fn fn_data_sites(cx: &mut Cx<'_>, did: DefId, owner: &Owner) -> Vec<Site> {
    let tcx = cx.tcx;
    if !tcx.is_mir_available(did) {
        return Vec::new();
    }
    let found = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut v = Refs {
            tcx,
            found: Vec::new(),
        };
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
    found
        .into_iter()
        .filter_map(|(named, span)| site(tcx, cx, owner, named, span, did, false))
        .collect()
}

fn site(
    tcx: TyCtxt<'_>,
    cx: &Cx<'_>,
    owner: &Owner,
    named: Named,
    span: rustc_span::Span,
    self_did: DefId,
    any_crate: bool,
) -> Option<Site> {
    let (target_did, is_const) = match named {
        Named::Static(d) => (d, false),
        Named::Const(d) => (d, true),
    };
    if target_did == self_did {
        return None;
    }
    let def = def_ref_internal(tcx, target_did);
    if !any_crate && !(target_did.is_local() || cx.kb_crates.contains(&def.krate.name)) {
        return None;
    }
    let (span, expansion) = locate(tcx, span);
    if span.line == 0 {
        return None;
    }
    Some(Site {
        tier: Tier::Present,
        owner: owner.clone(),
        span,
        expansion,
        target: if is_const {
            Target::Const { def }
        } else {
            Target::Static { def }
        },
        via: Vec::new(),
    })
}

/// Statics and consts named by constants in a MIR body, with the constant's span.
struct Refs<'tcx> {
    tcx: TyCtxt<'tcx>,
    found: Vec<(Named, rustc_span::Span)>,
}

impl<'tcx> Visitor<'tcx> for Refs<'tcx> {
    fn visit_const_operand(&mut self, c: &mir::ConstOperand<'tcx>, _: mir::Location) {
        let id = match c.const_ {
            mir::Const::Val(ConstValue::Scalar(Scalar::Ptr(p, _)), _) => {
                Some(p.provenance.alloc_id())
            }
            mir::Const::Val(ConstValue::Slice { alloc_id, .. }, _) => Some(alloc_id),
            mir::Const::Val(ConstValue::Indirect { alloc_id, .. }, _) => Some(alloc_id),
            // `const aead::AES_256_GCM` (aws-lc-rs) before evaluation; promoted constants are
            // visited as bodies of their own
            mir::Const::Unevaluated(uv, _)
                if uv.promoted.is_none()
                    && matches!(
                        self.tcx.def_kind(uv.def),
                        DefKind::Const | DefKind::AssocConst
                    ) =>
            {
                self.found.push((Named::Const(uv.def), c.span));
                None
            }
            _ => None,
        };
        if let Some(id) = id {
            let mut statics = Vec::new();
            statics_in(self.tcx, id, &mut statics, &mut HashSet::new(), 0);
            self.found
                .extend(statics.into_iter().map(|s| (Named::Static(s), c.span)));
        }
    }
}

fn statics_in(
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
        GlobalAlloc::Static(def) => out.push(def),
        GlobalAlloc::Memory(m) => {
            for (_, prov) in m.inner().provenance().ptrs().iter() {
                statics_in(tcx, prov.alloc_id(), out, seen, depth + 1);
            }
        }
        _ => {}
    }
}
