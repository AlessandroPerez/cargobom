//! `rcbom-driver`: a `RUSTC_WRAPPER` that compiles each crate normally and, after analysis,
//! writes the crypto-relevant facts of that crate (see `rcbom-facts`) to `$RCBOM_OUT`.
//!
//! Everything compiler-facing lives here; the rest of rcbom builds on stable. Analysis goes
//! through `rustc_public` except where it exposes nothing yet: spans of macro call sites,
//! static initializers with their promoted constants, vtable entries, and def-path hashes use
//! `rustc_middle` directly.
//!
//! Environment (set by `cargo cbom`):
//!   RCBOM_OUT          directory for `<crate>-<stable id>.json`
//!   RCBOM_KB_CRATES    comma-separated crate names the knowledge base covers; only sites
//!                      naming items of these crates are recorded
//!   RCBOM_STOP_CRATES  crates whose bodies the reachability walk does not enter (algorithm
//!                      implementations: the call into them is the fact, not their internals)
//!   RCBOM_MAX_INSTANCES  reachability walk limit (default 200000)
//!   RCBOM_SYSROOT      sysroot of the pinned toolchain (else asked from the wrapped rustc)

#![feature(rustc_private)]

extern crate rustc_driver;
extern crate rustc_hir;
extern crate rustc_interface;
extern crate rustc_middle;
#[macro_use]
extern crate rustc_public;
extern crate rustc_span;

mod origins;
mod statics;

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::process::{Command, exit};

use rcbom_facts::{
    CrateFacts, CrateInfo, CrateRef, DefRef, Expansion, FACTS_VERSION, Loc, Owner, OwnerKind,
    Reach, Site, Target, Tier, TyTree, ViaStep,
};
use rustc_middle::ty::TyCtxt;
use rustc_public::mir::alloc::GlobalAlloc;
use rustc_public::mir::mono::{Instance, InstanceKind};
use rustc_public::mir::visit::{Location, MirVisitor};
use rustc_public::mir::{
    Body, CastKind, ConstOperand, Operand, PointerCoercion, Rvalue, Terminator, TerminatorKind,
};
use rustc_public::rustc_internal;
use rustc_public::ty::{
    Allocation, ClosureKind, ConstantKind, GenericArgKind, RigidTy, Span, Ty, TyKind,
};
use rustc_public::{CrateDef, ItemKind};

fn main() {
    let mut args: Vec<String> = std::env::args().collect();
    // As RUSTC_WRAPPER, cargo calls `driver <path to rustc> <rustc args>`.
    let rustc = if args.len() > 1 && is_rustc_path(&args[1]) {
        Some(args.remove(1))
    } else {
        None
    };
    let crate_name = arg_value(&args, "--crate-name");
    let is_proc_macro = arg_values(&args, "--crate-type").any(|t| t == "proc-macro");
    let skip = match &crate_name {
        None => true, // `-vV`, `--print`, ...
        Some(n) => n.starts_with("build_script_") || is_proc_macro,
    };
    if skip || std::env::var_os("RCBOM_OUT").is_none() {
        // Build scripts and proc macros run on the host; compile them untouched.
        let rustc = rustc.unwrap_or_else(|| "rustc".into());
        let status = Command::new(rustc)
            .args(&args[1..])
            .status()
            .expect("running rustc");
        exit(status.code().unwrap_or(1));
    }
    if !args
        .iter()
        .any(|a| a == "--sysroot" || a.starts_with("--sysroot="))
    {
        args.push("--sysroot".into());
        args.push(sysroot(rustc.as_deref()));
    }
    // Dependency MIR must be in the metadata for the reachability walk to enter dependencies.
    args.push("-Zalways-encode-mir".into());
    // The MIR a debug build has, whatever the project's profile. At MIR opt-level 2, the default
    // for opt-level >= 1, GVN rebuilds constant operands without a span, callees included, so no
    // call has a position; in non-incremental crates the MIR inliner also folds calls into their
    // callers (minisign sets `[profile.dev] opt-level = 3`).
    args.push("-Zmir-opt-level=1".into());
    let result = run_with_tcx!(&args, |tcx| {
        // A panic inside the analysis is caught per item and counted; rustc's ICE hook would
        // otherwise turn it into a compilation error of the user's crate.
        let ice_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        analyze(tcx);
        std::panic::set_hook(ice_hook);
        ControlFlow::<(), ()>::Continue(())
    });
    exit(if result.is_ok() { 0 } else { 1 });
}

fn is_rustc_path(s: &str) -> bool {
    !s.starts_with('-') && PathBuf::from(s).file_stem().is_some_and(|n| n == "rustc")
}

fn arg_value(args: &[String], flag: &str) -> Option<String> {
    arg_values(args, flag).next()
}

fn arg_values<'a>(args: &'a [String], flag: &'a str) -> impl Iterator<Item = String> + 'a {
    args.windows(2)
        .filter(move |w| w[0] == flag)
        .map(|w| w[1].clone())
}

fn sysroot(rustc: Option<&str>) -> String {
    if let Ok(s) = std::env::var("RCBOM_SYSROOT") {
        return s;
    }
    let out = Command::new(rustc.unwrap_or("rustc"))
        .args(["--print", "sysroot"])
        .output()
        .expect("asking rustc for its sysroot");
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

fn env_set(name: &str) -> HashSet<String> {
    std::env::var(name)
        .unwrap_or_default()
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|s| s.replace('-', "_"))
        .collect()
}

/// Shared state for one crate's analysis.
pub(crate) struct Cx<'tcx> {
    pub tcx: TyCtxt<'tcx>,
    pub kb_crates: HashSet<String>,
    stop_crates: HashSet<String>,
    /// Memo: does this static (by def-path hash) lead to a knowledge-base static?
    interesting_statics: HashMap<String, bool>,
    pub errors: usize,
}

fn analyze(tcx: TyCtxt<'_>) {
    let mut cx = Cx {
        tcx,
        kb_crates: env_set("RCBOM_KB_CRATES"),
        stop_crates: env_set("RCBOM_STOP_CRATES"),
        interesting_statics: HashMap::new(),
        errors: 0,
    };
    let local = rustc_public::local_crate();
    let env = |k: &str| std::env::var(k).unwrap_or_default();
    let krate = CrateInfo {
        name: local.name.clone(),
        stable_id: format!(
            "{:016x}",
            tcx.stable_crate_id(rustc_span::def_id::LOCAL_CRATE)
                .as_u64()
        ),
        package: env("CARGO_PKG_NAME"),
        version: env("CARGO_PKG_VERSION"),
        manifest_dir: env("CARGO_MANIFEST_DIR"),
        cwd: std::env::current_dir().unwrap().display().to_string(),
        primary: std::env::var_os("CARGO_PRIMARY_PACKAGE").is_some(),
        crate_types: tcx.crate_types().iter().map(|t| t.to_string()).collect(),
    };

    let mut sites = Vec::new();
    // Static initializers first: a local static that leads to a KB static makes references to
    // it interesting.
    for s in statics::local_data_sites(&mut cx) {
        cx.interesting_statics.insert(owner_id_of(&s), true);
        sites.push(s);
    }
    for item in rustc_public::all_local_items() {
        if !matches!(item.kind(), ItemKind::Fn) || !item.has_body() {
            continue;
        }
        let r = catch_unwind(AssertUnwindSafe(|| {
            let (body, owner) = if item.requires_monomorphization() {
                (item.body(), fn_owner_item(&cx, &item))
            } else {
                // the item body, not the instance body: same types for a monomorphic fn, but
                // named consts are not evaluated away (aws-lc-rs algorithms are consts)
                let inst = Instance::try_from(item).ok();
                (
                    item.body(),
                    inst.map(|i| fn_owner(&cx, &i))
                        .unwrap_or_else(|| fn_owner_item(&cx, &item)),
                )
            };
            let mut out = Vec::new();
            if let Some(body) = body {
                let mut sc = Scanner::new(
                    &mut cx,
                    &body,
                    owner.clone(),
                    Tier::Present,
                    vec![],
                    &mut out,
                );
                sc.visit_body(&body);
            }
            let did = rustc_internal::internal(cx.tcx, item.def_id());
            out.extend(statics::fn_data_sites(&mut cx, did, &owner));
            out
        }));
        match r {
            Ok(out) => sites.extend(out),
            Err(_) => cx.errors += 1,
        }
    }

    // Roots: `main` of a binary; for a library the user asked to analyse (a workspace member),
    // its public monomorphic API. RCBOM_NO_WALK turns the walk off (ablation).
    let primary = std::env::var_os("CARGO_PRIMARY_PACKAGE").is_some();
    let roots: Vec<(Instance, String)> = if std::env::var_os("RCBOM_NO_WALK").is_some() {
        Vec::new()
    } else if let Some(entry) = rustc_public::entry_fn() {
        Instance::try_from(entry)
            .ok()
            .map(|i| (i, i.name()))
            .into_iter()
            .collect()
    } else if primary {
        public_api_roots(&cx)
    } else {
        Vec::new()
    };
    let reach = (!roots.is_empty()).then(|| {
        let mut w = Walker::new(&mut cx);
        let r = w.run(roots);
        sites.extend(w.sites);
        r
    });

    // Identical facts from the per-item scan and the walk collapse to one.
    let mut seen = HashSet::new();
    sites.retain(|s| seen.insert(s.clone()));

    let facts = CrateFacts {
        facts_version: FACTS_VERSION,
        krate,
        sites,
        reach,
    };
    let out = PathBuf::from(std::env::var("RCBOM_OUT").unwrap());
    std::fs::create_dir_all(&out).unwrap();
    let path = out.join(format!(
        "{}-{}.json",
        facts.krate.name, facts.krate.stable_id
    ));
    std::fs::write(&path, serde_json::to_vec(&facts).unwrap()).unwrap();
    if cx.errors > 0 {
        eprintln!(
            "rcbom-driver: {}: {} items could not be analysed",
            facts.krate.name, cx.errors
        );
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
        path: rustc_middle::ty::print::with_no_trimmed_paths!(tcx.def_path_str(did)),
        id: tcx.def_path_hash(did).0.to_hex(),
    }
}

fn def_ref(cx: &Cx<'_>, def: rustc_public::DefId) -> DefRef {
    let did = rustc_internal::internal(cx.tcx, def);
    def_ref_internal(cx.tcx, did)
}

fn owner_id_of(s: &Site) -> String {
    s.owner.id.clone()
}

fn fn_owner(cx: &Cx<'_>, inst: &Instance) -> Owner {
    let did = rustc_internal::internal(cx.tcx, inst.def.def_id());
    Owner {
        kind: OwnerKind::Fn,
        name: inst.name(),
        id: inst.mangled_name(),
        krate: crate_ref(cx.tcx, did),
    }
}

fn fn_owner_item(cx: &Cx<'_>, item: &rustc_public::CrateItem) -> Owner {
    let did = rustc_internal::internal(cx.tcx, item.def_id());
    Owner {
        kind: OwnerKind::Fn,
        name: item.name(),
        id: cx.tcx.def_path_hash(did).0.to_hex(),
        krate: crate_ref(cx.tcx, did),
    }
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
        let macro_name = match expn.kind {
            rustc_span::hygiene::ExpnKind::Macro(rustc_span::hygiene::MacroKind::Bang, name) => {
                format!("{name}!")
            }
            // code a derive or an attribute generates is attributed to that attribute
            rustc_span::hygiene::ExpnKind::Macro(rustc_span::hygiene::MacroKind::Derive, name) => {
                format!("derive:{name}")
            }
            rustc_span::hygiene::ExpnKind::Macro(rustc_span::hygiene::MacroKind::Attr, name) => {
                format!("attr:{name}")
            }
            // desugarings (`?`, `for`, `async`): the call site is ordinary code
            _ => String::new(),
        };
        let exp = Expansion {
            macro_name,
            def_site: raw_loc(tcx, span),
        };
        (raw_loc(tcx, call), Some(exp))
    } else {
        (raw_loc(tcx, span), None)
    }
}

fn raw_loc(tcx: TyCtxt<'_>, span: rustc_span::Span) -> Loc {
    let sm = tcx.sess.source_map();
    let (_, line, col, end_line, end_col) = sm.span_to_location_info(span);
    let file = sm
        .span_to_filename(span)
        .prefer_local_unconditionally()
        .to_string();
    Loc {
        file,
        line,
        col,
        end_line,
        end_col,
    }
}

fn locate_stable(tcx: TyCtxt<'_>, span: Span) -> (Loc, Option<Expansion>) {
    locate(tcx, rustc_internal::internal(tcx, span))
}

pub(crate) fn ty_tree(tcx: TyCtxt<'_>, ty: &Ty, depth: usize) -> TyTree {
    if depth > 16 {
        return TyTree::Other("…".into());
    }
    match ty.kind() {
        TyKind::RigidTy(r) => match r {
            RigidTy::Adt(def, args) => TyTree::Adt {
                krate: crate_ref(tcx, rustc_internal::internal(tcx, def.def_id())),
                path: def.name(),
                args: arg_trees(tcx, &args.0, depth + 1),
            },
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
                        rustc_public::ty::ExistentialPredicate::Trait(t) => Some(t.def_id.name()),
                        _ => None,
                    })
                    .collect(),
            ),
            _ => TyTree::Other(format!("{ty}")),
        },
        TyKind::Param(p) => TyTree::Param(p.name),
        _ => TyTree::Other(format!("{ty}")),
    }
}

fn arg_trees(tcx: TyCtxt<'_>, args: &[GenericArgKind], depth: usize) -> Vec<TyTree> {
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
fn split_self(
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

/// The value of an integer constant argument (`2048`, `1_000`); `None` for anything else.
fn const_int(op: &Operand) -> Option<i128> {
    let Operand::Constant(c) = op else {
        return None;
    };
    let ConstantKind::Allocated(a) = c.const_.kind() else {
        return None;
    };
    match c.const_.ty().kind().rigid()? {
        RigidTy::Uint(_) => a.read_uint().ok().and_then(|v| i128::try_from(v).ok()),
        RigidTy::Int(_) => a.read_int().ok(),
        _ => None,
    }
}

fn tree_mentions(t: &TyTree, crates: &HashSet<String>) -> bool {
    match t {
        TyTree::Adt { krate, args, .. } => {
            crates.contains(&krate.name) || args.iter().any(|a| tree_mentions(a, crates))
        }
        TyTree::Ref(t) | TyTree::Slice(t) | TyTree::Array(t, _) => tree_mentions(t, crates),
        TyTree::Tuple(ts) => ts.iter().any(|a| tree_mentions(a, crates)),
        _ => false,
    }
}

pub(crate) fn tree_is_generic(t: &TyTree) -> bool {
    match t {
        TyTree::Param(_) => true,
        TyTree::Adt { args, .. } | TyTree::Tuple(args) => args.iter().any(tree_is_generic),
        TyTree::Ref(t) | TyTree::Slice(t) | TyTree::Array(t, _) => tree_is_generic(t),
        _ => false,
    }
}

impl Cx<'_> {
    /// A static is worth recording if it belongs to a KB crate, or its value points (through
    /// any depth of allocations) at a static that is.
    fn static_interesting(&mut self, def: rustc_public::mir::mono::StaticDef) -> bool {
        let did = rustc_internal::internal(self.tcx, def.def_id());
        let key = self.tcx.def_path_hash(did).0.to_hex();
        if let Some(v) = self.interesting_statics.get(&key) {
            return *v;
        }
        self.interesting_statics.insert(key.clone(), false); // breaks cycles
        let krate = self.tcx.crate_name(did.krate).to_string();
        // an extern static (FFI) has no initializer to evaluate
        let v = self.kb_crates.contains(&krate)
            || !self.tcx.is_foreign_item(did)
                && catch_unwind(AssertUnwindSafe(|| def.eval_initializer().ok()))
                    .ok()
                    .flatten()
                    .is_some_and(|a| {
                        let mut found = Vec::new();
                        alloc_statics(&a, &mut found, &mut HashSet::new(), 0);
                        found.into_iter().any(|s| self.static_interesting(s))
                    });
        self.interesting_statics.insert(key, v);
        v
    }
}

/// Statics an allocation points at, following plain memory but not into other statics.
fn alloc_statics(
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

/// Records sites in one body: calls naming KB items and references to interesting statics.
struct Scanner<'a, 'tcx> {
    cx: &'a mut Cx<'tcx>,
    body: &'a Body,
    owner: Owner,
    tier: Tier,
    via: Vec<ViaStep>,
    out: &'a mut Vec<Site>,
    /// Statics referenced, for the walk.
    statics: Vec<rustc_public::mir::mono::StaticDef>,
    /// Def-use index of the body, for argument origins.
    origins: origins::Origins<'a, 'tcx>,
}

impl<'a, 'tcx> Scanner<'a, 'tcx> {
    fn new(
        cx: &'a mut Cx<'tcx>,
        body: &'a Body,
        owner: Owner,
        tier: Tier,
        via: Vec<ViaStep>,
        out: &'a mut Vec<Site>,
    ) -> Self {
        let origins = origins::Origins::new(cx.tcx, body);
        Scanner {
            cx,
            body,
            owner,
            tier,
            via,
            out,
            statics: Vec::new(),
            origins,
        }
    }

    fn push(&mut self, span: Span, target: Target) {
        let (span, expansion) = locate_stable(self.cx.tcx, span);
        if span.line == 0 {
            return; // compiler-generated code (shims) has no source position
        }
        self.out.push(Site {
            tier: self.tier,
            owner: self.owner.clone(),
            span,
            expansion,
            target,
            via: self.via.clone(),
        });
    }
}

impl MirVisitor for Scanner<'_, '_> {
    fn visit_terminator(&mut self, term: &Terminator, loc: Location) {
        if let TerminatorKind::Call {
            func,
            args: call_args,
            ..
        } = &term.kind
            && let Ok(ty) = func.ty(self.body.locals())
            && let Some(RigidTy::FnDef(def, args)) = ty.kind().rigid()
        {
            let trees = arg_trees(self.cx.tcx, &args.0, 0);
            let callee_crate = def.krate().name;
            let mentions = trees.iter().any(|t| tree_mentions(t, &self.cx.kb_crates));
            // `Result::unwrap`, `Vec::len`, drop glue: the standard library handling a crypto
            // value is not a use of it. A std trait implemented by the crypto type itself is:
            // `<Argon2 as Default>::default()` picks the algorithm and its parameters.
            let std = matches!(callee_crate.as_str(), "core" | "std" | "alloc");
            let interesting = if std {
                // only `Default::default`: `Clone`, `Drop`, `Debug` of a crypto type are not uses
                // printed through std's re-export (`std::default::Default::default`)
                def.name().ends_with("::default::Default::default")
                    && mentions
                    && !trees.iter().any(tree_is_generic)
                    && matches!(
                        split_self(self.cx.tcx, def.def_id(), args).0,
                        Some(TyTree::Adt { ref krate, .. }) if self.cx.kb_crates.contains(&krate.name)
                    )
            } else {
                self.cx.kb_crates.contains(&callee_crate) || mentions
            };
            if interesting && !trees.iter().any(tree_is_generic) {
                // the callee path's own span (`UnboundKey::new`, `.encrypt`), not the
                // whole call expression
                let span = match func {
                    Operand::Constant(c) => c.span,
                    _ => term.source_info.span,
                };
                let path = def.name();
                let method = path.rsplit("::").next().unwrap_or(&path).to_string();
                let callee = def_ref(self.cx, def.def_id());
                let (self_ty, own) = split_self(self.cx.tcx, def.def_id(), args);
                let const_args = call_args.iter().map(const_int).collect();
                let arg_origins = call_args
                    .iter()
                    .map(|a| self.origins.of_arg(a, func, call_args))
                    .collect();
                let arg_lens = call_args
                    .iter()
                    .map(|a| self.origins.array_len(a))
                    .collect();
                self.push(
                    span,
                    Target::Call {
                        callee,
                        method,
                        self_ty,
                        args: own,
                        const_args,
                        arg_origins,
                        arg_lens,
                    },
                );
            }
        }
        self.super_terminator(term, loc);
    }

    fn visit_const_operand(&mut self, c: &ConstOperand, loc: Location) {
        if let ConstantKind::Allocated(a) = c.const_.kind() {
            let mut found = Vec::new();
            alloc_statics(a, &mut found, &mut HashSet::new(), 0);
            for s in found {
                self.statics.push(s);
                if self.cx.static_interesting(s) {
                    let def = def_ref(self.cx, s.def_id());
                    self.push(c.span, Target::Static { def });
                }
            }
        }
        self.super_const_operand(c, loc);
    }
}

/// Public, monomorphic functions of the local crate (methods of public types included): the
/// entry points of a library. Generic public functions need a caller to be instantiated.
fn public_api_roots(cx: &Cx<'_>) -> Vec<(Instance, String)> {
    let vis = cx.tcx.effective_visibilities(());
    rustc_public::all_local_items()
        .into_iter()
        .filter(|item| {
            matches!(item.kind(), ItemKind::Fn)
                && item.has_body()
                && !item.requires_monomorphization()
        })
        .filter(|item| {
            let did = rustc_internal::internal(cx.tcx, item.def_id());
            did.as_local().is_some_and(|l| vis.is_exported(l))
        })
        .filter_map(|item| Instance::try_from(item).ok())
        .map(|i| {
            let n = format!("pub {}", i.name());
            (i, n)
        })
        .collect()
}

/// The instance graph from `main`, after the compiler's mono-item collector: calls resolved
/// to instances, drop glue, function pointers, closures, and for every unsizing to `dyn Trait`
/// all methods of the vtable (sound and over-approximate for dynamic dispatch).
struct Walker<'a, 'tcx> {
    cx: &'a mut Cx<'tcx>,
    queue: VecDeque<Instance>,
    seen: HashSet<Instance>,
    parent: HashMap<Instance, (Instance, Loc)>,
    statics: BTreeSet<String>,
    static_refs: Vec<DefRef>,
    static_seen: HashSet<String>,
    sites: Vec<Site>,
    /// Owner ids of the instances whose bodies were walked.
    fns: Vec<String>,
    limit: usize,
}

impl<'a, 'tcx> Walker<'a, 'tcx> {
    fn new(cx: &'a mut Cx<'tcx>) -> Self {
        let limit = std::env::var("RCBOM_MAX_INSTANCES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(200_000);
        Walker {
            cx,
            queue: VecDeque::new(),
            seen: HashSet::new(),
            parent: HashMap::new(),
            statics: BTreeSet::new(),
            static_refs: Vec::new(),
            static_seen: HashSet::new(),
            sites: Vec::new(),
            fns: Vec::new(),
            limit,
        }
    }

    fn run(&mut self, roots: Vec<(Instance, String)>) -> Reach {
        let names = roots.iter().map(|(_, n)| n.clone()).collect();
        for (root, _) in roots {
            self.enqueue(root, None);
        }
        let roots = names;
        let mut truncated = false;
        while let Some(inst) = self.queue.pop_front() {
            if self.seen.len() > self.limit {
                truncated = true;
                break;
            }
            if catch_unwind(AssertUnwindSafe(|| self.visit(inst))).is_err() {
                self.cx.errors += 1;
            }
        }
        let mut statics: Vec<DefRef> = std::mem::take(&mut self.static_refs);
        statics.sort_by(|a, b| a.id.cmp(&b.id));
        statics.dedup_by(|a, b| a.id == b.id);
        Reach {
            roots,
            instances: self.seen.len(),
            truncated,
            statics,
            fns: std::mem::take(&mut self.fns),
        }
    }

    fn enqueue(&mut self, inst: Instance, from: Option<(Instance, Loc)>) {
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
            self.queue.push_back(inst);
        }
    }

    fn via(&self, inst: Instance) -> Vec<ViaStep> {
        let mut out = Vec::new();
        let mut cur = inst;
        while let Some((p, loc)) = self.parent.get(&cur) {
            // only generic instantiations need the chain to explain their arguments
            if cur.args().0.is_empty() || out.len() >= 4 {
                break;
            }
            out.push(ViaStep {
                caller: p.name(),
                span: loc.clone(),
            });
            cur = *p;
        }
        out
    }

    fn visit(&mut self, inst: Instance) {
        let did = rustc_internal::internal(self.cx.tcx, inst.def.def_id());
        let krate = self.cx.tcx.crate_name(did.krate).to_string();
        if self.cx.stop_crates.contains(&krate) {
            return;
        }
        // Not `inst.has_body()`: in this rustc_public it asks about the instance's *def*, which
        // for a shim (`<closure as FnOnce>::call_once` behind a `dyn FnOnce`, as in every
        // `thread::spawn`) is a trait method without a body. `body()` checks the instance.
        let Some(body) = inst.body() else { return };
        let owner = fn_owner(self.cx, &inst);
        self.fns.push(owner.id.clone());
        let via = self.via(inst);
        let mut sites = Vec::new();
        let mut sc = Scanner::new(self.cx, &body, owner, Tier::Reachable, via, &mut sites);
        sc.visit_body(&body);
        let statics = std::mem::take(&mut sc.statics);
        self.sites.extend(sites);
        for s in statics {
            self.reach_static(s);
        }
        let mut edges = Edges {
            tcx: self.cx.tcx,
            body: &body,
            found: Vec::new(),
            cur: None,
        };
        edges.visit_body(&body);
        // RCBOM_DEBUG_WALK=<substring>: print the edges out of matching instances
        let debug = std::env::var("RCBOM_DEBUG_WALK")
            .ok()
            .filter(|d| inst.name().contains(d.as_str()));
        if debug.is_some() {
            eprintln!("rcbom-walk: {} ({:?})", inst.name(), inst.kind);
        }
        for (callee, span) in edges.found {
            if debug.is_some() {
                eprintln!("rcbom-walk:   -> {} ({:?})", callee.name(), callee.kind);
            }
            let loc = locate_stable(self.cx.tcx, span).0;
            self.enqueue(callee, Some((inst, loc)));
        }
    }

    /// A static is reached: remember it, and walk the function pointers and vtables in its
    /// value (rustls keeps its providers as `&dyn` objects inside statics).
    fn reach_static(&mut self, s: rustc_public::mir::mono::StaticDef) {
        let r = def_ref(self.cx, s.def_id());
        if !self.static_seen.insert(r.id.clone()) {
            return;
        }
        self.statics.insert(r.id.clone());
        if self.cx.static_interesting(s) {
            self.static_refs.push(r);
        }
        let did = rustc_internal::internal(self.cx.tcx, s.def_id());
        if self.cx.tcx.is_foreign_item(did) {
            return;
        }
        let Some(a) = catch_unwind(AssertUnwindSafe(|| s.eval_initializer().ok()))
            .ok()
            .flatten()
        else {
            return;
        };
        let mut found = Vec::new();
        let mut nested = Vec::new();
        alloc_callees(self.cx.tcx, &a, &mut found, &mut nested, 0);
        for i in found {
            self.enqueue(i, None);
        }
        for n in nested {
            self.reach_static(n);
        }
    }
}

/// Outgoing edges of one monomorphic body.
struct Edges<'a, 'tcx> {
    tcx: TyCtxt<'tcx>,
    body: &'a Body,
    found: Vec<(Instance, Span)>,
    /// Span of the statement being visited, for casts.
    cur: Option<Span>,
}

impl MirVisitor for Edges<'_, '_> {
    fn visit_statement(&mut self, stmt: &rustc_public::mir::Statement, loc: Location) {
        self.cur = Some(stmt.source_info.span);
        self.super_statement(stmt, loc);
    }

    fn visit_terminator(&mut self, term: &Terminator, loc: Location) {
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

    fn visit_rvalue(&mut self, rv: &Rvalue, loc: Location) {
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

    fn visit_const_operand(&mut self, c: &ConstOperand, loc: Location) {
        if let ConstantKind::Allocated(a) = c.const_.kind() {
            let mut found = Vec::new();
            alloc_callees(self.tcx, a, &mut found, &mut Vec::new(), 0);
            self.found.extend(found.into_iter().map(|i| (i, c.span)));
        }
        self.super_const_operand(c, loc);
    }
}

/// Function pointers and vtables inside a constant's memory; statics are reported separately.
fn alloc_callees(
    tcx: TyCtxt<'_>,
    a: &Allocation,
    found: &mut Vec<Instance>,
    statics: &mut Vec<rustc_public::mir::mono::StaticDef>,
    depth: usize,
) {
    if depth > 8 {
        return;
    }
    for (_, prov) in &a.provenance.ptrs {
        match GlobalAlloc::from(prov.0) {
            GlobalAlloc::Function(i) => found.push(i),
            GlobalAlloc::Memory(m) => alloc_callees(tcx, &m, found, statics, depth + 1),
            GlobalAlloc::Static(s) => statics.push(s),
            GlobalAlloc::VTable(..) => {
                let id = rustc_internal::internal(tcx, prov.0);
                if let rustc_middle::mir::interpret::GlobalAlloc::VTable(ty, preds) =
                    tcx.global_alloc(id)
                {
                    // as for an unsizing coercion: the methods and the type's drop glue
                    found.extend(vtable_methods_internal(tcx, ty, preds));
                    found.push(Instance::resolve_drop_in_place(rustc_internal::stable(ty)));
                }
            }
            GlobalAlloc::TypeId { .. } => {}
        }
    }
}

/// For an unsizing coercion `P<T> -> P<dyn Trait>`, the pair `(T, dyn Trait)`.
fn unsize_tails(src: &Ty, dst: &Ty) -> Option<(Ty, Ty)> {
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

fn vtable_methods(tcx: TyCtxt<'_>, concrete: Ty, dynamic: Ty) -> Vec<Instance> {
    let c = rustc_internal::internal(tcx, concrete);
    let d = rustc_internal::internal(tcx, dynamic);
    let mut out = Vec::new();
    if let rustc_middle::ty::Dynamic(preds, ..) = d.kind() {
        out = vtable_methods_internal(tcx, c, preds);
    }
    out.push(Instance::resolve_drop_in_place(concrete));
    out
}

fn vtable_methods_internal<'tcx>(
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
