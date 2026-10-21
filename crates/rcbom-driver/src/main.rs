//! `rcbom-driver`: a `RUSTC_WRAPPER` that compiles each crate normally and, after analysis,
//! writes the crypto-relevant facts of that crate (see `rcbom-facts`) to `$RCBOM_OUT`.
//!
//! Everything compiler-facing lives here; the rest of rcbom builds on stable. Analysis goes
//! through `rustc_public` except where it exposes nothing yet: spans of macro call sites,
//! static initializers with their promoted constants, vtable entries, and def-path hashes use
//! `rustc_middle` directly.
//!
//! Environment (set by `cargo cbom`):
//!   RCBOM_OUT          directory for `<crate><unit>.json` (`<crate>-<stable id>.json`
//!                      without a unit)
//!   RCBOM_KB_CRATES    crates the knowledge base covers, one `name=dir` per line (the package's
//!                      source directory); only sites naming items of these crates are recorded
//!   RCBOM_LOCAL_DIRS   directories of the program's own packages (workspace members, path
//!                      dependencies), one per line: their crates are never KB or stop crates
//!   RCBOM_IMPL_CRATES  the stop crates' dependencies: from a stop crate, calls into them are
//!                      their implementation, not callbacks (walked for usage only)
//!   RCBOM_STOP_CRATES  crates whose bodies the reachability walk records no sites in (algorithm
//!                      implementations: the call into them is the fact, not their internals);
//!                      their code is followed only to learn which crates run
//!   RCBOM_MAX_INSTANCES  reachability walk limit (default 200000)
//!   RCBOM_SYSROOT      sysroot of the pinned toolchain (else asked from the wrapped rustc)
//!   RCBOM_DEBUG        if set, print each panic the analysis catches (message and location),
//!                      and each site dropped for having no source position
//!   RCBOM_DEBUG_WALK   a substring of instance names: print the walk's edges out of the
//!                      matching instances
//!   RCBOM_DEBUG_CELLS  print each body's open cells (locals whose cells may change through an
//!                      alias the definitions do not follow)

#![feature(rustc_private)]

extern crate rustc_abi;
extern crate rustc_data_structures;
extern crate rustc_driver;
extern crate rustc_hir;
extern crate rustc_interface;
extern crate rustc_middle;
#[macro_use]
extern crate rustc_public;
extern crate rustc_span;

mod cx;
mod links;
mod names;
mod origins;
mod pta;
mod pta_solve;
mod pta_unify;
mod scan;
mod statics;
mod walk;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::process::{Command, exit};

use rcbom_facts::{
    CrateFacts, CrateInfo, CrateRef, DefRef, Expansion, FACTS_VERSION, Loc, MacroKind, Origin,
    Owner, OwnerKind, Reach, Site, Target, Tier, TyTree, ViaStep,
};
use rustc_middle::ty::{TyCtxt, TypeVisitableExt};
use rustc_public::mir::alloc::GlobalAlloc;
use rustc_public::mir::mono::{Instance, InstanceKind};
use rustc_public::mir::visit::{Location, MirVisitor};
use rustc_public::mir::{
    AggregateKind, Body, CastKind, ConstOperand, Operand, PointerCoercion, Rvalue, StatementKind,
    Terminator, TerminatorKind,
};
use rustc_public::rustc_internal;
use rustc_public::ty::{
    Allocation, ClosureKind, ConstantKind, GenericArgKind, GenericArgs, RigidTy, Span, Ty, TyKind,
};
use rustc_public::{CrateDef, ItemKind};

use cx::*;
use names::*;
use scan::*;
use walk::*;

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
    } || args
        .iter()
        .any(|a| a == "--print" || a.starts_with("--print="));
    if skip || std::env::var_os("RCBOM_OUT").is_none() {
        // Build scripts and proc macros run on the host; compile them untouched.
        let rustc = rustc.unwrap_or_else(|| "rustc".into());
        let status = Command::new(rustc)
            .args(&args[1..])
            .status()
            .expect("running rustc");
        exit(status.code().unwrap_or(1));
    }
    // The standard library's own crates under `-Zbuild-std` (cargo marks them
    // `force-unstable-if-unmarked`): compiled, not analysed, with every body's MIR kept for the
    // points-to engine.
    if args
        .iter()
        .any(|a| a.ends_with("force-unstable-if-unmarked"))
    {
        let rustc = rustc.unwrap_or_else(|| "rustc".into());
        let status = Command::new(rustc)
            .args(&args[1..])
            .arg("-Zalways-encode-mir")
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
    // The least transformed MIR rustc produces, whatever the project's profile. At MIR
    // opt-level 2 (the default when opt-level >= 1) GVN rebuilds constant operands without a
    // span, callees included, and the inliner folds calls into their callers; at level 1
    // RemoveZsts replaces every value of a zero-sized type (a callee held in a local, `OsRng`)
    // by a constant without a span, and CopyProp and SingleUseConsts merge the definitions the
    // argument origins follow.
    args.push("-Zmir-opt-level=0".into());
    // closures print by their path (`{closure@micro::seal::{closure#0}}`), not by their file
    // and position, which would put local paths (`OUT_DIR`) into owner names
    args.push("-Zspan-free-formats".into());
    let result = run_with_tcx!(&args, |tcx| {
        // A panic inside the analysis is caught per item and counted; rustc's ICE hook would
        // otherwise turn it into a compilation error of the user's crate. The guard puts the
        // hook back however `analyze` ends.
        type Hook = Box<dyn Fn(&std::panic::PanicHookInfo<'_>) + Sync + Send>;
        struct Restore(Option<Hook>);
        impl Drop for Restore {
            fn drop(&mut self) {
                // (not while a panic unwinds out of `analyze`: setting the hook then panics
                // again, and the process aborts without a message)
                if std::thread::panicking() {
                    return;
                }
                if let Some(h) = self.0.take() {
                    std::panic::set_hook(h);
                }
            }
        }
        let _restore = Restore(Some(std::panic::take_hook()));
        if std::env::var_os("RCBOM_DEBUG").is_some() {
            std::panic::set_hook(Box::new(|info| {
                let bt = std::backtrace::Backtrace::force_capture().to_string();
                let ours: Vec<&str> = bt
                    .lines()
                    .filter(|l| l.contains("rcbom_driver::"))
                    .map(str::trim)
                    .collect();
                eprintln!(
                    "rcbom-driver: caught panic: {info}\n  in {}",
                    ours.join("\n  in ")
                );
            }));
        } else {
            std::panic::set_hook(Box::new(|_| {}));
        }
        analyze(tcx);
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

/// A codegen option (`-C extra-filename=-abc`, `-Cextra-filename=-abc`).
fn codegen_opt(args: &[String], name: &str) -> Option<String> {
    let key = format!("{name}=");
    args.iter().enumerate().find_map(|(i, a)| {
        let v = if a == "-C" {
            args.get(i + 1)?.as_str()
        } else {
            a.strip_prefix("-C")?
        };
        v.strip_prefix(&key).map(str::to_string)
    })
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

/// Crates by name, each with the source directories of the packages it may come from
/// (`name=dir` entries, one per line; a bare name stands for any package): two packages can
/// name their library alike (md5 0.7 and md-5's `md5`), and only the directory tells them apart.
struct CrateSet(HashMap<String, Vec<std::path::PathBuf>>);

/// Shared state for one crate's analysis.
pub(crate) struct Cx<'tcx> {
    pub tcx: TyCtxt<'tcx>,
    kb_crates: CrateSet,
    stop_crates: CrateSet,
    /// The stop crates' dependencies (`RCBOM_IMPL_CRATES`).
    impl_crates: CrateSet,
    /// Memo: the root source file of each crate (where its package's sources are).
    crate_roots:
        std::cell::RefCell<HashMap<rustc_span::def_id::CrateNum, Option<std::path::PathBuf>>>,
    /// Memo: crates by stable id, for crates the facts name.
    by_stable_id: std::cell::OnceCell<HashMap<String, rustc_span::def_id::CrateNum>>,
    /// The program's own crates (workspace members, path dependencies), by crate number and
    /// stable id: never the crates the knowledge base describes, whatever their names (a member
    /// called `signature`).
    local: HashSet<rustc_span::def_id::CrateNum>,
    local_ids: HashSet<String>,
    /// Memo: does this static (by def-path hash) lead to a knowledge-base static?
    interesting_statics: HashMap<String, bool>,
    /// Value flow across this crate's functions (`links`).
    links: rcbom_facts::Links,
    /// This crate's statics whose contents change at run time and can hold key material
    /// (`links::mutable_static_defs`), computed once.
    pub(crate) mutable_statics: std::cell::OnceCell<HashSet<rustc_span::def_id::DefId>>,
    pub errors: usize,
    /// The points-to analysis over the walked bodies (`RCBOM_PTA`), solved after the walk.
    pub(crate) pta: Option<pta::Pta>,
}

fn analyze(tcx: TyCtxt<'_>) {
    let (local, local_ids) = local_crates(tcx);
    let mut cx = Cx {
        tcx,
        kb_crates: CrateSet::from_env("RCBOM_KB_CRATES"),
        stop_crates: CrateSet::from_env("RCBOM_STOP_CRATES"),
        impl_crates: CrateSet::from_env("RCBOM_IMPL_CRATES"),
        crate_roots: Default::default(),
        by_stable_id: Default::default(),
        local,
        local_ids,
        interesting_statics: HashMap::new(),
        links: Default::default(),
        mutable_statics: std::cell::OnceCell::new(),
        errors: 0,
        pta: None,
    };
    if std::env::var_os("RCBOM_PTA").is_some() {
        let stop = tcx
            .crates(())
            .iter()
            .copied()
            .chain(std::iter::once(rustc_span::def_id::LOCAL_CRATE))
            .filter(|&c| cx.stop_crate(c))
            .collect();
        cx.pta = Some(pta::Pta::new(stop));
    }
    // the crates whose generic items' instances the links may summarise: not the standard
    // library's, nor the stop crates' (`origins::body_name`)
    origins::set_summarised(
        tcx.crates(())
            .iter()
            .copied()
            .chain(std::iter::once(rustc_span::def_id::LOCAL_CRATE))
            .filter(|&c| {
                !cx.stop_crate(c) && !matches!(tcx.crate_name(c).as_str(), "core" | "std" | "alloc")
            })
            .collect(),
    );
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
        cwd: std::env::current_dir().unwrap().display().to_string(),
        unit: codegen_opt(&std::env::args().collect::<Vec<_>>(), "extra-filename")
            .unwrap_or_default(),
    };

    let mut sites = Vec::new();
    // RCBOM_DEBUG: how long each phase, and any slow item, takes
    let debug = std::env::var_os("RCBOM_DEBUG").is_some();
    let timer = std::time::Instant::now();
    let phase = |name: &str, since: std::time::Instant| {
        if debug {
            eprintln!(
                "rcbom-driver: {}: {name}: {:.2} s",
                local.name,
                since.elapsed().as_secs_f64()
            );
        }
    };
    // Static initializers first: a local static that leads to a KB static makes references to
    // it interesting.
    let (data_sites, data_edges) = statics::local_data_sites(&mut cx);
    phase("static and const sites", timer);
    let timer = std::time::Instant::now();
    for s in data_sites {
        cx.interesting_statics.insert(owner_id_of(&s), true);
        sites.push(s);
    }
    for e in &data_edges {
        cx.interesting_statics.insert(e.owner.id.clone(), true);
    }
    // a function named in a static's or const's initializer (`static HASH: fn(&[u8]) -> Hash =
    // blake3::hash;`): named there, whatever calls it later
    for did in tcx.hir_body_owners().map(|d| d.to_def_id()) {
        if !matches!(
            tcx.def_kind(did),
            rustc_hir::def::DefKind::Static { .. }
                | rustc_hir::def::DefKind::Const
                | rustc_hir::def::DefKind::AssocConst
        ) || tcx.is_foreign_item(did)
        {
            continue;
        }
        let r = catch_unwind(AssertUnwindSafe(|| {
            let item = rustc_public::CrateItem(rustc_internal::stable(did));
            let owner = Owner {
                kind: OwnerKind::Static,
                name: path_of(tcx, did),
                id: def_hash(tcx, did),
                krate: crate_ref(tcx, did),
                path: path_of(tcx, did),
            };
            let mut out = Vec::new();
            if !item.requires_monomorphization()
                && let Some(body) = item.body()
            {
                let mut sc = Scanner::new(
                    &mut cx,
                    &body,
                    Some(did),
                    owner,
                    Tier::Present,
                    vec![],
                    &mut out,
                    None,
                );
                sc.visit_body(&body);
                let mut l = rcbom_facts::Links::default();
                links::body_links(&cx, &body, did, false, None, &mut l);
                links::promoted_links(&cx, did, &mut l);
                cx.links.merge(l);
            }
            out
        }));
        match r {
            Ok(out) => sites.extend(
                out.into_iter()
                    .filter(|s| matches!(s.target, rcbom_facts::Target::Call { .. })),
            ),
            Err(_) => cx.errors += 1,
        }
    }
    for item in rustc_public::all_local_items() {
        if !matches!(item.kind(), ItemKind::Fn) || !item.has_body() {
            continue;
        }
        let item_timer = std::time::Instant::now();
        let r = catch_unwind(AssertUnwindSafe(|| {
            let owner = if item.requires_monomorphization() {
                fn_owner_item(&cx, &item)
            } else {
                Instance::try_from(item)
                    .ok()
                    .map(|i| fn_owner(&cx, &i))
                    .unwrap_or_else(|| fn_owner_item(&cx, &item))
            };
            let did = rustc_internal::internal(cx.tcx, item.def_id());
            let mut out = Vec::new();
            // the item body, not an instance body: for a monomorphic fn the types are the
            // same, and named consts are not evaluated away (aws-lc-rs algorithms are consts)
            if let Some(body) = item.body().map(|b| live_body(tcx, &b)) {
                let mut sc = Scanner::new(
                    &mut cx,
                    &body,
                    Some(did),
                    owner.clone(),
                    Tier::Present,
                    vec![],
                    &mut out,
                    None,
                );
                sc.visit_body(&body);
                sc.promoted_values(did);
                let mut l = rcbom_facts::Links::default();
                links::body_links(&cx, &body, did, true, None, &mut l);
                links::promoted_links(&cx, did, &mut l);
                cx.links.merge(l);
            }
            out.extend(statics::fn_data_sites(
                &mut cx,
                did,
                None,
                &owner,
                Tier::Present,
                &[],
            ));
            out
        }));
        match r {
            Ok(out) => sites.extend(out),
            Err(_) => cx.errors += 1,
        }
        if debug && item_timer.elapsed().as_secs_f64() > 1.0 {
            phase(&format!("item {}", item.name()), item_timer);
        }
    }
    phase("per-item scan", timer);
    let timer = std::time::Instant::now();

    // Roots: `main` of a binary; for a library the user asked to analyse (a workspace member),
    // its public monomorphic API and public statics; in both, what the linker keeps whatever
    // calls it (`#[no_mangle]`, `#[export_name]`, `#[used]` statics such as constructors in
    // `.init_array`).
    let primary = std::env::var_os("CARGO_PRIMARY_PACKAGE").is_some();
    let (roots, static_roots, generic) = if !primary {
        (Vec::new(), Vec::new(), Vec::new())
    } else {
        roots(&cx)
    };
    // a library's generic functions its users can call: their per-item sites (those whose
    // crypto does not depend on the type arguments: `PrivateJar<J>::add` sealing with
    // AES-256-GCM) are reachable, as when an instance of them is walked
    let generic_paths: Vec<String> = generic.iter().map(|d| path_of(cx.tcx, *d)).collect();
    let generic: Vec<String> = generic.iter().map(|d| def_hash(cx.tcx, *d)).collect();
    let reach = (!roots.is_empty() || !static_roots.is_empty() || !generic.is_empty()).then(|| {
        if let Some(p) = cx.pta.as_mut() {
            p.set_roots(&roots);
        }
        let mut w = Walker::new(&mut cx);
        let mut r = w.run(roots, static_roots);
        // a panic in the points-to analysis is counted as an item not analysed, like the
        // others; the facts are written without its answers
        if let Some(p) = w.cx.pta.take() {
            let tcx = w.cx.tcx;
            match catch_unwind(AssertUnwindSafe(|| pta_dump(tcx, p))) {
                Ok(pt) => r.points_to = Some(pt),
                Err(_) => w.cx.errors += 1,
            }
        }
        let coercions = std::mem::take(&mut w.coercions);
        w.cx.links.coercions = coercions
            .into_iter()
            .map(
                |((trait_path, ty), (at, in_static, methods))| rcbom_facts::Coercion {
                    trait_path,
                    ty,
                    at,
                    in_static,
                    methods,
                },
            )
            .collect();
        sites.extend(w.sites);
        r.fns.extend(generic);
        r.fns.sort();
        r.fns.dedup();
        r.generic = generic_paths.clone();
        r.generic.sort();
        r.paths.extend(generic_paths);
        r.paths.sort();
        r.paths.dedup();
        r
    });
    phase("walk", timer);

    // Identical facts from the per-item scan and the walk collapse to one.
    let mut seen = HashSet::new();
    sites.retain(|s| seen.insert(s.clone()));

    let mut crate_links = std::mem::take(&mut cx.links);
    links::instance_links(&cx, &mut crate_links);
    if catch_unwind(AssertUnwindSafe(|| {
        links::mutable_statics(&cx, &mut crate_links)
    }))
    .is_err()
    {
        cx.errors += 1;
    }
    // the field names of a knowledge-base crate's structs, for the boundary models that name
    // fields (`Header.alg`)
    let fields = if cx.kb_crate(rustc_span::def_id::LOCAL_CRATE) {
        tcx.hir_crate_items(())
            .definitions()
            .map(|d| d.to_def_id())
            .filter(|&d| matches!(tcx.def_kind(d), rustc_hir::def::DefKind::Struct))
            .map(|d| {
                let names = tcx
                    .adt_def(d)
                    .non_enum_variant()
                    .fields
                    .iter()
                    .map(|f| f.name.to_string())
                    .collect();
                (path_of(tcx, d), names)
            })
            .collect()
    } else {
        Default::default()
    };
    // and the variants of its field-less enums, for a constant of one (`const ALG: Algorithm`)
    let variants = if cx.kb_crate(rustc_span::def_id::LOCAL_CRATE) {
        tcx.hir_crate_items(())
            .definitions()
            .map(|d| d.to_def_id())
            .filter(|&d| matches!(tcx.def_kind(d), rustc_hir::def::DefKind::Enum))
            .filter(|&d| tcx.adt_def(d).all_fields().next().is_none())
            .map(|d| {
                let adt = tcx.adt_def(d);
                let vs = adt
                    .discriminants(tcx)
                    .map(|(i, discr)| {
                        (
                            adt.variant(i).name.to_string(),
                            i128::try_from(discr.val).unwrap_or(i128::MAX),
                        )
                    })
                    .collect();
                (path_of(tcx, d), vs)
            })
            .collect()
    } else {
        Default::default()
    };
    let facts = CrateFacts {
        facts_version: FACTS_VERSION,
        krate,
        sites,
        data_edges,
        reach,
        links: crate_links,
        fields,
        variants,
    };
    let out = PathBuf::from(std::env::var("RCBOM_OUT").unwrap());
    std::fs::create_dir_all(&out).unwrap();
    // named after cargo's unit, so `cargo cbom` can keep only this build's units
    let path = out.join(if facts.krate.unit.is_empty() {
        format!("{}-{}.json", facts.krate.name, facts.krate.stable_id)
    } else {
        format!("{}{}.json", facts.krate.name, facts.krate.unit)
    });
    std::fs::write(&path, serde_json::to_vec(&facts).unwrap()).unwrap();
    if cx.errors > 0 {
        eprintln!(
            "rcbom-driver: {}: {} items could not be analysed",
            facts.krate.name, cx.errors
        );
    }
}

/// Solves the points-to analysis: its answers for the facts (per call into a stop crate, what
/// each argument may point to), and its statistics beside them (`<crate>-pta.json`).
fn pta_dump(tcx: TyCtxt<'_>, p: pta::Pta) -> rcbom_facts::PointsTo {
    let t0 = std::time::Instant::now();
    let (queries, answers, stats) = p.solve();
    let mut why: Vec<(String, usize)> = stats
        .havoc_why
        .iter()
        .map(|(k, v)| (k.clone(), *v))
        .collect();
    why.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let listed: Vec<serde_json::Value> = queries
        .iter()
        .zip(&answers)
        .map(|(q, a)| {
            serde_json::json!({
                "file": q.at.file,
                "line": q.at.line,
                "col": q.at.col,
                "callee": q.callee,
                "live": q.live,
                "args": a.iter().map(|x| x.as_ref().map(|x| serde_json::json!({
                    "statics": x.statics.iter().map(|d| path_of(tcx, *d)).collect::<Vec<_>>(),
                    "unknown": x.unknown,
                    "others": x.others,
                }))).collect::<Vec<_>>(),
            })
        })
        .collect();
    let out = PathBuf::from(std::env::var("RCBOM_OUT").unwrap());
    let name = tcx.crate_name(rustc_span::def_id::LOCAL_CRATE);
    let v = serde_json::json!({
        "objects": stats.objects,
        "instances": stats.instances,
        "copies": stats.copies,
        "vcalls_without_vtable": stats.vcalls_without_vtable,
        "vcalls_without_vtable_in": stats.vcalls_without_vtable_in,
        "failed": stats.failed,
        "constraints": stats.constraints,
        "solve_ms": t0.elapsed().as_millis() as u64,
        "havoc": why.iter().take(200).map(|(k, v)| serde_json::json!([k, v])).collect::<Vec<_>>(),
        "queries": listed,
    });
    let _ = std::fs::write(
        out.join(format!("{name}-pta.json")),
        serde_json::to_vec_pretty(&v).unwrap(),
    );
    let calls = queries
        .iter()
        .zip(&answers)
        .map(|(q, a)| rcbom_facts::PtaCall {
            at: q.at.clone(),
            callee: q.callee_path.clone(),
            owner: q.owner.clone(),
            owner_def: q.owner_def.clone(),
            live: q.live,
            args: a
                .iter()
                .enumerate()
                .map(|(k, x)| {
                    x.as_ref().map(|x| rcbom_facts::PtaArg {
                        statics: x
                            .statics
                            .iter()
                            .map(|d| def_ref_internal(tcx, *d))
                            .collect(),
                        unknown: x.unknown,
                        others: x.others,
                        pointee: q.pointee(k).map(|d| path_of(tcx, d)),
                        direct: q.direct.get(k).copied().unwrap_or(false),
                    })
                })
                .collect(),
        })
        .collect();
    let static_types = stats
        .static_types
        .iter()
        .map(|(d, t)| (def_ref_internal(tcx, *d), path_of(tcx, *t)))
        .collect();
    rcbom_facts::PointsTo {
        calls,
        static_types,
    }
}

/// Records the calls in one body that name KB items, and collects the statics it references
/// (for the walk). Static and const sites come from `statics::fn_data_sites`, which reads the
/// MIR before evaluation and so has the spans that name them.
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
    /// The body holds a value `rustc_public` cannot convert the type of (`unconvertible`).
    unconvertible: bool,
    /// The item the body is of.
    def: Option<rustc_span::def_id::DefId>,
}

/// The instance graph from `main`, after the compiler's mono-item collector: calls resolved
/// to instances, drop glue, function pointers, closures, and for every unsizing to `dyn Trait`
/// all methods of the vtable (sound and over-approximate for dynamic dispatch).
///
/// Inside the stop crates the walk records no sites: it follows their code only to learn which
/// crates run (`Reach::crates`), as the usage of the packages the program does not call itself
/// (block-buffer under sha2's `Digest` impl, not ecdsa under p256 used for ECDH only).
struct Walker<'a, 'tcx> {
    cx: &'a mut Cx<'tcx>,
    /// Instances to visit; `true`: walked for usage only.
    queue: VecDeque<(Instance, bool)>,
    seen: HashSet<Instance>,
    usage_seen: HashSet<Instance>,
    usage_statics: HashSet<rustc_span::def_id::DefId>,
    /// Crates whose code the walk reached.
    crates: BTreeSet<rustc_span::def_id::CrateNum>,
    parent: HashMap<Instance, (Instance, Loc, Option<String>)>,
    statics: BTreeSet<String>,
    static_refs: Vec<DefRef>,
    static_seen: HashSet<String>,
    sites: Vec<Site>,
    /// Owner ids of the instances whose bodies were walked.
    fns: Vec<String>,
    /// Defining paths of the walked functions.
    paths: Vec<String>,
    /// Types coerced to trait objects in the walked code: first position seen (in a static's
    /// value or not), and the body each method of the object runs for the type.
    coercions: BTreeMap<(String, String), CoercedAt>,
    /// The trait objects (`dyn_key`) some walked code may call: called through one, handed by
    /// the program's code to code it does not walk, in a root's signature or a result.
    dyn_used: HashSet<String>,
    /// What waits for a trait object to be used (`dyn_key`): the methods a type coerced to it
    /// in the program's code runs, and a closure made one there; with the body and position.
    pending: HashMap<String, Vec<(Instance, Instance, Span)>>,
    /// The trait objects each type holds (`Walker::dyn_keys`).
    dyn_cache: HashMap<rustc_middle::ty::Ty<'tcx>, Vec<String>>,
    limit: usize,
}

/// The statics the constants of a body point at.
struct AllocStatics(Vec<rustc_public::mir::mono::StaticDef>);

/// Outgoing edges of one monomorphic body.
struct Edges<'a, 'tcx> {
    tcx: TyCtxt<'tcx>,
    body: &'a Body,
    found: Vec<(Instance, Span)>,
    /// Types coerced to a trait object, where, and whether in a constant's value.
    coerced: Vec<(Coerced, Span, bool)>,
    /// Span of the statement being visited, for casts.
    cur: Option<Span>,
    /// As in `Scanner`: the body holds an `async` closure; panics that are bugs.
    unconvertible: bool,
    errors: usize,
    /// The local the statement being visited assigns.
    dest: Option<rustc_public::mir::Local>,
    /// The body is the program's code (not the standard library's, a stop crate's or a
    /// shim): its coercions to trait objects wait for one to be used (`deferred`).
    program: bool,
    /// Methods of trait objects made here, by `dyn_key`, and a closure made one, with where:
    /// edges once such an object is used.
    deferred: Vec<(String, Vec<Instance>, Span)>,
    /// Trait objects this body uses without a call (`dyn_key`): an upcast.
    used: Vec<String>,
    /// The calls (the instance, none through a pointer) and their arguments' types.
    calls: Vec<(Option<Instance>, Vec<rustc_public::ty::Ty>)>,
}

/// A type coerced to a trait object: the trait's path, the type's, and for each trait method
/// the body the type's vtable holds (`origins::body_name`).
type Coerced = (String, String, Vec<(String, String, String)>);

/// Where a type was first seen coerced (in a static's value or not), and the bodies its
/// methods run.
type CoercedAt = (Option<Loc>, bool, Vec<(String, String, String)>);

#[cfg(test)]
mod tests {
    use super::args_start;

    #[test]
    fn the_argument_list_is_the_last_group() {
        let callee = |t: &str| args_start(t).map(|n| t[..n].trim_end().to_string());
        assert_eq!(callee("h(&SHA256, d)").as_deref(), Some("h"));
        assert_eq!(callee("(h.f)(&SHA384, &d)").as_deref(), Some("(h.f)"));
        assert_eq!(callee("get()(&SHA256, &d)").as_deref(), Some("get()"));
        assert_eq!(callee("fs[0](&SHA512, &d)").as_deref(), Some("fs[0]"));
        assert_eq!(callee("p(\n    &a,\n    &d,\n)").as_deref(), Some("p"));
        assert_eq!(callee("f(\")\", ')', '\\'')").as_deref(), Some("f"));
        assert_eq!(callee("a + b"), None);
        assert_eq!(callee("f(x)?"), None);
    }

    #[test]
    fn raw_identifiers_are_plain() {
        assert_eq!(
            super::unraw("rand::rng::Rng::r#gen::<[u8; 16]>"),
            "rand::rng::Rng::gen::<[u8; 16]>"
        );
        assert_eq!(super::unraw("<r#gen as r#try>::bar"), "<gen as try>::bar");
        assert_eq!(super::unraw("ber#x::car#y"), "ber#x::car#y");
    }
}
