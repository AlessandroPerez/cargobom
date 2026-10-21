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

mod links;
mod origins;
mod pta;
mod pta_solve;
mod pta_unify;
mod statics;

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

impl CrateSet {
    fn from_env(name: &str) -> CrateSet {
        let mut m: HashMap<String, Vec<std::path::PathBuf>> = HashMap::new();
        for e in std::env::var(name).unwrap_or_default().split('\n') {
            if e.is_empty() {
                continue;
            }
            let (n, dir) = match e.split_once('=') {
                Some((n, d)) => (n, Some(std::path::PathBuf::from(d))),
                None => (e, None),
            };
            let dirs = m.entry(n.replace('-', "_")).or_default();
            dirs.extend(dir);
        }
        CrateSet(m)
    }

    /// Does crate `name`, whose root source file is `root`, belong to the set? Under
    /// `--remap-path-prefix` a dependency's root is its remapped name (`/registry/md-5-0.10.6/
    /// src/lib.rs`): the package directory's own name (`md-5-0.10.6`) still tells it apart.
    fn contains(&self, name: &str, root: impl FnOnce() -> Option<std::path::PathBuf>) -> bool {
        match self.0.get(name) {
            None => false,
            Some(dirs) if dirs.is_empty() => true,
            Some(dirs) => root().is_some_and(|r| {
                dirs.iter().any(|d| {
                    r.starts_with(d)
                        || d.file_name()
                            .is_some_and(|n| r.components().any(|c| c.as_os_str() == n))
                })
            }),
        }
    }
}

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
fn unraw(p: &str) -> String {
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

fn owner_id_of(s: &Site) -> String {
    s.owner.id.clone()
}

fn fn_owner(cx: &Cx<'_>, inst: &Instance) -> Owner {
    let did = rustc_internal::internal(cx.tcx, inst.def.def_id());
    Owner {
        kind: OwnerKind::Fn,
        name: instance_name(cx.tcx, inst),
        id: inst.mangled_name(),
        krate: crate_ref(cx.tcx, did),
        path: path_of(cx.tcx, did),
    }
}

fn fn_owner_item(cx: &Cx<'_>, item: &rustc_public::CrateItem) -> Owner {
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
        };
        (raw_loc(tcx, call), Some(exp))
    } else {
        (raw_loc(tcx, span), None)
    }
}

fn raw_loc(tcx: TyCtxt<'_>, span: rustc_span::Span) -> Loc {
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
fn virtual_rust_src(tcx: TyCtxt<'_>) -> Option<&'static str> {
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
    match ty.kind() {
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
                        rustc_public::ty::ExistentialPredicate::Trait(t) => Some(t.def_id.name()),
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
pub(crate) fn const_int(op: &Operand) -> Option<i128> {
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

fn tree_mentions(t: &TyTree, cx: &Cx<'_>) -> bool {
    match t {
        TyTree::Adt { krate, args, .. } => {
            cx.kb_ref(krate) || args.iter().any(|a| tree_mentions(a, cx))
        }
        TyTree::Ref(t) | TyTree::Slice(t) | TyTree::Array(t, _) => tree_mentions(t, cx),
        TyTree::Tuple(ts) => ts.iter().any(|a| tree_mentions(a, cx)),
        _ => false,
    }
}

/// The crates of the program's own packages: those whose root file belongs to a workspace
/// member or path dependency (`RCBOM_LOCAL_DIRS`, their directories, one per line).
fn local_crates(tcx: TyCtxt<'_>) -> (HashSet<rustc_span::def_id::CrateNum>, HashSet<String>) {
    let dirs: Vec<PathBuf> = std::env::var("RCBOM_LOCAL_DIRS")
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.is_empty())
        .map(PathBuf::from)
        .collect();
    let cwd = std::env::current_dir().unwrap_or_default();
    let sm = tcx.sess.source_map();
    let mut nums = HashSet::new();
    let mut ids = HashSet::new();
    for c in tcx
        .crates(())
        .iter()
        .copied()
        .chain([rustc_span::def_id::LOCAL_CRATE])
    {
        let root = sm
            .span_to_filename(tcx.def_span(c.as_def_id()))
            .prefer_local_unconditionally()
            .to_string();
        let root = cwd.join(root);
        // the package the root file belongs to: the nearest directory above it with a
        // `Cargo.toml` (a crate vendored under the project, or a `CARGO_HOME` inside it, has its
        // own)
        let pkg = root
            .ancestors()
            .skip(1)
            .find(|d| d.join("Cargo.toml").is_file());
        if pkg.is_some_and(|p| dirs.iter().any(|d| d == p)) {
            nums.insert(c);
            ids.insert(format!("{:016x}", tcx.stable_crate_id(c).as_u64()));
        }
    }
    (nums, ids)
}

impl Cx<'_> {
    /// The root source file of a crate (`…/md-5-0.10.6/src/lib.rs`), or its remapped name.
    fn crate_root(&self, c: rustc_span::def_id::CrateNum) -> Option<std::path::PathBuf> {
        self.crate_roots
            .borrow_mut()
            .entry(c)
            .or_insert_with(|| {
                let span = self.tcx.def_span(c.as_def_id());
                let name = self.tcx.sess.source_map().span_to_filename(span);
                matches!(name, rustc_span::FileName::Real(_)).then(|| {
                    let cwd = std::env::current_dir().unwrap_or_default();
                    cwd.join(name.prefer_local_unconditionally().to_string())
                })
            })
            .clone()
    }

    fn in_set(&self, set: &CrateSet, c: rustc_span::def_id::CrateNum) -> bool {
        !self.local.contains(&c)
            && set.contains(self.tcx.crate_name(c).as_str(), || self.crate_root(c))
    }

    /// Is this crate one the knowledge base describes?
    pub(crate) fn kb_crate(&self, c: rustc_span::def_id::CrateNum) -> bool {
        self.in_set(&self.kb_crates, c)
    }

    /// The same for a crate as the facts name it.
    fn kb_ref(&self, k: &rcbom_facts::CrateRef) -> bool {
        if self.local_ids.contains(&k.stable_id) {
            return false;
        }
        let by_id = self.by_stable_id.get_or_init(|| {
            self.tcx
                .crates(())
                .iter()
                .chain(std::iter::once(&rustc_span::def_id::LOCAL_CRATE))
                .map(|&c| (format!("{:016x}", self.tcx.stable_crate_id(c).as_u64()), c))
                .collect()
        });
        match by_id.get(&k.stable_id) {
            Some(&c) => self.kb_crate(c),
            None => self.kb_crates.contains(&k.name, || None),
        }
    }

    /// Is this crate one of the program's own (a workspace member, a path dependency)?
    pub(crate) fn is_program(&self, c: rustc_span::def_id::CrateNum) -> bool {
        self.local.contains(&c)
    }

    /// Is this crate one whose code the walk does not enter (an algorithm implementation)?
    pub(crate) fn stop_crate(&self, c: rustc_span::def_id::CrateNum) -> bool {
        self.in_set(&self.stop_crates, c)
    }

    /// Is this crate a dependency of a stop crate (`RCBOM_IMPL_CRATES`): part of how an
    /// algorithm is implemented, when a stop crate calls into it?
    fn impl_crate(&self, c: rustc_span::def_id::CrateNum) -> bool {
        self.in_set(&self.impl_crates, c)
    }

    /// A static is worth recording if it belongs to a KB crate, or its value points (through
    /// any depth of allocations) at a static that is.
    pub(crate) fn static_interesting(&mut self, did: rustc_span::def_id::DefId) -> bool {
        let key = def_hash(self.tcx, did);
        if let Some(v) = self.interesting_statics.get(&key) {
            return *v;
        }
        // A search through the statics the initializers point at. Only complete answers are
        // remembered: an answer computed while another static of the same cycle was still being
        // searched could miss what that one leads to.
        let tcx = self.tcx;
        let mut stack = vec![did];
        let mut seen = HashSet::from([did]);
        let mut found = false;
        while let Some(s) = stack.pop() {
            match self.interesting_statics.get(&def_hash(tcx, s)) {
                Some(true) => {
                    found = true;
                    break;
                }
                Some(false) => continue,
                None => {}
            }
            if self.kb_crate(s.krate) {
                found = true;
                break;
            }
            // an extern static (FFI) has no initializer to evaluate
            if tcx.is_foreign_item(s) {
                continue;
            }
            let next = catch_unwind(AssertUnwindSafe(|| {
                tcx.eval_static_initializer(s).ok().map(|a| {
                    let mut found = Vec::new();
                    for (_, prov) in a.inner().provenance().ptrs().iter() {
                        statics::statics_in(
                            tcx,
                            prov.alloc_id(),
                            &mut found,
                            &mut HashSet::new(),
                            0,
                        );
                    }
                    found
                })
            }))
            .ok()
            .flatten()
            .unwrap_or_default();
            for t in next {
                if seen.insert(t) {
                    stack.push(t);
                }
            }
        }
        self.interesting_statics.insert(key, found);
        found
    }

    fn is_std(&self, krate: &str) -> bool {
        matches!(krate, "core" | "std" | "alloc")
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

/// Is a caught panic `rustc_public`'s for an `async` closure's type, which it cannot convert
/// yet ("FIXME(async_closures)"), wherever the type sits (a capture's field, a callee's
/// generic argument)?
pub(crate) fn async_closure(e: &Box<dyn std::any::Any + Send>) -> bool {
    let msg = e
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| e.downcast_ref::<&str>().copied())
        .unwrap_or("");
    msg.contains("FIXME(async_closures)")
}

/// Does a local of `body` have a type `rustc_public` cannot convert yet? An `async` closure's
/// (`CoroutineClosure`): converting it panics ("FIXME(async_closures): Lower these to SMIR").
/// Reading a statement or call that involves one is a known limit of the interface, not a bug.
pub(crate) fn has_unconvertible(tcx: TyCtxt<'_>, body: &Body) -> bool {
    let unconvertible = |ty: rustc_public::ty::Ty| {
        rustc_internal::internal(tcx, ty).walk().any(|g| {
            g.as_type()
                .is_some_and(|t| matches!(t.kind(), rustc_middle::ty::CoroutineClosure(..)))
        })
    };
    // in a local's type, or in a callee's generic arguments (`apply::<{async closure}>`)
    body.locals().iter().any(|l| unconvertible(l.ty))
        || body.blocks.iter().any(|b| match &b.terminator.kind {
            rustc_public::mir::TerminatorKind::Call { func, .. } => {
                func.ty(body.locals()).is_ok_and(unconvertible)
            }
            _ => false,
        })
}

impl<'a, 'tcx> Scanner<'a, 'tcx> {
    #[allow(clippy::too_many_arguments)]
    fn new(
        cx: &'a mut Cx<'tcx>,
        body: &'a Body,
        def: Option<rustc_span::def_id::DefId>,
        owner: Owner,
        tier: Tier,
        via: Vec<ViaStep>,
        out: &'a mut Vec<Site>,
        item: Option<(
            rustc_span::def_id::DefId,
            rustc_middle::ty::GenericArgsRef<'tcx>,
        )>,
    ) -> Self {
        let mut origins = origins::Origins::new(cx.tcx, body, def);
        if let Some((item, args)) = item {
            origins = origins.with_item(item, args);
        }
        let unconvertible = has_unconvertible(cx.tcx, body);
        Scanner {
            cx,
            body,
            owner,
            tier,
            via,
            out,
            statics: Vec::new(),
            origins,
            unconvertible,
            def,
        }
    }

    fn push_internal(&mut self, mut internal: rustc_span::Span, target: Target) {
        // code a derive generates with an input token's span (`quote_spanned!` at a field's
        // name): the derive's, not the field's
        if !internal.from_expansion()
            && let Some(did) = self.def
            && let Some(call) = derive_site(self.cx.tcx, did)
        {
            internal = call;
        }
        let text = span_text(self.cx.tcx, internal);
        let line_text = line_text(self.cx.tcx, internal);
        let (span, expansion) = locate(self.cx.tcx, internal);
        if span.line == 0 {
            // compiler-generated code (shims), and operands an optimization rebuilt, have no
            // source position
            if std::env::var_os("RCBOM_DEBUG").is_some() {
                eprintln!(
                    "rcbom-driver: site without a position dropped in {}: {:?}",
                    self.owner.name, target
                );
            }
            return;
        }
        self.out.push(Site {
            tier: self.tier,
            owner: self.owner.clone(),
            span,
            text,
            line_text,
            expansion,
            target,
            via: self.via.clone(),
        });
    }

    /// A call through a pointer or a trait object of a function: at its callee, with where the
    /// pointer comes from; an unknown pointer when that is not known or the call has no callee
    /// to place it at (the analysis takes it as a call of any function made a pointer).
    fn push_pointer(
        &mut self,
        origin: Origin,
        const_args: Vec<Option<i128>>,
        arg_origins: Vec<Origin>,
        arg_lens: Vec<Option<u64>>,
        sig: Option<String>,
        term: &Terminator,
    ) {
        let tcx = self.cx.tcx;
        let at = rustc_internal::internal(tcx, term.source_info.span);
        let (call, origin) = match callee_span(tcx, at) {
            Some(call) if !matches!(origin, Origin::Truncated) => (call, origin),
            Some(call) => (call, Origin::Unknown),
            None => (at, Origin::Unknown),
        };
        self.push_internal(
            call,
            Target::Pointer {
                origin,
                const_args,
                arg_origins,
                arg_lens,
                sig,
            },
        );
    }

    /// Is a call (or a function used as a value) of `def::<args>` a crypto fact?
    fn interesting(&self, def: &rustc_public::ty::FnDef, args: &GenericArgs) -> bool {
        let tcx = self.cx.tcx;
        let did = rustc_internal::internal(tcx, def.def_id());
        let iargs = rustc_internal::internal(tcx, args);
        // not monomorphic (`<A as KeyInit>::new_from_slice`, `Hkdf::<<Kdf as Kdf>::Hash>`):
        // the walk sees the instances
        if iargs.has_non_region_param() || iargs.has_aliases() {
            return false;
        }
        let krate = tcx.crate_name(did.krate).to_string();
        if self.cx.kb_crate(did.krate) {
            return true;
        }
        let trees = arg_trees(tcx, &args.0, 0);
        if !trees.iter().any(|t| tree_mentions(t, self.cx)) {
            return false;
        }
        if self.cx.is_std(&krate) {
            // `Result::unwrap`, `Vec::push`, `Clone::clone`, drop glue: the standard library
            // handling a crypto value is not a use of it. Constructors and conversions the
            // crypto type implements are: `<Argon2 as Default>::default()`,
            // `StaticSecret::from([7u8; 32])`, `SigningKey::try_from(bytes)`, `bytes.into()`;
            // so is data written into it through its `io::Write` impl (`h.write_all(data)`,
            // `io::copy(&mut file, &mut h)` hashing a file)
            let Some(tr) = tcx.trait_of_assoc(did) else {
                return path_of(tcx, did).ends_with("io::copy::copy")
                    && matches!(trees.get(1), Some(TyTree::Adt { krate, .. }) if self.cx.kb_ref(krate));
            };
            let name = tcx.get_diagnostic_name(tr).map(|s| s.to_string());
            let constructed = match name.as_deref() {
                Some("Default" | "From" | "TryFrom" | "FromStr" | "IoWrite") => trees.first(),
                // `Into<T>`: `Self` is the source, `T` the crypto type
                Some("Into" | "TryInto") => trees.get(1),
                _ => None,
            };
            return matches!(
                constructed,
                Some(TyTree::Adt { krate, .. }) if self.cx.kb_ref(krate)
            );
        }
        // another crate's generic function with a crypto type as argument: a crypto fact only
        // if that parameter is bounded by a trait of a KB crate (`fn seal<A: Aead>`), not a
        // container (`Mutex::new(cipher)`)
        kb_bounded(tcx, did, iargs, &|c| self.cx.kb_crate(c))
    }

    #[allow(clippy::too_many_arguments)]
    fn record_call(
        &mut self,
        def: &rustc_public::ty::FnDef,
        args: &GenericArgs,
        span: Span,
        call: Option<(&[Operand], &Terminator)>,
    ) {
        let internal = rustc_internal::internal(self.cx.tcx, span);
        self.record_call_at(def, args, internal, call, None);
    }

    /// `record_call` at a compiler span; `through`: where the function a pointer call calls was
    /// named.
    fn record_call_at(
        &mut self,
        def: &rustc_public::ty::FnDef,
        args: &GenericArgs,
        span: rustc_span::Span,
        call: Option<(&[Operand], &Terminator)>,
        through: Option<Loc>,
    ) {
        let tcx = self.cx.tcx;
        let did = rustc_internal::internal(tcx, def.def_id());
        let callee = def_ref_internal(tcx, did);
        let method = strip_generics(&callee.path)
            .rsplit("::")
            .next()
            .unwrap_or_default()
            .to_string();
        let (mut self_ty, mut own) = split_self(tcx, def.def_id(), args);
        // `bytes.into()` constructs its target: the crypto type is the one the call is about
        if let Some(tr) = tcx.trait_of_assoc(did)
            && matches!(
                tcx.get_diagnostic_name(tr)
                    .map(|s| s.to_string())
                    .as_deref(),
                Some("Into" | "TryInto")
            )
            && !own.is_empty()
        {
            self_ty = Some(own.remove(0));
        }
        // `io::copy(&mut reader, &mut h)` writes into its writer: the crypto type it is about
        if self_ty.is_none() && own.len() == 2 && path_of(tcx, did).ends_with("io::copy::copy") {
            self_ty = Some(own.remove(1));
        }
        let (const_args, arg_origins, arg_lens) = match call {
            Some((call_args, term)) => self.call_values(call_args, term),
            None => (Vec::new(), Vec::new(), Vec::new()),
        };
        self.push_internal(
            span,
            Target::Call {
                callee,
                method,
                self_ty,
                args: own,
                const_args,
                arg_origins,
                arg_lens,
                through,
                value: call.is_none(),
            },
        );
    }

    /// The value arguments of a call: integer constants, origins, array lengths.
    #[allow(clippy::type_complexity)]
    fn call_values(
        &self,
        call_args: &[Operand],
        term: &Terminator,
    ) -> (Vec<Option<i128>>, Vec<Origin>, Vec<Option<u64>>) {
        let origins: Vec<Origin> = call_args
            .iter()
            .map(|a| self.origins.of_arg(a, term))
            .collect();
        let consts = call_args
            .iter()
            .zip(&origins)
            .map(|(a, o)| {
                const_int(a).or(match o {
                    Origin::Const { value, .. }
                    | Origin::Data { value, .. }
                    | Origin::Unit { value, .. } => *value,
                    _ => None,
                })
            })
            .collect();
        let lens = call_args
            .iter()
            .map(|a| self.origins.array_len(a, term))
            .collect();
        (consts, origins, lens)
    }

    /// A call of function `def` held in a pointer or a place, named at `named`: the operation
    /// runs at the call (cited at its callee expression); the function was named where it was
    /// made the value. At the naming when the call has no callee expression in source.
    fn record_through(
        &mut self,
        def: &rustc_public::ty::FnDef,
        args: &GenericArgs,
        named: Span,
        call_args: &[Operand],
        term: &Terminator,
    ) {
        let tcx = self.cx.tcx;
        let named = rustc_internal::internal(tcx, named);
        let call = callee_span(tcx, rustc_internal::internal(tcx, term.source_info.span));
        let through = Some(locate(tcx, named).0).filter(|l| l.line != 0);
        match (call, through) {
            (Some(call), Some(t)) => {
                self.record_call_at(def, args, call, Some((call_args, term)), Some(t))
            }
            _ => self.record_call_at(def, args, named, Some((call_args, term)), None),
        }
    }

    /// A KB function used as a value (`iter.map(Sha256::digest)`, `let h: fn(..) = digest`):
    /// recorded where it is named (`Call::value`).
    fn function_value(&mut self, op: &Operand) {
        if let Operand::Constant(c) = op
            && let Some(RigidTy::FnDef(def, args)) = c.const_.ty().kind().rigid()
            && self.interesting(def, args)
        {
            self.record_call(def, args, c.span, None);
        }
    }
}

/// The callee expression of a call written in source (`h` of `h(x)`, `(h.f)` of `(h.f)(x)`,
/// `get()` of `get()(x)`, `fs[0]` of `fs[0](x)`): what precedes the argument list, the last
/// parenthesised group of the call's text; `None` when the call is not written as one (a
/// macro's, an operator's).
pub(crate) fn callee_span(tcx: TyCtxt<'_>, call: rustc_span::Span) -> Option<rustc_span::Span> {
    if call.from_expansion() {
        return None;
    }
    let text = tcx.sess.source_map().span_to_snippet(call).ok()?;
    let len = args_start(&text)?;
    let callee = text[..len].trim_end();
    if callee.is_empty() {
        return None;
    }
    Some(call.with_hi(call.lo() + rustc_span::BytePos(callee.len() as u32)))
}

/// Where the last top-level parenthesised group of `text` starts, when it ends the text:
/// brackets inside string and character literals do not count.
fn args_start(text: &str) -> Option<usize> {
    let b = text.as_bytes();
    let (mut depth, mut i, mut last, mut closed_at) = (0usize, 0usize, None, None);
    while i < b.len() {
        match b[i] {
            b'"' => {
                i += 1;
                while i < b.len() && b[i] != b'"' {
                    i += if b[i] == b'\\' { 2 } else { 1 };
                }
            }
            // a character literal (`'('`, `'\''`), not a lifetime (`'a`)
            b'\'' if b.get(i + 2) == Some(&b'\'') => i += 2,
            b'\'' if b.get(i + 1) == Some(&b'\\') => {
                // past the backslash and the escaped character
                i += 3;
                while i < b.len() && b[i] != b'\'' {
                    i += 1;
                }
            }
            b'(' | b'[' | b'{' => {
                if depth == 0 && b[i] == b'(' {
                    last = Some(i);
                }
                depth += 1;
            }
            b')' | b']' | b'}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    closed_at = Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    let end = text.trim_end().len().checked_sub(1)?;
    (depth == 0 && closed_at == Some(end) && b[end] == b')').then_some(last?)
}

/// The body without the blocks no execution reaches: those behind a branch on a constant
/// (`if cfg!(debug_assertions)` is `if false` in a release build, which MIR level 0 keeps).
/// Their statements are dropped and their terminators made `unreachable`.
fn live_body(tcx: TyCtxt<'_>, body: &rustc_public::mir::Body) -> rustc_public::mir::Body {
    let n = body.blocks.len();
    let mut live = vec![false; n];
    let mut work = vec![0usize];
    while let Some(b) = work.pop() {
        if b >= n || live[b] {
            continue;
        }
        live[b] = true;
        let block = &body.blocks[b];
        match &block.terminator.kind {
            TerminatorKind::SwitchInt { discr, targets } => match switch_value(tcx, block, discr) {
                Some(v) => work.push(
                    targets
                        .branches()
                        .find(|(x, _)| *x == v)
                        .map(|(_, t)| t)
                        .unwrap_or(targets.otherwise()),
                ),
                None => work.extend(block.terminator.successors()),
            },
            _ => work.extend(block.terminator.successors()),
        }
    }
    let mut out = body.clone();
    for (b, l) in live.iter().enumerate() {
        if !l {
            out.blocks[b].statements.clear();
            out.blocks[b].terminator.kind = TerminatorKind::Unreachable;
        }
    }
    out
}

/// The value a block switches on, when it is a constant: given directly, or assigned to the
/// switched local earlier in the block (`_3 = const false; switchInt(move _3)`).
fn switch_value(
    tcx: TyCtxt<'_>,
    block: &rustc_public::mir::BasicBlock,
    discr: &Operand,
) -> Option<u128> {
    let c = match discr {
        Operand::Constant(c) => c.clone(),
        Operand::Copy(p) | Operand::Move(p) if p.projection.is_empty() => {
            let rv = block.statements.iter().rev().find_map(|s| match &s.kind {
                rustc_public::mir::StatementKind::Assign(q, rv)
                    if q.local == p.local && q.projection.is_empty() =>
                {
                    Some(rv)
                }
                _ => None,
            })?;
            match rv {
                Rvalue::Use(Operand::Constant(c), _) => c.clone(),
                // `match MODE` with `const MODE: Mode = Mode::Fast`: the discriminant of the
                // variant the constant the block gave the matched local holds
                Rvalue::Discriminant(q) if q.projection.is_empty() => {
                    let c = block.statements.iter().rev().find_map(|s| match &s.kind {
                        rustc_public::mir::StatementKind::Assign(r, rv)
                            if r.local == q.local && r.projection.is_empty() =>
                        {
                            Some(rv)
                        }
                        _ => None,
                    })?;
                    let Rvalue::Use(Operand::Constant(c), _) = c else {
                        return None;
                    };
                    let k = rustc_internal::internal(tcx, &c.const_);
                    return statics::enum_discriminant(tcx, &k).map(|v| v.to_bits_unchecked());
                }
                _ => return None,
            }
        }
        _ => return None,
    };
    match c.const_.kind() {
        ConstantKind::Allocated(a) => a.read_uint().ok(),
        // a named constant (`if FLAG`), evaluated when it does not depend on generics
        ConstantKind::Unevaluated(_) => {
            use rustc_middle::ty::TypeVisitableExt;
            let k = rustc_internal::internal(tcx, &c.const_);
            if k.ty().has_non_region_param() || !statics::evaluable_const(tcx, &k, None) {
                return None;
            }
            k.try_eval_bits(tcx, rustc_middle::ty::TypingEnv::fully_monomorphized())
        }
        _ => None,
    }
}

fn strip_generics(path: &str) -> String {
    let mut out = String::new();
    let mut depth = 0usize;
    for ch in path.chars() {
        match ch {
            '<' => depth += 1,
            '>' => depth = depth.saturating_sub(1),
            _ if depth == 0 => out.push(ch),
            _ => {}
        }
    }
    out.replace("::::", "::")
}

/// Does a generic argument that names a KB type stand for a parameter bounded by a trait of
/// a KB crate?
fn kb_bounded<'tcx>(
    tcx: TyCtxt<'tcx>,
    did: rustc_span::def_id::DefId,
    args: rustc_middle::ty::GenericArgsRef<'tcx>,
    kb: &dyn Fn(rustc_span::def_id::CrateNum) -> bool,
) -> bool {
    let clauses = tcx.clauses_of(did).instantiate_identity(tcx);
    clauses.clauses.into_iter().any(|c| {
        let Some(tc) = c.skip_norm_wip().as_trait_clause() else {
            return false;
        };
        let tc = tc.skip_binder();
        if !kb(tc.def_id().krate) {
            return false;
        }
        let rustc_middle::ty::Param(p) = tc.self_ty().kind() else {
            return false;
        };
        args.get(p.index as usize)
            .and_then(|a| a.as_type())
            .is_some_and(|t| {
                t.walk().any(|g| {
                    g.as_type().is_some_and(|t| match t.kind() {
                        rustc_middle::ty::Adt(adt, _) => kb(adt.did().krate),
                        _ => false,
                    })
                })
            })
    })
}

impl MirVisitor for Scanner<'_, '_> {
    // a panic loses the call, rvalue or constant it was raised in, not the function: an
    // `async` closure's type is lost this way (`has_unconvertible`); any other panic is a bug,
    // counted as one
    fn visit_terminator(&mut self, term: &Terminator, loc: Location) {
        let r = catch_unwind(AssertUnwindSafe(|| self.scan_terminator(term, loc)));
        self.caught(r.err(), "a call");
    }

    fn visit_rvalue(&mut self, rv: &Rvalue, loc: Location) {
        let r = catch_unwind(AssertUnwindSafe(|| self.scan_rvalue(rv, loc)));
        self.caught(r.err(), "a value");
    }

    fn visit_const_operand(&mut self, c: &ConstOperand, loc: Location) {
        let r = catch_unwind(AssertUnwindSafe(|| self.scan_const(c, loc)));
        self.caught(r.err(), "a constant");
    }
}

impl Scanner<'_, '_> {
    fn caught(&mut self, panic: Option<Box<dyn std::any::Any + Send>>, what: &str) {
        let Some(e) = panic else {
            return;
        };
        let unconvertible = self.unconvertible || async_closure(&e);
        if !unconvertible {
            self.cx.errors += 1;
        }
        if std::env::var_os("RCBOM_DEBUG").is_some() {
            eprintln!(
                "rcbom-driver: {what} in {} could not be read{}",
                self.owner.name,
                if unconvertible {
                    " (an async closure's type, which rustc_public cannot convert)"
                } else {
                    ""
                }
            );
        }
    }
}

/// A call of `Fn::call`, `FnMut::call_mut` or `FnOnce::call_once` on a trait object (`dyn
/// Fn(..)`, behind a reference or a `Box`).
fn dyn_fn_call(
    tcx: TyCtxt<'_>,
    def: &rustc_public::ty::FnDef,
    args: &rustc_public::ty::GenericArgs,
) -> bool {
    fn dynamic(t: &Ty, depth: usize) -> bool {
        match t.kind().rigid() {
            Some(RigidTy::Dynamic(..)) => true,
            Some(RigidTy::Ref(_, t, _)) if depth < 4 => dynamic(t, depth + 1),
            Some(RigidTy::Adt(adt, a)) if depth < 4 && adt.is_box() => match a.0.first() {
                Some(GenericArgKind::Type(t)) => dynamic(t, depth + 1),
                _ => false,
            },
            _ => false,
        }
    }
    let did = rustc_internal::internal(tcx, def.def_id());
    let path = path_of(tcx, did);
    matches!(
        path.as_str(),
        "core::ops::function::Fn::call"
            | "core::ops::function::FnMut::call_mut"
            | "core::ops::function::FnOnce::call_once"
    ) && matches!(args.0.first(), Some(GenericArgKind::Type(t)) if dynamic(t, 0))
}

/// The operands a tuple argument was built from (`(a, b)` passed to `Fn::call`), when the body
/// builds it in one statement.
fn untuple(body: &Body, tuple: &Operand) -> Option<Vec<Operand>> {
    let (Operand::Copy(p) | Operand::Move(p)) = tuple else {
        return None;
    };
    if !p.projection.is_empty() {
        return None;
    }
    body.blocks
        .iter()
        .flat_map(|b| &b.statements)
        .find_map(|st| match &st.kind {
            StatementKind::Assign(lhs, Rvalue::Aggregate(AggregateKind::Tuple, ops))
                if lhs.local == p.local && lhs.projection.is_empty() =>
            {
                Some(ops.clone())
            }
            _ => None,
        })
}

impl Scanner<'_, '_> {
    fn scan_terminator(&mut self, term: &Terminator, loc: Location) {
        if let TerminatorKind::Call {
            func,
            args: call_args,
            ..
        } = &term.kind
        {
            if let Ok(ty) = func.ty(self.body.locals())
                && let Some(RigidTy::FnDef(def, args)) = ty.kind().rigid()
                && self.interesting(def, args)
            {
                match func {
                    // the callee path's own span (`UnboundKey::new`, `.encrypt`), not the whole
                    // call expression
                    Operand::Constant(c) => {
                        self.record_call(def, args, c.span, Some((call_args, term)))
                    }
                    // a function item held in a place (`let f = Sha256::digest; f(d)`): the call
                    // runs at its callee expression; the function was named where the place got
                    // it
                    _ => match self.origins.callee_name_span(func, term) {
                        Some(named) => self.record_through(def, args, named, call_args, term),
                        None => {
                            if std::env::var_os("RCBOM_DEBUG").is_some() {
                                eprintln!(
                                    "rcbom-driver: call of {} without a position for its callee \
                                     dropped in {}",
                                    def.name(),
                                    self.owner.name
                                );
                            }
                        }
                    },
                }
            } else if let Some((def, args, named)) = self.origins.callee_through_pointer(func)
                && self.interesting(&def, &args)
            {
                // a call through a pointer to a KB function reified here (`h(&SHA256, d)`)
                self.record_through(&def, &args, named, call_args, term);
            } else if let Ok(ty) = func.ty(self.body.locals())
                && matches!(ty.kind().rigid(), Some(RigidTy::FnPtr(..)))
            {
                // a pointer whose function is named elsewhere (`(h.f)(..)`, a parameter, a
                // returned pointer): where it comes from, for the analysis to follow to the
                // functions named as values
                // (one whose pointer is not known, or without a callee to place it at, too: a
                // call that may run any function made a pointer)
                let origin = self.origins.of_arg(func, term);
                let (const_args, arg_origins, arg_lens) = self.call_values(call_args, term);
                let tcx = self.cx.tcx;
                let sig = links::pointer_sig(tcx, rustc_internal::internal(tcx, ty)).map(|s| s.1);
                self.push_pointer(origin, const_args, arg_origins, arg_lens, sig, term);
            } else if let Ok(ty) = func.ty(self.body.locals())
                && let Some(RigidTy::FnDef(def, args)) = ty.kind().rigid()
                && dyn_fn_call(self.cx.tcx, def, args)
                && let [recv, tuple] = call_args.as_slice()
            {
                // a call through a closure or function boxed as a trait object (`b(&SHA1, d)`
                // with `b: Box<dyn Fn(..)>`): as through a pointer, the object's origin and the
                // call's own arguments (not known when the tuple is not built here)
                let origin = self.origins.of_arg(recv, term);
                let (const_args, arg_origins, arg_lens) = match untuple(self.body, tuple) {
                    Some(untupled) => self.call_values(&untupled, term),
                    None => {
                        let n = match tuple
                            .ty(self.body.locals())
                            .ok()
                            .and_then(|t| t.kind().rigid().cloned())
                        {
                            Some(RigidTy::Tuple(ts)) => ts.len(),
                            _ => 0,
                        };
                        (vec![None; n], vec![Origin::Unknown; n], vec![None; n])
                    }
                };
                let tcx = self.cx.tcx;
                let sig = match args.0.first() {
                    Some(GenericArgKind::Type(t)) => {
                        let mut t = rustc_internal::internal(tcx, *t);
                        while let rustc_middle::ty::Ref(_, i, _) = *t.kind() {
                            t = i;
                        }
                        if t.is_box() {
                            t = t.boxed_ty().unwrap_or(t);
                        }
                        links::pointer_sig(tcx, t).map(|s| s.1)
                    }
                    _ => None,
                };
                self.push_pointer(origin, const_args, arg_origins, arg_lens, sig, term);
            }
            for a in call_args {
                self.function_value(a);
            }
        }
        self.super_terminator(term, loc);
    }

    /// Functions named as values inside the item's promoted constants (`run(&Holder { f:
    /// digest::digest })`): where they are named, as `scan_rvalue` records it in a body (the
    /// body itself only holds the promoted constant).
    fn promoted_values(&mut self, did: rustc_span::def_id::DefId) {
        let tcx = self.cx.tcx;
        if !tcx.is_mir_available(did) || tcx.is_closure_like(did) && !did.is_local() {
            return;
        }
        for p in tcx.promoted_mir(did).iter() {
            let pb: Body = rustc_internal::stable(p);
            for block in &pb.blocks {
                for st in &block.statements {
                    match &st.kind {
                        StatementKind::Assign(
                            _,
                            Rvalue::Cast(
                                CastKind::PointerCoercion(PointerCoercion::ReifyFnPointer(_)),
                                op,
                                _,
                            )
                            | Rvalue::Use(op, _),
                        ) => self.function_value(op),
                        StatementKind::Assign(_, Rvalue::Aggregate(_, ops)) => {
                            for op in ops {
                                self.function_value(op);
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    fn scan_rvalue(&mut self, rv: &Rvalue, loc: Location) {
        match rv {
            // a function made a pointer, or kept as a value in a struct, a tuple, an array or a
            // local (`Some(blake3::hash)`, `Holder { f: Aes256Gcm::new_from_slice }`): it is
            // named here, whatever calls it later
            Rvalue::Cast(CastKind::PointerCoercion(PointerCoercion::ReifyFnPointer(_)), op, _)
            | Rvalue::Use(op, _) => self.function_value(op),
            Rvalue::Aggregate(_, ops) => {
                for op in ops {
                    self.function_value(op);
                }
            }
            _ => {}
        }
        self.super_rvalue(rv, loc);
    }

    fn scan_const(&mut self, c: &ConstOperand, loc: Location) {
        if let ConstantKind::Allocated(a) = c.const_.kind() {
            alloc_statics(a, &mut self.statics, &mut HashSet::new(), 0);
        }
        self.super_const_operand(c, loc);
    }
}

/// Roots of the walk in a workspace member: `main`; for a library, its exported monomorphic
/// functions and exported statics; in any crate, what the linker keeps whatever calls it
/// (`#[no_mangle]`, `#[export_name]` functions, `#[used]` statics). Last, a library's generic
/// functions its users can call (not walked: only a caller has their type arguments).
#[allow(clippy::type_complexity)]
fn roots(
    cx: &Cx<'_>,
) -> (
    Vec<Instance>,
    Vec<rustc_span::def_id::DefId>,
    Vec<rustc_span::def_id::DefId>,
) {
    use rustc_middle::middle::codegen_fn_attrs::CodegenFnAttrFlags as F;
    let tcx = cx.tcx;
    let vis = tcx.effective_visibilities(());
    let is_bin = rustc_public::entry_fn().is_some();
    let mut fns = Vec::new();
    if let Some(entry) = rustc_public::entry_fn()
        && let Ok(i) = Instance::try_from(entry)
    {
        fns.push(i);
    }
    for item in rustc_public::all_local_items() {
        if !matches!(item.kind(), ItemKind::Fn)
            || !item.has_body()
            || item.requires_monomorphization()
        {
            continue;
        }
        let did = rustc_internal::internal(tcx, item.def_id());
        let exported = !is_bin && did.as_local().is_some_and(|l| vis.is_exported(l));
        if (exported || tcx.codegen_fn_attrs(did).contains_extern_indicator())
            && let Ok(i) = Instance::try_from(item)
            && !fns.contains(&i)
        {
            fns.push(i);
        }
    }
    // a library: the non-generic functions its exported generic or inline functions call
    // (`pub fn hash(d: impl AsRef<[u8]>)` calling a private `fn inner(d: &[u8])`), which
    // every user of the library runs and rustc exports for them (`reachable_set`), and those
    // generic functions themselves
    let mut generic = Vec::new();
    if !is_bin {
        let reachable = tcx.reachable_set(());
        let mut extra: Vec<rustc_span::def_id::DefId> = tcx
            .hir_body_owners()
            .filter(|l| reachable.contains(l))
            .map(|l| l.to_def_id())
            .filter(|d| {
                matches!(
                    tcx.def_kind(*d),
                    rustc_hir::def::DefKind::Fn | rustc_hir::def::DefKind::AssocFn
                )
            })
            .collect();
        extra.sort_by_key(|d| def_hash(tcx, *d));
        for did in extra {
            let item = rustc_public::CrateItem(rustc_internal::stable(did));
            if !item.has_body() {
                continue;
            }
            if item.requires_monomorphization() {
                generic.push(did);
            } else if let Ok(i) = Instance::try_from(item)
                && !fns.contains(&i)
            {
                fns.push(i);
            }
        }
    }
    let mut statics = Vec::new();
    for did in tcx.hir_body_owners().map(|d| d.to_def_id()) {
        if !matches!(tcx.def_kind(did), rustc_hir::def::DefKind::Static { .. })
            || tcx.is_foreign_item(did)
        {
            continue;
        }
        let attrs = tcx.codegen_fn_attrs(did);
        let exported = !is_bin && did.as_local().is_some_and(|l| vis.is_exported(l));
        if exported
            || attrs.contains_extern_indicator()
            || attrs.flags.intersects(F::USED_COMPILER | F::USED_LINKER)
        {
            statics.push(did);
        }
    }
    (fns, statics, generic)
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
            usage_seen: HashSet::new(),
            usage_statics: HashSet::new(),
            crates: BTreeSet::new(),
            parent: HashMap::new(),
            statics: BTreeSet::new(),
            static_refs: Vec::new(),
            static_seen: HashSet::new(),
            sites: Vec::new(),
            fns: Vec::new(),
            paths: Vec::new(),
            coercions: BTreeMap::new(),
            limit,
        }
    }

    fn run(&mut self, roots: Vec<Instance>, static_roots: Vec<rustc_span::def_id::DefId>) -> Reach {
        for root in roots {
            self.enqueue(root, None);
        }
        for s in static_roots {
            self.reach_static(s);
        }
        let mut truncated = false;
        let mut usage_complete = true;
        while let Some((inst, usage)) = self.queue.pop_front() {
            if self.seen.len() > self.limit {
                truncated = true;
                break;
            }
            if usage && self.usage_seen.len() > self.limit {
                usage_complete = false;
                continue;
            }
            if catch_unwind(AssertUnwindSafe(|| self.visit(inst, usage))).is_err() {
                self.cx.errors += 1;
            }
        }
        let mut statics: Vec<DefRef> = std::mem::take(&mut self.static_refs);
        statics.sort_by(|a, b| a.id.cmp(&b.id));
        statics.dedup_by(|a, b| a.id == b.id);
        let mut fns = std::mem::take(&mut self.fns);
        fns.sort();
        fns.dedup();
        let mut paths = std::mem::take(&mut self.paths);
        paths.sort();
        paths.dedup();
        let tcx = self.cx.tcx;
        let crates = self
            .crates
            .iter()
            .filter(|c| !self.cx.local.contains(c))
            .map(|c| crate_ref(tcx, c.as_def_id()))
            .collect();
        Reach {
            instances: self.seen.len(),
            truncated,
            statics,
            fns,
            paths,
            crates,
            crates_complete: !truncated && usage_complete,
            points_to: None,
        }
    }

    fn enqueue(&mut self, inst: Instance, from: Option<(Instance, Loc, Option<String>)>) {
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
            self.queue.push_back((inst, false));
        }
    }

    /// Enqueues an instance a stop crate's code calls, walked for usage only: standard-library
    /// code only when instantiated with other crates' types (`Iterator::map` over its closure).
    fn enqueue_usage(&mut self, inst: Instance) {
        if matches!(
            inst.kind,
            InstanceKind::Virtual { .. } | InstanceKind::Intrinsic | InstanceKind::LlvmIntrinsic
        ) || self.seen.contains(&inst)
        {
            return;
        }
        let tcx = self.cx.tcx;
        let i = rustc_internal::internal(tcx, inst);
        let std_crate =
            |did: rustc_span::def_id::DefId| self.cx.is_std(tcx.crate_name(did.krate).as_str());
        if std_crate(i.def_id())
            && !i.args.iter().any(|a| {
                a.walk().any(|g| {
                    g.as_type().is_some_and(|t| match t.kind() {
                        rustc_middle::ty::Adt(adt, _) => !std_crate(adt.did()),
                        rustc_middle::ty::Closure(d, _)
                        | rustc_middle::ty::Coroutine(d, _)
                        | rustc_middle::ty::FnDef(d, _) => !std_crate(*d),
                        _ => false,
                    })
                })
            })
        {
            return;
        }
        if self.usage_seen.insert(inst) {
            self.queue.push_back((inst, true));
        }
    }

    /// A static a stop crate's code refers to: the functions its value points at run too.
    fn usage_static(&mut self, did: rustc_span::def_id::DefId) {
        let tcx = self.cx.tcx;
        if !self.usage_statics.insert(did) || tcx.is_foreign_item(did) {
            return;
        }
        self.crates.insert(did.krate);
        let Ok(s) = rustc_public::mir::mono::StaticDef::try_from(rustc_public::CrateItem(
            rustc_internal::stable(did),
        )) else {
            return;
        };
        let Some(a) = catch_unwind(AssertUnwindSafe(|| s.eval_initializer().ok()))
            .ok()
            .flatten()
        else {
            return;
        };
        let mut found = Vec::new();
        let mut nested = Vec::new();
        alloc_callees(tcx, &a, &mut found, &mut nested, &mut Vec::new(), 0);
        for i in found {
            self.enqueue_usage(i);
        }
        for n in nested {
            self.usage_static(rustc_internal::internal(tcx, n.def_id()));
        }
    }

    fn via(&self, inst: Instance) -> Vec<ViaStep> {
        let mut out = Vec::new();
        let mut cur = inst;
        while let Some((p, loc, text)) = self.parent.get(&cur) {
            // only generic instantiations need the chain to explain their arguments
            if cur.args().0.is_empty() || out.len() >= 4 {
                break;
            }
            out.push(ViaStep {
                caller: instance_name(self.cx.tcx, p),
                span: loc.clone(),
                text: text.clone(),
            });
            cur = *p;
        }
        out
    }

    /// Code outside the stop crates and the standard library, or standard-library code
    /// instantiated with such code (`Iterator::map` over the user's closure): what a stop crate
    /// calls back.
    fn calls_back(&self, callee: &Instance) -> bool {
        let tcx = self.cx.tcx;
        // a stop crate's own dependencies are its implementation (curve25519-dalek under
        // ed25519-dalek), not code it calls back
        let foreign = |did: rustc_span::def_id::DefId| {
            let k = tcx.crate_name(did.krate).to_string();
            !self.cx.stop_crate(did.krate) && !self.cx.is_std(&k) && !self.cx.impl_crate(did.krate)
        };
        let i = rustc_internal::internal(tcx, callee);
        if foreign(i.def_id()) {
            return true;
        }
        // a stop-crate or std function instantiated with user code (ring's `agree_ephemeral`
        // hands the user's closure to its internal `agree_ephemeral_`)
        i.args.iter().any(|a| {
            a.walk().any(|g| {
                g.as_type().is_some_and(|t| match t.kind() {
                    rustc_middle::ty::Adt(adt, _) => foreign(adt.did()),
                    rustc_middle::ty::Closure(d, _)
                    | rustc_middle::ty::Coroutine(d, _)
                    | rustc_middle::ty::FnDef(d, _) => foreign(*d),
                    _ => false,
                })
            })
        })
    }

    /// `usage`: walked only to learn which crates run (code a stop crate calls).
    fn visit(&mut self, inst: Instance, usage: bool) {
        let did = rustc_internal::internal(self.cx.tcx, inst.def.def_id());
        self.crates.insert(did.krate);
        // Not `inst.has_body()`: in this rustc_public it asks about the instance's *def*, which
        // for a shim (`<closure as FnOnce>::call_once` behind a `dyn FnOnce`, as in every
        // `thread::spawn`) is a trait method without a body. `body()` checks the instance.
        let Some(body) = inst.body().map(|b| live_body(self.cx.tcx, &b)) else {
            return;
        };
        let mut edges = Edges {
            tcx: self.cx.tcx,
            body: &body,
            found: Vec::new(),
            coerced: Vec::new(),
            cur: None,
            unconvertible: has_unconvertible(self.cx.tcx, &body),
            errors: 0,
            dest: None,
        };
        edges.visit_body(&body);
        self.cx.errors += edges.errors;
        for (c, span, in_const) in std::mem::take(&mut edges.coerced) {
            // a vtable in a named constant's value (`KP.alg()` with `const KP: &dyn Konst =
            // &K1`): the coercion is written at the constant's item
            let tcx = self.cx.tcx;
            let item = in_const
                .then(|| const_item_at(tcx, did, rustc_internal::internal(tcx, span)))
                .flatten();
            let at = match item {
                Some(k) => locate(tcx, tcx.def_span(k)).0,
                None => locate_stable(tcx, span).0,
            };
            self.coerced(c, (at.line > 0).then_some(at), false);
        }
        // RCBOM_DEBUG_WALK=<substring>: print the edges out of matching instances
        let debug = std::env::var("RCBOM_DEBUG_WALK")
            .ok()
            .filter(|d| inst.name().contains(d.as_str()));
        if debug.is_some() {
            eprintln!("rcbom-walk: {} ({:?})", inst.name(), inst.kind);
        }
        let stop = self.cx.stop_crate(did.krate);
        if !usage
            && !stop
            && let Some(p) = self.cx.pta.as_mut()
        {
            p.add_body(self.cx.tcx, inst, &body);
        }
        // a shim's body is the compiler's (a `dyn` method behind a function pointer, drop glue,
        // `<closure as FnOnce>::call_once`): what it calls is walked, but none of it is code
        // written at the span it carries (the trait method's declaration)
        let shim = matches!(inst.kind, InstanceKind::Shim);
        if usage {
            let mut v = AllocStatics(Vec::new());
            v.visit_body(&body);
            for s in v.0 {
                self.usage_static(rustc_internal::internal(self.cx.tcx, s.def_id()));
            }
        } else if !stop && !shim {
            let owner = fn_owner(self.cx, &inst);
            self.fns.push(owner.id.clone());
            self.paths.push(path_of(self.cx.tcx, did));
            // an instance whose summaries the links record under its own name (a trait's
            // default body for a type, `<app::Legacy as app::Pick>::alg`)
            if let Some(n) =
                origins::body_name(self.cx.tcx, rustc_internal::internal(self.cx.tcx, inst))
                && n != path_of(self.cx.tcx, did)
            {
                self.paths.push(n);
            }
            let item = matches!(inst.kind, InstanceKind::Item);
            if item {
                // a generic fn's per-item sites are owned by its def-path hash
                self.fns.push(def_hash(self.cx.tcx, did));
            }
            let via = self.via(inst);
            // A monomorphic function is scanned in its item body, as the per-item scan does:
            // the types are the same, and the instance body has its named consts evaluated away
            // (`SSH_ED25519_RECIPIENT_KEY_LABEL` would read as a literal). The statics it
            // reaches are still taken from the instance body, where a const pointing at a static
            // has become that pointer.
            let generic =
                item && rustc_public::CrateItem(inst.def.def_id()).requires_monomorphization();
            let item_body = (item && !generic)
                .then(|| rustc_public::CrateItem(inst.def.def_id()).body())
                .flatten()
                .map(|b| live_body(self.cx.tcx, &b));
            let mut sites = Vec::new();
            let scanned = item_body.as_ref().unwrap_or(&body);
            // A generic instance (or a closure) must be scanned in its instance body, where the
            // types are concrete; its constants are named in the item's MIR at the same span.
            let inst_args = rustc_internal::internal(self.cx.tcx, inst).args;
            let lookup = (item && generic).then_some((did, inst_args));
            let mut sc = Scanner::new(
                self.cx,
                scanned,
                Some(did),
                owner.clone(),
                Tier::Reachable,
                via.clone(),
                &mut sites,
                lookup,
            );
            sc.visit_body(scanned);
            let mut statics = std::mem::take(&mut sc.statics);
            if item_body.is_some() {
                let mut v = AllocStatics(Vec::new());
                v.visit_body(&body);
                statics = v.0;
            }
            if item {
                let args = rustc_internal::internal(self.cx.tcx, inst).args;
                sites.extend(statics::fn_data_sites(
                    self.cx,
                    did,
                    Some(args),
                    &owner,
                    Tier::Reachable,
                    &via,
                ));
            }
            self.sites.extend(sites);
            for s in statics {
                self.reach_static(rustc_internal::internal(self.cx.tcx, s.def_id()));
            }
        }
        for (callee, span) in edges.found {
            if debug.is_some() {
                eprintln!("rcbom-walk:   -> {} ({:?})", callee.name(), callee.kind);
            }
            // inside an algorithm implementation, only what it calls back into is walked; the
            // rest for usage only
            if (usage || stop) && !(stop && self.calls_back(&callee)) {
                self.enqueue_usage(callee);
                continue;
            }
            let loc = locate_stable(self.cx.tcx, span).0;
            // the text of the function named at the call (`decrypt::aes_ctr::<Aes128Ctr>`: the
            // span is the callee's); none for a call through a value (the span is the call's)
            let internal = rustc_internal::internal(self.cx.tcx, span);
            let text = callee_span(self.cx.tcx, internal)
                .is_none()
                .then(|| span_text(self.cx.tcx, internal))
                .flatten();
            self.enqueue(callee, Some((inst, loc, text)));
        }
    }

    /// A type is coerced to a trait object at `at` (in a function's body, a constant's or a
    /// static's item; `in_static`: the static's value).
    fn coerced(&mut self, (trait_path, ty, methods): Coerced, at: Option<Loc>, in_static: bool) {
        self.coercions
            .entry((trait_path, ty))
            .or_insert((at, in_static, methods));
    }

    /// A static is reached: remember it, and walk the function pointers and vtables in its
    /// value (rustls keeps its providers as `&dyn` objects inside statics).
    fn reach_static(&mut self, did: rustc_span::def_id::DefId) {
        let tcx = self.cx.tcx;
        let r = def_ref_internal(tcx, did);
        if !self.static_seen.insert(r.id.clone()) {
            return;
        }
        self.statics.insert(r.id.clone());
        if self.cx.static_interesting(did) {
            self.static_refs.push(r);
        }
        if tcx.is_foreign_item(did) {
            return;
        }
        let s = match rustc_public::mir::mono::StaticDef::try_from(rustc_public::CrateItem(
            rustc_internal::stable(did),
        )) {
            Ok(s) => s,
            Err(_) => return,
        };
        let Some(a) = catch_unwind(AssertUnwindSafe(|| s.eval_initializer().ok()))
            .ok()
            .flatten()
        else {
            return;
        };
        let mut found = Vec::new();
        let mut nested = Vec::new();
        let mut coerced = Vec::new();
        alloc_callees(tcx, &a, &mut found, &mut nested, &mut coerced, 0);
        let at = locate(tcx, tcx.def_span(did)).0;
        for c in coerced {
            self.coerced(c, (at.line > 0).then(|| at.clone()), true);
        }
        for i in found {
            self.enqueue(i, None);
        }
        for n in nested {
            self.reach_static(rustc_internal::internal(tcx, n.def_id()));
        }
    }
}

/// The statics the constants of a body point at.
struct AllocStatics(Vec<rustc_public::mir::mono::StaticDef>);

impl MirVisitor for AllocStatics {
    fn visit_const_operand(&mut self, c: &ConstOperand, loc: Location) {
        if let ConstantKind::Allocated(a) = c.const_.kind() {
            alloc_statics(a, &mut self.0, &mut HashSet::new(), 0);
        }
        self.super_const_operand(c, loc);
    }
}

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
}

/// Is `local` used anywhere in `body` but where it is assigned whole, its storage marked or it
/// is dropped (a closure built and never called, passed on, stored or returned is not)?
fn local_used(body: &Body, local: rustc_public::mir::Local) -> bool {
    struct Uses {
        local: rustc_public::mir::Local,
        used: bool,
    }
    impl MirVisitor for Uses {
        fn visit_statement(&mut self, stmt: &rustc_public::mir::Statement, loc: Location) {
            match &stmt.kind {
                StatementKind::StorageLive(_)
                | StatementKind::StorageDead(_)
                | StatementKind::FakeRead(..)
                | StatementKind::PlaceMention(_)
                | StatementKind::AscribeUserType { .. } => {}
                StatementKind::Assign(p, rv)
                    if p.local == self.local && p.projection.is_empty() =>
                {
                    self.visit_rvalue(rv, loc)
                }
                _ => self.super_statement(stmt, loc),
            }
        }
        fn visit_terminator(&mut self, term: &Terminator, loc: Location) {
            match &term.kind {
                TerminatorKind::Drop { place, .. } if place.local == self.local => {}
                _ => self.super_terminator(term, loc),
            }
        }
        fn visit_local(
            &mut self,
            local: &rustc_public::mir::Local,
            _: rustc_public::mir::visit::PlaceContext,
            _: Location,
        ) {
            self.used |= *local == self.local;
        }
        // (a debugger's name for it, `_never`, is no use)
        fn visit_var_debug_info(&mut self, _: &rustc_public::mir::VarDebugInfo) {}
    }
    if local == rustc_public::mir::RETURN_LOCAL {
        return true;
    }
    let mut u = Uses { local, used: false };
    u.visit_body(body);
    u.used
}

impl MirVisitor for Edges<'_, '_> {
    fn visit_statement(&mut self, stmt: &rustc_public::mir::Statement, loc: Location) {
        self.cur = Some(stmt.source_info.span);
        self.dest = match &stmt.kind {
            StatementKind::Assign(p, _) if p.projection.is_empty() => Some(p.local),
            _ => None,
        };
        self.super_statement(stmt, loc);
    }

    // a type `rustc_public` cannot convert (an `async` closure's) loses one edge, not the
    // instance's others; any other panic is a bug, counted
    fn visit_terminator(&mut self, term: &Terminator, loc: Location) {
        let r = catch_unwind(AssertUnwindSafe(|| self.edges_of_terminator(term, loc)));
        self.errors += usize::from(r.is_err_and(|e| !self.unconvertible && !async_closure(&e)));
    }

    fn visit_rvalue(&mut self, rv: &Rvalue, loc: Location) {
        let r = catch_unwind(AssertUnwindSafe(|| self.edges_of_rvalue(rv, loc)));
        self.errors += usize::from(r.is_err_and(|e| !self.unconvertible && !async_closure(&e)));
    }

    fn visit_const_operand(&mut self, c: &ConstOperand, loc: Location) {
        let r = catch_unwind(AssertUnwindSafe(|| self.edges_of_const(c, loc)));
        self.errors += usize::from(r.is_err_and(|e| !self.unconvertible && !async_closure(&e)));
    }
}

impl Edges<'_, '_> {
    fn edges_of_terminator(&mut self, term: &Terminator, loc: Location) {
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

    fn edges_of_rvalue(&mut self, rv: &Rvalue, loc: Location) {
        // a closure or coroutine built here: its body runs when it is called or polled, by
        // the code it is handed to or returned to (a library's `pub async fn`, a returned
        // `impl Fn`); built here, it is reachable from here
        if let Rvalue::Aggregate(kind, _) = rv {
            let built = match kind {
                rustc_public::mir::AggregateKind::Closure(def, args) => Some((def.def_id(), args)),
                rustc_public::mir::AggregateKind::Coroutine(def, args) => {
                    Some((def.def_id(), args))
                }
                rustc_public::mir::AggregateKind::CoroutineClosure(def, args) => {
                    Some((def.def_id(), args))
                }
                _ => None,
            };
            // (a closure built and never used, `let _never = || ..;`: not run from here)
            let unused = matches!(kind, rustc_public::mir::AggregateKind::Closure(..))
                && self.dest.is_some_and(|d| !local_used(self.body, d));
            if let Some((def, args)) = built
                && !unused
            {
                let did = rustc_internal::internal(self.tcx, def);
                let iargs = rustc_internal::internal(self.tcx, args);
                if !iargs.has_non_region_param() {
                    let i = rustc_middle::ty::Instance::new_raw(did, iargs);
                    let span = self.cur.unwrap_or(self.body.span);
                    self.found.push((rustc_internal::stable(i), span));
                }
            }
        }
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
                            let c = rustc_internal::internal(self.tcx, concrete);
                            if let rustc_middle::ty::Dynamic(preds, ..) =
                                rustc_internal::internal(self.tcx, dynamic).kind()
                                && let Some(c) = coercion(self.tcx, c, preds)
                            {
                                self.coerced.push((c, span, false));
                            }
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

    fn edges_of_const(&mut self, c: &ConstOperand, loc: Location) {
        if let ConstantKind::Allocated(a) = c.const_.kind() {
            let mut found = Vec::new();
            let mut coerced = Vec::new();
            alloc_callees(self.tcx, a, &mut found, &mut Vec::new(), &mut coerced, 0);
            self.found.extend(found.into_iter().map(|i| (i, c.span)));
            self.coerced
                .extend(coerced.into_iter().map(|x| (x, c.span, true)));
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
    coerced: &mut Vec<Coerced>,
    depth: usize,
) {
    if depth > 8 {
        return;
    }
    for (_, prov) in &a.provenance.ptrs {
        match GlobalAlloc::from(prov.0) {
            GlobalAlloc::Function(i) => found.push(i),
            GlobalAlloc::Memory(m) => alloc_callees(tcx, &m, found, statics, coerced, depth + 1),
            GlobalAlloc::Static(s) => statics.push(s),
            GlobalAlloc::VTable(..) => {
                let id = rustc_internal::internal(tcx, prov.0);
                if let rustc_middle::mir::interpret::GlobalAlloc::VTable(ty, preds) =
                    tcx.global_alloc(id)
                {
                    // as for an unsizing coercion: the methods and the type's drop glue
                    coerced.extend(coercion(tcx, ty, preds));
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

/// A type coerced to a trait object: the trait's path, the type's, and for each trait method
/// the body the type's vtable holds (`origins::body_name`).
type Coerced = (String, String, Vec<(String, String, String)>);

/// Where a type was first seen coerced (in a static's value or not), and the bodies its
/// methods run.
type CoercedAt = (Option<Loc>, bool, Vec<(String, String, String)>);

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

/// A coercion of `concrete` to a trait object with predicates `preds`: the trait's path, the
/// type's (an ADT's defining path with its type arguments, `app::W<app::A>`; `dyn` and the
/// trait of another trait object; any other type as rustc prints it), and for each method of
/// the object the body it runs for the type (`origins::body_name`).
fn coercion<'tcx>(
    tcx: TyCtxt<'tcx>,
    concrete: rustc_middle::ty::Ty<'tcx>,
    preds: &'tcx rustc_middle::ty::List<rustc_middle::ty::PolyExistentialPredicate<'tcx>>,
) -> Option<Coerced> {
    let t = path_of(tcx, preds.principal_def_id()?);
    let ty = match concrete.kind() {
        rustc_middle::ty::Adt(adt, _) => {
            type_name(tcx, concrete).unwrap_or_else(|| path_of(tcx, adt.did()))
        }
        // an upcast (`&dyn Sub` to `&dyn Super`): the types coerced to `Sub`; none for the
        // same trait (a reborrow)
        rustc_middle::ty::Dynamic(p, ..) => {
            let sub = path_of(tcx, p.principal_def_id()?);
            if sub == t {
                return None;
            }
            format!("dyn {sub}")
        }
        _ => concrete.to_string(),
    };
    // each method of the vtable: the trait's item it is, and the body it runs
    let methods = if concrete.is_trait() {
        Vec::new()
    } else {
        let principal = preds.principal()?;
        let trait_ref = principal.with_self_ty(tcx, concrete);
        let trait_ref = tcx.instantiate_bound_regions_with_erased(trait_ref);
        tcx.vtable_entries(trait_ref)
            .iter()
            .filter_map(|e| match e {
                rustc_middle::ty::VtblEntry::Method(i) => Some(*i),
                _ => None,
            })
            .filter_map(|i| {
                let d = i.def_id();
                let item = if tcx.trait_of_assoc(d).is_some() {
                    d
                } else {
                    tcx.trait_item_of(d)?
                };
                Some((
                    path_of(tcx, item),
                    crate::origins::body_name(tcx, i)?,
                    crate::links::method_sig(tcx, i.def_id(), i.args),
                ))
            })
            .collect()
    };
    Some((t, ty, methods))
}

/// The named constant a body's constant operand at `span` is (`KP` in `KP.alg()`), read from
/// the item's MIR, where it is not evaluated away.
fn const_item_at(
    tcx: TyCtxt<'_>,
    did: rustc_span::def_id::DefId,
    span: rustc_span::Span,
) -> Option<rustc_span::def_id::DefId> {
    use rustc_middle::mir::visit::Visitor;
    struct V {
        span: rustc_span::Span,
        out: Option<rustc_span::def_id::DefId>,
    }
    impl<'tcx> Visitor<'tcx> for V {
        fn visit_const_operand(
            &mut self,
            c: &rustc_middle::mir::ConstOperand<'tcx>,
            _: rustc_middle::mir::Location,
        ) {
            if c.span == self.span
                && let rustc_middle::mir::Const::Unevaluated(uv, _) = c.const_
                && uv.promoted.is_none()
            {
                self.out = Some(uv.def);
            }
        }
    }
    if !tcx.is_mir_available(did) || tcx.is_closure_like(did) && !did.is_local() {
        return None;
    }
    let mut v = V { span, out: None };
    v.visit_body(tcx.optimized_mir(did));
    v.out
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
