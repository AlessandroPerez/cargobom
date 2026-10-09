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
//!   RCBOM_KB_CRATES    comma-separated crate names the knowledge base covers; only sites
//!                      naming items of these crates are recorded
//!   RCBOM_LOCAL_DIRS   directories of the program's own packages (workspace members, path
//!                      dependencies), one per line: their crates are never KB or stop crates
//!   RCBOM_STOP_CRATES  crates whose bodies the reachability walk does not enter (algorithm
//!                      implementations: the call into them is the fact, not their internals)
//!   RCBOM_MAX_INSTANCES  reachability walk limit (default 200000)
//!   RCBOM_SYSROOT      sysroot of the pinned toolchain (else asked from the wrapped rustc)
//!   RCBOM_DEBUG        if set, print each panic the analysis catches (message and location),
//!                      and each site dropped for having no source position

#![feature(rustc_private)]

extern crate rustc_abi;
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
    Body, CastKind, ConstOperand, Operand, PointerCoercion, Rvalue, Terminator, TerminatorKind,
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
    kb_crates: HashSet<String>,
    stop_crates: HashSet<String>,
    /// The program's own crates (workspace members, path dependencies), by crate number and
    /// stable id: never the crates the knowledge base describes, whatever their names (a member
    /// called `signature`).
    local: HashSet<rustc_span::def_id::CrateNum>,
    local_ids: HashSet<String>,
    /// Memo: does this static (by def-path hash) lead to a knowledge-base static?
    interesting_statics: HashMap<String, bool>,
    pub errors: usize,
}

fn analyze(tcx: TyCtxt<'_>) {
    let (local, local_ids) = local_crates(tcx);
    let mut cx = Cx {
        tcx,
        kb_crates: env_set("RCBOM_KB_CRATES"),
        stop_crates: env_set("RCBOM_STOP_CRATES"),
        local,
        local_ids,
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
            if let Some(body) = item.body() {
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
    // `.init_array`). RCBOM_NO_WALK turns the walk off (ablation).
    let primary = std::env::var_os("CARGO_PRIMARY_PACKAGE").is_some();
    let (roots, static_roots) = if std::env::var_os("RCBOM_NO_WALK").is_some() || !primary {
        (Vec::new(), Vec::new())
    } else {
        roots(&cx)
    };
    let reach = (!roots.is_empty() || !static_roots.is_empty()).then(|| {
        let mut w = Walker::new(&mut cx);
        let r = w.run(roots, static_roots);
        sites.extend(w.sites);
        r
    });
    phase("walk", timer);

    // Identical facts from the per-item scan and the walk collapse to one.
    let mut seen = HashSet::new();
    sites.retain(|s| seen.insert(s.clone()));

    let facts = CrateFacts {
        facts_version: FACTS_VERSION,
        krate,
        sites,
        data_edges,
        reach,
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

/// `crate::` (how rustc prints the local crate under `with_crate_prefix!`) as the crate's name:
/// `<crate::AesSealer as crate::Sealer>::seal` is `<micro::AesSealer as micro::Sealer>::seal`.
fn local_crate_name(tcx: TyCtxt<'_>, p: String) -> String {
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
    }
}

fn fn_owner_item(cx: &Cx<'_>, item: &rustc_public::CrateItem) -> Owner {
    let did = rustc_internal::internal(cx.tcx, item.def_id());
    Owner {
        kind: OwnerKind::Fn,
        name: path_of(cx.tcx, did),
        id: def_hash(cx.tcx, did),
        krate: crate_ref(cx.tcx, did),
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

/// The crates of the program's own packages: those whose root file is in the directory of a
/// workspace member or path dependency (`RCBOM_LOCAL_DIRS`, one per line).
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
        if dirs.iter().any(|d| root.starts_with(d)) {
            nums.insert(c);
            ids.insert(format!("{:016x}", tcx.stable_crate_id(c).as_u64()));
        }
    }
    (nums, ids)
}

impl Cx<'_> {
    /// Is this crate one the knowledge base describes?
    pub(crate) fn kb_crate(&self, c: rustc_span::def_id::CrateNum) -> bool {
        !self.local.contains(&c) && self.kb_crates.contains(self.tcx.crate_name(c).as_str())
    }

    /// The same for a crate as the facts name it.
    fn kb_ref(&self, k: &rcbom_facts::CrateRef) -> bool {
        !self.local_ids.contains(&k.stable_id) && self.kb_crates.contains(&k.name)
    }

    /// Is this crate one whose code the walk does not enter (an algorithm implementation)?
    fn stop_crate(&self, c: rustc_span::def_id::CrateNum) -> bool {
        !self.local.contains(&c) && self.stop_crates.contains(self.tcx.crate_name(c).as_str())
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
        let internal = rustc_internal::internal(self.cx.tcx, span);
        let text = span_text(self.cx.tcx, internal);
        let line_text = line_text(self.cx.tcx, internal);
        let (span, expansion) = locate_stable(self.cx.tcx, span);
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
            // `StaticSecret::from([7u8; 32])`, `SigningKey::try_from(bytes)`, `bytes.into()`.
            let Some(tr) = tcx.trait_of_assoc(did) else {
                return false;
            };
            let name = tcx.get_diagnostic_name(tr).map(|s| s.to_string());
            let constructed = match name.as_deref() {
                Some("Default" | "From" | "TryFrom" | "FromStr") => trees.first(),
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
        let (const_args, arg_origins, arg_lens) = match call {
            Some((call_args, term)) => {
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
                    .map(|a| self.origins.array_len(a))
                    .collect();
                (consts, origins, lens)
            }
            None => (Vec::new(), Vec::new(), Vec::new()),
        };
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

    /// A KB function used as a value (`iter.map(Sha256::digest)`, `let h: fn(..) = digest`):
    /// recorded where it is named, like a call.
    fn function_value(&mut self, op: &Operand) {
        if let Operand::Constant(c) = op
            && let Some(RigidTy::FnDef(def, args)) = c.const_.ty().kind().rigid()
            && self.interesting(def, args)
        {
            self.record_call(def, args, c.span, None);
        }
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
    fn visit_terminator(&mut self, term: &Terminator, loc: Location) {
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
                // the callee path's own span (`UnboundKey::new`, `.encrypt`), not the whole
                // call expression; for a callee held in a local, where it was named
                let span = match func {
                    Operand::Constant(c) => Some(c.span),
                    _ => self.origins.callee_name_span(func, term),
                };
                if span.is_none() && std::env::var_os("RCBOM_DEBUG").is_some() {
                    eprintln!(
                        "rcbom-driver: call of {} without a position for its callee dropped in {}",
                        def.name(),
                        self.owner.name
                    );
                }
                if let Some(span) = span {
                    self.record_call(def, args, span, Some((call_args, term)));
                }
            } else if let Some((def, args, span)) = self.origins.callee_through_pointer(func)
                && self.interesting(&def, &args)
            {
                // a call through a pointer to a KB function reified here
                self.record_call(&def, &args, span, Some((call_args, term)));
            }
            for a in call_args {
                self.function_value(a);
            }
        }
        self.super_terminator(term, loc);
    }

    fn visit_rvalue(&mut self, rv: &Rvalue, loc: Location) {
        if let Rvalue::Cast(CastKind::PointerCoercion(PointerCoercion::ReifyFnPointer(_)), op, _) =
            rv
        {
            self.function_value(op);
        }
        self.super_rvalue(rv, loc);
    }

    fn visit_const_operand(&mut self, c: &ConstOperand, loc: Location) {
        if let ConstantKind::Allocated(a) = c.const_.kind() {
            alloc_statics(a, &mut self.statics, &mut HashSet::new(), 0);
        }
        self.super_const_operand(c, loc);
    }
}

/// Roots of the walk in a workspace member: `main`; for a library, its exported monomorphic
/// functions and exported statics; in any crate, what the linker keeps whatever calls it
/// (`#[no_mangle]`, `#[export_name]` functions, `#[used]` statics).
fn roots(cx: &Cx<'_>) -> (Vec<(Instance, String)>, Vec<rustc_span::def_id::DefId>) {
    use rustc_middle::middle::codegen_fn_attrs::CodegenFnAttrFlags as F;
    let tcx = cx.tcx;
    let vis = tcx.effective_visibilities(());
    let is_bin = rustc_public::entry_fn().is_some();
    let mut fns = Vec::new();
    if let Some(entry) = rustc_public::entry_fn()
        && let Ok(i) = Instance::try_from(entry)
    {
        fns.push((i, instance_name(tcx, &i)));
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
            && !fns.iter().any(|(r, _)| *r == i)
        {
            let n = format!("pub {}", instance_name(tcx, &i));
            fns.push((i, n));
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
    (fns, statics)
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

    fn run(
        &mut self,
        roots: Vec<(Instance, String)>,
        static_roots: Vec<rustc_span::def_id::DefId>,
    ) -> Reach {
        let mut names: Vec<String> = roots.iter().map(|(_, n)| n.clone()).collect();
        for (root, _) in roots {
            self.enqueue(root, None);
        }
        for s in static_roots {
            names.push(format!("static {}", path_of(self.cx.tcx, s)));
            self.reach_static(s);
        }
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
        let mut fns = std::mem::take(&mut self.fns);
        fns.sort();
        fns.dedup();
        Reach {
            roots: names,
            instances: self.seen.len(),
            truncated,
            statics,
            fns,
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
                caller: instance_name(self.cx.tcx, p),
                span: loc.clone(),
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
        let foreign = |did: rustc_span::def_id::DefId| {
            let k = tcx.crate_name(did.krate).to_string();
            !self.cx.stop_crate(did.krate) && !self.cx.is_std(&k)
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

    fn visit(&mut self, inst: Instance) {
        let did = rustc_internal::internal(self.cx.tcx, inst.def.def_id());
        // Not `inst.has_body()`: in this rustc_public it asks about the instance's *def*, which
        // for a shim (`<closure as FnOnce>::call_once` behind a `dyn FnOnce`, as in every
        // `thread::spawn`) is a trait method without a body. `body()` checks the instance.
        let Some(body) = inst.body() else { return };
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
        let stop = self.cx.stop_crate(did.krate);
        if !stop {
            let owner = fn_owner(self.cx, &inst);
            self.fns.push(owner.id.clone());
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
                .flatten();
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
            // inside an algorithm implementation, only what it calls back into
            if stop && !self.calls_back(&callee) {
                continue;
            }
            if debug.is_some() {
                eprintln!("rcbom-walk:   -> {} ({:?})", callee.name(), callee.kind);
            }
            let loc = locate_stable(self.cx.tcx, span).0;
            self.enqueue(callee, Some((inst, loc)));
        }
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
        alloc_callees(tcx, &a, &mut found, &mut nested, 0);
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
