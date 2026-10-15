//! `cargo cbom verify`: reopen every file a CBOM cites and check that the code at
//! `line`/`offset` names what `symbol` says was found. Independent of the driver's span
//! handling, so an off-by-one line or column fails.
//!
//! A code position must start a token (not inside an identifier, not after `::`), lie in code
//! (not in a comment or a literal), and begin a path (comments between its segments skipped, raw
//! identifiers read without `r#`) whose last segment is the symbol's name or an import alias of
//! it: from the file's `use` items, or from those of any file of its package or of the crate the
//! path goes through (`pub use ring::digest::digest as hash_it;` in `src/algs.rs`, a re-export
//! inside that crate, `pub use inner::DEEP as SHALLOW;`). Besides:
//! - the source line the context records (`line: `..``) is the line's, and the text at the
//!   position is the one it records (`code: `..``) when it records one; only the leading `[..]`
//!   tags of the context are read as tags, never the recorded source text;
//! - one asset has one occurrence per (position, symbol), as the generator writes them;
//! - a `[component] .. part of X` occurrence is where X is, or on the line where X was merged
//!   into a more specific name;
//! - a path qualified by a type the source imports from a crate of the CBOM (`Hmac::<Sha256>::`)
//!   is evidence only of what that crate, or one it depends on, provides. Crate names are those
//!   the dependencies of the package owning the file have there (`cargo metadata`), so two
//!   versions of one crate, and renamed dependencies, are told apart;
//! - a `Cargo.toml` position is the start of a key (a quoted key at its opening quote; not in a
//!   comment or a string) in the table the context names, in the manifest of the package it
//!   names; a `Cargo.lock` position is the `name` line of the locked version the context names;
//!   lines are compared without the `\r` of a CRLF file;
//! - a standard-library location (`/rustc/<commit>/..`) names the pinned toolchain's commit, and
//!   is read from its rust-src: a line a standard-library macro expands from names the symbol
//!   (`= __RUST_STD_INTERNAL_INIT;`), or uses a metavariable the invocation's line, which names
//!   the symbol, fills;
//! - "algorithm from X in the arguments": X is named in the code the call reads: the argument
//!   that carries the algorithm (the knowledge base's operation says which, the receiver of a
//!   method being the first; every argument and the receiver for other calls), the variables it
//!   reads through bindings in scope (the part a destructuring pattern binds, `let (p, q) =
//!   (..)`, `let Two { h, l } = ..`), the stores into them that may reach the call (an
//!   assignment, a `mem::swap` / `mem::replace` with another argument in a block around the
//!   read, one on some ways only as a value beside the one before, a store through another
//!   binding that may point to the variable: `let r = &mut a; *r = v`, reborrows, copies,
//!   holders, `*f(&mut v) = x`, a method's returned borrow), a store or a call of the file's
//!   function that replaces the place read on every way to it; an `Option` combinator's closure
//!   (`o.map_or(&SHA512, |_| &SHA1)`: the default and the closure's value, not `o`'s unless the
//!   closure reads its parameter); the file's functions and methods it calls, the method of a
//!   value of one of the file's types; the statics, consts and `const fn`s named, projected
//!   through the fields, tuple elements and array elements read (`TABLE[i].h`, `NESTED.inner.h`,
//!   `PAIRS[i].1`, through a constant an initializer names, `[BASE, ..]`), also of other files
//!   and packages of the build (by the module path written and `pub use` re-exports; one not
//!   found in a package at hand names nothing); an instance's associated constant (`T::ALG` in
//!   `hash_c::<CFast>`: CFast's, else the trait's default); an index (`[i]`) is no value read.
//!   No other descriptor of the asset's primitive (nor a type the knowledge base gives one) is
//!   read instead. A claim that the values found are all (no unknown beside them) is held to a
//!   store through a pointer that replaces the place on every way to the call; a member found
//!   beside others not followed may be the value before it;
//! - a member reaching the call from another function (`member: object`, `caller`, `fixed`,
//!   `dyn`, `container`, and `type-join`, `impl` at a call reading no field): where the argument
//!   carrying the algorithm holds no value from elsewhere (a parameter, a variable lent to a
//!   call not followed, a constant of a crate not at hand, a static the program may change), it
//!   names no other descriptor of the primitive (nor a type the knowledge base gives one)
//!   instead; a witness function (`member: object, from F`, `caller, passed by F`, `impl,
//!   possible (what F writes)`, `type-join, possible (a value F stores ..)`) of the build's own
//!   packages, not made by the compiler, exists (`<T as Tr>::m`, `Tr::m for T`: T's impl of Tr,
//!   or the trait's default body where T's impl writes no `m`) and can give X: its body names
//!   X, or reads a parameter that can hold it (not an integer, a string, bytes), or, returning or
//!   writing the object, has a result or a `&mut` parameter that can (a writer not replacing what
//!   it writes, on every way, with other descriptors only);
//! - a static table's member ("one of the N in `T`", "stored in `static T`", `member: table`,
//!   `member: static`) is held by the static or const `T` of the package (the fields read, where
//!   the context reads some), and, where the argument carrying the algorithm reads no value from
//!   elsewhere, that code reads `T` and, through the fields it reads, X; a coercion ("`T` is
//!   coerced to `dyn Tr` at F:L") is a pointer made of a `T` (or of a variable bound to one, a
//!   parameter declared of `T` or of a type parameter of its function, a type parameter's value
//!   in a generic function) on that line that becomes an object of `Tr`, or of a trait whose
//!   supertraits include `Tr`, there: by the innermost context it is in (an `as` cast after it,
//!   the parameter of the function it is passed to, also another crate's, the field of the
//!   struct literal, the variable whose method stores it, the annotation of the `let`, `static`
//!   or `const` whose value, tuple element or array element it is, the return type of the
//!   function whose tail or `return` it is), in a static's item exactly when the detail says "in
//!   a static";
//! - a pointer's `named at` is where the variable called is bound, the binding in scope (blocks,
//!   closures, nested functions, shadowing, `let f = f;`, a macro's `let`), or the statement
//!   storing it into the container it is read from (`map.insert("a", digest)`, also a field's,
//!   `t.map.insert(1, digest)`); a variable computed by code not followed (another crate's
//!   function, a labelled block) must read a variable bound there;
//! - a closure's instantiation detail cites the innermost closure, or `async` closure's body,
//!   whose extent strictly holds the next position inward, and a closure caller that is the
//!   closure's parent but for closure indexes is its parent; an instantiation detail citing an
//!   `[instantiation]` occurrence's position is of one of that position's assets, and an
//!   `[instantiation]` occurrence cited by details is cited by its own asset's; a method call it
//!   cites on a value whose type the code says (a variable's annotation or initializer, a
//!   field's declared type, a function's or method's return type, `vec![..]`'s elements) is of
//!   the chain's type, or of one implementing the chain's trait; a generic function's instance
//!   (`pass::<A>`) is called with those type arguments, written or given by an argument of a
//!   type of the file (`pass(&B, ..)` is `pass::<B>`); a vtable's detail cites the coercion's
//!   expression from its first token (a cast to a pointer, not `as fn(..)`), also a value made
//!   an object of the method's trait by a function's parameter (`up_dyn(&mut a1)`, a default
//!   body only for a type whose impl does not write it); a call a macro invoked in the function
//!   makes is cited at the invocation, one through a variable bound to a function item running
//!   the chain's body at the variable's call (not at the `let` binding it);
//! - a macro's body line cited is in the rule the invocation matches (rustc's first; repetitions
//!   `$(..)sep*+?` matched), and uses the metavariable that rule binds to the symbol; of several
//!   invocations of one macro, the one inside the modules the item's path names and naming most
//!   of its words (and the occurrence's descriptor: the algorithm a call's comes from, a
//!   static's own symbol) makes it.
//!
//! Verdicts: a position is verified exactly, or, where the context cannot tell identical
//! candidates apart (invocations of one macro that make the same item as far as its path says),
//! within a range of them (counted apart, never as exact; the self-test counts a shift that
//! lands only within such a range as rejected, and shifts a detail once per function, position
//! and text it cites, not once per instance of a generic function citing the same). A shifted
//! coercion detail that lands on another line coercing a value of the type to the trait is as
//! true: counted apart and printed (`AS TRUE`), not hidden.
//!
//! Known limits:
//! - The check of "in the arguments" follows stores by the file's functions and inherent
//!   methods named in the function, not trait methods dispatched on a type the code does not
//!   say (`u.up()` on a `&mut dyn`, `t.up()` in a generic function): a value such a call
//!   replaces is still read as the variable's binding. The check of members from other
//!   functions takes such a call as a value from elsewhere (no check).
//! - A store through a pointer bound by a pattern, a loop or a condition (`if let Some(r) = o {
//!   *r = v }`, `for r in [&mut x]`), or through a function's result whose body is not one
//!   returned expression, is a possible store: the value before is still accepted. A member
//!   labelled beside others not followed is accepted where such a store replaces it on every way
//!   (the analysis may not have followed that store); only claims without an unknown are held
//!   to it.
//! - `type-join` and `impl` members (any value stored in a field of that type, or that a
//!   function writes) are checked against the call's code only where the call reads no field.
//!   A `dyn` member is checked to be at a call on an object of its trait (where the receivers'
//!   types are known), not on the object the coerced value reaches: moved to a call on another
//!   object of the same trait, it is accepted.
//! - Witness functions are checked in the build's own packages only, and by what their bodies
//!   name and their signatures can carry, not by whether the call's value comes through them.
//! - A coercion's detail is checked as a coercion of the type to the trait on that line, not as
//!   the one whose value reaches the call: of two lines coercing the same type to the same trait
//!   (two generic functions boxing their `T`), a shift from one to the other is as true.
//! - A generic call's type arguments are compared only where written, or given by an argument
//!   whose type is one of the file's; an elided `<..>` is not compared. A closure's index is not
//!   counted against the closures of its parent's body.
//! - A standard-library macro's line is checked against the symbol or a metavariable, not
//!   against the rule the invocation matches (the standard library's `macro` items are not read).
//! - The jsonwebtoken boundary model's members (`Validation.algorithms`, `Header.alg`) are not
//!   checked against the call's code (open plan item 10).
//! - `#[cfg(..)]` is not evaluated. A shifted position that lands on an identical line that the
//!   configuration removes (`#[cfg(any())] let d = Sha256::digest(data);` just above the same
//!   statement) is accepted by the self-test. The generator never cites such code (rustc does not
//!   compile it), so this weakens the self-test only, not the check of the CBOM's positions.
//! - Imports are read per file, not per scope. When a file binds a name to several crates
//!   (`use sha1::Sha1 as H;` in one module, `use sha2::Sha256 as H;` in another), any of them may
//!   provide the asset. When the name may be the program's own (a definition or a generic
//!   parameter in the file, a `crate::`/`self::`/`super::` import, a module, a glob import), the
//!   provider rule makes no check.
//! - Of a dependency key, the kind of table is checked, not which `[target.'cfg(..)'.*]` table it
//!   is in (the context does not record it), nor the features the context lists.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::rc::Rc;

use anyhow::Result;
use rcbom_kb::Kb;
use regex::Regex;
use serde_json::Value;

#[derive(Clone)]
struct Occ {
    component: String,
    component_ref: String,
    location: String,
    line: usize,
    offset: usize,
    symbol: String,
    context: String,
}

macro_rules! re {
    ($s:expr) => {{
        static R: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| Regex::new($s).unwrap());
        &*R
    }};
}

/// A package's `#[path]` modules and `include!`d files (see `Files::pkg_mods`).
#[derive(Default)]
struct PkgMods {
    paths: Vec<(PathBuf, PathBuf, String)>,
    included: HashSet<PathBuf>,
}

/// A constant `Files::resolve_foreign` looks for: the package directory and module where it is
/// named (None: modules not known), the path written before it, its name, the fields read of it.
type Pending = (
    PathBuf,
    Option<Vec<String>>,
    Vec<String>,
    String,
    Option<String>,
);

/// Where `Files::resolve_foreign` found one: the file, the item's extent, its module.
type Spot = (PathBuf, (usize, usize), Option<Vec<String>>);

/// Reads the type of a parameter of another crate's function (`Files::foreign_param`): the
/// path written before the function's name, the name, the argument's index.
type ForeignParam<'a> = dyn FnMut(&[String], &str, usize) -> Option<String> + 'a;

/// What the CBOM says about packages: which assets each provides, and its dependencies.
struct Graph {
    /// bom-refs of the packages that are components of the CBOM
    packages: HashSet<String>,
    depends_on: HashMap<String, Vec<String>>,
    /// asset bom-ref -> package bom-refs providing it
    providers: HashMap<String, HashSet<String>>,
    /// asset bom-ref -> its algorithm family
    family: HashMap<String, String>,
    /// asset bom-ref -> its primitive (`hash`, `ae`, `signature`, ..)
    primitive: HashMap<String, String>,
    /// asset bom-ref -> its `cryptoFunctions`, and whether it is reachable (its functions are
    /// then those of its reachable occurrences or entries)
    functions: HashMap<String, (Vec<String>, bool)>,
}

impl Graph {
    fn closure(&self, r: &str) -> HashSet<String> {
        let mut seen = HashSet::new();
        let mut stack = vec![r.to_string()];
        while let Some(x) = stack.pop() {
            if !seen.insert(x.clone()) {
                continue;
            }
            for d in self.depends_on.get(&x).into_iter().flatten() {
                if d.starts_with("pkg:") {
                    stack.push(d.clone());
                }
            }
        }
        seen
    }
}

/// The crate names each package's code sees, from `cargo metadata`: package id -> crate
/// identifier -> bom-refs of the packages it names (its own library, its dependencies under
/// their extern names: `sha2_11 = { package = "sha2" }` is `sha2_11`).
type Externs = HashMap<String, HashMap<String, Vec<String>>>;

/// Library crate name -> bom-refs of the packages whose library it is (`aws_lc_rs` is
/// aws-lc-rs's), from `cargo metadata`.
type Libs = HashMap<String, Vec<String>>;

fn pkg_ref(name: &str, version: &str) -> String {
    format!("pkg:cargo/{name}@{version}")
}

fn load_externs(
    manifest_path: &Path,
    target: &str,
    features: &[String],
) -> Option<(Externs, Libs, Vec<PathBuf>)> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut cmd = Command::new(cargo);
    cmd.args([
        "metadata",
        "--format-version",
        "1",
        "--locked",
        "--filter-platform",
        target,
        "--manifest-path",
    ])
    .arg(manifest_path);
    if !features.is_empty() {
        cmd.arg("--features").arg(features.join(","));
    }
    let out = cmd.stderr(Stdio::null()).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let md: Value = serde_json::from_slice(&out.stdout).ok()?;
    let mut refs: HashMap<&str, String> = HashMap::new();
    let mut ext: Externs = HashMap::new();
    let mut libs: Libs = HashMap::new();
    let mut roots = Vec::new();
    for p in md["packages"].as_array()? {
        let (Some(id), Some(n), Some(v)) =
            (p["id"].as_str(), p["name"].as_str(), p["version"].as_str())
        else {
            continue;
        };
        let r = pkg_ref(n, v);
        refs.insert(id, r.clone());
        // its own library, as its binaries name it
        let own = ext.entry(id.to_string()).or_default();
        for t in p["targets"].as_array().into_iter().flatten() {
            // (a build script's modules are not the crate's)
            let build = t["kind"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|k| k == "custom-build");
            if let Some(sp) = t["src_path"].as_str()
                && !build
            {
                roots.push(PathBuf::from(sp));
            }
            let lib = t["kind"].as_array().into_iter().flatten().any(|k| {
                matches!(
                    k.as_str(),
                    Some("lib" | "rlib" | "dylib" | "cdylib" | "staticlib" | "proc-macro")
                )
            });
            if lib && let Some(tn) = t["name"].as_str() {
                own.entry(tn.replace('-', "_")).or_default().push(r.clone());
                libs.entry(tn.replace('-', "_"))
                    .or_default()
                    .push(r.clone());
            }
        }
    }
    for n in md["resolve"]["nodes"].as_array()? {
        let Some(id) = n["id"].as_str() else { continue };
        let m = ext.entry(id.to_string()).or_default();
        for d in n["deps"].as_array().into_iter().flatten() {
            if let (Some(name), Some(r)) = (
                d["name"].as_str(),
                d["pkg"].as_str().and_then(|p| refs.get(p)),
            ) {
                let v = m.entry(name.to_string()).or_default();
                if !v.contains(r) {
                    v.push(r.clone());
                }
            }
        }
    }
    Some((ext, libs, roots))
}

/// The pinned toolchain's sysroot and commit (`rustc -vV`).
fn toolchain() -> Option<(PathBuf, String)> {
    let sysroot = crate::sysroot().ok()?;
    let out = Command::new("rustc")
        .arg(format!("+{}", crate::TOOLCHAIN))
        .arg("-vV")
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let commit = text
        .lines()
        .find_map(|l| l.strip_prefix("commit-hash: "))?
        .trim()
        .to_string();
    Some((PathBuf::from(sysroot), commit))
}

pub fn run(cbom: &Path, manifest_path: &Path, self_test: bool) -> Result<()> {
    let doc: Value = serde_json::from_slice(&std::fs::read(cbom)?)?;
    let features: Vec<String> = doc["metadata"]["properties"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|p| p["name"] == "rcbom:run:features")
        .and_then(|p| p["value"].as_str())
        .map(|s| {
            s.split(',')
                .filter(|f| !f.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let kb = Kb::seed()?;
    // the platform the CBOM was made for (its dependency tables and features)
    let target = match doc["metadata"]["properties"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|p| p["name"] == "rcbom:run:target")
        .and_then(|p| p["value"].as_str())
    {
        Some(t) => t.to_string(),
        None => rcbom_manifest::host_triple()?,
    };
    let man = rcbom_manifest::load_locked(manifest_path, &target, &features, &kb)?;
    let (externs, libs, roots) = match load_externs(manifest_path, &target, &features) {
        Some((e, l, r)) => (Some(e), Some(l), Some(r)),
        None => {
            eprintln!("verify: cargo metadata failed; crate names are resolved by package name");
            (None, None, None)
        }
    };
    let mut graph = Graph {
        packages: HashSet::new(),
        depends_on: HashMap::new(),
        providers: HashMap::new(),
        family: HashMap::new(),
        primitive: HashMap::new(),
        functions: HashMap::new(),
    };
    // the components, and the root package (`metadata.component`)
    let root = doc["metadata"]["component"].clone();
    for c in doc["components"]
        .as_array()
        .into_iter()
        .flatten()
        .chain(std::iter::once(&root).filter(|r| r.is_object()))
    {
        let Some(r) = c["bom-ref"].as_str() else {
            continue;
        };
        match c["type"].as_str() {
            Some("library" | "application") => {
                graph.packages.insert(r.to_string());
            }
            Some("cryptographic-asset") => {
                // or the property for a family `algorithmFamily` cannot say (`TLS-PRF`)
                let prop = c["properties"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .find_map(|p| {
                        (p["name"] == "rcbom:algorithm-family")
                            .then(|| p["value"].as_str())
                            .flatten()
                    });
                if let Some(f) = c["cryptoProperties"]["algorithmProperties"]["algorithmFamily"]
                    .as_str()
                    .or(prop)
                {
                    graph.family.insert(r.to_string(), f.to_string());
                }
                if let Some(p) = c["cryptoProperties"]["algorithmProperties"]["primitive"].as_str()
                {
                    graph.primitive.insert(r.to_string(), p.to_string());
                }
                let prop = |n: &str| {
                    c["properties"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .find(|p| p["name"] == n)
                        .and_then(|p| p["value"].as_str())
                };
                if let Some(fs) =
                    c["cryptoProperties"]["algorithmProperties"]["cryptoFunctions"].as_array()
                {
                    graph.functions.insert(
                        r.to_string(),
                        (
                            fs.iter()
                                .filter_map(|f| f.as_str().map(str::to_string))
                                .collect(),
                            prop("rcbom:reachability") == Some("reachable"),
                        ),
                    );
                }
            }
            _ => {}
        }
    }
    for d in doc["dependencies"].as_array().into_iter().flatten() {
        let r = d["ref"].as_str().unwrap_or("").to_string();
        let on: Vec<String> = d["dependsOn"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|x| x.as_str().map(str::to_string))
            .collect();
        for a in d["provides"].as_array().into_iter().flatten() {
            if let Some(a) = a.as_str() {
                graph
                    .providers
                    .entry(a.to_string())
                    .or_default()
                    .insert(r.clone());
            }
        }
        graph.depends_on.insert(r, on);
    }
    let mut occs = Vec::new();
    let mut without_line = 0;
    for c in doc["components"]
        .as_array()
        .into_iter()
        .flatten()
        .chain(std::iter::once(&root).filter(|r| r.is_object()))
    {
        for o in c["evidence"]["occurrences"]
            .as_array()
            .into_iter()
            .flatten()
        {
            let (Some(line), Some(offset)) = (o["line"].as_u64(), o["offset"].as_u64()) else {
                // the generator gives every occurrence a position: one without is not evidence
                without_line += 1;
                println!(
                    "MISMATCH {} {}: an occurrence without a line and offset",
                    c["name"].as_str().unwrap_or(""),
                    o["location"].as_str().unwrap_or("")
                );
                continue;
            };
            occs.push(Occ {
                component: c["name"].as_str().unwrap_or("").into(),
                component_ref: c["bom-ref"].as_str().unwrap_or("").into(),
                location: o["location"].as_str().unwrap_or("").into(),
                line: line as usize,
                offset: offset as usize,
                symbol: o["symbol"].as_str().unwrap_or("").into(),
                context: o["additionalContext"].as_str().unwrap_or("").into(),
            });
        }
    }
    let mut at_pos: HashMap<(String, usize, usize), Vec<usize>> = HashMap::new();
    let mut at_line: HashMap<(String, usize), Vec<usize>> = HashMap::new();
    for (i, o) in occs.iter().enumerate() {
        at_pos
            .entry((o.location.clone(), o.line, o.offset))
            .or_default()
            .push(i);
        at_line
            .entry((o.location.clone(), o.line))
            .or_default()
            .push(i);
    }
    let mut cited: HashMap<(String, usize, usize), HashSet<String>> = HashMap::new();
    for o in &occs {
        for m in re!(r"instantiated by .*? at ([^\s;]+?):(\d+):(\d+)(?: as `[^`]*`)?(?:;|$)")
            .captures_iter(&o.context)
        {
            cited
                .entry((
                    m[1].to_string(),
                    m[2].parse().unwrap_or(0),
                    m[3].parse().unwrap_or(0),
                ))
                .or_default()
                .insert(o.component_ref.clone());
        }
    }
    let mut files = Files {
        man: &man,
        kb: &kb,
        externs,
        libs,
        toolchain: None,
        cache: HashMap::new(),
        pkg_binds: HashMap::new(),
        pkg_aliases: HashMap::new(),
        roots,
        pkg_mods: HashMap::new(),
        std_items: HashMap::new(),
        occs: &occs,
        at_pos,
        at_line,
        cited,
        graph,
        inst: Vec::new(),
        alg_arg: None,
    };
    let mut bad = 0;
    let mut ranged = 0;
    let mut verified = vec![false; occs.len()];
    for (i, o) in occs.iter().enumerate() {
        RANGED.with(|r| r.set(false));
        match files.check(i, o.line, o.offset) {
            Ok(()) if RANGED.with(|r| r.get()) => {
                // identical candidates the context cannot tell apart: a range, not exact
                verified[i] = true;
                ranged += 1;
                println!(
                    "RANGE {} {}:{}:{}: one of identical candidates",
                    o.component, o.location, o.line, o.offset
                );
            }
            Ok(()) => verified[i] = true,
            Err(e) => {
                bad += 1;
                println!(
                    "MISMATCH {} {}:{}:{}: {e}",
                    o.component, o.location, o.line, o.offset
                );
            }
        }
    }
    println!(
        "{}: {} positions verified, {} mismatched, {} occurrences without a line, {} within a range \
         of identical candidates",
        cbom.display(),
        occs.len() - bad - ranged,
        bad,
        without_line,
        ranged
    );
    let bad = bad + without_line;
    if self_test {
        for (dl, dc, what) in [
            (1i64, 0i64, "line +1"),
            (-1, 0, "line -1"),
            (0, 1, "column +1"),
            (0, -1, "column -1"),
        ] {
            // only positions that verified: a mismatched one would count its shifts as caught
            let shifted: Vec<_> = (0..occs.len())
                .filter(|&i| verified[i])
                .filter_map(|i| {
                    let o = &occs[i];
                    let l = usize::try_from(o.line as i64 + dl)
                        .ok()
                        .filter(|&l| l >= 1)?;
                    let c = usize::try_from(o.offset as i64 + dc).ok()?;
                    Some((i, l, c))
                })
                .collect();
            let (mut caught, mut in_range) = (0, 0);
            for &(i, l, c) in &shifted {
                RANGED.with(|r| r.set(false));
                let ok = files.check(i, l, c).is_ok();
                if ok && RANGED.with(|r| r.get()) {
                    // not confirmed: one of identical candidates (a range)
                    caught += 1;
                    in_range += 1;
                } else if !ok {
                    caught += 1;
                } else {
                    let o = &occs[i];
                    println!(
                        "ACCEPTED {what}: {} {}:{}:{} -> {}:{} symbol={}",
                        o.component, o.location, o.line, o.offset, l, c, o.symbol
                    );
                }
            }
            println!(
                "self-test {what}: {caught}/{} shifted positions rejected ({in_range} of them \
                 only placed within a range of identical candidates)",
                shifted.len()
            );
        }
        // the positions the details cite (`instantiated by X at F:L:C`, `expanded from F:L`,
        // `named at F:L:C` of a function pointer)
        for (dl, dc, what) in [
            (1i64, 0i64, "detail line +1"),
            (-1, 0, "detail line -1"),
            (0, 1, "detail column +1"),
            (0, -1, "detail column -1"),
        ] {
            let (mut caught, mut total, mut also_true) = (0, 0, 0);
            for (i, o) in occs.iter().enumerate().filter(|&(i, _)| verified[i]) {
                // one shift per function, position and text cited: the instances of a generic
                // function cite the same lines (thousands, in a chain of macro-made types)
                let mut tried = HashSet::new();
                let details = re!(
                    r"(?:instantiated by .*? at|expanded from|named at) [^\s;]+?:(\d+)(?::(\d+))?(?: as `[^`]*`)?(?:;|$)"
                )
                .captures_iter(&o.context)
                .chain(
                    re!(r"coerced to `[^`]+` (?:in a static )?at [^\s;)]+?:(\d+)\)")
                        .captures_iter(&o.context),
                );
                for m in details {
                    let (Some(lg), cg) = (m.get(1), m.get(2)) else {
                        continue;
                    };
                    let l: i64 = lg.as_str().parse().unwrap_or(0);
                    let shifted = match (dc, cg) {
                        (0, _) if l + dl >= 1 => format!(
                            "{}{}{}",
                            &o.context[..lg.start()],
                            l + dl,
                            &o.context[lg.end()..]
                        ),
                        (0, _) => continue,
                        (_, Some(cg)) => {
                            let c: i64 = cg.as_str().parse().unwrap_or(0);
                            if c + dc < 0 {
                                continue;
                            }
                            format!(
                                "{}{}{}",
                                &o.context[..cg.start()],
                                c + dc,
                                &o.context[cg.end()..]
                            )
                        }
                        (_, None) => continue,
                    };
                    // landing on another detail the occurrence itself gives (a pointer named in
                    // both arms of a `match`): a copy of a correct detail, not a wrong one
                    let start = m.get(0).map_or(0, |g| g.start());
                    let part_end = shifted[start..]
                        .find(';')
                        .map_or(shifted.len(), |e| start + e);
                    let part = &shifted[start..part_end];
                    if o.context.split("; ").any(|p| p.ends_with(part)) {
                        continue;
                    }
                    if !tried.insert(
                        re!(r"::<[^<>;]*(?:<[^<>;]*>[^<>;]*)*>")
                            .replace_all(part, "")
                            .into_owned(),
                    ) {
                        continue;
                    }
                    total += 1;
                    RANGED.with(|r| r.set(false));
                    let ok = files
                        .check_with(i, o.line, o.offset, Some(&shifted))
                        .is_ok();
                    if !ok || RANGED.with(|r| r.get()) {
                        caught += 1;
                    } else if m[0].starts_with("coerced to") {
                        // the shifted line coerces the type to the trait too (a value of the type
                        // becomes an object of that trait there, as `check_coercions` reads it):
                        // the claim is as true, no wrong position; printed, not hidden
                        total -= 1;
                        also_true += 1;
                        println!(
                            "AS TRUE {what}: {} {}:{}:{} cites {}",
                            o.component,
                            o.location,
                            o.line,
                            o.offset,
                            &shifted[start..part_end]
                        );
                    } else {
                        println!(
                            "ACCEPTED {what}: {} {}:{}:{} cites {}",
                            o.component,
                            o.location,
                            o.line,
                            o.offset,
                            m[0].trim_end_matches(';')
                        );
                    }
                }
            }
            if also_true > 0 {
                println!(
                    "self-test {what}: {caught}/{total} shifted positions rejected ({also_true} \
                     more landed on another coercion of the same type, as true)"
                );
            } else {
                println!("self-test {what}: {caught}/{total} shifted positions rejected");
            }
        }
    }
    if bad > 0 {
        anyhow::bail!("{bad} positions do not match the source");
    }
    Ok(())
}

/// What a character of a Rust source is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Class {
    Code,
    Comment,
    /// a string or character literal
    Literal,
}

/// A name a `use` or `extern crate` item binds, and the path it imports (`use a::{b::c as d}`
/// binds `d` to `a::b::c`).
#[derive(Clone, Debug, PartialEq, Eq)]
struct Binding {
    name: String,
    path: Vec<String>,
}

struct Source {
    /// the lines, without the `\r` of a CRLF line end
    lines: Vec<String>,
    /// per line, per char
    class: Vec<Vec<Class>>,
    /// Rust: the names the file's `use` and `extern crate` items bind
    binds: Vec<Binding>,
    /// Rust: the names the file defines (types, traits, modules) or declares as generic
    /// parameters, which may shadow an import
    locals: HashSet<String>,
    /// `Cargo.toml`: its keys
    toml: Vec<TomlKey>,
    /// Rust: where each `use` or `extern crate` item is, from (line, col) to (line, col)
    /// (1-based lines, 0-based char columns, end exclusive): a path there is an import, not a use
    use_spans: Vec<((usize, usize), (usize, usize))>,
    /// Rust: the items with a body (functions, statics, consts, impl blocks, traits, modules,
    /// `macro_rules!`), where a position's enclosing item is looked up
    items: Vec<Item>,
    /// Rust: the file's chars with comments and literals blanked (line breaks kept), and the
    /// index of each line's first char in it
    code: Vec<char>,
    line_start: Vec<usize>,
    /// Rust: the bindings of each function read so far (`fn_scope`), by its start
    scopes: std::cell::RefCell<HashMap<usize, Rc<FnScope>>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ItemKind {
    Fn,
    Static,
    Impl,
    Trait,
    Mod,
    /// a type's definition (`struct S`, `enum E`, `union U`, `type T`): its keyword only
    TypeDef,
    Macro,
    /// a macro's invocation (`thread_local! { .. }`): the items it makes are named by it
    MacroCall,
}

/// An item of a Rust file, from its keyword to the end of its body ((line, col), end
/// exclusive), with its name: a function's, static's or const's, a trait's, a module's, a
/// `macro_rules!`'s; for an impl block, the last segment of its self type (and `trait_name`,
/// the trait's).
#[derive(Debug)]
struct Item {
    kind: ItemKind,
    name: String,
    trait_name: Option<String>,
    start: (usize, usize),
    end: (usize, usize),
}

impl Item {
    fn contains(&self, at: (usize, usize)) -> bool {
        self.start <= at && at < self.end
    }
}

impl Source {
    fn new(text: &str, rust: bool, toml: bool) -> Source {
        // a CRLF file: the `\r` is not part of the line
        let lines: Vec<String> = text
            .split('\n')
            .map(|l| l.strip_suffix('\r').unwrap_or(l).to_string())
            .collect();
        if !rust {
            return Source {
                class: lines
                    .iter()
                    .map(|l| vec![Class::Code; l.chars().count()])
                    .collect(),
                lines,
                binds: Vec::new(),
                locals: HashSet::new(),
                toml: if toml { toml_keys(text) } else { Vec::new() },
                use_spans: Vec::new(),
                items: Vec::new(),
                code: Vec::new(),
                line_start: Vec::new(),
                scopes: Default::default(),
            };
        }
        let (mut class, code_text) = lex(text);
        for (c, l) in class.iter_mut().zip(&lines) {
            c.truncate(l.chars().count());
        }
        // char index -> (line, col)
        let mut starts = vec![0usize];
        for (i, c) in code_text.chars().enumerate() {
            if c == '\n' {
                starts.push(i + 1);
            }
        }
        let at = |i: usize| {
            let l = starts.partition_point(|&s| s <= i) - 1;
            (l + 1, i - starts[l])
        };
        let char_of = |b: usize| code_text[..b].chars().count();
        let use_spans = USE_ITEM
            .find_iter(&code_text)
            .map(|m| (at(char_of(m.start())), at(char_of(m.end()))))
            .collect();
        let chars: Vec<char> = code_text.chars().collect();
        let items = items(&chars)
            .into_iter()
            .map(|(kind, name, trait_name, a, b)| Item {
                kind,
                name,
                trait_name,
                start: at(a),
                end: at(b),
            })
            .collect();
        Source {
            lines,
            class,
            binds: bindings(&code_text),
            locals: locals(&code_text),
            toml: Vec::new(),
            use_spans,
            items,
            code: chars,
            line_start: starts,
            scopes: Default::default(),
        }
    }

    /// The index in `code` of (line, col) (1-based line, 0-based char column).
    fn idx(&self, at: (usize, usize)) -> usize {
        self.line_start
            .get(at.0.wrapping_sub(1))
            .map_or(self.code.len(), |s| s + at.1)
            .min(self.code.len())
    }

    /// The (line, col) of an index in `code`.
    fn pos(&self, i: usize) -> (usize, usize) {
        let l = self.line_start.partition_point(|&s| s <= i).max(1) - 1;
        (l + 1, i - self.line_start[l])
    }

    /// The code from `a` to `b` (indexes in `code`).
    fn text(&self, a: usize, b: usize) -> String {
        self.code[a.min(self.code.len())..b.min(self.code.len())]
            .iter()
            .collect()
    }

    /// An item's extent in `code`.
    fn span(&self, i: &Item) -> (usize, usize) {
        (self.idx(i.start), self.idx(i.end))
    }

    /// The source text (comments and literals kept) from `a` to `b`, indexes in `code`.
    fn orig(&self, a: usize, b: usize) -> String {
        let ((la, ca), (lb, cb)) = (self.pos(a), self.pos(b));
        let mut out = String::new();
        for l in la..=lb.min(self.lines.len()) {
            let chars: Vec<char> = self.lines[l - 1].chars().collect();
            let from = if l == la { ca } else { 0 };
            let to = if l == lb {
                cb.min(chars.len())
            } else {
                chars.len()
            };
            out.extend(&chars[from.min(to)..to]);
            if l != lb {
                out.push('\n');
            }
        }
        out
    }

    /// The innermost item of one of `kinds` that contains the position.
    fn enclosing(&self, at: (usize, usize), kinds: &[ItemKind]) -> Option<&Item> {
        self.items
            .iter()
            .filter(|i| kinds.contains(&i.kind) && i.contains(at))
            .max_by_key(|i| i.start)
    }
}

/// The items of a Rust file with comments and literals blanked: (kind, name, trait, start, end)
/// in chars. A keyword counts at an item's place (not `-> impl Trait`, `*const T`, `<const N>`,
/// `const { .. }`); a function without a body (a trait's declaration) has none.
#[allow(clippy::type_complexity)]
fn items(s: &[char]) -> Vec<(ItemKind, String, Option<String>, usize, usize)> {
    let word_at = |i: usize| -> String {
        s[i..]
            .iter()
            .take_while(|c| is_ident(**c))
            .collect::<String>()
    };
    let skip_ws = |mut i: usize| {
        while i < s.len() && s[i].is_whitespace() {
            i += 1;
        }
        i
    };
    // the code before `i`: its last non-blank char, and the word ending there
    let prev = |i: usize| s[..i].iter().rev().find(|c| !c.is_whitespace()).copied();
    let prev_word = |i: usize| -> String {
        let mut j = i;
        while j > 0 && s[j - 1].is_whitespace() {
            j -= 1;
        }
        let end = j;
        while j > 0 && is_ident(s[j - 1]) {
            j -= 1;
        }
        s[j..end].iter().collect()
    };
    // an item's place: after another item, a block's start, an attribute, a visibility or a
    // qualifier
    let item_place = |i: usize| {
        matches!(prev(i), None | Some('}' | ';' | '{' | ']' | ')'))
            || matches!(
                prev_word(i).as_str(),
                "pub" | "unsafe" | "default" | "extern" | "auto"
            )
    };
    // the matching close of the bracket at `open`
    let close_of = |open: usize| -> Option<usize> {
        let (o, c) = match s[open] {
            '{' => ('{', '}'),
            '(' => ('(', ')'),
            '[' => ('[', ']'),
            _ => return None,
        };
        let mut depth = 0;
        for (j, ch) in s.iter().enumerate().skip(open) {
            if *ch == o {
                depth += 1;
            } else if *ch == c {
                depth -= 1;
                if depth == 0 {
                    return Some(j + 1);
                }
            }
        }
        None
    };
    // from `i`, the first `{` (or `;` when `semi`) outside parentheses, brackets and generic
    // arguments: a body, or the end of a declaration
    let body_or_end = |i: usize| -> Option<(usize, bool)> {
        let mut depth = 0i32;
        let mut j = i;
        while j < s.len() {
            match s[j] {
                '(' | '[' => depth += 1,
                ')' | ']' => depth -= 1,
                '<' => depth += 1,
                '>' if j > 0 && s[j - 1] != '-' && s[j - 1] != '=' => depth -= 1,
                '{' if depth <= 0 => return Some((j, true)),
                ';' if depth <= 0 => return Some((j, false)),
                _ => {}
            }
            j += 1;
        }
        None
    };
    let last_segment = type_name;
    let mut out = Vec::new();
    let mut i = 0;
    while i < s.len() {
        if !is_ident(s[i]) || (i > 0 && is_ident(s[i - 1])) {
            i += 1;
            continue;
        }
        let w = word_at(i);
        let after = skip_ws(i + w.len());
        match w.as_str() {
            "fn" if after < s.len() && is_ident(s[after]) => {
                // a raw identifier (`fn r#type`) is named without its `r#`
                let raw = s.get(after + 1) == Some(&'#') && s[after] == 'r';
                let name = word_at(if raw { after + 2 } else { after });
                let len = name.len() + if raw { 2 } else { 0 };
                if let Some((b, true)) = body_or_end(after + len)
                    && let Some(e) = close_of(b)
                {
                    out.push((ItemKind::Fn, name, None, i, e));
                }
            }
            "static" | "const"
                if after < s.len()
                    && is_ident(s[after])
                    && item_place(i)
                    && !matches!(
                        word_at(after).as_str(),
                        "fn" | "unsafe" | "extern" | "async"
                    ) =>
            {
                let mut n = after;
                // `static mut X`, `lazy_static!`'s `static ref X`
                if matches!(word_at(n).as_str(), "mut" | "ref") {
                    n = skip_ws(n + word_at(n).len());
                }
                let name = word_at(n);
                // `static NAME: T = ..;`: to the `;` outside all brackets
                let mut depth = 0i32;
                let mut j = n;
                while j < s.len() {
                    match s[j] {
                        '(' | '[' | '{' => depth += 1,
                        ')' | ']' | '}' => depth -= 1,
                        ';' if depth == 0 => break,
                        _ => {}
                    }
                    if depth < 0 {
                        break;
                    }
                    j += 1;
                }
                if !name.is_empty() {
                    out.push((ItemKind::Static, name, None, i, (j + 1).min(s.len())));
                }
            }
            "impl" if item_place(i) && prev(i) != Some(')') => {
                if let Some((b, true)) = body_or_end(i + 4)
                    && let Some(e) = close_of(b)
                {
                    let mut header: String = s[i + 4..b].iter().collect();
                    // the impl's own generic parameters
                    let mut params = Vec::new();
                    if header.trim_start().starts_with('<') {
                        let h = header.trim_start().to_string();
                        let hc: Vec<char> = h.chars().collect();
                        let cls = vec![Class::Code; hc.len()];
                        if let Some(end) = skip_angle(&hc, &cls, 0) {
                            let inner: String = hc[1..end.saturating_sub(1)].iter().collect();
                            params = strip_generics(&inner)
                                .split(',')
                                .filter_map(|p| {
                                    let p = p.trim().trim_start_matches("const ").trim();
                                    let n: String =
                                        p.chars().take_while(|c| is_ident(*c)).collect();
                                    (!n.is_empty() && !p.starts_with('\'')).then_some(n)
                                })
                                .collect();
                        }
                        header = strip_generics(&h).to_string();
                    }
                    // blanks collapsed: a `where` or `for` may start a line
                    let one_line = |h: &str| h.split_whitespace().collect::<Vec<_>>().join(" ");
                    let header = one_line(&header);
                    let header = header.split(" where ").next().unwrap_or("").to_string();
                    let header_full: String = one_line(&s[i + 4..b].iter().collect::<String>());
                    let header_full = header_full
                        .split(" where ")
                        .next()
                        .unwrap_or("")
                        .to_string();
                    let (tr, ty) = match header.split_once(" for ") {
                        Some((_, y)) => {
                            // the trait with its arguments (`TryFrom<&PrivateKeyDer<'_>>`),
                            // unless they are the impl's own parameters: then its name
                            let t = header_full
                                .split_once(" for ")
                                .map(|(t, _)| t.trim().to_string())
                                .unwrap_or_default();
                            let t = if t.starts_with('<') {
                                let tc: Vec<char> = t.chars().collect();
                                let cls = vec![Class::Code; tc.len()];
                                skip_angle(&tc, &cls, 0)
                                    .map(|e| tc[e..].iter().collect::<String>())
                                    .unwrap_or(t)
                            } else {
                                t
                            };
                            let generic = re!(r"\w+")
                                .find_iter(&t)
                                .any(|m| params.iter().any(|p| p == m.as_str()));
                            let t = if generic {
                                last_segment(&t)
                            } else {
                                norm_path(&t)
                            };
                            (Some(t), y.to_string())
                        }
                        None => (None, header.clone()),
                    };
                    // a blanket impl (`impl<T: Foo> Bar for T`): any type, named by its trait
                    let ty = last_segment(&ty);
                    let ty = if params.contains(&ty) {
                        String::new()
                    } else if ty.starts_with(['(', '[']) {
                        // the impl's parameters in a tuple or array are any type or value
                        // (`[u8; N]`): `?`
                        re!(r"\b\w+\b")
                            .replace_all(&ty, |m: &regex::Captures| {
                                if params.iter().any(|p| p == &m[0]) {
                                    "?".to_string()
                                } else {
                                    m[0].to_string()
                                }
                            })
                            .to_string()
                    } else {
                        ty
                    };
                    out.push((ItemKind::Impl, ty, tr, i, e));
                }
            }
            "struct" | "enum" | "union" | "type"
                if after < s.len() && is_ident(s[after]) && item_place(i) =>
            {
                out.push((ItemKind::TypeDef, word_at(after), None, i, i + w.len()));
            }
            "trait" | "mod" if after < s.len() && is_ident(s[after]) && item_place(i) => {
                let name = word_at(after);
                if let Some((b, true)) = body_or_end(after + name.len())
                    && let Some(e) = close_of(b)
                {
                    let kind = if w == "trait" {
                        ItemKind::Trait
                    } else {
                        ItemKind::Mod
                    };
                    out.push((kind, name, None, i, e));
                }
            }
            "macro_rules" if s.get(after) == Some(&'!') => {
                let n = skip_ws(after + 1);
                let name = word_at(n);
                let b = skip_ws(n + name.len());
                if b < s.len()
                    && let Some(e) = close_of(b)
                {
                    // the body: inside its brackets
                    out.push((ItemKind::Macro, name, None, b, e));
                }
            }
            // `name! (..)`, `name! [..]`, `name! { .. }`
            _ if after < s.len()
                && s[after] == '!'
                && w != "macro_rules"
                && s.get(skip_ws(after + 1))
                    .is_some_and(|c| matches!(c, '(' | '[' | '{')) =>
            {
                let b = skip_ws(after + 1);
                if let Some(e) = close_of(b) {
                    out.push((ItemKind::MacroCall, w.clone(), None, b, e));
                }
            }
            _ => {}
        }
        i += w.len().max(1);
    }
    out
}

struct Files<'a> {
    man: &'a rcbom_manifest::Manifest,
    kb: &'a Kb,
    externs: Option<Externs>,
    libs: Option<Libs>,
    /// The pinned toolchain's sysroot and commit, for `/rustc/<commit>/library/..` locations;
    /// read when first needed
    toolchain: Option<Option<(PathBuf, String)>>,
    cache: HashMap<PathBuf, Option<Rc<Source>>>,
    /// the `use` bindings of every Rust file of a package, by package directory
    pkg_binds: HashMap<PathBuf, Rc<Vec<Binding>>>,
    /// the type aliases of a package, by package directory: name -> what they stand for
    pkg_aliases: HashMap<PathBuf, Rc<HashMap<String, Vec<String>>>>,
    /// the root files of every target of the build (`src/lib.rs`, `src/bin/x.rs`), from
    /// `cargo metadata`
    roots: Option<Vec<PathBuf>>,
    /// a package's `#[path = ".."] mod name;` declarations, by package directory: (declaring
    /// file, the file named, the module's name); and the files an `include!` reads
    pkg_mods: HashMap<PathBuf, Rc<PkgMods>>,
    /// standard-library paths checked (`std_item`)
    std_items: HashMap<String, bool>,
    occs: &'a [Occ],
    at_pos: HashMap<(String, usize, usize), Vec<usize>>,
    at_line: HashMap<(String, usize), Vec<usize>>,
    /// (location, line, column) -> the assets whose details cite it (`instantiated by X at
    /// F:L:C`)
    cited: HashMap<(String, usize, usize), HashSet<String>>,
    graph: Graph,
    /// the type arguments of the generic function's instance the occurrence being checked is
    /// in, by the function's type parameters (`Reads::inst`)
    inst: Vec<(String, String)>,
    /// the argument of the occurrence's call that carries the algorithm (`alg_arg`)
    alg_arg: Option<usize>,
}

fn strip_generics(s: &str) -> String {
    let re = re!(r"<[^<>]*>");
    let mut s = s.to_string();
    loop {
        let n = re.replace_all(&s, "").to_string();
        if n == s {
            return s;
        }
        s = n;
    }
}

fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Classifies each char of a Rust source: in a `//` or `/* */` comment (nested), in a string
/// literal (`"..."`, `b".."`, `c".."`, raw `r#".."#`) or a char literal, or code.
fn classify(text: &str) -> Vec<Class> {
    let chars: Vec<char> = text.chars().collect();
    let mut class = vec![Class::Code; chars.len()];
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        let prev_ident = i > 0 && is_ident(chars[i - 1]);
        if c == '/' && next == Some('/') {
            while i < chars.len() && chars[i] != '\n' {
                class[i] = Class::Comment;
                i += 1;
            }
        } else if c == '/' && next == Some('*') {
            let mut depth = 0;
            while i < chars.len() {
                if chars[i] == '/' && chars.get(i + 1) == Some(&'*') {
                    depth += 1;
                    class[i] = Class::Comment;
                    class[i + 1] = Class::Comment;
                    i += 2;
                } else if chars[i] == '*' && chars.get(i + 1) == Some(&'/') {
                    depth -= 1;
                    class[i] = Class::Comment;
                    class[i + 1] = Class::Comment;
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    class[i] = Class::Comment;
                    i += 1;
                }
            }
        } else if !prev_ident && (c == 'r' || ((c == 'b' || c == 'c') && next == Some('r'))) && {
            // raw string: r#*"
            let mut j = i + if c == 'r' { 1 } else { 2 };
            while chars.get(j) == Some(&'#') {
                j += 1;
            }
            chars.get(j) == Some(&'"')
        } {
            let mut j = i + if c == 'r' { 1 } else { 2 };
            let mut hashes = 0;
            while chars[j] == '#' {
                hashes += 1;
                j += 1;
            }
            j += 1; // opening quote
            loop {
                if j >= chars.len() {
                    break;
                }
                if chars[j] == '"' && (0..hashes).all(|k| chars.get(j + 1 + k) == Some(&'#')) {
                    j += 1 + hashes;
                    break;
                }
                j += 1;
            }
            for k in class.iter_mut().take(j.min(chars.len())).skip(i) {
                *k = Class::Literal;
            }
            i = j;
        } else if c == '"' {
            let mut j = i + 1;
            while j < chars.len() && chars[j] != '"' {
                if chars[j] == '\\' {
                    j += 1;
                }
                j += 1;
            }
            let end = (j + 1).min(chars.len());
            for k in class.iter_mut().take(end).skip(i) {
                *k = Class::Literal;
            }
            i = end;
        } else if c == '\'' {
            // char literal, or a lifetime / label (code)
            let end = if next == Some('\\') {
                // skip the backslash and the escaped char (`'\''`), then find the closing quote
                let mut j = i + 3;
                while j < chars.len() && chars[j] != '\'' && chars[j] != '\n' {
                    j += 1;
                }
                Some(j + 1)
            } else if next.is_some() && next != Some('\n') && chars.get(i + 2) == Some(&'\'') {
                Some(i + 3)
            } else {
                None
            };
            match end {
                Some(e) => {
                    let e = e.min(chars.len());
                    for k in class.iter_mut().take(e).skip(i) {
                        *k = Class::Literal;
                    }
                    i = e;
                }
                None => i += 1,
            }
        } else {
            i += 1;
        }
    }
    class
}

/// Per line, per char: the class of each char of a Rust source; and the file with comments and
/// literals blanked, for finding `use` items.
fn lex(text: &str) -> (Vec<Vec<Class>>, String) {
    let class = classify(text);
    let mut per_line = vec![Vec::new()];
    let mut blank = String::with_capacity(text.len());
    for (c, k) in text.chars().zip(class) {
        if c == '\n' {
            per_line.push(Vec::new());
            blank.push('\n');
        } else {
            per_line.last_mut().unwrap().push(k);
            blank.push(if k == Class::Code { c } else { ' ' });
        }
    }
    (per_line, blank)
}

/// Skips a balanced `<...>` starting at `i` (which must be `<`); `->` does not close, and
/// brackets in comments and literals do not count.
fn skip_angle(s: &[char], cls: &[Class], mut i: usize) -> Option<usize> {
    let mut depth = 0;
    while i < s.len() {
        if cls[i] == Class::Code {
            match s[i] {
                '<' => depth += 1,
                '>' if i > 0 && s[i - 1] == '-' => {}
                '>' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(i + 1);
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }
    None
}

/// Skips whitespace, line breaks and comments.
fn ws(s: &[char], cls: &[Class], mut i: usize) -> usize {
    while i < s.len() && (s[i].is_whitespace() || cls[i] == Class::Comment) {
        i += 1;
    }
    i
}

/// The path at the start of `at`: `(<T as Tr>::)? ::? (seg (::<..>)? ::)* last`, as its idents
/// (qualifiers first) and the final segment; raw identifiers (`r#digest`) without their `r#`.
/// Whitespace, line breaks and comments between tokens are allowed (rustfmt breaks long
/// turbofishes and qualified paths). None if `at` does not start with a path.
#[cfg(test)]
fn path_at(at: &str) -> Option<(Vec<String>, String)> {
    let s: Vec<char> = at.chars().collect();
    path_and_generics(&s, &classify(at)).map(|(q, l, _)| (q, l))
}

/// Like `path_at`, on chars and their classes, plus the first segment of every path written
/// inside the generic arguments (`Hmac::<sha2::Sha256>::new` gives `sha2`).
fn path_and_generics(s: &[char], cls: &[Class]) -> Option<(Vec<String>, String, Vec<String>)> {
    let mut generics: Vec<String> = Vec::new();
    let mut heads = |from: usize, to: usize| {
        let mut k = from;
        while k < to {
            if cls[k] != Class::Code || !is_ident(s[k]) || s[k].is_ascii_digit() {
                k += 1;
                continue;
            }
            let mut st = k;
            while k < to && cls[k] == Class::Code && is_ident(s[k]) {
                k += 1;
            }
            // `r#Type`
            if k - st == 1 && s[st] == 'r' && s.get(k) == Some(&'#') {
                st = k + 1;
                k = st;
                while k < to && cls[k] == Class::Code && is_ident(s[k]) {
                    k += 1;
                }
                if k == st {
                    continue;
                }
            }
            // the code chars before: not after `::` (a later segment) or `'` (a lifetime)
            let mut before = Vec::new();
            let mut b = st;
            while b > from && before.len() < 2 {
                b -= 1;
                if cls[b] == Class::Code && !s[b].is_whitespace() {
                    before.push(s[b]);
                } else if cls[b] == Class::Literal {
                    break;
                }
            }
            if before != [':', ':'] && before.first() != Some(&'\'') {
                generics.push(s[st..k].iter().collect());
            }
        }
    };
    let colons = |i: usize| {
        s.get(i) == Some(&':')
            && s.get(i + 1) == Some(&':')
            && cls[i] == Class::Code
            && cls[i + 1] == Class::Code
    };
    let ident_at = |i: usize| s.get(i).is_some_and(|&c| is_ident(c)) && cls[i] == Class::Code;
    // a segment: an identifier, or a raw identifier; its name and end
    let segment = |i: usize| -> Option<(String, usize)> {
        let start = if s.get(i) == Some(&'r') && s.get(i + 1) == Some(&'#') && ident_at(i + 2) {
            i + 2
        } else {
            i
        };
        let mut e = start;
        while ident_at(e) {
            e += 1;
        }
        (e > start).then(|| (s[start..e].iter().collect(), e))
    };
    let mut i = 0;
    if s.first() == Some(&'<') {
        let close = skip_angle(s, cls, 0)?;
        heads(1, close - 1);
        i = ws(s, cls, close);
        if !colons(i) {
            return None;
        }
        i = ws(s, cls, i + 2);
    } else if colons(0) {
        // `::sha2::Sha256`: a crate named from the root
        i = ws(s, cls, 2);
    }
    let mut segs = Vec::new();
    loop {
        let (seg, end) = segment(i)?;
        segs.push(seg);
        // `::<..>` turbofish
        let mut j = ws(s, cls, end);
        if colons(j) && s.get(ws(s, cls, j + 2)) == Some(&'<') {
            let open = ws(s, cls, j + 2);
            let close = skip_angle(s, cls, open)?;
            heads(open + 1, close - 1);
            j = ws(s, cls, close);
        }
        if colons(j) && segment(ws(s, cls, j + 2)).is_some() {
            i = ws(s, cls, j + 2);
            continue;
        }
        let last = segs.pop().unwrap();
        return Some((segs, last, generics));
    }
}

/// Whether a token starts at `col` of `line` (1-based): not inside an identifier (nor after the
/// `r#` of a raw identifier), and not after `::`, with whitespace and comments in between: a
/// path is cited at its first segment. A single `:` (`W { n:Sha256::digest(d) }`) does not
/// continue a path.
fn token_start(src: &Source, line: usize, col: usize) -> bool {
    let Some(text) = src.lines.get(line.wrapping_sub(1)) else {
        return false;
    };
    let chars: Vec<char> = text.chars().collect();
    let before = |k: usize| col.checked_sub(k).and_then(|i| chars.get(i)).copied();
    if before(1).is_some_and(is_ident) {
        return false;
    }
    if before(1) == Some('#') && before(2) == Some('r') && !before(3).is_some_and(is_ident) {
        return false;
    }
    // the two code (or literal) chars before, whitespace and comments skipped, over a few lines
    let mut prev = Vec::new();
    let (mut l, mut c) = (line - 1, col.min(chars.len()));
    loop {
        let lc: Vec<char> = src.lines[l].chars().collect();
        while c > 0 && prev.len() < 2 {
            c -= 1;
            let comment = src.class[l].get(c) == Some(&Class::Comment);
            if !comment && !lc[c].is_whitespace() {
                prev.push(lc[c]);
            }
        }
        if prev.len() == 2 || l == 0 || line - 1 - l >= 8 {
            break;
        }
        l -= 1;
        c = src.lines[l].chars().count();
    }
    prev != [':', ':']
}

/// The parts of an occurrence's context: the leading `[..]` tags, the details, and the source
/// line and text the generator recorded last.
struct Ctx<'a> {
    tags: &'a str,
    details: &'a str,
    line: Option<&'a str>,
    code: Option<&'a str>,
}

/// Reads a context back: the code text first, as the backquoted text at the very end; the line
/// is then what remains between `line: `` and the last backquote (it may hold backquotes).
fn split_context(ctx: &str) -> Ctx<'_> {
    let tags = re!(r"^(?:\[[^\[\]]*\] ?)*")
        .find(ctx)
        .map_or("", |m| m.as_str());
    let (before_code, code) = match re!(r"; code: `([^`]*)`$").captures(ctx) {
        Some(m) => (
            &ctx[..m.get(0).map_or(0, |g| g.start())],
            m.get(1).map(|g| g.as_str()),
        ),
        None => (ctx, None),
    };
    let (details, line) = match re!(r"; line: `(.*)`$").captures(before_code) {
        Some(m) => (
            &before_code[..m.get(0).map_or(0, |g| g.start())],
            m.get(1).map(|g| g.as_str()),
        ),
        None => (before_code, None),
    };
    Ctx {
        tags,
        details,
        line,
        code,
    }
}

/// Whether `name` is a more specific name `parent` was merged into on a line (the generator
/// merges `PBKDF2-SHA-256` into `PBKDF2-SHA-256-1000-32`, and the family name `Argon2` into
/// `Argon2id-19456-2-1`): strictly longer, at a `-` boundary, or extending the family name it
/// belongs to.
fn extends(name: &str, parent: &str, family: Option<&str>) -> bool {
    name.len() > parent.len()
        && name.starts_with(parent)
        && (name[parent.len()..].starts_with('-') || family == Some(parent))
}

/// The (name, version) of the package a component's manifest evidence is of: a package
/// (`pkg:cargo/<name>@<version>`), or the package a candidate algorithm is declared through
/// (`crypto:candidate:<name>@<version>:<asset>`).
fn package_of(component: &str) -> Option<(&str, &str)> {
    if let Some(c) = component.strip_prefix("crypto:candidate:") {
        let (nv, _) = c.split_once(':')?;
        return nv.split_once('@');
    }
    component.strip_prefix("pkg:cargo/")?.split_once('@')
}

/// A `Cargo.lock` position: the `name = "<symbol>"` line, at column 0, whose next line is the
/// version the context names (`locked sha2 0.10.9; ..`), which is the package the occurrence
/// is evidence of: two locked versions are told apart.
fn check_lock(
    lines: &[String],
    line: usize,
    offset: usize,
    symbol: &str,
    context: &str,
    component: &str,
) -> Result<(), String> {
    let m = re!(r"^\[manifest\] locked (\S+) (\S+);")
        .captures(context)
        .ok_or("a Cargo.lock occurrence whose context names no locked package")?;
    if &m[1] != symbol {
        return Err(format!("the context names {}, the symbol {symbol}", &m[1]));
    }
    if package_of(component) != Some((&m[1], &m[2])) {
        return Err(format!(
            "the context names {} {}, but this is evidence of {component}",
            &m[1], &m[2]
        ));
    }
    let text = lines.get(line.wrapping_sub(1)).ok_or("line out of range")?;
    let want = format!("name = \"{symbol}\"");
    let version = format!("version = \"{}\"", &m[2]);
    if offset == 0 && *text == want && lines.get(line).is_some_and(|l| *l == version) {
        Ok(())
    } else {
        Err(format!(
            "expected `{want}` at column 0, then `{version}`, in {text:?}"
        ))
    }
}

/// A key segment of a TOML document: where it starts (1-based line, 0-based char column; a
/// quoted key at its opening quote), the full path of keys it ends (table header and dotted
/// prefix included), and, for the last key of a key/value pair, its value if a string.
#[derive(Clone, Debug, PartialEq, Eq)]
struct TomlKey {
    line: usize,
    col: usize,
    path: Vec<String>,
    value: Option<String>,
}

/// Enough of a TOML lexer to know comments, strings, table headers and keys.
struct Toml {
    s: Vec<char>,
    i: usize,
    line: usize,
    col: usize,
    keys: Vec<TomlKey>,
}

/// Every key of a TOML document, with where it starts and its full path.
fn toml_keys(text: &str) -> Vec<TomlKey> {
    let mut t = Toml {
        s: text.chars().collect(),
        i: 0,
        line: 1,
        col: 0,
        keys: Vec::new(),
    };
    if t.peek(0) == Some('\u{feff}') {
        t.bump();
    }
    t.document();
    t.keys
}

impl Toml {
    fn peek(&self, k: usize) -> Option<char> {
        self.s.get(self.i + k).copied()
    }

    fn bump(&mut self) {
        if let Some(c) = self.peek(0) {
            if c == '\n' {
                self.line += 1;
                self.col = 0;
            } else {
                self.col += 1;
            }
            self.i += 1;
        }
    }

    fn eat(&mut self, c: char) -> bool {
        let ok = self.peek(0) == Some(c);
        if ok {
            self.bump();
        }
        ok
    }

    /// spaces and tabs
    fn blank(&mut self) {
        while matches!(self.peek(0), Some(' ' | '\t')) {
            self.bump();
        }
    }

    /// whitespace, line breaks and comments
    fn skip(&mut self) {
        loop {
            match self.peek(0) {
                Some(' ' | '\t' | '\r' | '\n') => self.bump(),
                Some('#') => self.rest_of_line(),
                _ => return,
            }
        }
    }

    fn rest_of_line(&mut self) {
        while self.peek(0).is_some_and(|c| c != '\n') {
            self.bump();
        }
    }

    fn triple(&self, q: char) -> bool {
        (0..3).all(|k| self.peek(k) == Some(q))
    }

    /// A basic (`"`) or literal (`'`) string at the cursor; its text if it is on one line.
    fn string(&mut self) -> Option<String> {
        let q = self.peek(0)?;
        if self.triple(q) {
            (0..3).for_each(|_| self.bump());
            loop {
                match self.peek(0) {
                    None => return None,
                    Some('\\') if q == '"' => {
                        self.bump();
                        self.bump();
                    }
                    Some(c) if c == q && self.triple(q) => {
                        (0..3).for_each(|_| self.bump());
                        // up to two more quotes end the content
                        for _ in 0..2 {
                            self.eat(q);
                        }
                        return None;
                    }
                    _ => self.bump(),
                }
            }
        }
        self.bump();
        let mut out = String::new();
        loop {
            match self.peek(0) {
                None | Some('\n') => return None,
                Some(c) if c == q => {
                    self.bump();
                    return Some(out);
                }
                Some('\\') if q == '"' => {
                    self.bump();
                    let e = self.peek(0)?;
                    self.bump();
                    match e {
                        'n' => out.push('\n'),
                        't' => out.push('\t'),
                        'r' => out.push('\r'),
                        'b' => out.push('\u{8}'),
                        'f' => out.push('\u{c}'),
                        'e' => out.push('\u{1b}'),
                        '"' | '\\' => out.push(e),
                        'x' | 'u' | 'U' => {
                            let n = match e {
                                'x' => 2,
                                'u' => 4,
                                _ => 8,
                            };
                            let mut h = String::new();
                            for _ in 0..n {
                                h.push(self.peek(0)?);
                                self.bump();
                            }
                            out.push(char::from_u32(u32::from_str_radix(&h, 16).ok()?)?);
                        }
                        _ => return None,
                    }
                }
                Some(c) => {
                    out.push(c);
                    self.bump();
                }
            }
        }
    }

    /// One segment of a key, bare (`A-Za-z0-9_-`) or quoted, and where it starts.
    fn segment(&mut self) -> Option<(usize, usize, String)> {
        let (line, col) = (self.line, self.col);
        match self.peek(0)? {
            q @ ('"' | '\'') if !self.triple(q) => Some((line, col, self.string()?)),
            c if c.is_ascii_alphanumeric() || c == '_' || c == '-' => {
                let mut s = String::new();
                while let Some(c) = self
                    .peek(0)
                    .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
                {
                    s.push(c);
                    self.bump();
                }
                Some((line, col, s))
            }
            _ => None,
        }
    }

    /// A dotted key; blanks around the dots.
    fn key(&mut self) -> Option<Vec<(usize, usize, String)>> {
        let mut segs = vec![self.segment()?];
        loop {
            self.blank();
            if !self.eat('.') {
                return Some(segs);
            }
            self.blank();
            segs.push(self.segment()?);
        }
    }

    fn record(&mut self, prefix: &[String], segs: &[(usize, usize, String)]) -> Vec<String> {
        let mut path = prefix.to_vec();
        for (line, col, s) in segs {
            path.push(s.clone());
            self.keys.push(TomlKey {
                line: *line,
                col: *col,
                path: path.clone(),
                value: None,
            });
        }
        path
    }

    fn document(&mut self) {
        let mut table: Vec<String> = Vec::new();
        loop {
            self.skip();
            let at = self.i;
            match self.peek(0) {
                None => return,
                Some('[') => {
                    self.bump();
                    let array = self.eat('[');
                    self.blank();
                    // what follows a malformed header belongs to no table of interest
                    table = vec!["<malformed>".into()];
                    if let Some(segs) = self.key() {
                        let path = self.record(&[], &segs);
                        self.blank();
                        if self.eat(']') && (!array || self.eat(']')) {
                            table = path;
                        }
                    }
                    self.rest_of_line();
                }
                Some(_) => {
                    if !self.keyval(&table) {
                        self.rest_of_line();
                    }
                }
            }
            if self.i == at {
                self.bump();
            }
        }
    }

    fn keyval(&mut self, prefix: &[String]) -> bool {
        let Some(segs) = self.key() else {
            return false;
        };
        let path = self.record(prefix, &segs);
        let k = self.keys.len() - 1;
        self.blank();
        if !self.eat('=') {
            return false;
        }
        self.blank();
        self.keys[k].value = self.value(&path);
        true
    }

    fn value(&mut self, path: &[String]) -> Option<String> {
        match self.peek(0)? {
            '"' | '\'' => self.string(),
            '[' => {
                self.bump();
                // the elements' keys are not keys of the table
                let mut inner = path.to_vec();
                inner.push("[]".into());
                loop {
                    self.skip();
                    match self.peek(0) {
                        None => break,
                        Some(']') => {
                            self.bump();
                            break;
                        }
                        Some(',') => self.bump(),
                        Some(_) => {
                            let at = self.i;
                            self.value(&inner);
                            if self.i == at {
                                self.bump();
                            }
                        }
                    }
                }
                None
            }
            '{' => {
                self.bump();
                loop {
                    self.skip();
                    match self.peek(0) {
                        None => break,
                        Some('}') => {
                            self.bump();
                            break;
                        }
                        Some(',') => self.bump(),
                        Some(_) => {
                            let at = self.i;
                            if !self.keyval(path) && self.i == at {
                                self.bump();
                            }
                        }
                    }
                }
                None
            }
            _ => {
                while self
                    .peek(0)
                    .is_some_and(|c| !matches!(c, ',' | ']' | '}' | '#' | '\n'))
                {
                    self.bump();
                }
                None
            }
        }
    }
}

/// A `Cargo.toml` position: the start of a key (a quoted key at its opening quote, as the
/// generator writes it) whose last segment is the symbol, and:
/// - `declared by P (K)`: a dependency key in `[K]` (`[K] sym = ..`, `[K.sym]`, `K.sym = ..`,
///   `sym.version = ..`) or `[target.<platform>.K]`, in the manifest of package P, that names
///   the package the occurrence is evidence of: its name (`package = ..` if renamed), and a
///   version requirement its version meets;
/// - `native library `L``: the `links` key of `[package]`, with value L, in the manifest of the
///   package the occurrence is evidence of.
fn check_toml(
    keys: &[TomlKey],
    text: &str,
    line: usize,
    offset: usize,
    symbol: &str,
    context: &str,
    component: &str,
) -> Result<(), String> {
    let (cname, cversion) = package_of(component)
        .ok_or_else(|| format!("a manifest occurrence of {component}, not a package"))?;
    let k = keys
        .iter()
        .find(|k| k.line == line && k.col == offset)
        .ok_or_else(|| format!("no key of `{symbol}` starts at this position in {text:?}"))?;
    let path: Vec<&str> = k.path.iter().map(String::as_str).collect();
    let dotted = path.join(".");
    if path.last() != Some(&symbol) {
        return Err(format!("the key here is `{dotted}`, not `{symbol}`"));
    }
    if let Some(m) = re!(r"^\[manifest\] declared by (\S+) \(([\w-]+)\)(?:;|$)").captures(context) {
        let (pkg, kind) = (&m[1], &m[2]);
        let in_table = match path.as_slice() {
            [t, _] | ["target", _, t, _] => *t == kind,
            _ => false,
        };
        if !in_table {
            return Err(format!(
                "the key here is `{dotted}`, not in [{kind}] or [target.<platform>.{kind}]"
            ));
        }
        let name = keys
            .iter()
            .find(|k| k.path == ["package", "name"])
            .and_then(|k| k.value.as_deref());
        if name != Some(pkg) {
            return Err(format!(
                "this is the manifest of {}, not of {pkg}",
                name.unwrap_or("no package")
            ));
        }
        // the dependency this key declares: its package and version requirement
        let field = |f: &str| {
            keys.iter().find(|x| {
                x.path.len() == k.path.len() + 1
                    && x.path.starts_with(&k.path)
                    && x.path.last().is_some_and(|l| l == f)
            })
        };
        let package = field("package")
            .and_then(|x| x.value.as_deref())
            .unwrap_or(symbol);
        if package != cname {
            return Err(format!(
                "the key here declares {package}, but this is evidence of {component}"
            ));
        }
        let req = k
            .value
            .as_deref()
            .or_else(|| field("version").and_then(|x| x.value.as_deref()));
        if let Some(req) = req
            && let (Ok(req), Ok(v)) = (
                semver::VersionReq::parse(req),
                semver::Version::parse(cversion),
            )
            && !req.matches(&v)
        {
            return Err(format!(
                "the key here requires {package} {req}, but this is evidence of {component}"
            ));
        }
        Ok(())
    } else if let Some(m) = re!(r"^\[manifest\] native library `([^`]*)`").captures(context) {
        if path != ["package", "links"] || k.value.as_deref() != Some(&m[1]) {
            return Err(format!(
                "expected `links = \"{}\"` in [package], found `{dotted}`",
                &m[1]
            ));
        }
        let name = keys
            .iter()
            .find(|k| k.path == ["package", "name"])
            .and_then(|k| k.value.as_deref());
        if name != Some(cname) {
            return Err(format!(
                "this is the manifest of {}, but this is evidence of {component}",
                name.unwrap_or("no package")
            ));
        }
        Ok(())
    } else {
        Err(format!("unrecognized manifest context {context:?}"))
    }
}

/// A `use` or `extern crate` item, in a source with comments and literals blanked.
static USE_ITEM: std::sync::LazyLock<Regex> =
    std::sync::LazyLock::new(|| Regex::new(r"(?s)\b(?:use|extern\s+crate)\s[^;]*;").unwrap());

/// Every name the `use` and `extern crate` items of a source bind (comments and literals
/// blanked: `as` renames there, not in casts).
fn bindings(code_text: &str) -> Vec<Binding> {
    USE_ITEM
        .find_iter(code_text)
        .flat_map(|m| use_bindings(m.as_str()))
        .collect()
}

/// The names one item binds: `use a::{b::c as d, e, f::*};` binds `d` (to `a::b::c`) and `e`
/// (to `a::e`); `extern crate x as y;` binds `y` to `x`. `as _` and globs bind no name.
fn use_bindings(item: &str) -> Vec<Binding> {
    let s: Vec<char> = item.chars().collect();
    let mut toks: Vec<String> = Vec::new();
    let mut i = 0;
    while i < s.len() {
        let c = s[i];
        if c.is_whitespace() {
            i += 1;
        } else if c == ':' && s.get(i + 1) == Some(&':') {
            toks.push("::".into());
            i += 2;
        } else if is_ident(c) || c == '$' {
            let st = if c == 'r' && s.get(i + 1) == Some(&'#') {
                i + 2
            } else {
                i
            };
            let mut e = st.max(i + 1);
            while e < s.len() && is_ident(s[e]) {
                e += 1;
            }
            toks.push(s[st..e].iter().collect());
            i = e;
        } else {
            toks.push(c.to_string());
            i += 1;
        }
    }
    let mut out = Vec::new();
    let t = |k: usize| toks.get(k).map_or("", String::as_str);
    if t(0) == "extern" && t(1) == "crate" {
        let name = if t(3) == "as" { t(4) } else { t(2) };
        if !name.is_empty() && name != "_" {
            out.push(Binding {
                name: name.into(),
                path: vec![t(2).into()],
            });
        }
        return out;
    }
    if t(0) == "use" {
        let mut k = 1;
        use_tree(&toks, &mut k, &mut Vec::new(), &mut out);
    }
    out
}

fn use_tree(toks: &[String], k: &mut usize, prefix: &mut Vec<String>, out: &mut Vec<Binding>) {
    let start = prefix.len();
    let t = |k: usize| toks.get(k).map_or("", String::as_str);
    if t(*k) == "::" {
        *k += 1;
    }
    loop {
        match t(*k) {
            "{" => {
                *k += 1;
                loop {
                    if t(*k) == "}" {
                        *k += 1;
                        break;
                    }
                    let at = *k;
                    use_tree(toks, k, prefix, out);
                    if t(*k) == "," {
                        *k += 1;
                    } else if t(*k) == "}" {
                        *k += 1;
                        break;
                    } else if *k == at || *k >= toks.len() {
                        break;
                    }
                }
                break;
            }
            "*" => {
                *k += 1;
                break;
            }
            id if id.chars().next().is_some_and(|c| is_ident(c) || c == '$') => {
                prefix.push(id.to_string());
                *k += 1;
                if t(*k) == "::" {
                    *k += 1;
                    continue;
                }
                // `a::b::{self}` binds `b`
                let mut path = prefix.clone();
                if path.last().is_some_and(|l| l == "self") && path.len() > 1 {
                    path.pop();
                }
                let name = if t(*k) == "as" {
                    *k += 2;
                    t(*k - 1).to_string()
                } else {
                    path.last().cloned().unwrap_or_default()
                };
                if !name.is_empty() && name != "_" {
                    out.push(Binding { name, path });
                }
                break;
            }
            _ => break,
        }
    }
    prefix.truncate(start);
}

/// The names a source defines as types, traits or modules, or declares as generic parameters
/// (`fn f<D: Digest>`, `impl<T>`): such a name may shadow an import.
fn locals(code_text: &str) -> HashSet<String> {
    let mut out: HashSet<String> = re!(r"\b(?:struct|enum|union|type|trait|mod)\s+(?:r#)?(\w+)")
        .captures_iter(code_text)
        .map(|c| c[1].to_string())
        .collect();
    for m in
        re!(r"\b(?:(?:fn|struct|enum|union|trait|type)\s+(?:r#)?\w+|impl)\s*<").find_iter(code_text)
    {
        let s: Vec<char> = code_text[m.end() - 1..].chars().take(4000).collect();
        let cls = vec![Class::Code; s.len()];
        let Some(end) = skip_angle(&s, &cls, 0) else {
            continue;
        };
        // the parameters, split at top-level commas
        let mut depth = 0i32;
        let mut params = vec![String::new()];
        for k in 1..end - 1 {
            match s[k] {
                '<' | '(' | '[' => depth += 1,
                '>' if s[k - 1] != '-' => depth -= 1,
                ')' | ']' => depth -= 1,
                ',' if depth == 0 => {
                    params.push(String::new());
                    continue;
                }
                _ => {}
            }
            params.last_mut().unwrap().push(s[k]);
        }
        for p in params {
            let p = p.trim();
            let p = p.strip_prefix("const ").unwrap_or(p).trim_start();
            let name: String = p.chars().take_while(|&c| is_ident(c)).collect();
            if !name.is_empty() {
                out.insert(name);
            }
        }
    }
    out
}

/// The first segments of the paths the imports bind `name` to (`use sha2::Sha256 as H;` gives
/// `sha2` for `H`; two imports of `H` from different crates give both), or `name` itself when
/// no import binds it. None when an import is relative to this crate (`crate::`, `self::`,
/// `super::`).
fn import_roots(binds: &[Binding], name: &str) -> Option<BTreeSet<String>> {
    let mut roots = BTreeSet::new();
    for b in binds.iter().filter(|b| b.name == name) {
        let head = b.path.first()?;
        if matches!(
            head.as_str(),
            "crate" | "self" | "super" | "Self" | "$crate"
        ) {
            return None;
        }
        roots.insert(head.clone());
    }
    if roots.is_empty() {
        roots.insert(name.to_string());
    }
    Some(roots)
}

/// Every Rust file under a package's directory, not in `target/`, a hidden directory or
/// another package's directory.
fn package_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd.flatten() {
            let p = e.path();
            let name = e.file_name().to_string_lossy().to_string();
            let Ok(ft) = e.file_type() else {
                continue;
            };
            if ft.is_dir() {
                if name != "target" && !name.starts_with('.') && !p.join("Cargo.toml").exists() {
                    stack.push(p);
                }
            } else if name.ends_with(".rs") {
                out.push(p);
            }
        }
    }
    out
}

impl Files<'_> {
    fn source(&mut self, path: &Path) -> Option<Rc<Source>> {
        self.cache
            .entry(path.to_path_buf())
            .or_insert_with(|| {
                let mut t = std::fs::read_to_string(path).ok()?;
                let rust = path.extension().is_some_and(|e| e == "rs");
                // rustc drops a byte-order mark before counting columns
                if rust && t.starts_with('\u{feff}') {
                    t.remove(0);
                }
                let toml = path.file_name().is_some_and(|n| n == "Cargo.toml");
                Some(Rc::new(Source::new(&t, rust, toml)))
            })
            .clone()
    }

    /// The `use` bindings of every Rust file of the package in `dir`: an alias may be defined
    /// in one file (`pub use ring::digest::digest as hash_it;` in `src/algs.rs`) and used in
    /// another.
    fn package_binds(&mut self, dir: &Path) -> Rc<Vec<Binding>> {
        if let Some(b) = self.pkg_binds.get(dir) {
            return b.clone();
        }
        let mut out = Vec::new();
        for f in package_files(dir) {
            if let Ok(t) = std::fs::read_to_string(&f)
                && re!(r"\sas\s").is_match(&t)
            {
                out.extend(bindings(&lex(&t).1));
            }
        }
        let b = Rc::new(out);
        self.pkg_binds.insert(dir.to_path_buf(), b.clone());
        b
    }

    /// The type aliases the Rust files of the package in `dir` define (`pub type Sha256 =
    /// CoreWrapper<..>;`): name -> the types they stand for, as `norm_path` writes them. Only
    /// aliases without generic parameters.
    fn package_aliases(&mut self, dir: &Path) -> Rc<HashMap<String, Vec<String>>> {
        if let Some(a) = self.pkg_aliases.get(dir) {
            return a.clone();
        }
        let mut out: HashMap<String, Vec<String>> = HashMap::new();
        for f in package_files(dir) {
            let Ok(t) = std::fs::read_to_string(&f) else {
                continue;
            };
            for m in re!(r"\btype\s+(\w+)\s*=\s*([^;{}]+);").captures_iter(&t) {
                out.entry(m[1].to_string())
                    .or_default()
                    .push(norm_path(&m[2]));
            }
        }
        let a = Rc::new(out);
        self.pkg_aliases.insert(dir.to_path_buf(), a.clone());
        a
    }

    /// Whether a standard-library path (`core::convert::From::from`, generics stripped) names a
    /// type or trait of the module it names (its file, or the files of its directory) with a
    /// function of the last name. True when the toolchain's sources cannot be read.
    fn std_item(&mut self, path: &str) -> bool {
        if let Some(&k) = self.std_items.get(path) {
            return k;
        }
        let Some((sysroot, _)) = self.toolchain.get_or_insert_with(toolchain).clone() else {
            return true;
        };
        let segs: Vec<&str> = path.split("::").collect();
        let ok = match segs.as_slice() {
            [krate, mods @ .., ty, f] => {
                let base = sysroot
                    .join("lib/rustlib/src/rust/library")
                    .join(krate)
                    .join("src");
                let dir = mods.iter().fold(base.clone(), |d, m| d.join(m));
                let mut files = package_files(&dir);
                files.push(dir.with_extension("rs"));
                if mods.is_empty() {
                    files = vec![base.join("lib.rs")];
                }
                let ty_re = Regex::new(&format!(
                    r"\b(?:trait|struct|enum|union|type)\s+{}\b",
                    regex::escape(ty)
                ))
                .unwrap();
                let fn_re = Regex::new(&format!(r"\bfn\s+{}\b", regex::escape(f))).unwrap();
                let texts: Vec<String> = files
                    .iter()
                    .filter_map(|f| std::fs::read_to_string(f).ok())
                    .collect();
                // or a free function of the module the path names up to it (`alloc::io::copy::
                // copy`)
                let mut mod_files = package_files(&dir.join(ty));
                mod_files.push(dir.join(format!("{ty}.rs")));
                let in_module = mod_files
                    .iter()
                    .filter_map(|f| std::fs::read_to_string(f).ok())
                    .any(|t| fn_re.is_match(&t));
                texts.is_empty()
                    || (texts.iter().any(|t| ty_re.is_match(t))
                        && texts.iter().any(|t| fn_re.is_match(t)))
                    || in_module
            }
            _ => false,
        };
        self.std_items.insert(path.to_string(), ok);
        ok
    }

    /// The `#[path]` module declarations and `include!`d files of the package in `dir`.
    fn package_mods(&mut self, dir: &Path) -> Rc<PkgMods> {
        if let Some(m) = self.pkg_mods.get(dir) {
            return m.clone();
        }
        let mut out = PkgMods::default();
        for f in package_files(dir) {
            let Ok(t) = std::fs::read_to_string(&f) else {
                continue;
            };
            let here = f.parent().unwrap_or(dir);
            for m in re!(r#"#\[path\s*=\s*"([^"]+)"\s*\]\s*(?:#\[[^\]]*\]\s*)*(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+(\w+)\s*;"#)
                .captures_iter(&t)
            {
                out.paths.push((f.clone(), rcbom_manifest::normalize(&here.join(&m[1])), m[2].to_string()));
            }
            for m in re!(r#"\binclude!\s*\(\s*"([^"]+)"\s*\)"#).captures_iter(&t) {
                out.included
                    .insert(rcbom_manifest::normalize(&here.join(&m[1])));
            }
        }
        let m = Rc::new(out);
        self.pkg_mods.insert(dir.to_path_buf(), m.clone());
        m
    }

    /// The module paths the code of a file is compiled as, from its crate's root:
    /// `src/crypto/ring/tls12.rs` is `crypto::ring::tls12` (a crate root is `[]`), also as a
    /// `#[path]` module of another file (rustls's `aws_lc_rs::kx` is `src/crypto/ring/kx.rs`).
    /// None when unknown: no `cargo metadata`, a file outside every target's directory, one an
    /// `include!` reads, or a build script's output.
    fn module_chains(&mut self, path: &Path, depth: usize) -> Option<Vec<Vec<String>>> {
        let roots = self.roots.as_ref()?;
        // code a build script wrote (`<target>/build/<pkg>-<hash>/out/gen.rs`), included where
        // the crate says
        let comps: Vec<_> = path.components().map(|c| c.as_os_str()).collect();
        if comps.windows(3).any(|w| w[0] == "build" && w[2] == "out") {
            return None;
        }
        let mut out = Vec::new();
        if roots.iter().any(|r| r == path) {
            out.push(Vec::new());
        } else if let Some(dir) = roots
            .iter()
            .filter_map(|r| r.parent())
            .filter(|d| path.starts_with(d))
            .max_by_key(|d| d.as_os_str().len())
        {
            let rel = path.strip_prefix(dir).ok()?;
            let mut comps: Vec<String> = rel
                .components()
                .map(|c| c.as_os_str().to_string_lossy().to_string())
                .collect();
            let last = comps.pop()?;
            if last != "mod.rs" {
                comps.push(last.strip_suffix(".rs").unwrap_or(&last).to_string());
            }
            out.push(comps);
        }
        let dir = self.man.owner_of(path).map(|p| p.manifest_dir.clone())?;
        let mods = self.package_mods(&dir);
        if mods.included.contains(path) {
            return None;
        }
        if depth < 3 {
            for (decl, target, name) in &mods.paths {
                if target == path {
                    for mut c in self.module_chains(decl, depth + 1).unwrap_or_default() {
                        c.push(name.clone());
                        out.push(c);
                    }
                }
            }
        }
        (!out.is_empty()).then_some(out)
    }

    /// The types a name in a file of package `owner` may be an alias of: those its own
    /// package defines under that name, else those of the packages the file imports the name
    /// from (ssh-encoding's `impl Writer for Sha256` names sha2's alias).
    fn alias_targets(
        &mut self,
        src: &Source,
        owner: Option<&rcbom_manifest::Pkg>,
        name: &str,
    ) -> Vec<String> {
        let mut dirs: Vec<PathBuf> = owner.map(|p| p.manifest_dir.clone()).into_iter().collect();
        let owner_id = owner.map(|p| p.id.repr.clone());
        for r in import_roots(&src.binds, name).into_iter().flatten() {
            for p in self.crate_refs(owner_id.as_deref(), &r) {
                if let Some(pkg) = self
                    .man
                    .packages
                    .iter()
                    .find(|k| pkg_ref(&k.name, &k.version.to_string()) == p)
                {
                    dirs.push(pkg.manifest_dir.clone());
                }
            }
        }
        let mut out = Vec::new();
        for d in dirs {
            if let Some(t) = self.package_aliases(&d).get(name) {
                out.extend(t.iter().cloned());
            }
        }
        out
    }

    /// A location's file. The standard library's sources are named as rustc names them
    /// (`/rustc/<commit>/library/core/src/ops/function.rs`); they are read from the pinned
    /// toolchain's rust-src component (`<sysroot>/lib/rustlib/src/rust/library/..`), and the
    /// commit must be that toolchain's.
    fn resolve(&mut self, location: &str) -> Result<PathBuf, String> {
        let Some(rest) = location.strip_prefix("/rustc/") else {
            // as the generator writes them: relative, without `.`, `..` or empty segments
            if location.starts_with('/')
                || location
                    .split('/')
                    .any(|g| g.is_empty() || g == "." || g == "..")
            {
                return Err(format!(
                    "`{location}` is not a normalised relative location"
                ));
            }
            return Ok(self.man.resolve(location));
        };
        let (commit, rest) = rest
            .split_once('/')
            .ok_or_else(|| format!("no commit in {location}"))?;
        let Some((sysroot, pinned)) = self.toolchain.get_or_insert_with(toolchain).clone() else {
            return Err(format!(
                "toolchain {} not available to read {location}",
                crate::TOOLCHAIN
            ));
        };
        if commit != pinned {
            return Err(format!(
                "rustc commit {commit} cited, but the pinned toolchain {} is commit {pinned}",
                crate::TOOLCHAIN
            ));
        }
        Ok(sysroot.join("lib/rustlib/src/rust").join(rest))
    }

    /// The bom-refs of the packages a crate identifier names in the code of package `owner`
    /// (by package id): one of its dependencies under its extern name, or its own library.
    /// Without `cargo metadata`, or for a file of no package, every package of that name.
    fn crate_refs(&self, owner: Option<&str>, ident: &str) -> Vec<String> {
        if let (Some(ext), Some(id)) = (&self.externs, owner)
            && let Some(m) = ext.get(id)
        {
            return m.get(ident).cloned().unwrap_or_default();
        }
        self.man
            .packages
            .iter()
            .filter(|p| p.name.replace('-', "_") == ident)
            .map(|p| pkg_ref(&p.name, &p.version.to_string()))
            .collect()
    }

    /// The packages of the CBOM a name in this file can come from: the crates its imports name
    /// (any of them, when it imports the name from several), or the crate of that name. None
    /// when the name may be the program's own (a definition or generic parameter in the file,
    /// an import relative to this crate or from one of its modules) or a crate outside the CBOM.
    fn origins(&self, src: &Source, owner: Option<&str>, name: &str) -> Option<Vec<String>> {
        if src.locals.contains(name) {
            return None;
        }
        let mut out = Vec::new();
        for r in import_roots(&src.binds, name)? {
            let refs: Vec<String> = self
                .crate_refs(owner, &r)
                .into_iter()
                .filter(|p| self.graph.packages.contains(p))
                .collect();
            if refs.is_empty() {
                return None;
            }
            out.extend(refs);
        }
        Some(out)
    }

    fn check(&mut self, oi: usize, line: usize, offset: usize) -> Result<(), String> {
        self.check_with(oi, line, offset, None)
    }

    /// `check`, with the occurrence's context replaced by `context` when given (the self-test
    /// shifts the lines its details cite).
    fn check_with(
        &mut self,
        oi: usize,
        line: usize,
        offset: usize,
        context: Option<&str>,
    ) -> Result<(), String> {
        let occs = self.occs;
        let man = self.man;
        let mut o = occs[oi].clone();
        if let Some(c) = context {
            o.context = c.to_string();
        }
        let o = &o;
        let path = self.resolve(&o.location)?;
        let src = self
            .source(&path)
            .ok_or_else(|| format!("cannot read {}", path.display()))?;
        let text = src
            .lines
            .get(line.wrapping_sub(1))
            .ok_or("line out of range")?
            .clone();
        let chars: Vec<char> = text.chars().collect();
        if offset > chars.len() {
            return Err("offset past end of line".into());
        }
        let at: String = chars[offset..].iter().collect();

        // one occurrence per asset, position and symbol (the generator deduplicates by it): a
        // shifted position that lands on another occurrence of the same name is caught here
        if self
            .at_pos
            .get(&(o.location.clone(), line, offset))
            .into_iter()
            .flatten()
            .any(|&j| {
                j != oi && occs[j].component_ref == o.component_ref && occs[j].symbol == o.symbol
            })
        {
            return Err(
                "another occurrence of the same asset and symbol is at this position".into(),
            );
        }

        if o.context.starts_with("[manifest]") {
            let file = o.location.rsplit('/').next().unwrap_or("");
            return match file {
                "Cargo.lock" => check_lock(
                    &src.lines,
                    line,
                    offset,
                    &o.symbol,
                    &o.context,
                    &o.component_ref,
                ),
                "Cargo.toml" => check_toml(
                    &src.toml,
                    &text,
                    line,
                    offset,
                    &o.symbol,
                    &o.context,
                    &o.component_ref,
                ),
                _ => Err("a manifest occurrence outside Cargo.toml and Cargo.lock".into()),
            };
        }
        // evidence in code is one of the kinds the generator writes, after its tier
        let ctx = split_context(&o.context);
        let kind =
            re!(r"^\[(?:reachable|present)\] \[(call|static|via-static|instantiation|component)\]")
                .captures(ctx.tags)
                .map(|m| m[1].to_string())
                .ok_or("no tier and evidence kind among the tags")?;
        let starts_token = token_start(&src, line, offset);
        // the instance of a generic function the occurrence is in (`in tlib::hash_c::<ilib::
        // CFast>`, or a closure in it): its function's type parameters' arguments
        self.alg_arg = alg_arg(self.kb, &o.symbol);
        self.inst = ctx
            .details
            .strip_prefix(ctx.tags)
            .unwrap_or(ctx.details)
            .trim_start()
            .strip_prefix("in ")
            .and_then(|d| parts(d).into_iter().next())
            .and_then(|item| {
                let item = re!(r"(?:::\{closure#\d+\})+\s*$").replace(item.trim(), "");
                let args = instance_args(&item)?;
                let f = src.enclosing((line, offset), &[ItemKind::Fn])?;
                let g = fn_sig(&src, f).generics;
                (g.len() == args.len()).then(|| g.into_iter().zip(args).collect())
            })
            .unwrap_or_default();
        // code positions are in code, not in a comment or a literal
        if src.class[line - 1].get(offset) != Some(&Class::Code) {
            return Err(format!("position inside a comment or literal in {text:?}"));
        }
        // the generator records the source line and, when it is on one line outside a macro,
        // the exact text at the position, last in the context, in that order; the line may hold
        // backquotes, the text does not
        let Some(l) = ctx.line else {
            return Err("no source line recorded".into());
        };
        if text.trim() != l {
            return Err(format!("expected the line `{l}`, found {text:?}"));
        }
        if let Some(code) = ctx.code
            && !at.starts_with(code)
        {
            return Err(format!("expected `{code}` in {text:?}"));
        }
        // an import names an item, it does not use it
        if src
            .use_spans
            .iter()
            .any(|&(a, b)| a <= (line, offset) && (line, offset) < b)
        {
            return Err(format!("position inside a `use` item in {text:?}"));
        }
        // the positions the details name: where a generic instance was instantiated, where a
        // macro's code was written
        self.check_details(
            ctx.details,
            ctx.tags,
            &o.symbol,
            ctx.line,
            (&path, line, offset),
            &o.component_ref,
        )?;
        // where a type was made a trait object
        self.check_coercions(ctx.details)?;
        // the macro tags are among the leading tags, never in the recorded source text; a tagged
        // position is the macro's, derive's or attribute's name, not the symbol's
        let mut tagged = false;
        let mut macro_tagged = false;
        if let Some(m) = re!(r"\[macro ([\w:]+!)\]").captures(ctx.tags) {
            let name = &m[1];
            let ok = Regex::new(&format!(r"^(?:\w+::)*{}", regex::escape(name)))
                .unwrap()
                .is_match(&at);
            if !(ok && starts_token) {
                return Err(format!("expected `{name}` in {text:?}"));
            }
            tagged = true;
            macro_tagged = true;
        }
        // derive: the position is the derive's name inside `#[derive(..)]` (or a `cfg_attr`'s
        // `derive(..)`)
        if !tagged && let Some(m) = re!(r"\[derive ([\w:]+)\]").captures(ctx.tags) {
            let name = m[1].rsplit("::").next().unwrap_or(&m[1]).to_string();
            let ok = Regex::new(&format!(r"^(?:\w+::)*{}\b", regex::escape(&name)))
                .unwrap()
                .is_match(&at);
            let in_derive = attribute_before(&src, line, offset).is_some_and(|a| {
                re!(r"^(?:derive|cfg_attr)\s*\(").is_match(&a) && open_in(&a, "derive")
            });
            if !(ok && starts_token && in_derive) {
                return Err(format!(
                    "expected derive `{name}` inside `#[derive(..)]` in {text:?}"
                ));
            }
            tagged = true;
        }
        // attribute macro: the position is the attribute, or its name inside a `cfg_attr`
        if !tagged && let Some(m) = re!(r"\[attribute ([\w:]+)\]").captures(ctx.tags) {
            let name = m[1].rsplit("::").next().unwrap_or(&m[1]).to_string();
            let direct = Regex::new(&format!(r"^#!?\[\s*(?:\w+::)*{}\b", regex::escape(&name)))
                .unwrap()
                .is_match(&at)
                && at.starts_with('#');
            let in_cfg_attr = Regex::new(&format!(r"^(?:\w+::)*{}\b", regex::escape(&name)))
                .unwrap()
                .is_match(&at)
                && attribute_before(&src, line, offset)
                    .is_some_and(|a| re!(r"^cfg_attr\s*\(").is_match(&a));
            if !((direct || in_cfg_attr) && starts_token) {
                return Err(format!("expected an attribute in {text:?}"));
            }
            tagged = true;
        }
        // the symbol's crate is a package of the CBOM (or the standard library): a made-up one
        // would switch the checks below off
        let sym = strip_generics(&o.symbol);
        let sym_crate = sym.split("::").next().unwrap_or("").to_string();
        // (a qualified path's, `<t14::S384 as t14::Scheme>::ALG`, is its type's)
        let first = o
            .symbol
            .trim_start_matches('<')
            .split("::")
            .next()
            .unwrap_or("");
        let known = matches!(first, "core" | "std" | "alloc")
            || self.libs.as_ref().is_some_and(|l| l.contains_key(first))
            || self
                .man
                .packages
                .iter()
                .any(|p| p.name.replace('-', "_") == first);
        if !known {
            return Err(format!("`{}`: no crate `{first}` in the build", o.symbol));
        }
        // a standard-library path names a type or trait and a function of it that exist
        // (`core::convert::From::from`), in the module it names or one inside it
        if matches!(first, "core" | "std" | "alloc") && !self.std_item(&sym) {
            return Err(format!(
                "`{}`: no such item in the standard library",
                o.symbol
            ));
        }
        let mut parsed = None;
        let owner = man.owner_of(&path);
        let owner_id = owner.map(|p| p.id.repr.clone());
        // a macro's invocation is in the item the context names, as any position
        if macro_tagged {
            let chains = self.module_chains(&path, 0);
            let mut aliases = |n: &str| self.alias_targets(&src, owner, n);
            // (a static's own descriptor tells invocations apart too: `#[cfg(unix)] g!(run,
            // SHA384)` beside `#[cfg(not(unix))] g!(run, SHA512)`)
            let own = sym.rsplit("::").next().unwrap_or("");
            let own = (kind == "static"
                && own
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'))
            .then_some(own);
            check_item(
                &src,
                ctx.details.strip_prefix(ctx.tags).unwrap_or(ctx.details),
                (line, offset),
                &mut aliases,
                chains.as_deref(),
                own,
            )?;
        }
        if !tagged {
            // the enclosing item the context names (an identical statement in another
            // function, or in another type's method of that name, is another occurrence), and
            // no macro's body (a macro's code is cited where it is called)
            let chains = self.module_chains(&path, 0);
            let mut aliases = |n: &str| self.alias_targets(&src, owner, n);
            check_item(
                &src,
                ctx.details.strip_prefix(ctx.tags).unwrap_or(ctx.details),
                (line, offset),
                &mut aliases,
                chains.as_deref(),
                None,
            )?;
            // a definition names a new item, it does not use one (`fn seal<..>`, `pub fn digest`)
            if let Some(w) = word_before(&src, line, offset)
                && matches!(
                    w.as_str(),
                    "fn" | "struct"
                        | "enum"
                        | "union"
                        | "trait"
                        | "type"
                        | "mod"
                        | "static"
                        | "const"
                        | "let"
                        | "macro_rules"
                )
            {
                return Err(format!("position after `{w}`: a definition, in {text:?}"));
            }
            // code: the callee or static, by name or by an import alias of it (a raw
            // identifier's name without `r#`: `rand::Rng::r#gen` is written `.r#gen()`)
            let ident = sym
                .trim_end_matches(':')
                .rsplit("::")
                .next()
                .unwrap_or("")
                .trim_start_matches("r#")
                .to_string();
            if ident.is_empty() {
                return Err("no identifier in symbol".into());
            }
            // a call through a function pointer (`h(&SHA256, d)`): the position is the call's
            // callee expression, a name, a field or a parenthesised expression followed by its
            // arguments; the position the detail gives for where the function was made the
            // pointer names it (or an import alias of it)
            // (each function the pointer may hold: `FNS[i](..)` over `[digest, my_hash]`)
            let pointers: Vec<(String, usize, usize)> = re!(
                r"called through a function pointer to `[^`]+` named at ([^\s;]+?):(\d+):(\d+)(?:;|$)"
            )
            .captures_iter(ctx.details)
            .map(|m| {
                (
                    m[1].to_string(),
                    m[2].parse::<usize>().unwrap_or(0),
                    m[3].parse::<usize>().unwrap_or(0),
                )
            })
            .collect();
            let pointer = pointers.first().cloned();
            for (file, l2, c2) in &pointers {
                let (l2, c2) = (*l2, *c2);
                // the callee expression: a parenthesised expression (`(h.f)`), or a name with
                // fields, indexes and calls after it (`h`, `fs[0]`, `get()`), then the
                // arguments
                let callee = re!(
                    r"^(?:\(([^()]*(?:\([^()]*\)[^()]*)*)\)|([A-Za-z_]\w*)(?:\s*\.\s*\w+|\s*\[[^\[\]]*\]|\s*\([^()]*\))*)\s*\("
                )
                .captures(&at);
                // not a method (`.next(`) or a path (`ring::digest::digest(`): those name a
                // function, not a pointer
                let before = chars[..offset].iter().rev().find(|c| !c.is_whitespace());
                let method = matches!(before, Some('.' | ':'));
                let Some(callee) = callee.filter(|_| starts_token && !method) else {
                    return Err(format!(
                        "expected a call through a function pointer in {text:?}"
                    ));
                };
                // the root of the callee: a variable, not a function of the file (`run(`)
                let root = callee
                    .get(2)
                    .map(|m| m.as_str().to_string())
                    .or_else(|| {
                        callee.get(1).and_then(|m| {
                            re!(r"^\s*([A-Za-z_]\w*)")
                                .captures(m.as_str())
                                .map(|r| r[1].to_string())
                        })
                    })
                    .unwrap_or_default();
                let plain = callee.get(2).is_some_and(|m| {
                    callee[0][m.end()..].trim_start().starts_with('(')
                        && callee[0][m.end()..].trim() == "("
                });
                if plain
                    && src
                        .items
                        .iter()
                        .any(|i| i.kind == ItemKind::Fn && i.name == root)
                {
                    return Err(format!(
                        "`{root}` is a function of the file, not a pointer, in {text:?}"
                    ));
                }
                // the variable holds the function named where the function binds it: in the
                // statement when it calls nothing (`let p: HashFn = digest::digest;`), in the
                // binding of the variable it copies (`if let Some(f) = o`: `o`'s), in the body
                // of the file's function it calls (`let g = get();`: `get`'s)
                if !root.is_empty() && self.resolve(file).ok().as_deref() == Some(path.as_path()) {
                    // (the root as read at the call: `self` in `(self.f)(..)`)
                    let rest: String = chars[offset..].iter().collect();
                    let k = Regex::new(&format!(r"\b{}\b", regex::escape(&root)))
                        .ok()
                        .and_then(|r| r.find(&rest))
                        .map_or(0, |m| rest[..m.start()].chars().count());
                    let root_at = src.idx((line, offset + k));
                    pointer_bound(&src, root_at, &root, l2).map_err(|e| {
                        format!("{e}, not where the function is named ({file}:{l2}:{c2})")
                    })?;
                }
                let p2 = self.resolve(file)?;
                let src2 = self
                    .source(&p2)
                    .ok_or_else(|| format!("cannot read {file}, named in the context"))?;
                let named = src2.lines.get(l2.wrapping_sub(1)).and_then(|t| {
                    let chars: Vec<char> = t.chars().collect();
                    let (rs, rc) = rest(&src2, l2, c2);
                    (c2 < chars.len() && token_start(&src2, l2, c2))
                        .then(|| path_and_generics(&rs, &rc))
                        .flatten()
                });
                let names = named.is_some_and(|(_, last, _)| {
                    last == ident
                        || src2.binds.iter().any(|b| {
                            b.name == last
                                && self.alias_of(
                                    b,
                                    &ident,
                                    &sym_crate,
                                    owner_id.as_deref(),
                                    &src2.binds,
                                )
                        })
                });
                // or a macro of the file whose expansion binds it is invoked there (`bind!(m)`
                // with `let $n: HashFn = digest::digest;`): its body names it
                let by_macro = !names
                    && macro_call_at(&src2, (l2, c2))
                    && invocation_text(&src2, (l2, c2)).is_some_and(|(m, _)| {
                        src2.items
                            .iter()
                            .filter(|i| i.kind == ItemKind::Macro && i.name == m)
                            .any(|i| {
                                let (a, b) = src2.span(i);
                                Regex::new(&format!(r"\b{}\b", regex::escape(&ident)))
                                    .is_ok_and(|r| r.is_match(&src2.text(a, b)))
                            })
                    });
                if !names && !by_macro {
                    return Err(format!(
                        "the function pointer's position {file}:{l2}:{c2} does not name `{ident}`"
                    ));
                }
            }
            // the path, from the position on over the next lines (rustfmt breaks long paths);
            // generic arguments balanced, so it cannot run on into the next expression
            let (rs, rc) = rest(&src, line, offset);
            parsed = path_and_generics(&rs, &rc);
            let mut ok = parsed.as_ref().is_some_and(|(_, last, _)| {
                *last == ident
                    || src.binds.iter().any(|b| {
                        b.name == *last
                            && self.alias_of(b, &ident, &sym_crate, owner_id.as_deref(), &src.binds)
                    })
            });
            // an alias another file defines: of this package, or of the crate the path goes
            // through (`mylib::hash_it` for `pub use ring::digest::digest as hash_it;` in mylib)
            if !ok
                && starts_token
                && let Some((quals, last, _)) = &parsed
            {
                let mut dirs: Vec<PathBuf> =
                    owner.map(|p| p.manifest_dir.clone()).into_iter().collect();
                for root in import_roots(&src.binds, quals.first().unwrap_or(last))
                    .into_iter()
                    .flatten()
                {
                    for r in self.crate_refs(owner_id.as_deref(), &root) {
                        let pkg = r
                            .strip_prefix("pkg:cargo/")
                            .and_then(|nv| nv.split_once('@'))
                            .and_then(|(n, v)| man.by_name_version(n, v));
                        if let Some(p) = pkg
                            && !dirs.contains(&p.manifest_dir)
                        {
                            dirs.push(p.manifest_dir.clone());
                        }
                    }
                }
                for d in dirs {
                    let binds = self.package_binds(&d);
                    // (a re-export inside the symbol's own crate, relative to it: `pub use
                    // inner::DEEP as SHALLOW;` in picklib for `picklib::inner::DEEP`)
                    let own_crate = self
                        .man
                        .packages
                        .iter()
                        .find(|p| p.manifest_dir == d)
                        .is_some_and(|p| {
                            p.lib_name.as_deref() == Some(sym_crate.as_str())
                                || p.name.replace('-', "_") == sym_crate
                        });
                    if binds.iter().any(|b| {
                        b.name == *last
                            && (self.alias_of(b, &ident, &sym_crate, owner_id.as_deref(), &binds)
                                || (own_crate && b.path.last() == Some(&ident) && {
                                    let rel: Vec<&str> = b
                                        .path
                                        .iter()
                                        .map(String::as_str)
                                        .skip_while(|g| matches!(*g, "crate" | "self"))
                                        .collect();
                                    sym.ends_with(&format!("::{}", rel.join("::")))
                                }))
                    }) {
                        ok = true;
                        break;
                    }
                }
            }
            if pointer.is_none() && !(ok && starts_token) {
                return Err(format!("expected `{ident}` in {text:?}"));
            }
        }
        // an instantiation's position that details cite (`instantiated by X at F:L:C`) is cited
        // by one of this asset's
        if kind == "instantiation"
            && let Some(by) = self.cited.get(&(o.location.clone(), line, offset))
            && !by.contains(&o.component_ref)
        {
            return Err(format!(
                "the instantiation here is cited by {} occurrences of other assets only",
                by.len()
            ));
        }
        // a component is used where the asset it is part of is used
        if kind == "component" {
            let Some(m) = re!(r"; part of ([^\s;(]+)").captures(ctx.details) else {
                return Err("a component that names no asset it is part of".into());
            };
            let parent = &m[1];
            let here = self
                .at_pos
                .get(&(o.location.clone(), line, offset))
                .into_iter()
                .flatten()
                .any(|&j| j != oi && occs[j].component == parent);
            // a parent merged into a more specific name on the same line (Argon2 ->
            // Argon2id-19456-2-1) keeps the line, not necessarily the column
            let merged = self
                .at_line
                .get(&(o.location.clone(), line))
                .into_iter()
                .flatten()
                .any(|&j| {
                    j != oi
                        && extends(
                            &occs[j].component,
                            parent,
                            self.graph
                                .family
                                .get(&occs[j].component_ref)
                                .map(String::as_str),
                        )
                });
            if !(here || merged) {
                return Err(format!("`{parent}`, which this is part of, is not here"));
            }
        }
        // what a call does is one of the asset's functions (those of its reachable occurrences,
        // observed or the knowledge base's, when it has any): an encryption is no use of SHA-512
        if let Some(f) = parts(ctx.details)
            .into_iter()
            .find_map(|p| p.strip_prefix("use: "))
            && let Some((fs, reachable)) = self.graph.functions.get(&o.component_ref)
            && (ctx.tags.starts_with("[reachable]") || !reachable)
            && !f.split(" or ").all(|f| fs.iter().any(|x| x == f))
        {
            return Err(format!(
                "use `{f}` is not among {}'s functions ({})",
                o.component,
                fs.join(", ")
            ));
        }
        // a descriptor is evidence of the asset the knowledge base names it (`ring::digest::
        // SHA512` is SHA-512, not SHA-384): the static itself, or the one a table leads to
        let descriptor = match kind.as_str() {
            "static" => Some(sym.clone()),
            "via-static" => re!(r" -> ([\w:]+)(?:;|$)")
                .captures(ctx.details)
                .map(|m| m[1].to_string()),
            _ => None,
        };
        // the descriptor a call's algorithm comes from names the asset too
        let mut descriptors: Vec<String> = Vec::new();
        // the call a table member is read at (not a macro's: its code is the macro's)
        let call_at = (kind == "call" && !ctx.tags.contains("[macro ")).then_some((line, offset));
        for p in parts(ctx.details) {
            // a static a member is stored by holds it (`member: table, stored by `static T``);
            // one a member is a value of exists (`member: static, possible (a value `static T`
            // holds ..)`)
            if let Some(m) =
                re!(r"^member: table, stored by `(?:static|const) ([^`]+)`").captures(p)
            {
                for d in &descriptors {
                    self.check_table(&src, &path, &m[1], d, call_at)?;
                }
                continue;
            }
            if let Some(m) = re!(
                r"^member: static, possible \((?:a value `static ([^`]+)` holds|the value `static ([^`]+)` starts with|a value `[^`]+` puts in `static ([^`]+)`)"
            )
            .captures(p)
            {
                let st = m.get(1).or(m.get(2)).or(m.get(3)).map_or("", |g| g.as_str());
                self.check_table(&src, &path, st, "", call_at)?;
                continue;
            }
            // a member through a trait object (`member: dyn, possible (dyn: `T` is coerced to
            // `dyn Tr` ..)`): the call calls a method on an object of `Tr` (or of a trait whose
            // supertraits include it), wherever the receivers' types are known
            if let Some(m) = re!(r"^member: dyn, possible \(dyn: `[^`]+`(?:, the only type)? (?:is )?coerced to `([^`]+)`")
                .captures(p)
                && let Some(at) = call_at
            {
                let want = type_name(m[1].trim().trim_start_matches("dyn ").trim());
                let supers = self.supertraits(&path, &m[1]);
                if let Some(ts) = call_dyn_receivers(&src, src.idx(at))
                    && !ts.iter().any(|t| {
                        let mut seen = vec![t.clone()];
                        let mut k = 0;
                        while k < seen.len() {
                            if seen[k] == want {
                                return true;
                            }
                            for s2 in supers.get(&seen[k]).into_iter().flatten() {
                                if !seen.contains(s2) {
                                    seen.push(s2.clone());
                                }
                            }
                            k += 1;
                        }
                        false
                    })
                {
                    return Err(format!(
                        "the call calls no method on a `dyn {want}` (its trait objects: {})",
                        if ts.is_empty() { "none".to_string() } else { ts.join(", ") }
                    ));
                }
                continue;
            }
            // the function a member comes from (returned or written by it, passed by it, stored
            // by it in the field) is one of the build's that can give it
            if let Some(m) = re!(
                r"^member: (object, from|caller, passed by|impl, possible \(what|type-join, possible \(a value) `([^`]+)`"
            )
            .captures(p)
            {
                for d in &descriptors {
                    self.check_witness(&path, &m[1], &m[2], d, &o.component_ref)?;
                }
                continue;
            }
            let named: Vec<&str> = if let Some(m) = re!(
                r"^algorithm (?:possibly )?from ([\w:]+)(?: in the arguments|, reaching .*|, the only one found reaching .*)?$"
            )
            .captures(p)
            {
                vec![m.get(1).map_or("", |g| g.as_str())]
            } else if let Some(m) = re!(
                r"^algorithm (?:from ([\w:]+), stored in `(?:static|const) ([^`]+)`|one of the \d+ in `(?:static |const )?([^`]+)`(?:,| that) .*?: ([\w:]+))$"
            )
            .captures(p)
            {
                // a member of a static (a table): it holds it
                let d = m.get(1).or(m.get(4)).map_or("", |g| g.as_str());
                let table = m.get(2).or(m.get(3)).map_or("", |g| g.as_str());
                self.check_table(&src, &path, table, d, call_at)?;
                vec![d]
            } else if let Some(m) = re!(r"^algorithm one of \d+ that .*?: (.+)$").captures(p) {
                m.get(1)
                    .map_or("", |g| g.as_str())
                    .split(", ")
                    .map(|d| d.trim_end_matches(" in the arguments"))
                    .collect()
            } else {
                continue;
            };
            let family = self.graph.family.get(&o.component_ref).cloned();
            let family = family.as_deref();
            // the values the label says are all that reach the call (no unknown beside them):
            // a store through a pointer that replaces one on every way to the call excludes it
            let exact = !p.contains("beside others not followed") && !p.contains(" possibly ");
            // the code the call reads names it (`Salt::new(hkdf::HKDF_SHA256, ..)` is no
            // `HKDF_SHA384`; `prk.expand(.., HKDF_SHA256)` with `prk` from `Salt::new(HKDF_SHA384,
            // ..)` may be either)
            if p.ends_with(" in the arguments") {
                let members = named.clone();
                let expanded: Vec<usize> = re!(r"expanded from ([^\s;]+?):(\d+)(?:;|$)")
                    .captures_iter(ctx.details)
                    .filter(|m| self.resolve(&m[1]).ok().as_deref() == Some(path.as_path()))
                    .filter_map(|m| m[2].parse().ok())
                    .collect();
                self.check_args(
                    &src,
                    &path,
                    (line, offset),
                    &members,
                    &o.component_ref,
                    ctx.tags.contains("[macro ").then_some(expanded.as_slice()),
                    exact,
                )?;
            }
            // a member reaching the call from another function, labelled as one that does
            // (`object`, `caller`, `fixed`): the code the call reads does not name another
            // descriptor of its primitive instead, where it reads no value from elsewhere
            if !p.ends_with(" in the arguments")
                && kind == "call"
                && !ctx.tags.contains("[macro ")
                && re!(r"reaching the call from another function|from other functions").is_match(p)
                && re!(r"; member: (?:object|caller|fixed|dyn|container|type-join|impl)\b")
                    .is_match(ctx.details)
            {
                // (a `type-join` or `impl` member is any value stored in a field of that type,
                // or that a function writes: only a call that reads no field is checked)
                let join = re!(r"; member: (?:type-join|impl)\b").is_match(ctx.details);
                self.check_elsewhere(
                    &src,
                    &path,
                    (line, offset),
                    &named,
                    &o.component_ref,
                    exact,
                    join,
                )?;
            }
            descriptors.extend(named.iter().map(|d| d.to_string()));
            for d in named {
                let names =
                    rcbom_analysis::static_names(self.kb, d.split("::").next().unwrap_or(""), d);
                if !names.is_empty()
                    && !names
                        .iter()
                        .any(|n| *n == o.component || extends(&o.component, n, family))
                {
                    return Err(format!(
                        "the algorithm `{d}` is {}, not {}",
                        names.join(" or "),
                        o.component
                    ));
                }
            }
        }
        if kind == "via-static" && descriptor.is_none() {
            return Err("a `[via-static]` occurrence without its chain to a descriptor".into());
        }
        if let Some(d) = descriptor {
            let k = d.split("::").next().unwrap_or("");
            let names = rcbom_analysis::static_names(self.kb, k, &d);
            let family = self.graph.family.get(&o.component_ref).map(String::as_str);
            if names.is_empty() {
                return Err(format!("`{d}` is no knowledge-base descriptor"));
            }
            if !names
                .iter()
                .any(|n| *n == o.component || extends(&o.component, n, family))
            {
                return Err(format!(
                    "`{d}` is {}, not {}",
                    names.join(" or "),
                    o.component
                ));
            }
        }
        // what the path names must provide the asset: the callee's crate, a self type written
        // as a qualifier (`Hmac::<Sha256>::new_from_slice` for `crypto_common::KeyInit::
        // new_from_slice`), or a type in the generic arguments (`<Hmac<Sha256> as Mac>::m`,
        // `seal::<Aes256Gcm>`). Each is a package of the CBOM the file can name it from; the
        // standard library, an interface crate and the program's own code provide nothing and
        // decide nothing. A type parameter or a local type could carry any asset: no check.
        if matches!(
            kind.as_str(),
            "call" | "static" | "via-static" | "instantiation"
        ) && let Some((quals, _, generics)) = &parsed
            && let Some(provs) = self.graph.providers.get(&o.component_ref)
        {
            let sym_segs: Vec<String> = sym
                .split("::")
                .map(|s| s.trim_start_matches('<').to_string())
                .collect();
            const NEUTRAL: &[&str] = &[
                "u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32", "i64", "i128",
                "isize", "f32", "f64", "bool", "char", "str", "String", "Vec", "Option", "Box",
                "Result", "as", "dyn", "impl", "mut", "const", "fn", "static", "_",
            ];
            let owner_id = owner_id.as_deref();
            let mut roots: Vec<String> = Vec::new();
            let mut unknown = false;
            // the callee's crate
            roots.extend(
                self.lib_refs(&sym_crate)
                    .into_iter()
                    .filter(|r| !self.neutral(r)),
            );
            // a written qualifier: a self type, unless the path is the trait's own path
            // (`aes_gcm::aead::KeyInit::new_from_slice`: the qualifiers lead to the trait)
            let trait_path = quals.last().is_some_and(|q| sym_segs.contains(q));
            if let Some(q0) = quals.first()
                && !matches!(q0.as_str(), "crate" | "self" | "super" | "Self")
                && !sym_segs.contains(q0)
                && !trait_path
            {
                match self.origins(&src, owner_id, q0) {
                    Some(r) => roots.extend(r.into_iter().filter(|r| !self.neutral(r))),
                    None => unknown = true,
                }
            }
            for g in generics.iter().filter(|g| !NEUTRAL.contains(&g.as_str())) {
                match self.origins(&src, owner_id, g) {
                    Some(r) => roots.extend(r.into_iter().filter(|r| !self.neutral(r))),
                    None => unknown = true,
                }
            }
            let provided = roots.iter().any(|r| {
                let cl = self.graph.closure(r);
                provs.iter().any(|p| cl.contains(p))
            });
            if !unknown && !roots.is_empty() && !provided {
                roots.sort();
                roots.dedup();
                return Err(format!(
                    "the path names {}, which does not provide {}",
                    roots.join(", "),
                    o.component
                ));
            }
        }
        Ok(())
    }

    /// The packages of the CBOM whose library is the crate `name` (the crate a symbol's path
    /// starts with).
    fn lib_refs(&self, name: &str) -> Vec<String> {
        let refs = match &self.libs {
            Some(l) => l.get(name).cloned().unwrap_or_default(),
            None => self.crate_refs(None, name),
        };
        refs.into_iter()
            .filter(|r| self.graph.packages.contains(r))
            .collect()
    }

    /// "algorithm from X in the arguments" (or one of several such `members`) at the call at
    /// `at`: X is named in the code the call reads (`call_reads`: the argument carrying the
    /// algorithm, the variables it reads and what the function stores in them, the statics,
    /// consts and `const fn`s those name), and the call reads no other descriptor of the asset's
    /// primitive instead. `exact`: the label says the values found are all (`Reads::strict`).
    /// Where that code reads values from elsewhere (a parameter), X is named in the function.
    /// A macro's call (`expanded` gives the lines of its body cited) reads the invocation and
    /// those lines.
    #[allow(clippy::too_many_arguments)]
    fn check_args(
        &mut self,
        src: &Source,
        path: &Path,
        at: (usize, usize),
        members: &[&str],
        component_ref: &str,
        expanded: Option<&[usize]>,
        exact: bool,
    ) -> Result<(), String> {
        let s = &src.code;
        let lasts: Vec<String> = members
            .iter()
            .map(|d| d.rsplit("::").next().unwrap_or(d).to_string())
            .collect();
        let has = |r: &Reads| lasts.iter().any(|l| r.names.contains(l));
        let p = src.idx(at);
        if let Some(lines) = expanded {
            let mut seen = HashSet::new();
            let mut call = Reads::default();
            // the invocation's arguments and the macro's lines
            let open = scan_to(s, p, s.len(), |i| matches!(s[i], '(' | '[' | '{' | ';'));
            if let Some(close) = close_of_at(s, open) {
                names_read(src, self.kb, open + 1, close, 3, &mut seen, &mut call, true);
            }
            for &l in lines {
                let (a, b) = (src.idx((l, 0)), src.idx((l + 1, 0)));
                names_read(src, self.kb, a, b, 1, &mut seen, &mut call, false);
            }
            if has(&call) || call.open || lines.is_empty() {
                return Ok(());
            }
            return Err(format!(
                "neither the invocation nor the macro's line names {}",
                lasts.join(", ")
            ));
        }
        let Some(mut call) = call_reads(src, self.kb, p, exact, &self.inst, self.alg_arg) else {
            return Ok(());
        };
        self.resolve_foreign(path, &mut call);
        self.resolve_assoc(path, &mut call);
        if has(&call) {
            return Ok(());
        }
        // other descriptors of its primitive, or a type of the build's crates that the knowledge
        // base gives one (`kp.sign(..)` with `kp` an `Ed25519KeyPair`)
        let prim = self.graph.primitive.get(component_ref);
        let others: Vec<&String> = call
            .names
            .iter()
            .filter(|w| {
                self.kb
                    .statics
                    .iter()
                    .any(|e| e.pattern.is_match(w) && Some(&e.algo.primitive) == prim)
            })
            .chain(call.types.iter().filter(|w| {
                self.kb.types.iter().any(|e| {
                    e.name == **w
                        && Some(&e.algo.primitive) == prim
                        && self.libs.as_ref().is_some_and(|l| l.contains_key(&e.krate))
                })
            }))
            .collect();
        if !(call.open || call.foreign) || (!others.is_empty() && !call.replaced) {
            let read = if others.is_empty() {
                "no descriptor of its kind".to_string()
            } else {
                others
                    .iter()
                    .map(|w| w.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            return Err(format!(
                "the code the call reads names {read}, not {}",
                lasts.join(", ")
            ));
        }
        // values from elsewhere: X named in the function at least
        if let Some(f) = src.enclosing(at, &[ItemKind::Fn]) {
            let (a, b) = src.span(f);
            let mut whole = Reads {
                inst: self.inst.clone(),
                ..Reads::default()
            };
            names_read(src, self.kb, a, b, 2, &mut HashSet::new(), &mut whole, true);
            self.resolve_foreign(path, &mut whole);
            self.resolve_assoc(path, &mut whole);
            if !has(&whole) && !whole.foreign {
                return Err(format!(
                    "the function names no {} (the call reads values from elsewhere)",
                    lasts.join(", ")
                ));
            }
        }
        Ok(())
    }

    /// The statics and consts named `item` in module `module` of the package in `dir`: those its
    /// files define there, else those a `use` item of that module re-exports under that name
    /// (`pub use inner::DEEP as SHALLOW;`, a glob `pub use inner::*;`), followed in turn: (file,
    /// the item's extent in its `code`, the item's module). None when the modules of the
    /// package's files are not known (no `cargo metadata`).
    #[allow(clippy::type_complexity)]
    fn find_item(
        &mut self,
        dir: &Path,
        module: &[String],
        item: &str,
        depth: usize,
    ) -> Option<Vec<(PathBuf, (usize, usize), Vec<String>)>> {
        let files = package_files(dir);
        let mut out = Vec::new();
        let mut known = false;
        for f in &files {
            let Some(chains) = self.module_chains(f, 0) else {
                continue;
            };
            known = true;
            let Some(src) = self.source(f) else { continue };
            for it in src
                .items
                .iter()
                .filter(|it| it.kind == ItemKind::Static && it.name == item)
            {
                // (an associated const of an impl or trait is no module's item)
                if src.items.iter().any(|b| {
                    matches!(b.kind, ItemKind::Impl | ItemKind::Trait | ItemKind::Fn)
                        && b.contains(it.start)
                        && b.start != it.start
                }) {
                    continue;
                }
                for c in &chains {
                    let mut full = c.clone();
                    full.extend(modules_at(&src, it.start));
                    if full == module {
                        out.push((f.clone(), src.span(it), full));
                    }
                }
            }
        }
        if !known {
            return None;
        }
        if !out.is_empty() || depth == 0 {
            return Some(out);
        }
        // a re-export: a `use` of a file of that module binding the name (or a glob)
        for f in &files {
            let Some(chains) = self.module_chains(f, 0) else {
                continue;
            };
            if !chains.iter().any(|c| c == module) {
                continue;
            }
            let Some(src) = self.source(f) else { continue };
            let binds: Vec<Binding> = src
                .binds
                .iter()
                .filter(|b| b.name == item || b.name == "*")
                .cloned()
                .collect();
            for b in binds {
                let (target, name) = if b.name == "*" {
                    (b.path.clone(), item.to_string())
                } else {
                    let Some((last, head)) = b.path.split_last() else {
                        continue;
                    };
                    (head.to_vec(), last.clone())
                };
                let Some((d2, m2)) = self.module_of(dir, module, &target) else {
                    continue;
                };
                if let Some(found) = self.find_item(&d2, &m2, &name, depth - 1) {
                    out.extend(found);
                }
            }
        }
        Some(out)
    }

    /// The package and module a path written in module `here` of the package in `dir` names
    /// (`crate::a`, `self::a`, `super::a`, `a` a child module, `dep::a` another package's).
    fn module_of(
        &self,
        dir: &Path,
        here: &[String],
        prefix: &[String],
    ) -> Option<(PathBuf, Vec<String>)> {
        let Some(first) = prefix.first() else {
            return Some((dir.to_path_buf(), here.to_vec()));
        };
        match first.as_str() {
            "crate" | "$crate" => Some((dir.to_path_buf(), prefix[1..].to_vec())),
            "self" => {
                let mut m = here.to_vec();
                m.extend(prefix[1..].iter().cloned());
                Some((dir.to_path_buf(), m))
            }
            "super" => {
                let mut m = here.to_vec();
                let mut k = 0;
                while prefix.get(k).is_some_and(|g| g == "super") {
                    m.pop();
                    k += 1;
                }
                m.extend(prefix[k..].iter().cloned());
                Some((dir.to_path_buf(), m))
            }
            _ => {
                let pkg = self.man.packages.iter().find(|p| {
                    p.lib_name.as_deref() == Some(first.as_str())
                        || p.name.replace('-', "_") == *first
                });
                match pkg {
                    // (another package's, unless a child module of the same name shadows it:
                    // the caller tries both)
                    Some(p) if p.manifest_dir != dir => {
                        Some((p.manifest_dir.clone(), prefix[1..].to_vec()))
                    }
                    _ => {
                        let mut m = here.to_vec();
                        m.extend(prefix.iter().cloned());
                        Some((dir.to_path_buf(), m))
                    }
                }
            }
        }
    }

    /// The constants of other files and packages of the build `r` reads (`algs::CHOSEN`, `use
    /// picklib::CALG as X`, `picklib::SHALLOW` re-exporting `inner::DEEP`): found by the module
    /// path the code writes (from the module of the file `path`, or another package's root), what
    /// their initializers name (the field read, where one is) is read into `r`, and what those
    /// name in turn, from their own module. One not found in a package of the build makes the
    /// code name nothing there; `r.foreign` stays only for one of a crate whose sources are not
    /// at hand. Where the modules are not known (no `cargo metadata`), by name in the package.
    fn resolve_foreign(&mut self, path: &Path, r: &mut Reads) {
        let items = std::mem::take(&mut r.foreign_items);
        let own = self.man.owner_of(path).map(|p| p.manifest_dir.clone());
        let here = self
            .module_chains(path, 0)
            .and_then(|c| c.into_iter().next());
        // (package dir, module where it is written, prefix, item, field)
        let mut pending: Vec<Pending> = Vec::new();
        let mut unresolved = false;
        for (prefix, item, field) in items {
            match &own {
                Some(d) => pending.push((d.clone(), here.clone(), prefix, item, field)),
                None => unresolved = true,
            }
        }
        let mut done = Vec::new();
        while let Some(key) = pending.pop() {
            if done.contains(&key) || done.len() > 32 {
                continue;
            }
            done.push(key.clone());
            let (dir, here, prefix, item, field) = key;
            // where it is: by module path, else (modules not known) by name in the package
            let mut spots: Vec<Spot> = Vec::new();
            let mut local = true;
            let by_module = here.as_ref().and_then(|h| {
                let (d2, m2) = self.module_of(&dir, h, &prefix)?;
                local = self
                    .man
                    .packages
                    .iter()
                    .find(|p| p.manifest_dir == d2)
                    .is_some_and(|p| p.local);
                let mut found = self.find_item(&d2, &m2, &item, 4)?;
                // (`a::X` with no child module `a`: a path from the root, 2015 style)
                if found.is_empty()
                    && prefix
                        .first()
                        .is_some_and(|f| !matches!(f.as_str(), "crate" | "self" | "super"))
                {
                    found = self.find_item(&d2, &prefix, &item, 4).unwrap_or_default();
                }
                Some(found)
            });
            match by_module {
                Some(found) => spots.extend(found.into_iter().map(|(f, sp, m)| (f, sp, Some(m)))),
                None => {
                    // the package the path names, else the file's own
                    let named = prefix.first().and_then(|first| {
                        self.man
                            .packages
                            .iter()
                            .find(|p| {
                                p.lib_name.as_deref() == Some(first.as_str())
                                    || p.name.replace('-', "_") == *first
                            })
                            .map(|p| (p.manifest_dir.clone(), p.local))
                    });
                    let (d2, l2) = named.unwrap_or((dir.clone(), true));
                    local = l2;
                    for f in package_files(&d2) {
                        let Some(src) = self.source(&f) else { continue };
                        for it in src
                            .items
                            .iter()
                            .filter(|it| it.kind == ItemKind::Static && it.name == item)
                        {
                            spots.push((f.clone(), src.span(it), None));
                        }
                    }
                }
            }
            if spots.is_empty() {
                // a package of the build whose sources are at hand: nothing of that name there
                unresolved |= !local;
                continue;
            }
            for (f, sp, m) in spots {
                let Some(src) = self.source(&f) else { continue };
                let mut sub = Reads::default();
                let parts = field
                    .as_deref()
                    .map(|fd| {
                        project(
                            &src,
                            sp.0,
                            sp.1,
                            &fd.split('.').collect::<Vec<_>>(),
                            8,
                            &mut sub.names,
                        )
                    })
                    .unwrap_or(vec![sp]);
                for (x, y) in parts {
                    names_read(&src, self.kb, x, y, 3, &mut HashSet::new(), &mut sub, false);
                }
                r.names.extend(sub.names);
                r.types.extend(sub.types);
                r.replaced |= sub.replaced;
                // what that initializer names in turn, from its own module
                let d3 = self
                    .man
                    .owner_of(&f)
                    .map(|p| p.manifest_dir.clone())
                    .unwrap_or_else(|| dir.clone());
                for (pre, it, fd) in sub.foreign_items {
                    pending.push((d3.clone(), m.clone(), pre, it, fd));
                }
            }
        }
        // (`names_read` marks every such constant; what is left is what was not found)
        r.foreign = unresolved;
    }

    /// The associated items `r` reads of an instance's types (`Reads::assoc`, `T::ALG` in
    /// `hash_c::<CFast>`): what the type's impl gives them (`impl HasConst for CFast { const ALG:
    /// .. = &SHA512; }`), in the package its path names or the file's, else the trait's default
    /// (a const of that name in a trait); neither found: a value from elsewhere (`foreign`).
    fn resolve_assoc(&mut self, path: &Path, r: &mut Reads) {
        let items = std::mem::take(&mut r.assoc);
        for (ty, name) in items {
            let krate = ty
                .trim_start_matches(['&', '<'])
                .split("::")
                .next()
                .unwrap_or("")
                .trim()
                .to_string();
            let tname = type_name(&ty);
            let mut dirs: Vec<PathBuf> = Vec::new();
            if let Some(p) = self.man.packages.iter().find(|p| {
                p.lib_name.as_deref() == Some(krate.as_str()) || p.name.replace('-', "_") == krate
            }) {
                dirs.push(p.manifest_dir.clone());
            }
            if let Some(p) = self.man.owner_of(path)
                && !dirs.contains(&p.manifest_dir)
            {
                dirs.push(p.manifest_dir.clone());
            }
            let files: Vec<PathBuf> = dirs.iter().flat_map(|d| package_files(d)).collect();
            let mut found = false;
            for in_trait in [false, true] {
                for f in &files {
                    let Some(src2) = self.source(f) else { continue };
                    for it in src2.items.iter().filter(|it| {
                        it.kind == ItemKind::Static
                            && it.name == name
                            && src2.items.iter().any(|b| {
                                b.contains(it.start)
                                    && b.start != it.start
                                    && if in_trait {
                                        b.kind == ItemKind::Trait
                                    } else {
                                        b.kind == ItemKind::Impl && b.name == tname
                                    }
                            })
                    }) {
                        found = true;
                        let (a, b) = src2.span(it);
                        let mut sub = Reads::default();
                        names_read(
                            &src2,
                            self.kb,
                            a,
                            b,
                            3,
                            &mut HashSet::new(),
                            &mut sub,
                            false,
                        );
                        r.names.extend(sub.names);
                        r.types.extend(sub.types);
                    }
                }
                if found {
                    break;
                }
            }
            r.foreign |= !found;
        }
    }

    /// A member said to reach the call at `at` from another function (any label but a table's
    /// or a static's, which `check_table` reads): when the argument carrying the algorithm holds
    /// no value from elsewhere (a parameter, a constant of a crate not at hand, a variable a swap
    /// may change, a static the program may change), it does not name only other descriptors of
    /// the asset's primitive, or a type the knowledge base gives one (`digest(b2.alg)` with `b2 =
    /// B { alg: &SHA256 }` and nothing storing into it is no SHA-384). `join`: a `type-join` or
    /// `impl` member, any value of a field's type, is not checked at a call reading a field.
    #[allow(clippy::too_many_arguments)]
    fn check_elsewhere(
        &mut self,
        src: &Source,
        path: &Path,
        at: (usize, usize),
        members: &[&str],
        component_ref: &str,
        exact: bool,
        join: bool,
    ) -> Result<(), String> {
        let Some(mut r) = call_reads(src, self.kb, src.idx(at), exact, &self.inst, self.alg_arg)
        else {
            return Ok(());
        };
        if join && r.fields {
            return Ok(());
        }
        self.resolve_foreign(path, &mut r);
        self.resolve_assoc(path, &mut r);
        let lasts: Vec<&str> = members
            .iter()
            .map(|d| d.rsplit("::").next().unwrap_or(d))
            .collect();
        if r.open || r.foreign || r.replaced || r.lent || lasts.iter().any(|l| r.names.contains(*l))
        {
            return Ok(());
        }
        // a static the program may change at run time (`static mut`, a lock, a cell): a value
        // from elsewhere
        let changed = src.items.iter().any(|it| {
            it.kind == ItemKind::Static && r.names.contains(&it.name) && {
                let (a, b) = src.span(it);
                let head = src.text(a, scan_to(&src.code, a, b, |k| src.code[k] == '='));
                re!(r"^static\s+mut\b|\b(?:RwLock|Mutex|OnceLock|OnceCell|Cell|RefCell|UnsafeCell|ArcSwap\w*|Atomic\w*)\b")
                    .is_match(head.trim_start())
            }
        });
        if changed {
            return Ok(());
        }
        let prim = self.graph.primitive.get(component_ref);
        // other descriptors of its primitive, or a type of the build's crates the knowledge
        // base gives one (`kp.sign(..)` with `kp` an `Ed25519KeyPair` is no ECDSA)
        let others: Vec<&String> = r
            .names
            .iter()
            .filter(|w| {
                self.kb
                    .statics
                    .iter()
                    .any(|e| e.pattern.is_match(w) && Some(&e.algo.primitive) == prim)
            })
            .chain(r.types.iter().filter(|w| {
                self.kb.types.iter().any(|e| {
                    e.name == **w
                        && Some(&e.algo.primitive) == prim
                        && self.libs.as_ref().is_some_and(|l| l.contains_key(&e.krate))
                })
            }))
            .collect();
        if others.is_empty() {
            return Ok(());
        }
        Err(format!(
            "the code the call reads names {}, not {}",
            others
                .iter()
                .map(|w| w.as_str())
                .collect::<Vec<_>>()
                .join(", "),
            lasts.join(", ")
        ))
    }

    /// The witness `w` of a member `d` (`member: object, from `w``, `caller, passed by `w``,
    /// `impl, possible (what `w` writes)`, `type-join, possible (a value `w` stores ..)`) is a
    /// function of the build's sources (of the package its path names) that can give it: its
    /// body names `d`, or reads its parameters (a value it passes on or keeps), and, for one
    /// returning or writing it, does not replace on every way what it writes with other
    /// descriptors only. Witnesses that are no function (a static's initializer, a constant
    /// expression, an element write, `vec![..]`, the standard library's) are not checked here.
    fn check_witness(
        &mut self,
        path: &Path,
        kind: &str,
        w: &str,
        d: &str,
        component_ref: &str,
    ) -> Result<(), String> {
        // (an instance's name printed with an empty turbofish, `m1::gen_set::`: its function;
        // a trait's method of a type printed as `a::Tr::m for a::T`: `<a::T as a::Tr>::m`)
        let w = w.trim_end_matches("::");
        let w = match re!(r"^(.+)::(\w+) for (.+)$").captures(w) {
            Some(m) => format!("<{} as {}>::{}", &m[3], &m[1], &m[2]),
            None => w.to_string(),
        };
        let w = w.as_str();
        // (what the compiler or a macro makes, `t::TA::__rust_std_internal_init_fn`, is not
        // written in the source)
        if !w.contains("::")
            || w.contains('{')
            || w.split("::").any(|g| g.starts_with("__"))
            || re!(r"^(?:static |const |core::|std::|alloc::|<core::|<std::|<alloc::)").is_match(w)
        {
            return Ok(());
        }
        let Some(n) = in_item(w) else {
            return Ok(());
        };
        // the packages its path names: its own, and the trait's for a default body
        // (`<app::Legacy as lib::Pick>::alg` runs `lib`'s)
        let mut krates = vec![
            w.trim_start_matches('<')
                .split("::")
                .next()
                .unwrap_or("")
                .to_string(),
        ];
        if let Some(m) = re!(r" as ([A-Za-z_]\w*)::").captures(w) {
            krates.push(m[1].to_string());
        }
        let dirs: Vec<PathBuf> = krates
            .iter()
            .filter_map(|k| {
                self.man
                    .packages
                    .iter()
                    .find(|p| {
                        p.lib_name.as_deref() == Some(k.as_str()) || p.name.replace('-', "_") == *k
                    })
                    .filter(|p| p.local)
                    .map(|p| p.manifest_dir.clone())
            })
            .collect();
        if dirs.is_empty() {
            return Ok(());
        }
        let _ = path;
        let last = d.rsplit("::").next().unwrap_or(d).to_string();
        let prim = self.graph.primitive.get(component_ref).cloned();
        let files: Vec<PathBuf> = dirs.iter().flat_map(|d| package_files(d)).collect();
        // `<T as Tr>::m` runs the trait's default body only where T's impl of Tr writes no `m`
        let overrides = match (n.self_ty.as_deref(), n.trait_name.as_deref()) {
            (Some(t), Some(tr)) => files.iter().any(|f| {
                self.source(f).is_some_and(|src| {
                    src.items.iter().any(|b| {
                        b.kind == ItemKind::Impl
                            && b.name == t
                            && b.trait_name
                                .as_deref()
                                .is_some_and(|bt| type_name(bt) == type_name(tr))
                            && src.items.iter().any(|g| {
                                g.kind == ItemKind::Fn
                                    && g.name == n.name
                                    && b.contains(g.start)
                                    && b.start != g.start
                            })
                    })
                })
            }),
            _ => false,
        };
        let mut found = false;
        for f in files {
            let Some(src) = self.source(&f) else { continue };
            let is_trait = |t: &str| {
                src.items
                    .iter()
                    .any(|i| i.kind == ItemKind::Trait && i.name == t)
            };
            let in_block = |kind: ItemKind, name: &str, tr: Option<&str>, f: &Item| {
                src.items.iter().any(|b| {
                    b.kind == kind
                        && b.name == name
                        && b.contains(f.start)
                        && b.start != f.start
                        && tr.is_none_or(|t| {
                            b.trait_name
                                .as_deref()
                                .is_some_and(|bt| type_name(bt) == type_name(t))
                        })
                })
            };
            let candidates: Vec<&Item> = src
                .items
                .iter()
                .filter(|f| f.kind == ItemKind::Fn && f.name == n.name)
                .filter(|f| match (n.self_ty.as_deref(), n.trait_name.as_deref()) {
                    // `<T as Tr>::m`: T's impl of Tr, else the trait's default body
                    (Some(t), Some(tr)) => {
                        in_block(ItemKind::Impl, t, Some(tr), f)
                            || (!overrides && in_block(ItemKind::Trait, &type_name(tr), None, f))
                    }
                    // a trait's method, or an inherent one
                    (Some(t), None) if is_trait(t) => in_block(ItemKind::Trait, t, None, f),
                    (Some(t), None) => in_block(ItemKind::Impl, t, None, f),
                    // a free function
                    (None, _) => !src.items.iter().any(|o| {
                        matches!(o.kind, ItemKind::Impl | ItemKind::Trait) && o.contains(f.start)
                    }),
                })
                .collect();
            for f in candidates {
                found = true;
                // (its body: not its own name, read as a call)
                let (a, b) = src.span(f);
                let a = scan_to(&src.code, a, b, |k| src.code[k] == '{');
                let mut r = Reads::default();
                names_read(&src, self.kb, a, b, 3, &mut HashSet::new(), &mut r, true);
                if r.names.contains(&last) || r.foreign {
                    return Ok(());
                }
                let others = r.names.iter().any(|x| {
                    self.kb
                        .statics
                        .iter()
                        .any(|e| e.pattern.is_match(x) && Some(&e.algo.primitive) == prim.as_ref())
                });
                // a parameter it reads that can hold the algorithm (not an integer, a string,
                // bytes): a value from its caller it passes on or keeps
                let sig = fn_sig(&src, f);
                let body = src.text(a, b);
                let carrying = r.open
                    && sig.params.iter().any(|(p, ty)| {
                        !neutral_type(ty)
                            && Regex::new(&format!(
                                r"\b{}\b",
                                regex::escape(p.trim_start_matches("mut ").trim())
                            ))
                            .is_ok_and(|x| x.is_match(&body))
                    });
                if !others {
                    // one that returns or writes the object: of a type that can hold it (not a
                    // `String` made of the arguments)
                    let gives = sig.ret.as_deref().is_some_and(|t| !neutral_type(t))
                        || sig.params.iter().any(|(p, ty)| {
                            (p == "self" || ty.contains("&mut")) && !neutral_type(ty)
                        });
                    if carrying
                        || r.lent
                        || ((kind == "object, from" || kind.starts_with("impl")) && gives)
                    {
                        return Ok(());
                    }
                    continue;
                }
                // it names other descriptors only: a writer keeping the value before on some way
                if kind == "object, from" || kind.starts_with("impl") {
                    let sc = src.fn_scope(f);
                    let replaced = sc
                        .params
                        .iter()
                        .any(|p| !body_assigns(&src, f, p, 3).is_empty());
                    if !replaced && carrying {
                        return Ok(());
                    }
                }
            }
        }
        Err(if found {
            format!("`{w}` gives no `{last}`")
        } else {
            format!("no function `{w}` in its package")
        })
    }

    /// The supertraits the traits of the package of `path`, and of the crate `trait_path` names
    /// (`dyn tlib::Pick`), declare (`trait Sub: Super + Send`: `Sub` -> `[Super, Send]`).
    fn supertraits(&mut self, path: &Path, trait_path: &str) -> HashMap<String, Vec<String>> {
        let mut dirs: Vec<PathBuf> = self
            .man
            .owner_of(path)
            .map(|p| p.manifest_dir.clone())
            .into_iter()
            .collect();
        let krate = trait_path
            .trim()
            .trim_start_matches("dyn ")
            .split("::")
            .next()
            .unwrap_or("")
            .to_string();
        if let Some(p) = self.man.packages.iter().find(|p| {
            p.lib_name.as_deref() == Some(krate.as_str()) || p.name.replace('-', "_") == krate
        }) && !dirs.contains(&p.manifest_dir)
        {
            dirs.push(p.manifest_dir.clone());
        }
        let mut out: HashMap<String, Vec<String>> = HashMap::new();
        for d in dirs {
            for f in package_files(&d) {
                let Some(src) = self.source(&f) else { continue };
                let text: String = src.code.iter().collect();
                for m in
                    re!(r"\btrait\s+(\w+)\s*(?:<[^>{]*>)?\s*:\s*([^{;]+?)\s*(?:\bwhere\b|\{|;)")
                        .captures_iter(&text)
                {
                    let e = out.entry(m[1].to_string()).or_default();
                    for b in split_top(&m[2].replace('+', ",")) {
                        let b = b.trim();
                        if !b.is_empty() && !b.starts_with('\'') && !b.starts_with('?') {
                            e.push(type_name(b));
                        }
                    }
                }
            }
        }
        out
    }

    /// The type of parameter `idx` of the function `name` that a call in `src` names with the
    /// path `prefix` (`tlib::by_dyn`, or `by_dyn` imported from `tlib`), read from the sources
    /// of the package the path or the import leads to (the file's own for a `crate::` path).
    fn foreign_param(
        &mut self,
        src: &Source,
        owner: Option<&rcbom_manifest::Pkg>,
        prefix: &[String],
        name: &str,
        idx: usize,
    ) -> Option<String> {
        let owner_id = owner.map(|p| p.id.repr.clone());
        let roots: Vec<String> = match prefix.first() {
            Some(f) if matches!(f.as_str(), "crate" | "self" | "super") => Vec::new(),
            Some(f) => import_roots(&src.binds, f)
                .map(|r| r.into_iter().collect())
                .unwrap_or_else(|| vec![f.clone()]),
            None => import_roots(&src.binds, name)?.into_iter().collect(),
        };
        let mut dirs: Vec<PathBuf> = Vec::new();
        for r in &roots {
            for p in self.crate_refs(owner_id.as_deref(), r) {
                if let Some(pkg) = self
                    .man
                    .packages
                    .iter()
                    .find(|k| pkg_ref(&k.name, &k.version.to_string()) == p)
                    && !dirs.contains(&pkg.manifest_dir)
                {
                    dirs.push(pkg.manifest_dir.clone());
                }
            }
        }
        if dirs.is_empty() {
            dirs.extend(owner.map(|p| p.manifest_dir.clone()));
        }
        for d in dirs {
            for f in package_files(&d) {
                let Some(s2) = self.source(&f) else { continue };
                for it in s2.items.iter().filter(|it| {
                    it.kind == ItemKind::Fn
                        && it.name == name
                        && !s2.items.iter().any(|o| {
                            matches!(o.kind, ItemKind::Impl | ItemKind::Trait)
                                && o.contains(it.start)
                        })
                }) {
                    if let Some(p) = fn_sig(&s2, it).params.get(idx) {
                        return Some(p.1.clone());
                    }
                }
            }
        }
        None
    }

    /// "dyn: `T` is coerced to `dyn Tr` at F:L" (or "in a static at F:L"): line L of F makes a
    /// `T` a pointer there that becomes a `dyn Tr` (or a trait object of a trait whose
    /// supertraits include `Tr`; `coercion_traits`): it names the type (`Box::new(Fast)`,
    /// `&Legacy`, `W::<A>(..)` with its type arguments, `3u8`), or a variable or parameter whose
    /// binding does (`&mut c4` with `let mut c4 = Ctx { .. }`, a parameter declared of the type or
    /// of a type parameter of its function).
    fn check_coercions(&mut self, details: &str) -> Result<(), String> {
        for m in re!(
            r"dyn: `([^`]+)`(?:, the only type)? (?:is )?coerced to `([^`]+)` (in a static )?at ([^\s;)]+?):(\d+)\)"
        )
        .captures_iter(details)
        {
            let (ty, file, line) = (&m[1], &m[4], m[5].parse::<usize>().unwrap_or(0));
            let what = m[0].trim_end_matches(')');
            let want = type_name(m[2].trim().trim_start_matches("dyn ").trim());
            let path = self.resolve(file)?;
            let src = self
                .source(&path)
                .ok_or_else(|| format!("cannot read {file}, named in `{what}`"))?;
            // the traits whose objects are objects of `want` too (their supertraits include it)
            let supers = self.supertraits(&path, &m[2]);
            let fits = |ts: &[String]| {
                ts.iter().any(|t| {
                    let mut seen = vec![t.clone()];
                    let mut k = 0;
                    while k < seen.len() {
                        if seen[k] == want {
                            return true;
                        }
                        for s2 in supers.get(&seen[k]).into_iter().flatten() {
                            if !seen.contains(s2) {
                                seen.push(s2.clone());
                            }
                        }
                        k += 1;
                    }
                    false
                })
            };
            let Some(text) = src.lines.get(line.wrapping_sub(1)) else {
                return Err(format!("`{what}`: no line {line} in {file}"));
            };
            // a static's value is "in a static", a function's or a const's not
            let in_static = src
                .enclosing((line, text.chars().count()), &[ItemKind::Static])
                .or_else(|| src.enclosing((line, 0), &[ItemKind::Static]))
                .is_some_and(|i| kw(&src.code, src.span(i).0, "static"));
            if in_static != m.get(3).is_some() {
                return Err(format!(
                    "`{what}`: line {line} of {file} is {}in a static",
                    if in_static { "" } else { "not " }
                ));
            }
            let code: String = text
                .chars()
                .zip(&src.class[line - 1])
                .map(|(c, k)| if *k == Class::Code { c } else { ' ' })
                .collect();
            let base = type_name(ty);
            // the type's arguments (`d3::W<d3::A>`: `A`)
            let args: Vec<String> = ty
                .find('<')
                .map(|i| {
                    let inner = &ty[i + 1..ty.len().saturating_sub(1)];
                    inner
                        .split(',')
                        .map(type_name)
                        .filter(|a| !a.is_empty() && a.chars().all(is_ident))
                        .collect()
                })
                .unwrap_or_default();
            let word = |w: &str| {
                Regex::new(&format!(r"\b{}\b", regex::escape(w))).is_ok_and(|r| r.is_match(&code))
            };
            const PRIMS: &[&str] = &[
                "u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32", "i64", "i128",
                "isize", "f32", "f64",
            ];
            let s = &src.code;
            let (l0, l1) = (src.idx((line, 0)), src.idx((line + 1, 0)));
            let dyn_here = word("dyn");
            // a value made a pointer at `i`: `&x`, `&mut x`, `Box::new(x`, `Rc::new(x`, or the
            // value of a statement with a `dyn` type (`let d: Box<dyn Tr> = b;`)
            let made_pointer = |i: usize| -> bool {
                let Some(p) = before_blank(s, i) else {
                    return false;
                };
                match s[p] {
                    '&' => true,
                    '=' => dyn_here,
                    '(' => {
                        let w = word_before_at(s, p);
                        let start = before_blank(s, p).map_or(p, |e| e + 1 - w.len().min(e + 1));
                        let head = src.text(l0.min(start), start);
                        matches!(w.as_str(), "new" | "pin")
                            && re!(r"\b(?:Box|Rc|Arc)\s*::\s*$").is_match(head.trim_end())
                    }
                    c if is_ident(c) => {
                        word_before_at(s, i) == "mut"
                            && p >= 2
                            && before_blank(s, p - 2).is_some_and(|q| s[q] == '&')
                    }
                    _ => false,
                }
            };
            // where it is made a pointer, it becomes an object of the trait (`coercion_traits`;
            // another crate's function's parameter read from its sources)
            let man = self.man;
            let owner = man.owner_of(&path);
            let mut foreign = |prefix: &[String], name: &str, idx: usize| {
                self.foreign_param(&src, owner, prefix, name, idx)
            };
            let mut coerced =
                |i: usize| coercion_traits(&src, i, &mut foreign).is_some_and(|ts| fits(&ts));
            // its arguments are written on the line, or the line is in a generic function whose
            // instance gives them (`Box::new(W(t))` in `fn boxed<T: Pick>(t: T) -> Box<dyn Gen>`)
            let generic_at = |i: usize| {
                src.enclosing(src.pos(i), &[ItemKind::Fn]).is_some_and(|f| {
                    let (fa, fb) = src.span(f);
                    let open = scan_to(s, fa, fb, |k| s[k] == '(');
                    src.text(fa, open).contains('<')
                })
            };
            let args_written = args.iter().all(|a| word(a));
            // the type, with its arguments, made a pointer
            let names_type = ((l0..l1).any(|i| {
                kw(s, i, &base)
                    && (args_written || generic_at(i))
                    && made_pointer(i)
                    && coerced(i)
            }))
                || (PRIMS.contains(&base.as_str())
                    && (l0..l1).any(|i| {
                        s[i].is_ascii_digit()
                            && (i == 0 || !is_ident(s[i - 1]))
                            && word_of(s, i).ends_with(base.as_str())
                            && made_pointer(i)
                            && coerced(i)
                    }));
            if names_type {
                continue;
            }
            // a variable or parameter of the type, made a pointer there
            let ty_word = Regex::new(&format!(r"\b{}\b", regex::escape(&base))).ok();
            let via_var = (l0..l1).any(|i| {
                    if !word_start(s, i)
                        || before_blank(s, i).is_some_and(|p| s[p] == '.' || s[p] == ':')
                        || !made_pointer(i)
                        || !coerced(i)
                    {
                        return false;
                    }
                    let w = word_of(s, i);
                    if !w.chars().next().is_some_and(|c| c.is_lowercase() || c == '_')
                        || is_keyword(&w)
                    {
                        return false;
                    }
                    match binding(&src, i, &w) {
                        // (not one that is a trait object already: `let up: &dyn Super = s;`
                        // with `let s: &dyn Sub = &S1;` coerces no `S1`)
                        Some(Bound::Let {
                            init, first, last, ..
                        }) => {
                            let stmt: Vec<&str> =
                                (first..=last).map(|l| src.lines[l - 1].as_str()).collect();
                            ty_word.as_ref().is_some_and(|r| {
                                r.is_match(&init) || stmt.iter().any(|l| r.is_match(l))
                            }) && !stmt.iter().any(|l| re!(r"\bdyn\b").is_match(l))
                        }
                        // a parameter declared of the type, or of a type parameter of its
                        // function or impl block
                        Some(Bound::Param { .. }) => {
                            src.enclosing(src.pos(i), &[ItemKind::Fn]).is_some_and(|f| {
                                let sig = fn_sig(&src, f);
                                let impl_params = impl_of(&src, f)
                                    .map(|b| {
                                        let (ba, bb) = src.span(b);
                                        let h = src.text(
                                            ba,
                                            scan_to(&src.code, ba, bb, |k| src.code[k] == '{'),
                                        );
                                        h.trim_start()
                                            .strip_prefix("impl")
                                            .filter(|r| r.trim_start().starts_with('<'))
                                            .map(|r| r.to_string())
                                            .unwrap_or_default()
                                    })
                                    .unwrap_or_default();
                                sig.params.iter().any(|(p, t)| {
                                    p.trim_start_matches("mut ").trim() == w && {
                                        let tn = type_name(&deref_type(t));
                                        tn == base
                                            || sig.generics.contains(&tn)
                                            || t.trim_start_matches('&').trim().starts_with("impl ")
                                            || re!(r"[<,]\s*(\w+)\s*[:,>]")
                                                .captures_iter(&impl_params)
                                                .any(|x| x[1] == tn)
                                    }
                                })
                            })
                        }
                        _ => false,
                    }
                });
            if !via_var {
                return Err(format!(
                    "`{what}`: line {line} of {file} makes no `{ty}` a pointer to a trait object"
                ));
            }
        }
        Ok(())
    }

    /// "one of the N in `TABLE`, ..: X": a static or const `TABLE` of the package holds X (in
    /// its initializer, or in a static or const it names). At a call (`at`) whose code reads no
    /// value from elsewhere, that code reads `TABLE` and, through the field it reads of it
    /// (`TABLE[i].legacy`), X.
    fn check_table(
        &mut self,
        src: &Source,
        path: &Path,
        table: &str,
        d: &str,
        at: Option<(usize, usize)>,
    ) -> Result<(), String> {
        let name = table.rsplit("::").next().unwrap_or(table);
        let last = d.rsplit("::").next().unwrap_or(d).to_string();
        // (at a call whose code reads no value from elsewhere, that code reads the static and,
        // through the field it reads of it, the descriptor)
        let tie = |this: &mut Self| -> Result<(), String> {
            if let Some(at) = at
                && let Some(mut r) =
                    call_reads(src, this.kb, src.idx(at), false, &this.inst, this.alg_arg)
            {
                this.resolve_foreign(path, &mut r);
                this.resolve_assoc(path, &mut r);
                if !r.open && !r.foreign {
                    if !r.names.contains(name) {
                        return Err(format!("the call reads no `{table}`"));
                    }
                    if !last.is_empty() && !r.names.contains(&last) {
                        return Err(format!(
                            "what the call reads of `{table}` names no `{last}`"
                        ));
                    }
                }
            }
            Ok(())
        };
        let mut files: Vec<PathBuf> = vec![path.to_path_buf()];
        let own = self.man.owner_of(path);
        if let Some(p) = own {
            files.extend(package_files(&p.manifest_dir));
        }
        // a static of another package of the build (`dep::N1`): that package's files; of a
        // crate whose sources are not at hand, not checked
        let krate = table.split("::").next().unwrap_or("");
        if table.contains("::") && own.is_none_or(|p| p.name.replace('-', "_") != krate) {
            match self
                .man
                .packages
                .iter()
                .find(|p| p.name.replace('-', "_") == krate)
            {
                Some(p) => files.extend(package_files(&p.manifest_dir)),
                None => return Ok(()),
            }
        }
        let mut found = false;
        files.dedup();
        for f in files {
            let owned;
            let src2: &Source = if f == path {
                src
            } else {
                match self.source(&f) {
                    Some(s) => {
                        owned = s;
                        &owned
                    }
                    None => continue,
                }
            };
            for it in src2
                .items
                .iter()
                .filter(|i| i.kind == ItemKind::Static && i.name == name)
            {
                found = true;
                let (a, b) = src2.span(it);
                let mut r = Reads::default();
                names_read(src2, self.kb, a, b, 3, &mut HashSet::new(), &mut r, false);
                if last.is_empty() || r.names.contains(&last) {
                    return tie(self);
                }
            }
        }
        Err(if found {
            format!("`{table}` holds no `{last}`")
        } else {
            format!("no static or const `{name}` in the package")
        })
    }

    /// A package that provides no asset by being named: the program's own, or an interface
    /// crate (`digest`, `aead`, `signature`: their traits are implemented by others).
    fn neutral(&self, r: &str) -> bool {
        r.strip_prefix("pkg:cargo/")
            .and_then(|nv| nv.split_once('@'))
            .and_then(|(n, v)| self.man.by_name_version(n, v))
            .is_some_and(|p| p.local || matches!(p.role, Some(rcbom_kb::Role::Trait)))
    }

    /// Whether binding `b` (`use x::y::ident as name;`) is an alias of the item `ident` of crate
    /// `krate`: imported from that crate, from one that depends on it (a re-export), or from the
    /// program's own module when the package imports `ident` from such a crate (a local
    /// re-export); not an unrelated item that happens to share the last segment.
    fn alias_of(
        &self,
        b: &Binding,
        ident: &str,
        krate: &str,
        owner: Option<&str>,
        binds: &[Binding],
    ) -> bool {
        if b.path.last().map(String::as_str) != Some(ident) || b.name == ident {
            return false;
        }
        let target = self.lib_refs(krate);
        // the symbol's crate is not a package of the CBOM (the standard library): no check
        if target.is_empty() {
            return true;
        }
        let from = |root: &str| {
            self.crate_refs(owner, root)
                .iter()
                .any(|r| target.iter().any(|t| self.graph.closure(r).contains(t)))
        };
        match b.path.first().map(String::as_str) {
            Some("crate" | "self" | "super") => binds.iter().any(|o| {
                o.name == ident
                    && o.path.last().map(String::as_str) == Some(ident)
                    && o.path.first().is_some_and(|r| {
                        !matches!(r.as_str(), "crate" | "self" | "super") && from(r)
                    })
            }),
            Some(root) => root == krate || from(root),
            None => false,
        }
    }

    /// The positions a context's details name: `instantiated by <caller> at <file>:<line>`
    /// (where a generic instance was instantiated) and `expanded from <file>:<line>` (where a
    /// macro's code is written) must be lines of code of files that exist; a standard-library
    /// file is read from the pinned toolchain, whose commit it must name. Outside the standard
    /// library, an instantiation's line is in the caller and names what it instantiates (the
    /// occurrence's item, then each caller in turn; a closure is instantiated where it is
    /// written), and a macro's line is in the body of the `macro_rules!` of its tag.
    fn check_details(
        &mut self,
        details: &str,
        tags: &str,
        symbol: &str,
        call_line: Option<&str>,
        at: (&Path, usize, usize),
        component_ref: &str,
    ) -> Result<(), String> {
        let mut callee = details
            .strip_prefix(tags)
            .unwrap_or(details)
            .strip_prefix("in ")
            .and_then(|d| parts(d).into_iter().next())
            .map(str::to_string);
        // the names of the occurrence's item and of the callers so far
        let mut earlier: Vec<String> = callee
            .as_deref()
            .and_then(in_item)
            .map(|n| n.name)
            .into_iter()
            .collect();
        // the position the next detail's code holds: the occurrence's, then each cited
        // caller's (line, and column where the detail gives one)
        let mut inner: (PathBuf, usize, Option<usize>) = (at.0.to_path_buf(), at.1, Some(at.2));
        for part in parts(details) {
            let Some(m) =
                re!(r"^(instantiated by (.*) at|expanded from) ([^\s;]+?):(\d+)(?::(\d+))?(?: as `([^`]*)`)?$")
                    .captures(part)
            else {
                continue;
            };
            let (file, line) = (m[3].to_string(), m[4].parse::<usize>().unwrap_or(0));
            let col: Option<usize> = m.get(5).and_then(|c| c.as_str().parse().ok());
            // the call's text, where the detail gives it, is what the line holds at the column
            // (`aes_ctr::<Aes128Ctr>`, not its neighbour's `aes_ctr::<Aes192Ctr>`)
            let call_text = m.get(6).map(|t| t.as_str().to_string());
            let caller = m.get(2).map(|c| c.as_str().to_string());
            let path = self.resolve(&file)?;
            let src = self
                .source(&path)
                .ok_or_else(|| format!("cannot read {file}, named in `{part}`"))?;
            let cols: Vec<usize> = src
                .class
                .get(line.wrapping_sub(1))
                .zip(src.lines.get(line.wrapping_sub(1)))
                .map(|(cls, l)| {
                    l.chars()
                        .zip(cls)
                        .enumerate()
                        .filter(|(_, (c, k))| **k == Class::Code && !c.is_whitespace())
                        .map(|(j, _)| j)
                        .collect()
                })
                .unwrap_or_default();
            if cols.is_empty() {
                return Err(format!("`{part}`: no code at line {line} of {file}"));
            }
            if let (Some(t), Some(c0)) = (&call_text, col) {
                let at: String = src.lines[line - 1].chars().skip(c0).collect();
                if !at.starts_with(t.as_str()) {
                    return Err(format!("`{part}`: line {line} has no `{t}` at column {c0}"));
                }
            }
            // where the CBOM records what an instantiation chooses there (`[instantiation]`
            // occurrences: `h::<sha2::Sha384>` is SHA-384's), this asset is among it
            if let (Some(_), Some(c0)) = (&caller, col) {
                let here: Vec<usize> = self
                    .at_pos
                    .get(&(file.clone(), line, c0))
                    .cloned()
                    .unwrap_or_default();
                let chosen: Vec<&str> = here
                    .iter()
                    .filter(|&&j| self.occs[j].context.contains("] [instantiation]"))
                    .map(|&j| self.occs[j].component.as_str())
                    .collect();
                if !chosen.is_empty()
                    && !here
                        .iter()
                        .any(|&j| self.occs[j].component_ref == component_ref)
                {
                    return Err(format!(
                        "`{part}`: the instantiation at {file}:{line}:{c0} chooses {}",
                        chosen.join(", ")
                    ));
                }
            }
            // in the standard library, the line names the caller: a closure's `call_once` shim
            // is cited at the trait's declaration of it
            if file.starts_with("/rustc/") {
                if let Some(n) = caller.as_deref().and_then(in_item) {
                    // in code (not `#[lang = "drop_glue"]` above the function)
                    let text = &src.lines[line - 1];
                    let in_code = Regex::new(&format!(r"\b{}\b", regex::escape(&n.name)))
                        .unwrap()
                        .find_iter(text)
                        .any(|m| cols.contains(&text[..m.start()].chars().count()));
                    if !in_code {
                        return Err(format!("`{part}`: line {line} does not name `{}`", n.name));
                    }
                    // at the start of a token
                    if let Some(c0) = col {
                        let chars: Vec<char> = src.lines[line - 1].chars().collect();
                        let start = cols.contains(&c0)
                            && (!is_ident(chars[c0]) || c0 == 0 || !is_ident(chars[c0 - 1]));
                        if !start {
                            return Err(format!("`{part}`: no token starts at column {c0}"));
                        }
                    }
                    if !earlier.contains(&n.name) {
                        earlier.push(n.name);
                    }
                } else if caller.is_none() {
                    // a standard-library macro's line (`thread_local!`'s, read from the
                    // toolchain's sources): it names the symbol (`= __RUST_STD_INTERNAL_INIT;`),
                    // or uses a metavariable the invocation's line, which names it, fills
                    let sym = strip_generics(symbol);
                    let ident = sym.rsplit("::").next().unwrap_or(&sym);
                    let word = Regex::new(&format!(r"\b{}\b", regex::escape(ident))).unwrap();
                    let text: String = src.lines[line - 1]
                        .chars()
                        .zip(&src.class[line - 1])
                        .map(|(c, k)| if *k == Class::Code { c } else { ' ' })
                        .collect();
                    let metavar = re!(r"\$(\w+)")
                        .captures_iter(&text)
                        .any(|m| &m[1] != "crate");
                    if !word.is_match(&text)
                        && !(metavar && call_line.is_some_and(|l| word.is_match(l)))
                    {
                        return Err(format!("`{part}`: line {line} does not name `{ident}`"));
                    }
                }
                callee = caller;
                inner = (path.clone(), line, col);
                continue;
            }
            match &caller {
                // an instantiation in the items a macro invocation outside any item makes,
                // cited at the invocation (hpke's `impl_dhkem!(..)` makes `encap`)
                Some(c)
                    if {
                        let c0 = col.unwrap_or(cols[0]);
                        src.enclosing((line, c0), &[ItemKind::Fn, ItemKind::Static])
                            .is_none()
                            && macro_call_at(&src, (line, c0))
                            && match invocation_names(&src, (line, c0), c, &[]) {
                                Pick::Exact => true,
                                Pick::Range => {
                                    RANGED.with(|r| r.set(true));
                                    true
                                }
                                Pick::No => false,
                            }
                    } =>
                {
                    if let Some(n) = in_item(c)
                        && !earlier.contains(&n.name)
                    {
                        earlier.push(n.name);
                    }
                    callee = Some(c.clone());
                    inner = (path.clone(), line, col);
                }
                Some(c) => {
                    let want = in_item(c).ok_or_else(|| format!("`{part}`: no item"))?;
                    // where the line names what it instantiates, as a use (not `fn seal(..)`
                    // defining the caller): the item or a caller before it (an occurrence
                    // instantiated along two chains lists both last callers, each naming the
                    // item before them). A closure is called through a variable, and what
                    // syntax calls (`.await` polls, a scope's end drops, `?`, operators,
                    // `for`) is not named: any code of the line then.
                    let text = &src.lines[line - 1];
                    // a closure (or `async` body) the caller itself writes is cited where it
                    // does: `|..|`, `async`, `move`
                    let own_closure = callee
                        .as_deref()
                        .and_then(closure_parent)
                        .is_some_and(|p| strip_generics(p) == strip_generics(c));
                    // a closure's caller that is its parent but for the closures' indexes
                    // (`main::{closure#7}` for `main::{closure#0}::{closure#0}`) names another
                    // closure than the one holding it
                    if let Some(p) = callee.as_deref().and_then(closure_parent) {
                        let idx = |x: &str| {
                            re!(r"\{closure#\d+\}")
                                .replace_all(x, "{closure}")
                                .to_string()
                        };
                        let (p, c2) = (strip_generics(p), strip_generics(c));
                        if p.trim() != c2.trim() && idx(&p).trim() == idx(&c2).trim() {
                            return Err(format!(
                                "`{part}`: the closure is in `{}`, not in `{}`",
                                p.trim(),
                                c2.trim()
                            ));
                        }
                    }
                    let unnamed = callee.as_deref().is_none_or(|p| {
                        p.trim_end().ends_with('}') || in_item(p).is_some_and(|n| by_syntax(&n))
                    });
                    let chars: Vec<char> = text.chars().collect();
                    // an `async` closure's body is made where it starts (`async move |d| expr`:
                    // at `expr`)
                    let closure_caller = c.trim_end().ends_with('}');
                    let named: Vec<usize> = if own_closure {
                        // and an `async fn`'s body at its `{`
                        let starts = re!(r"\|\|?|\basync\b|\bmove\b|\bstatic\b|\{")
                            .find_iter(text)
                            .map(|m| text[..m.start()].chars().count())
                            .filter(|col| cols.contains(col));
                        let body = col.filter(|&c0| {
                            closure_caller
                                && cols.contains(&c0)
                                && async_body_at(&src.code, src.idx((line, c0))).is_some()
                        });
                        starts.chain(body).collect()
                    } else if unnamed {
                        // a token the language calls through: a name (`poll`, a closure's
                        // variable), `?`, a bracket
                        cols.iter()
                            .copied()
                            .filter(|&j| {
                                col.is_none()
                                    || (is_ident(chars[j]) && (j == 0 || !is_ident(chars[j - 1])))
                                    || "?{}()[]|".contains(chars[j])
                            })
                            .collect()
                    } else {
                        // a method is also instantiated where a value of its type is made a
                        // trait object (`let b: Box<dyn H> = Box::new(A)` makes `<A as H>::h`'s
                        // vtable): the line names the type or the trait
                        let owners: Vec<String> = callee
                            .as_deref()
                            .and_then(in_item)
                            .map(|n| {
                                n.self_ty
                                    .into_iter()
                                    .chain(n.owner.map(|(t, _)| t))
                                    .chain(
                                        n.trait_name
                                            .map(|t| t.split('<').next().unwrap_or(&t).to_string()),
                                    )
                                    .filter(|t| t.chars().all(is_ident) && !t.is_empty())
                                    .collect()
                            })
                            .unwrap_or_default();
                        // (a value of a generic type, `Box::new(conn)` in reqwest: a coercion to a
                        // trait object, for a method of a trait)
                        let coerces = callee
                            .as_deref()
                            .and_then(in_item)
                            .is_some_and(|n| n.trait_name.is_some() || n.owner.is_some())
                            && re!(r"\b(Box|Arc|Rc)::(new|pin)\(|\bas\s+(?:[&*]|dyn\b|Box\b|Arc\b|Rc\b|Pin\b)|\bdyn\s")
                                .is_match(text);
                        // (or the value at the column becomes an object of the method's trait
                        // there: `up_dyn(&mut a1)` with `fn up_dyn(u: &mut dyn Up)` makes the
                        // vtable of `a1`'s type, whose `up` is the trait's default body unless the
                        // type's impl writes its own)
                        let vtable = match (col, callee.as_deref().and_then(in_item)) {
                            (Some(c0), Some(n)) if c0 < chars.len() => {
                                let s = &src.code;
                                let is_trait = |t: &str| {
                                    src.items
                                        .iter()
                                        .any(|x| x.kind == ItemKind::Trait && x.name == t)
                                };
                                let (ty, tr) = match (n.self_ty.clone(), n.trait_name.clone()) {
                                    (Some(st), Some(tr)) => (Some(st), Some(type_name(&tr))),
                                    (Some(st), None) if is_trait(&st) => (None, Some(st)),
                                    _ => (None, None),
                                };
                                let mut v = src.idx((line, c0));
                                if s.get(v) == Some(&'&') {
                                    v = skip_blank(s, v + 1);
                                    if kw(s, v, "mut") {
                                        v = skip_blank(s, v + 3);
                                    }
                                }
                                let vty = expr_type(&src, v, src.idx((line + 1, 0)), 4)
                                    .map(|t| type_name(&deref_type(&t)));
                                let overrides = |vt: &str, tr: &str| {
                                    src.items.iter().any(|b| {
                                        b.kind == ItemKind::Impl
                                            && b.name == vt
                                            && b.trait_name.as_deref().map(type_name).as_deref()
                                                == Some(tr)
                                            && src.items.iter().any(|f| {
                                                f.kind == ItemKind::Fn
                                                    && f.name == n.name
                                                    && b.contains(f.start)
                                                    && b.start != f.start
                                            })
                                    })
                                };
                                match tr {
                                    Some(tr)
                                        if word_start(s, v)
                                            && match (&ty, &vty) {
                                                (Some(st), Some(vt)) => type_name(st) == *vt,
                                                (Some(_), None) => false,
                                                (None, Some(vt)) => !overrides(vt, &tr),
                                                (None, None) => true,
                                            } =>
                                    {
                                        let supers = self.supertraits(&path, "");
                                        let man = self.man;
                                        let owner = man.owner_of(&path);
                                        let mut foreign = |p: &[String], f: &str, k: usize| {
                                            self.foreign_param(&src, owner, p, f, k)
                                        };
                                        coercion_traits(&src, v, &mut foreign).is_some_and(|ts| {
                                            ts.iter().any(|t| {
                                                *t == tr
                                                    || supers
                                                        .get(t)
                                                        .is_some_and(|x| x.contains(&tr))
                                            })
                                        })
                                    }
                                    _ => false,
                                }
                            }
                            _ => false,
                        };
                        let names_owner =
                            coerces || vtable || owners.iter().any(|o| path_names(text, o));
                        earlier
                            .iter()
                            .flat_map(|n| {
                                Regex::new(&format!(r"\b{}\b", regex::escape(n)))
                                    .unwrap()
                                    .find_iter(text)
                                    .map(|m| text[..m.start()].chars().count())
                                    .collect::<Vec<_>>()
                            })
                            // the coercion's expression, from its first token
                            .chain(col.filter(|_| names_owner))
                            .chain(
                                cols.first()
                                    .copied()
                                    .filter(|_| col.is_none() && names_owner),
                            )
                            .filter(|&j| {
                                cols.contains(&j) && {
                                    let before: String = chars[..j].iter().collect();
                                    !re!(r"\bfn\s+$").is_match(&before)
                                }
                            })
                            // with a column: the path written there names it (`hash::<S384>`,
                            // `crate::m::seal`, a method's name)
                            .filter_map(|j| match col {
                                None => Some(j),
                                // (a column past the line's end, as a shifted position may be)
                                Some(c0) if c0 > chars.len() => None,
                                Some(c0) => {
                                    let start =
                                        chars.get(c0).is_some_and(|ch| is_ident(*ch) || *ch == '<')
                                            && (c0 == 0 || !is_ident(chars[c0 - 1]));
                                    // (a coercion's expression may start with `&` or `(`:
                                    // `&Legacy` made a `&dyn Pick`)
                                    let coercion = j == c0
                                        && names_owner
                                        && chars.get(c0).is_some_and(|ch| matches!(ch, '&' | '('));
                                    // (the coercion's expression from its first token: not a
                                    // token inside `&W(S2)` or `Box::new(X)`)
                                    let prev: String = chars[..c0].iter().collect();
                                    let inside = re!(r"(?:&\s*(?:mut\s+)?|\b(?:new|pin)\s*\(\s*)$")
                                        .is_match(&prev);
                                    // (a token naming none of the chain's items is the
                                    // coercion's, which starts there)
                                    let names_item = earlier.iter().any(|n| {
                                        word_of(&chars, j) == *n
                                            || chars
                                                [c0..(c0 + path_len(&chars, c0)).min(chars.len())]
                                                .iter()
                                                .collect::<String>()
                                                .split("::")
                                                .any(|g| g.trim() == n)
                                    });
                                    ((start
                                        && (names_item || !inside)
                                        && ((j >= c0 && j < c0 + path_len(&chars, c0))
                                            || (j == c0 && names_owner)))
                                        || coercion)
                                        .then_some(c0)
                                }
                            })
                            .collect()
                    };
                    // with a column, that token; not a function item a `let` binds to a variable
                    // (`let h = Local::alg;`): that is instantiated where the variable is called
                    let item_bound = col.is_some_and(|c0| {
                        re!(r"^(\s*let\s+(?:mut\s+)?\w+\s*=\s*)([\w:<>, ]+?)\s*;\s*$")
                            .captures(text)
                            .is_some_and(|m| {
                                let a = m[1].chars().count();
                                (a..a + m[2].chars().count()).contains(&c0)
                            })
                    });
                    let mut named: Vec<usize> = match col {
                        Some(_) if item_bound => Vec::new(),
                        Some(c0) => named.into_iter().filter(|&j| j == c0).collect(),
                        None => named,
                    };
                    // a call a macro invoked in the function makes (`calls!(T0 T1)` expanding to
                    // `outer::<T0>()`), or one through a variable bound to the function item
                    // (`let h = Local::alg; h(&d)`)
                    if named.is_empty()
                        && !own_closure
                        && let Some(c0) = col
                        && let Some(want_name) = callee.as_deref().and_then(in_item).map(|n| n.name)
                    {
                        let word = Regex::new(&format!(r"\b{}\b", regex::escape(&want_name))).ok();
                        let names_it = |t: &str| word.as_ref().is_some_and(|r| r.is_match(t));
                        let ci = src.idx((line, c0));
                        let by_macro = macro_call_at(&src, (line, c0))
                            && expansion(&src, (line, c0)).is_some_and(|e| names_it(&e));
                        let w = word_of(&src.code, ci);
                        let by_variable = !w.is_empty()
                            && w.starts_with(|c: char| c.is_lowercase() || c == '_')
                            && skip_blank(&src.code, ci + w.chars().count()) < src.code.len()
                            && src.code[skip_blank(&src.code, ci + w.chars().count())] == '('
                            && matches!(binding(&src, ci, &w),
                                Some(Bound::Let { init, .. }) if names_it(&init)
                                    && !init.contains('(')
                                    && fn_item_runs(&src, callee.as_deref().unwrap_or(""), init.trim()));
                        if by_macro || by_variable {
                            named.push(c0);
                        }
                    }
                    if named.is_empty() && own_closure {
                        return Err(format!(
                            "`{part}`: line {line} writes no closure or `async` body"
                        ));
                    }
                    // the closure cited holds the code instantiated in it (not the closure
                    // beside it)
                    if own_closure
                        && let Some(c0) = col
                        && inner.0 == path
                    {
                        let ci = src.idx((line, c0));
                        let Some((a, b)) =
                            closure_span(&src.code, ci).or_else(|| async_body_at(&src.code, ci))
                        else {
                            return Err(format!(
                                "`{part}`: no closure or `async` body starts at column {c0}"
                            ));
                        };
                        // strictly inside it, and in no closure nested in it
                        // (`run1(|x| run1(|y| digest(..), x), d)`: the code is `|y|`'s)
                        let bar = src.code.get(a) == Some(&'|')
                            || ["move", "async", "static"]
                                .iter()
                                .any(|w| kw(&src.code, a, w));
                        let holds = match inner.2 {
                            Some(ic) => {
                                let ii = src.idx((inner.1, ic));
                                (a < ii || (a == ii && !bar))
                                    && ii < b
                                    && !(a + 1..ii).any(|k| {
                                        closure_at(&src.code, k)
                                            && closure_span(&src.code, k)
                                                .is_some_and(|(x, y)| x < ii && ii < y && y < b)
                                    })
                            }
                            None => a <= src.idx((inner.1 + 1, 0)) && src.idx((inner.1, 0)) < b,
                        };
                        if !holds {
                            let (el, ec) = src.pos(b);
                            return Err(format!(
                                "`{part}`: the closure at {line}:{c0} (to {el}:{ec}) does not hold \
                                 {}:{}",
                                inner.1,
                                inner.2.unwrap_or(0)
                            ));
                        }
                    }
                    if named.is_empty() {
                        return Err(format!(
                            "`{part}`: line {line} does not name `{}`",
                            callee
                                .as_deref()
                                .and_then(in_item)
                                .map(|n| n.name)
                                .unwrap_or_default()
                        ));
                    }
                    // a method called on a value of a type of the file: of the chain's type
                    // (`E2.ext()` instantiates `<E2 as Ext>::ext`, not `E1.ext()`), or one
                    // implementing the chain's trait
                    if let Some(c0) = col
                        && !own_closure
                        && let Some(n) = callee.as_deref().and_then(in_item)
                        && let Some(t) = receiver_type(&src, src.idx((line, c0)))
                        && !receiver_fits(&src, &n, &t)
                    {
                        return Err(format!(
                            "`{part}`: the method at {line}:{c0} is called on a `{t}`, not on what \
                             `{}` is of",
                            n.path
                        ));
                    }
                    // a generic function's instance (`pass::<A>`): the call's type arguments,
                    // written (`pass::<Last>(..)`) or given by its arguments (`pass(&B, ..)` for
                    // `fn pass<T: Pick>(t: &T, ..)`), are the instance's
                    if let Some(c0) = col
                        && !own_closure
                        && let Some(want_args) = callee.as_deref().and_then(instance_args)
                        && let Some(n) = callee.as_deref().and_then(in_item)
                        && let Some(found) = call_type_args(&src, src.idx((line, c0)), &n.name)
                    {
                        for (k, t) in found.iter().enumerate() {
                            if let (Some(w), Some(t)) = (want_args.get(k), t)
                                && type_name(w) != type_name(t)
                            {
                                return Err(format!(
                                    "`{part}`: the call at {line}:{c0} instantiates `{}` with `{}`, \
                                     not `{}`",
                                    n.name,
                                    type_name(t),
                                    type_name(w)
                                ));
                            }
                        }
                    }
                    // the caller is around it, as for an occurrence: its item, the impl block
                    // or trait, the module; or the attribute on it (`#[tokio::main]` makes
                    // `main`'s body)
                    let chains = self.module_chains(&path, 0);
                    let man = self.man;
                    let owner = man.owner_of(&path);
                    let mut aliases = |n: &str| self.alias_targets(&src, owner, n);
                    let mut first_err = None;
                    let mut inside = false;
                    for &col in &named {
                        match check_item(
                            &src,
                            &format!("in {c}"),
                            (line, col),
                            &mut aliases,
                            chains.as_deref(),
                            None,
                        ) {
                            Ok(()) => {
                                inside = true;
                                break;
                            }
                            Err(e) => {
                                first_err.get_or_insert(e);
                            }
                        }
                    }
                    if !inside && attribute_of(&src, line).is_some_and(|i| i.name == want.name) {
                        inside = true;
                    }
                    if !inside {
                        return Err(format!(
                            "`{part}`: line {line} is not in `{}` ({})",
                            want.name,
                            first_err.unwrap_or_default()
                        ));
                    }
                    if !earlier.contains(&want.name) {
                        earlier.push(want.name);
                    }
                    callee = Some(c.clone());
                    inner = (path.clone(), line, col);
                }
                None => {
                    // a procedural macro's code (a derive's, an attribute's, a function-like
                    // one's) is cited at its use: the attribute or invocation the position is
                    // in, from its first line
                    let bang = re!(r"\[macro (?:[\w]+::)*(\w+)!\]").captures(tags);
                    let rules = bang.as_ref().is_some_and(|t| {
                        src.items
                            .iter()
                            .any(|i| i.kind == ItemKind::Macro && i.name == t[1])
                    });
                    let Some(t) = bang.filter(|_| rules) else {
                        let first = attribute_start(self, at.0, at.1);
                        if path != at.0 || first != Some(line) {
                            return Err(format!(
                                "`{part}`: not the first line of the attribute or macro call at line {}",
                                at.1
                            ));
                        }
                        continue;
                    };
                    // the tagged macro's body, or that of a macro of the same file it invokes
                    // (primeorder's `impl_mont_field_element!` writes its arithmetic through
                    // `impl_mont_field_element_arithmetic!`)
                    let invoked = macros_invoked(&src, &t[1]);
                    let inside = cols.iter().any(|&col| {
                        src.enclosing((line, col), &[ItemKind::Macro])
                            .is_some_and(|m| invoked.contains(&m.name))
                    });
                    if !inside {
                        return Err(format!(
                            "`{part}`: line {line} is not in the body of `macro_rules! {}`",
                            &t[1]
                        ));
                    }
                    // the macro's line names the symbol, or the call passes it in
                    // (`hash_with!(SHA384)` for a body calling `digest(&$alg, ..)`): the line
                    // then uses a metavariable, which a matcher's `$alg:expr` only declares
                    let sym = strip_generics(symbol);
                    let ident = sym.rsplit("::").next().unwrap_or(&sym);
                    let word = Regex::new(&format!(r"\b{}\b", regex::escape(ident))).unwrap();
                    let text = &src.lines[line - 1];
                    // the metavariables the line uses (not declares); where the macro's rule and
                    // the invocation say which one the call's token binds (`mk!(m256, hash_a,
                    // SHA256)` with `($m:ident, $f:ident, $alg:ident)`: `$alg`), that one
                    let used: Vec<&str> = re!(r"\$(\w+)")
                        .captures_iter(text)
                        .filter(|m| {
                            !text[m.get(0).map_or(0, |g| g.end())..]
                                .trim_start()
                                .starts_with(':')
                        })
                        .filter_map(|m| m.get(1).map(|g| g.as_str()))
                        .collect();
                    // the rule the occurrence's invocation matches (rustc's first), where it can
                    // be read: the line is in its transcriber, and its metavariables are bound
                    let occ = self.source(at.0);
                    let rule = src
                        .items
                        .iter()
                        .find(|i| {
                            i.kind == ItemKind::Macro
                                && i.name == t[1]
                                && (i.start.0..=i.end.0).contains(&line)
                        })
                        .and_then(|m| {
                            let (_, args) = invocation_args(occ.as_deref()?, (at.1, at.2))?;
                            rule_for(&src, m, &args)
                        });
                    if let Some((r, _)) = &rule {
                        let (l0, l1) = (src.pos(r.body.0).0, src.pos(r.body.1).0);
                        if !(l0..=l1).contains(&line) {
                            return Err(format!(
                                "`{part}`: line {line} is not in the rule of `macro_rules! {}` the \
                                 invocation matches (lines {l0}-{l1})",
                                &t[1]
                            ));
                        }
                    }
                    let binding = match &rule {
                        Some((_, binds)) => Some(
                            binds
                                .iter()
                                .filter(|(_, toks)| word.is_match(&toks_text(toks)))
                                .map(|(n, _)| n.clone())
                                .collect::<Vec<_>>(),
                        ),
                        None => cols
                            .iter()
                            .find_map(|&col| src.enclosing((line, col), &[ItemKind::Macro]))
                            .and_then(|m| {
                                let body: String = (m.start.0..=m.end.0.min(src.lines.len()))
                                    .map(|l| src.lines[l - 1].as_str())
                                    .collect::<Vec<_>>()
                                    .join("\n");
                                call_line.and_then(|l| metavars_of(&body, l, &word))
                            }),
                    };
                    let uses_metavar = match &binding {
                        Some(vars) => used.iter().any(|u| vars.iter().any(|v| v == u)),
                        None => !used.is_empty(),
                    };
                    if !word.is_match(text)
                        && !(uses_metavar && call_line.is_some_and(|l| word.is_match(l)))
                    {
                        return Err(format!(
                            "`{part}`: line {line} of the macro does not name `{ident}`"
                        ));
                    }
                }
            }
        }
        Ok(())
    }
}

/// How a variable, read at an index of `code`, is bound.
enum Bound {
    /// By a statement or pattern of the function at lines `first..=last`, from `init` (a
    /// `let`'s initializer, an `if let`'s or `while let`'s scrutinee, a `for`'s iterator, a
    /// `match`'s scrutinee for an arm's pattern, a macro's invocation), which starts at `at`.
    Let {
        first: usize,
        last: usize,
        init: String,
        at: usize,
    },
    /// A parameter of the function `fun`.
    Param { fun: String },
    /// A closure's parameter: not followed.
    ClosureParam,
    /// A static or const of the file, at lines `start..=end`.
    Item { start: usize, end: usize },
}

/// Where the variable `name`, read at `at`, is bound (`lookup`): the nearest binding in scope
/// in its function, its parameters, then the statics and consts.
fn binding(src: &Source, at: usize, name: &str) -> Option<Bound> {
    Some(match lookup(src, at, name)? {
        Found::Bind(b) if b.kind == BindKind::Closure => Bound::ClosureParam,
        Found::Bind(b) => {
            let (i0, i1) = b.init.unwrap_or(b.stmt);
            Bound::Let {
                first: src.pos(b.stmt.0).0,
                last: src.pos(b.stmt.1.saturating_sub(1).max(b.stmt.0)).0,
                // (a macro's binding holds what the invocation's line names)
                init: if b.kind == BindKind::Macro {
                    String::new()
                } else {
                    src.text(i0, i1)
                },
                at: i0,
            }
        }
        Found::Param(fun) => Bound::Param { fun },
        Found::Item(k) => Bound::Item {
            start: src.items[k].start.0,
            end: src.items[k].end.0,
        },
    })
}

/// Is a function pointer held by variable `name`, read at `at`, the one named at line `named`:
/// the variable bound where the function is named (a `let`, a pattern of `if let`, `while let`,
/// `for` or a `match` arm, over lines; the binding in scope, so a block's or a closure's own
/// `let` of the name is another variable), or copied from one that is (`let f = f;`: the one
/// before), or from the result of the file's function or method whose body names it, or of a
/// closure that does; a parameter of a function called where it is named (in the call's
/// arguments or its receiver's binding); a static or const whose value (or another static it
/// refers to) names it? A variable bound by a closure's parameter is not checked.
fn pointer_bound(src: &Source, at: usize, name: &str, named: usize) -> Result<(), String> {
    let mut cur = (at, name.to_string());
    let file_fns = |n: &str| -> Vec<&Item> {
        src.items
            .iter()
            .filter(|i| i.kind == ItemKind::Fn && i.name == n)
            .collect()
    };
    for _ in 0..8 {
        let bound = binding(src, cur.0, &cur.1);
        // the file's function (`get()(..)`): named in its body
        if bound.is_none()
            && let Some(f) = file_fns(&cur.1).first()
        {
            return if (f.start.0..=f.end.0).contains(&named) {
                Ok(())
            } else {
                Err(format!(
                    "`{}` is the function at lines {}-{}",
                    cur.1, f.start.0, f.end.0
                ))
            };
        }
        let bound =
            bound.ok_or_else(|| format!("`{}` is not bound in its function or its file", cur.1))?;
        let (first, last, init, init_at) = match bound {
            Bound::ClosureParam => return Ok(()),
            Bound::Param { fun } => return param_passes(src, &fun, &cur.1, named),
            Bound::Item { start, end } => {
                if (start..=end).contains(&named) {
                    return Ok(());
                }
                // a static of another static (`static B: &HashFn = &A`)
                let text: String = (start..=end)
                    .map(|l| src.lines[l - 1].as_str())
                    .collect::<Vec<_>>()
                    .join("\n");
                let refers = src.items.iter().any(|i| {
                    i.kind == ItemKind::Static
                        && i.name != cur.1
                        && (i.start.0..=i.end.0).contains(&named)
                        && Regex::new(&format!(r"\b{}\b", regex::escape(&i.name)))
                            .is_ok_and(|r| r.is_match(&text))
                });
                return if refers {
                    Ok(())
                } else {
                    Err(format!("`{}` is the item at lines {start}-{end}", cur.1))
                };
            }
            Bound::Let {
                first,
                last,
                init,
                at,
            } => (first, last, init, at),
        };
        // the statement names it
        if (first..=last).contains(&named) {
            return Ok(());
        }
        let init = init.trim();
        // a call of the file's function or method (`get()`, `pk.pick()`, `Reg::make()`; not
        // `HashMap::new()`, another type's): named in its body
        let fns = file_fns_called(src, init);
        if fns.iter().any(|f| (f.start.0..=f.end.0).contains(&named)) {
            return Ok(());
        }
        // a container in a field of it the function fills (`t.map.insert(1, digest)` with `let
        // mut t = Table::new();`): the statement storing it names it
        if container_stores(src, init_at, &cur.1)
            .iter()
            .any(|&(a, b)| (a..=b).contains(&named))
        {
            return Ok(());
        }
        // a container the function fills (`map.insert("a", digest)`, `v.push(digest)`): one of
        // the statements storing into it names it
        if re!(r"^(?:\w+\s*::\s*)*(?:Vec|VecDeque|HashMap|BTreeMap|HashSet|BTreeSet|IndexMap)\s*(?:::\s*<[^>]*>\s*)?::\s*(?:new|with_capacity|default)\s*\(|^vec!\s*\[\s*\]|^Vec\s*::\s*from").is_match(init)
        {
            let stores = container_stores(src, init_at, &cur.1);
            if stores.iter().any(|&(a, b)| (a..=b).contains(&named)) {
                return Ok(());
            }
            return Err(if stores.is_empty() {
                format!("`{}` is bound at lines {first}-{last}", cur.1)
            } else {
                format!(
                    "`{}` is given its values at lines {}",
                    cur.1,
                    stores
                        .iter()
                        .map(|(a, b)| if a == b { format!("{a}") } else { format!("{a}-{b}") })
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            });
        }
        // a copy of another variable (`if let Some(f) = o`, `let h = p;`, `let f = f;`: the
        // one before), or a method of it (`it.next()`, `fs.iter()`): where that one is bound
        if let Some(v) = re!(
            r"^&?\s*(?:mut\s+)?\*?\s*([A-Za-z_]\w*)(?:\s*\.\s*\w+\s*(?:\([^()]*\))?|\s*\[[^\[\]]*\])*\s*\??$"
        )
        .captures(init)
        {
            let v = v[1].to_string();
            if binding(src, init_at, &v).is_none() && file_fns(&v).is_empty() {
                // an imported function item (`let f = digest;`): this statement names it
                return Err(format!("`{}` is bound at lines {first}-{last}", cur.1));
            }
            cur = (init_at, v);
            continue;
        }
        // the result of a call of a closure of the function (`let k = mk();`): named in the
        // closure's statement; a tuple struct's or variant's constructor (`Some(digest::
        // digest)`) holds what it is given, named in the statement
        if let Some(c) = re!(r"^(?:\w+::)*([a-z_]\w*)\s*\(").captures(init) {
            if !fns.is_empty() {
                return Err(format!(
                    "`{}` holds what `{}` returns (lines {first}-{last})",
                    cur.1, &c[1]
                ));
            }
            match binding(src, init_at, &c[1]) {
                Some(Bound::Let {
                    first: f, last: l, ..
                }) if !(f..=l).contains(&named) => {
                    return Err(format!(
                        "`{}` holds what `{}` returns (lines {f}-{l})",
                        cur.1, &c[1]
                    ));
                }
                Some(Bound::Let { .. }) => return Ok(()),
                _ => {}
            }
        }
        // a value the statement computes from others not followed (another crate's function,
        // a labelled block): one of the variables it reads is bound where the function is named
        if re!(r"\w\s*\(|\w!|'\w+\s*:").is_match(init)
            && !re!(r"^(?:\w+::)*[A-Z]\w*\s*[({]|^vec!|^\[").is_match(init)
        {
            let reads_bound = re!(r"\b([a-z_]\w*)\b").captures_iter(init).any(|v| {
                !is_keyword(&v[1])
                    && matches!(
                        binding(src, init_at, &v[1]),
                        Some(Bound::Let { first: f, last: l, .. }) if (f..=l).contains(&named)
                    )
            });
            if reads_bound {
                return Ok(());
            }
        }
        return Err(format!("`{}` is bound at lines {first}-{last}", cur.1));
    }
    Ok(())
}

/// The file's method taking `self` that a method call at `m` (`v.reset()`) names: of the impl
/// for the receiver's type when the code says which (`let v = B { .. }`), else the first.
fn method_for<'a>(src: &'a Source, m: &usize, name: &str) -> Option<&'a Item> {
    let methods: Vec<&Item> = src
        .items
        .iter()
        .filter(|x| {
            x.kind == ItemKind::Fn
                && x.name == name
                && src.fn_scope(x).params.first().is_some_and(|p| p == "self")
        })
        .collect();
    let ty = receiver_type(src, *m);
    ty.as_deref()
        .and_then(|t| {
            methods.iter().copied().find(|f| {
                src.items.iter().any(|b| {
                    b.kind == ItemKind::Impl
                        && b.name == t
                        && b.contains(f.start)
                        && b.start != f.start
                })
            })
        })
        .or_else(|| methods.first().copied())
}

/// The calls the variable bound by `bd` is lent to before the read at `start`, as `&mut` (`f(&mut
/// v)`) or as a method's receiver (`v.up()`): the file's function or method called (its body
/// may write it), or None for another crate's function taking `&mut v` (`mem::swap` aside, which
/// `lent_mut` reads).
fn lent_to<'a>(src: &'a Source, bd: &Bind, start: usize) -> Vec<(usize, Option<&'a Item>)> {
    let s = &src.code;
    let mut out = Vec::new();
    let mut i = bd.scope.0;
    while i < start.min(s.len()) {
        if !kw(s, i, &bd.name)
            || !matches!(lookup(src, i, &bd.name), Some(Found::Bind(b)) if b.stmt == bd.stmt)
        {
            i += 1;
            continue;
        }
        let after = skip_blank(s, i + bd.name.chars().count());
        let by_mut = word_before_at(s, i) == "mut"
            && before_blank(s, i)
                .and_then(|m| before_blank(s, m + 1 - 3))
                .is_some_and(|a| s[a] == '&');
        if by_mut && !swapping_call(src, i) {
            // the call it is an argument of
            let mut depth = 0;
            let mut j = i;
            let mut open = None;
            while j > 0 {
                j -= 1;
                match s[j] {
                    ')' | ']' | '}' => depth += 1,
                    '(' if depth == 0 => {
                        open = Some(j);
                        break;
                    }
                    '(' | '[' | '{' => {
                        if depth == 0 {
                            break;
                        }
                        depth -= 1;
                    }
                    ';' if depth == 0 => break,
                    _ => {}
                }
            }
            match open {
                Some(o) => {
                    let f = word_before_at(s, o);
                    let fb = o - f.chars().count();
                    let method = before_blank(s, fb).is_some_and(|p| s[p] == '.');
                    let fi = if method {
                        exact_method(src, &fb, &f)
                    } else {
                        free_fn_called(src, fb, &f, &path_before(s, fb))
                    };
                    out.push((i, fi.filter(|g| !dispatches(src, g))));
                }
                // lent into a binding (`let u: &mut dyn Up = &mut a2;`): written through it
                None => out.push((i, None)),
            }
        } else if s.get(after) == Some(&'.') {
            let m = skip_blank(s, after + 1);
            let name = word_of(s, m);
            if s.get(skip_blank(s, m + name.chars().count())) == Some(&'(') && !name.is_empty() {
                // the file's method of the value's type, else one not known (a trait's,
                // dispatched on a type the code does not say)
                let fi = exact_method(src, &m, &name).filter(|g| !dispatches(src, g));
                if fi.is_some()
                    || src
                        .items
                        .iter()
                        .any(|x| x.kind == ItemKind::Fn && x.name == name)
                {
                    out.push((i, fi));
                }
            }
        }
        i += bd.name.chars().count();
    }
    out
}

/// The file's method a call at `m` names, when the receiver's type is one of the file's and it
/// implements the method (or the trait's default body it runs): none otherwise.
fn exact_method<'a>(src: &'a Source, m: &usize, name: &str) -> Option<&'a Item> {
    let t = receiver_type(src, *m)?;
    let methods: Vec<&Item> = src
        .items
        .iter()
        .filter(|x| x.kind == ItemKind::Fn && x.name == name)
        .collect();
    methods.iter().copied().find(|f| {
        src.items.iter().any(|b| {
            b.kind == ItemKind::Impl && b.name == t && b.contains(f.start) && b.start != f.start
        })
    })
}

/// Does the function's body call a method on one of its parameters (`t.up()`, `self.set(..)`),
/// which a type parameter or the receiver's type dispatches?
fn dispatches(src: &Source, f: &Item) -> bool {
    let s = &src.code;
    let sc = src.fn_scope(f);
    let (a, b) = sc.body;
    (a..b).any(|k| {
        s[k] == '.' && receiver_at(s, k).is_some_and(|(_, w, _)| sc.params.contains(&w)) && {
            let m = skip_blank(s, k + 1);
            let w = word_of(s, m);
            !w.is_empty()
                && s.get(skip_blank(s, m + w.chars().count())) == Some(&'(')
                && src
                    .items
                    .iter()
                    .any(|it| it.kind == ItemKind::Fn && it.name == w)
        }
    })
}

/// The module path of the items around `at` (`mod a { mod b { .. } }`: `[a, b]`).
fn modules_at(src: &Source, at: (usize, usize)) -> Vec<String> {
    let mut mods: Vec<&Item> = src
        .items
        .iter()
        .filter(|i| i.kind == ItemKind::Mod && i.contains(at))
        .collect();
    mods.sort_by_key(|i| i.start);
    mods.into_iter().map(|m| m.name.clone()).collect()
}

/// The file's free function (not a method) a call at `at` names `name` with the path `prefix`
/// written before it (`other::fill`, `fill`, `crate::m::f`): the one in the module the path
/// leads to from the call's, else the only one of that name.
fn free_fn_called<'a>(
    src: &'a Source,
    at: usize,
    name: &str,
    prefix: &[String],
) -> Option<&'a Item> {
    let free: Vec<&Item> = src
        .items
        .iter()
        .filter(|i| {
            i.kind == ItemKind::Fn
                && i.name == name
                && !src.items.iter().any(|o| {
                    matches!(o.kind, ItemKind::Impl | ItemKind::Trait) && o.contains(i.start)
                })
        })
        .collect();
    let here = modules_at(src, src.pos(at));
    let want: Vec<String> = match prefix.first().map(String::as_str) {
        Some("crate") => prefix[1..].to_vec(),
        Some("self") => here
            .iter()
            .cloned()
            .chain(prefix[1..].iter().cloned())
            .collect(),
        Some("super") => here[..here.len().saturating_sub(1)]
            .iter()
            .cloned()
            .chain(prefix[1..].iter().cloned())
            .collect(),
        _ => here.iter().cloned().chain(prefix.iter().cloned()).collect(),
    };
    free.iter()
        .find(|f| modules_at(src, f.start) == want)
        .or_else(|| {
            free.iter()
                .find(|f| modules_at(src, f.start).ends_with(prefix))
        })
        .or_else(|| (free.len() == 1).then(|| &free[0]))
        .copied()
}

/// The file's functions a piece of code calls: a method (`pk.pick()`: of any impl), a path call
/// qualified by a type (`Reg::make()`: of that type's impl; `HashMap::new()` is no function of the
/// file unless the file implements `HashMap`), a function of the file or of one of its modules.
fn file_fns_called<'a>(src: &'a Source, code: &str) -> Vec<&'a Item> {
    let mut out: Vec<&Item> = Vec::new();
    for c in re!(r"(\.\s*)?(?:([A-Za-z_]\w*)\s*::\s*)?([a-z_]\w*)\s*(?:::\s*<[^>]*>\s*)?\(")
        .captures_iter(code)
    {
        let name = &c[3];
        for f in src
            .items
            .iter()
            .filter(|i| i.kind == ItemKind::Fn && i.name == name)
        {
            let in_impl = |ty: Option<&str>| {
                src.items.iter().any(|i| {
                    i.kind == ItemKind::Impl
                        && ty.is_none_or(|t| i.name == t)
                        && i.contains(f.start)
                        && i.start != f.start
                })
            };
            let ok = match (c.get(1), c.get(2)) {
                (Some(_), _) => in_impl(None),
                // a type's (`Self::f`, `Reg::make`), or a module's
                (None, Some(q)) if q.as_str() == "Self" => in_impl(None),
                (None, Some(q)) if q.as_str().starts_with(char::is_uppercase) => {
                    in_impl(Some(q.as_str()))
                }
                _ => true,
            };
            if ok && !out.iter().any(|o| std::ptr::eq(*o, f)) {
                out.push(f);
            }
        }
    }
    out
}

/// The statements of the function around `at` that store into the container `var`
/// (`var.insert(..)`, `var.push(..)`, `var.extend(..)`, `var.entry(..).or_insert(..)`): their
/// lines.
fn container_stores(src: &Source, at: usize, var: &str) -> Vec<(usize, usize)> {
    let s = &src.code;
    let Some(f) = src.enclosing(src.pos(at), &[ItemKind::Fn]) else {
        return Vec::new();
    };
    let (a, b) = src.span(f);
    let text = src.text(a, b);
    // (of the variable, or of a field of it: `t.map.insert(..)`)
    let Ok(r) = Regex::new(&format!(
        r"(?:^|[^\w.])({})(?:\s*\.\s*\w+)*?\s*\.\s*(?:insert|push|push_back|push_front|extend|append|entry\s*\([^)]*\)\s*\.\s*or_insert(?:_with)?)\s*\(",
        regex::escape(var)
    )) else {
        return Vec::new();
    };
    r.captures_iter(&text)
        .filter_map(|c| {
            let (m, v) = (c.get(0)?, c.get(1)?);
            let i = a + text[..v.start()].chars().count();
            let open = a + text[..m.end()].chars().count() - 1;
            let close = close_of_at(s, open)?;
            Some((src.pos(i).0, src.pos(close).0))
        })
        .collect()
}

/// Is a parameter `var` of the function `fun` given the pointer named at line `named`: by a
/// call of `fun` in the function around the naming whose arguments name it (over lines), or
/// pass a variable bound where it is named, or whose receiver is (`ho.run(&d)` with `let ho =
/// Holder { f: digest::digest };` for `self`)?
fn param_passes(src: &Source, fun: &str, var: &str, named: usize) -> Result<(), String> {
    let call = Regex::new(&format!(
        r"\b{}\b\s*(?:::\s*<[^>]*>\s*)?\(",
        regex::escape(fun)
    ))
    .map_err(|e| e.to_string())?;
    let caller = src.enclosing((named, 0), &[ItemKind::Fn]);
    let (from, to) = caller
        .map(|c| (c.start.0, c.end.0))
        .unwrap_or((named, named));
    let s = &src.code;
    let bound_here = |at: usize, v: &str| matches!(binding(src, at, v), Some(Bound::Let { first, last, .. }) if (first..=last).contains(&named));
    for l in from..=to.min(src.lines.len()) {
        let text = &src.lines[l - 1];
        for m in call.find_iter(text) {
            let open = src.idx((l, text[..m.end()].chars().count() - 1));
            let Some(close) = close_of_at(s, open) else {
                continue;
            };
            if (l..=src.pos(close).0).contains(&named) {
                return Ok(());
            }
            let args = src.text(open, close);
            for v in re!(r"\b([a-z_]\w*)\b").captures_iter(&args) {
                if bound_here(open, &v[1]) {
                    return Ok(());
                }
            }
            // a method's receiver
            let name_at = src.idx((l, text[..m.start()].chars().count()));
            if let Some(dot) = before_blank(s, name_at).filter(|&d| s[d] == '.')
                && let Some((r, root, _)) = receiver_at(s, dot)
                && bound_here(r, &root)
            {
                return Ok(());
            }
        }
    }
    Err(format!(
        "`{var}` is a parameter of `{fun}`, whose calls do not pass it"
    ))
}

/// The macro an invocation at or around `at` calls, and the invocation's text from its path to
/// its closing bracket.
fn invocation_text(src: &Source, at: (usize, usize)) -> Option<(String, String)> {
    let start = invocation_start(src, at)?;
    let (mut text, mut depth, mut opened) = (String::new(), 0i32, false);
    for l in start.0..=src.lines.len().min(start.0 + 400) {
        let chars: Vec<char> = src.lines[l - 1].chars().collect();
        let from = if l == start.0 { start.1 } else { 0 };
        for (ci, &ch) in chars.iter().enumerate().skip(from) {
            text.push(ch);
            let code = src
                .class
                .get(l - 1)
                .and_then(|k| k.get(ci))
                .is_some_and(|k| *k == Class::Code);
            if !code {
                continue;
            }
            match ch {
                '(' | '[' | '{' => {
                    depth += 1;
                    opened = true;
                }
                ')' | ']' | '}' => {
                    depth -= 1;
                    if opened && depth == 0 {
                        let name = re!(r"^(?:\w+::)*(\w+)\s*!").captures(text.trim_start())?[1]
                            .to_string();
                        return Some((name, text));
                    }
                }
                _ => {}
            }
        }
        text.push('\n');
    }
    None
}

/// Where the macro invocation at or around `at` starts: its path (`sel!(..)`, `a::m!(..)`).
fn invocation_start(src: &Source, at: (usize, usize)) -> Option<(usize, usize)> {
    if macro_call_at(src, at) {
        return Some(at);
    }
    let s = &src.code;
    let b = src.idx(src.enclosing(at, &[ItemKind::MacroCall])?.start);
    let bang = before_blank(s, b).filter(|&k| s[k] == '!')?;
    let mut w = bang;
    while w > 0 && (is_ident(s[w - 1]) || s[w - 1] == ':') {
        w -= 1;
    }
    Some(src.pos(w))
}

/// Does the macro invocation at `at` make the item `path` names rather than another invocation
/// of the same macro in the file: the macro is invoked once, or no other invocation names as
/// many of the path's words in what it expands to (the transcriber of the rule it matches, its
/// arguments put in; its own code when that is not known: `nistp_dhkex!("P-256", DhP256, p256,
/// ..)` for `<..::p256::DhP256 as DhKeyExchange>::dh`, not the P-384 invocation), with the
/// modules it declares in the path's order (`sel!(gamma, delta, 256)` makes
/// `gamma::delta::run`, `sel!(delta, gamma, 384)` `delta::gamma::run`)? Another that does as
/// well: a range. `extra`: other words the item's code names (the descriptor of the asset).
fn invocation_names(src: &Source, at: (usize, usize), path: &str, extra: &[String]) -> Pick {
    let Some(start) = invocation_start(src, at) else {
        return Pick::Exact;
    };
    let Some((name, mine)) = invocation_text(src, start) else {
        return Pick::Exact;
    };
    let call = Regex::new(&format!(r"\b{}\s*!\s*[(\[{{]", regex::escape(&name))).ok();
    let mut others = Vec::new();
    for (l, text) in src.lines.iter().enumerate() {
        for m in call.iter().flat_map(|r| r.find_iter(text)) {
            let c = text[..m.start()].chars().count();
            let code = src
                .class
                .get(l)
                .and_then(|k| k.get(c))
                .is_some_and(|k| *k == Class::Code);
            // (an identical invocation in another module is another candidate: `mod a { h!(run); }`
            // and `mod b { h!(run); }`; the modules around each tell them apart)
            if code
                && (l + 1, c) != start
                && let Some((_, t)) = invocation_text(src, (l + 1, c))
            {
                others.push(((l + 1, c), t));
            }
        }
    }
    if others.is_empty() {
        return Pick::Exact;
    }
    // the words of the code (not of comments inside the invocation)
    let words = |t: &str| -> HashSet<String> {
        let code = re!(r"(?s)//[^\n]*|/\*.*?\*/").replace_all(t, " ");
        re!(r"[A-Za-z_]\w*")
            .find_iter(&code)
            .map(|m| m.as_str().to_string())
            .collect()
    };
    // the path's segments, after its crate, as `mod` declarations in order
    let segs: Vec<String> = strip_generics(path)
        .split("::")
        .skip(1)
        .map(|g| g.trim().to_string())
        .filter(|g| !g.is_empty() && g.chars().all(is_ident))
        .collect();
    // (a one-letter word only as a type's name, `<A as Tr>::f`, or a segment of the path, the
    // module `a` of `app::a::run`)
    let mut wanted: Vec<String> = words(path)
        .into_iter()
        .filter(|w| w.len() > 1 || w.chars().all(|c| c.is_ascii_uppercase()) || segs.contains(w))
        .collect();
    for e in extra {
        if !wanted.contains(e) {
            wanted.push(e.clone());
        }
    }
    let order = |t: &str| -> usize {
        let at: Vec<Option<usize>> = segs
            .iter()
            .map(|g| {
                Regex::new(&format!(r"\bmod\s+{}\b", regex::escape(g)))
                    .ok()
                    .and_then(|r| r.find(t))
                    .map(|m| m.start())
            })
            .collect();
        at.windows(2)
            .filter(|w| matches!((w[0], w[1]), (Some(a), Some(b)) if a < b))
            .count()
    };
    let score = |p: (usize, usize), inv: &str| {
        // in the modules around the invocation (`mod alpha { h!(run); }` makes `alpha::run`)
        let mut mods: Vec<&Item> = src
            .items
            .iter()
            .filter(|i| i.kind == ItemKind::Mod && i.contains(p))
            .collect();
        mods.sort_by_key(|i| i.start);
        let mut t = mods
            .iter()
            .map(|m| format!("mod {} {{ ", m.name))
            .collect::<String>();
        t.push_str(&expansion(src, p).unwrap_or_else(|| inv.to_string()));
        let w = words(&t);
        (wanted.iter().filter(|x| w.contains(*x)).count(), order(&t))
    };
    // an invocation inside `mod` items makes items in those modules: the path names them all
    let in_modules = |p: (usize, usize)| {
        src.items
            .iter()
            .filter(|i| i.kind == ItemKind::Mod && i.contains(p))
            .all(|m| segs.contains(&m.name))
    };
    if !in_modules(start) {
        return Pick::No;
    }
    // the invocation naming most of the path's words (others naming as many: the range)
    let mine = score(start, &mine);
    if mine.0 == 0 {
        return Pick::No;
    }
    let mut tie = false;
    for (p, t) in others.iter().filter(|(p, _)| in_modules(*p)) {
        let o = score(*p, t);
        if o > mine {
            return Pick::No;
        }
        tie |= o == mine;
    }
    if tie { Pick::Range } else { Pick::Exact }
}

/// The metavariables of a `macro_rules!` (`body`) that the invocation on `call` binds to a
/// token matching `word`, for a rule whose matcher lists only metavariables (`($m:ident,
/// $alg:ident)`) and as many as the invocation's arguments; `None` when no rule says.
fn metavars_of(body: &str, call: &str, word: &Regex) -> Option<Vec<String>> {
    let args_text = re!(r"\w+\s*!\s*[(\[{](.*)[)\]}]").captures(call)?;
    let mut args = Vec::new();
    let (mut depth, mut cur) = (0i32, String::new());
    for c in args_text[1].chars() {
        match c {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            ',' if depth == 0 => {
                args.push(std::mem::take(&mut cur));
                continue;
            }
            _ => {}
        }
        cur.push(c);
    }
    if !cur.trim().is_empty() {
        args.push(cur);
    }
    for m in re!(r"\(\s*((?:\$\w+\s*:\s*\w+\s*,?\s*)+)\)\s*=>").captures_iter(body) {
        let names: Vec<String> = re!(r"\$(\w+)\s*:")
            .captures_iter(&m[1])
            .map(|n| n[1].to_string())
            .collect();
        if names.len() == args.len() {
            let bound: Vec<String> = names
                .into_iter()
                .zip(&args)
                .filter(|(_, a)| word.is_match(a))
                .map(|(n, _)| n)
                .collect();
            return Some(bound);
        }
    }
    None
}

/// Does a macro invocation's path start exactly at `at` (`impl_dhkem!(`,
/// `primeorder::impl_mont_field_element!(`)?
fn macro_call_at(src: &Source, at: (usize, usize)) -> bool {
    let Some(text) = src.lines.get(at.0.wrapping_sub(1)) else {
        return false;
    };
    let chars: Vec<char> = text.chars().collect();
    let c = at.1;
    c < chars.len()
        && (c == 0 || !is_ident(chars[c - 1]))
        && src
            .class
            .get(at.0 - 1)
            .and_then(|k| k.get(c))
            .is_some_and(|k| *k == Class::Code)
        && re!(r"^(?:\w+::)*\w+!\s*[(\[{]").is_match(&chars[c..].iter().collect::<String>())
}

/// The `macro_rules!` of a file whose expansion a macro of it writes: the macro itself and
/// those its body invokes, in turn.
fn macros_invoked(src: &Source, name: &str) -> Vec<String> {
    let mut out = vec![name.to_string()];
    let mut i = 0;
    while i < out.len() {
        let body: Vec<&Item> = src
            .items
            .iter()
            .filter(|m| m.kind == ItemKind::Macro && m.name == out[i])
            .collect();
        for m in body {
            let text = src
                .lines
                .get(m.start.0.saturating_sub(1)..m.end.0.min(src.lines.len()))
                .unwrap_or_default()
                .join("\n");
            for other in src.items.iter().filter(|o| o.kind == ItemKind::Macro) {
                if !out.contains(&other.name)
                    && Regex::new(&format!(r"\b{}!", regex::escape(&other.name)))
                        .unwrap()
                        .is_match(&text)
                {
                    out.push(other.name.clone());
                }
            }
        }
        i += 1;
    }
    out
}

/// The first line of the attribute (`#[derive(..)]`, `#[hashed]`) or the macro invocation
/// (`hash_it!(..)`) a line of a file is in: the line itself when it starts one, else the
/// nearest line above, within a few, that starts one and that no other line in between does.
fn attribute_start(files: &mut Files<'_>, path: &Path, line: usize) -> Option<usize> {
    let src = files.source(path)?;
    let starts = |l: usize| {
        src.lines.get(l.wrapping_sub(1)).is_some_and(|t| {
            let t = t.trim_start();
            t.starts_with("#[")
                || t.starts_with("#![")
                || re!(r"^[\w:]+!\s*[\(\[\{]").is_match(t)
                || re!(r"[=(,]\s*[\w:]+!\s*[\(\[\{]").is_match(t)
        })
    };
    (line.saturating_sub(12).max(1)..=line)
        .rev()
        .find(|&l| starts(l))
}

/// A method the language calls without naming it: `.await` polls, a scope's end drops, `?`
/// branches, `for` iterates, operators and indexing, closures called through a variable.
fn by_syntax(item: &InItem) -> bool {
    const TRAITS: &[&str] = &[
        "Future",
        "IntoFuture",
        "Drop",
        "Deref",
        "DerefMut",
        "Fn",
        "FnMut",
        "FnOnce",
        "AsyncFn",
        "AsyncFnMut",
        "AsyncFnOnce",
        "Iterator",
        "IntoIterator",
        "Try",
        "FromResidual",
        "Index",
        "IndexMut",
        "Add",
        "Sub",
        "Mul",
        "Div",
        "Rem",
        "Neg",
        "Not",
        "BitAnd",
        "BitOr",
        "BitXor",
        "Shl",
        "Shr",
        "AddAssign",
        "SubAssign",
        "MulAssign",
        "DivAssign",
        "RemAssign",
        "BitAndAssign",
        "BitOrAssign",
        "BitXorAssign",
        "ShlAssign",
        "ShrAssign",
        "PartialEq",
        "PartialOrd",
        "Coroutine",
    ];
    matches!(item.name.as_str(), "drop_in_place" | "drop_glue")
        || item
            .trait_name
            .as_deref()
            .is_some_and(|t| TRAITS.contains(&t.split('<').next().unwrap_or(t)))
}

/// The function an attribute on a line belongs to (`#[tokio::main]` above `async fn main`): the
/// line holds an attribute, and the next item after it and any further attributes is that
/// function.
fn attribute_of(src: &Source, line: usize) -> Option<&Item> {
    let text = src.lines.get(line.wrapping_sub(1))?;
    if !text.trim_start().starts_with("#[") {
        return None;
    }
    src.items
        .iter()
        .filter(|i| i.kind == ItemKind::Fn && i.start.0 >= line && i.start.0 <= line + 8)
        .min_by_key(|i| i.start)
        .filter(|i| {
            (line + 1..i.start.0).all(|l| {
                let t = src.lines[l - 1].trim_start();
                t.is_empty() || t.starts_with("#[") || t.starts_with("//")
            })
        })
}

/// The length of the path written at `start` of a line: segments, `::`, and generic or
/// qualified-path brackets (`<T as Tr>::f`, `seal::<Aes256Gcm>`).
fn path_len(chars: &[char], start: usize) -> usize {
    let (mut j, mut depth) = (start, 0i32);
    while j < chars.len() {
        let c = chars[j];
        match c {
            '<' => depth += 1,
            '>' if depth > 0 => depth -= 1,
            _ if is_ident(c) || c == ':' => {}
            _ if depth > 0 => {}
            _ => break,
        }
        j += 1;
    }
    j - start
}

/// The item a closure or `async` body is written in: `t2::o1` for `t2::o1::{closure#0}`.
fn closure_parent(path: &str) -> Option<&str> {
    let p = path.trim_end();
    let i = p.rfind("::{closure#")?;
    p[i..].ends_with('}').then(|| &p[..i])
}

/// A path names an item: one of its segments is the item's name.
fn path_names(path: &str, name: &str) -> bool {
    re!(r"\w+").find_iter(path).any(|m| m.as_str() == name)
}

/// A context's parts, split at the `; ` outside brackets (`in <[u8; 32] as From>::from; ..`).
fn parts(details: &str) -> Vec<&str> {
    let b = details.as_bytes();
    let (mut out, mut depth, mut start) = (Vec::new(), 0i32, 0);
    for (i, &c) in b.iter().enumerate() {
        match c {
            b'<' | b'[' | b'(' => depth += 1,
            b'>' if i == 0 || b[i - 1] != b'-' => depth -= 1,
            b']' | b')' => depth -= 1,
            b';' if depth <= 0 && b.get(i + 1) == Some(&b' ') => {
                out.push(&details[start..i]);
                start = i + 2;
            }
            _ => {}
        }
    }
    out.push(&details[start..]);
    out
}

/// A type as an impl header or a context names it: a path's last segment without its
/// arguments (`&'a mut path::Type<A, B>` -> `Type`), a tuple, array or slice whole, blanks
/// and paths dropped (`(u8, u8)` -> `(u8,u8)`, `[u8; 32]` -> `[u8;32]`).
fn type_name(t: &str) -> String {
    let t = t.trim().trim_start_matches(['&', '*']).trim();
    let t = t
        .strip_prefix("mut ")
        .or_else(|| t.strip_prefix("const "))
        .unwrap_or(t)
        .trim();
    let t = re!(r"^'\w+\s+").replace(t, "");
    let t = t.strip_prefix("mut ").unwrap_or(&t).trim();
    if t.starts_with('(') || t.starts_with('[') {
        return norm_path(t);
    }
    let t = strip_generics(t);
    let t = t
        .split_whitespace()
        .rfind(|w| !w.starts_with('\'') && *w != "mut" && *w != "dyn" && *w != "const")
        .unwrap_or("");
    t.rsplit("::").next().unwrap_or(t).trim().to_string()
}

/// The item a context says an occurrence is in (`in t1::xchacha`, `in <A as T>::f::{closure#0}`,
/// `in r1::Jar::<J>::seal`): its name, and the type and trait of the impl block it is a
/// method of (`A`, `T`), when its path names them.
struct InItem {
    /// the path whole
    path: String,
    name: String,
    self_ty: Option<String>,
    /// the type whole, as `norm_path` writes it
    self_full: Option<String>,
    trait_name: Option<String>,
    /// the modules and functions a plain path names the item in (`v02::a::f` is in `[a]`,
    /// `app::outer::inner` in `[outer]`), after the crate; None for a method
    mods: Option<Vec<String>>,
    /// a method's type or trait (`<v02::a::S as T>::f`, `v02::a::Tr::f`) and the modules its
    /// path names it in
    owner: Option<(String, Vec<String>)>,
}

/// The function item `init` (`<Over as Local>::alg`, `Local::alg`, `Over::alg`) runs `callee`'s
/// body: the same type's, a trait's path (dispatched on the argument), or a type's not
/// overriding the trait's default body `callee`.
fn fn_item_runs(src: &Source, callee: &str, init: &str) -> bool {
    let (Some(c), Some(i)) = (in_item(callee), in_item(init)) else {
        return true;
    };
    let ty = |n: &InItem| {
        n.self_ty
            .clone()
            .or_else(|| n.owner.as_ref().map(|(t, _)| t.clone()))
            .map(|t| type_name(&t))
    };
    let (Some(ct), Some(it)) = (ty(&c), ty(&i)) else {
        return true;
    };
    let is_trait = |t: &str| {
        src.items
            .iter()
            .any(|x| x.kind == ItemKind::Trait && x.name == t)
    };
    if ct == it || is_trait(&it) {
        return true;
    }
    // `<Def as Local>::alg` (or `Def::alg`) runs `Local::alg` when Def's impl does not write `alg`
    is_trait(&ct)
        && i.trait_name.as_deref().is_none_or(|t| type_name(t) == ct)
        && !src.items.iter().any(|b| {
            b.kind == ItemKind::Impl
                && b.name == it
                && b.trait_name.as_deref().map(type_name) == Some(ct.clone())
                && src.items.iter().any(|f| {
                    f.kind == ItemKind::Fn
                        && f.name == c.name
                        && b.contains(f.start)
                        && b.start != f.start
                })
        })
}

/// A type that holds no algorithm: an integer, a float, `bool`, `char`, a string, bytes, a path
/// (`&[u8]`, `String`, `Vec<u8>`, `&mut [u8; 32]`).
fn neutral_type(t: &str) -> bool {
    let d = deref_type(t);
    let d: String = d.chars().filter(|c| !c.is_whitespace()).collect();
    re!(r"^(?:u8|u16|u32|u64|u128|usize|i8|i16|i32|i64|i128|isize|f32|f64|bool|char|str|String|\[u8(?:;\w+)?\]|Vec<u8>|Path|PathBuf|OsStr|OsString)$")
        .is_match(&d)
}

fn in_item(item: &str) -> Option<InItem> {
    // the path's segments, generic arguments kept whole
    let chars: Vec<char> = item.chars().collect();
    let mut segs = Vec::new();
    let (mut depth, mut cur, mut k) = (0i32, String::new(), 0);
    while k < chars.len() {
        let c = chars[k];
        match c {
            '<' => depth += 1,
            '>' if k == 0 || chars[k - 1] != '-' => depth -= 1,
            _ => {}
        }
        if depth == 0 && c == ':' && chars.get(k + 1) == Some(&':') {
            segs.push(std::mem::take(&mut cur));
            k += 2;
            continue;
        }
        cur.push(c);
        k += 1;
    }
    segs.push(cur);
    let last_of = type_name;
    // generic arguments (`<J>`, `<..>`) and what the compiler makes (`{closure#0}`) are not
    // items written in the source; the arguments belong to the segment before them
    // (`Inner::<u8>::hash` is a method of `Inner<u8>`)
    let mut kept: Vec<(String, String)> = Vec::new();
    for g in segs {
        if g.starts_with('{') {
            continue;
        }
        if g.starts_with('<') && !g.contains(" as ") && !g.starts_with("<impl ") {
            if let Some((_, full)) = kept.last_mut() {
                full.push_str(&g);
            }
            continue;
        }
        kept.push((g.clone(), g));
    }
    let (name, _) = kept.pop()?;
    let name = name.strip_prefix("r#").unwrap_or(&name).to_string();
    // the modules: a plain path's segments after the crate, up to a type's or trait's
    let module = |g: &str| g.strip_prefix("r#").unwrap_or(g).to_string();
    let path_mods = |segs: &[String]| -> Vec<String> {
        segs.iter()
            .skip(1)
            .filter(|g| *g != "_")
            .map(|g| module(g))
            .collect()
    };
    let (mut mods, mut owner) = (None, None);
    let plain: Vec<String> = kept.iter().map(|(g, _)| g.clone()).collect();
    if plain.first().is_some_and(|g| !g.starts_with('<')) {
        match plain
            .iter()
            .skip(1)
            .position(|g| g.chars().next().is_some_and(char::is_uppercase))
        {
            Some(i) => owner = Some((plain[i + 1].clone(), path_mods(&plain[..=i]))),
            None => mods = Some(path_mods(&plain)),
        }
    } else if let Some(inner) = plain
        .last()
        .and_then(|g| g.strip_prefix('<'))
        .and_then(|g| g.strip_suffix('>'))
    {
        let t = inner.strip_prefix("impl ").unwrap_or(inner);
        let t = t.split(" as ").next().unwrap_or(t);
        let t = strip_generics(t);
        let segs: Vec<String> = t.trim().split("::").map(str::to_string).collect();
        if segs.len() >= 2
            && segs
                .iter()
                .all(|g| g.chars().all(is_ident) && !g.is_empty())
        {
            let ty = segs.last().cloned().unwrap_or_default();
            owner = Some((ty, path_mods(&segs[..segs.len() - 1])));
        }
    }
    let (mut self_ty, mut self_full, mut trait_name) = (None, None, None);
    if let Some((g, full)) = kept.last() {
        if let Some(inner) = g.strip_prefix('<').and_then(|g| g.strip_suffix('>')) {
            if let Some(t) = inner.strip_prefix("impl ") {
                self_ty = Some(last_of(t));
                self_full = Some(norm_path(t));
            } else if let Some((t, tr)) = inner.split_once(" as ") {
                self_ty = Some(last_of(t));
                self_full = Some(norm_path(t));
                trait_name = Some(norm_path(tr));
            }
        } else if g.chars().next().is_some_and(char::is_uppercase) {
            self_ty = Some(last_of(g));
            self_full = Some(norm_path(full));
        }
    }
    Some(InItem {
        path: item.to_string(),
        name: strip_generics(&name),
        self_ty,
        self_full,
        trait_name,
        mods,
        owner,
    })
}

/// A type or trait path as compared between a context and the source: paths cut to their last
/// segment at every level, lifetimes and blanks dropped (`core::convert::TryFrom<&rustls_pki_types::
/// PrivateKeyDer<'_>>` -> `TryFrom<&PrivateKeyDer>`).
fn norm_path(t: &str) -> String {
    let t = re!(r"\b\w+::").replace_all(t.trim(), "");
    let t = re!(r"'\w+\s*,?").replace_all(&t, "");
    let t: String = t.chars().filter(|c| !c.is_whitespace()).collect();
    t.replace("<>", "").replace(",>", ">")
}

/// Two traits are one: the same path, or the same name where either has no arguments.
fn same_trait(a: &str, b: &str) -> bool {
    let name = |t: &str| t.split('<').next().unwrap_or(t).to_string();
    a == b || (name(a) == name(b) && (!a.contains('<') || !b.contains('<')))
}

/// A code position is inside the item its context names (`in <item>; ..`): the innermost
/// function, static or const around it has the item's name, and, for a method whose path names
/// its type, the impl block (or the trait, for a default method) around that names it too. Not
/// inside a `macro_rules!` body. The source may name a type through an alias (`impl Writer for
/// Sha256`, where the context names `CoreWrapper<..>`): `aliases` gives what a name stands for.
fn check_item(
    src: &Source,
    details: &str,
    at: (usize, usize),
    aliases: &mut dyn FnMut(&str) -> Vec<String>,
    chains: Option<&[Vec<String>]>,
    descriptor: Option<&str>,
) -> Result<(), String> {
    if let Some(m) = src.enclosing(at, &[ItemKind::Macro]) {
        return Err(format!(
            "position inside the body of `macro_rules! {}`",
            m.name
        ));
    }
    let Some(want) = details
        .strip_prefix("in ")
        .and_then(|d| parts(d).into_iter().next())
        .and_then(in_item)
    else {
        return Err("no enclosing item in the context".into());
    };
    let Some(item) = src.enclosing(at, &[ItemKind::Fn, ItemKind::Static]) else {
        // an item a macro invocation outside any item makes (`hash_fn!(..)` at module level),
        // cited inside the invocation or at its start (hpke's `nistp_dhkex!(..)`)
        if src.enclosing(at, &[ItemKind::MacroCall]).is_some() || macro_call_at(src, at) {
            let path = details
                .strip_prefix("in ")
                .and_then(|d| parts(d).into_iter().next())
                .unwrap_or_default();
            // the descriptor the occurrence's algorithm comes from, which the item's code names
            let extra: Vec<String> = re!(r"algorithm (?:possibly )?from (?:\w+::)*(\w+)")
                .captures_iter(details)
                .map(|m| m[1].to_string())
                .chain(descriptor.map(str::to_string))
                .collect();
            match invocation_names(src, at, path, &extra) {
                Pick::Exact => return Ok(()),
                Pick::Range => {
                    RANGED.with(|r| r.set(true));
                    return Ok(());
                }
                Pick::No => {}
            }
            return Err(format!(
                "the macro invocation does not make `{}`: another invocation of the same \
                 macro in the file does",
                want.name
            ));
        }
        return Err(format!("position outside any item, not in `{}`", want.name));
    };
    // code a macro's invocation wraps (`thread_local! { static TL: .. = digest(..) }`) is in
    // the items the macro makes inside the item around it, which the context's path names
    // (`t7::TL::__rust_std_internal_init_fn`); `format!(..)` makes none
    let in_call = src.enclosing(at, &[ItemKind::MacroCall]).is_some();
    if item.name != want.name {
        if in_call && path_names(&want.path, &item.name) {
            return Ok(());
        }
        return Err(format!(
            "position in `{}`, not in `{}`",
            item.name, want.name
        ));
    }
    // the module: the file's and those of the inline modules (and functions) around the
    // position are those the context names; for a method, around its type's or trait's
    // definition when the file has it. An identical statement in another module or file is
    // another item (rustls's `crypto::ring::tls12` repeats `crypto::aws_lc_rs::tls12`).
    if let Some(chains) = chains {
        let around = |p: (usize, usize)| -> Vec<String> {
            let mut v: Vec<&Item> = src
                .items
                .iter()
                .filter(|i| matches!(i.kind, ItemKind::Mod | ItemKind::Fn) && i.contains(p))
                .collect();
            v.sort_by_key(|i| i.start);
            v.iter().map(|i| i.name.clone()).collect()
        };
        let in_chain = |inner: &[String], want: &[String]| {
            chains.iter().any(|c| {
                c.len() + inner.len() == want.len()
                    && c.iter().chain(inner).zip(want).all(|(a, b)| a == b)
            })
        };
        if let Some(mods) = &want.mods {
            let mut inner = around(at);
            if item.kind == ItemKind::Fn {
                inner.pop();
            }
            if !in_chain(&inner, mods) {
                return Err(format!(
                    "position in module `{}`, not in `{}`",
                    chains
                        .first()
                        .map(|c| c
                            .iter()
                            .chain(&inner)
                            .cloned()
                            .collect::<Vec<_>>()
                            .join("::"))
                        .unwrap_or_default(),
                    mods.join("::")
                ));
            }
        } else if let Some((ty, mods)) = &want.owner {
            let defs: Vec<&Item> = src
                .items
                .iter()
                .filter(|i| matches!(i.kind, ItemKind::TypeDef | ItemKind::Trait) && i.name == *ty)
                .collect();
            if !defs.is_empty() && !defs.iter().any(|d| in_chain(&around(d.start), mods)) {
                return Err(format!(
                    "`{ty}` of this file is not the one in `{}`",
                    mods.join("::")
                ));
            }
        }
    }
    // the block the function is written in (not the function itself)
    let container = src
        .items
        .iter()
        .filter(|i| {
            matches!(i.kind, ItemKind::Impl | ItemKind::Trait | ItemKind::Fn)
                && i.start < item.start
                && i.contains(item.start)
        })
        .max_by_key(|i| i.start);
    if let Some(ty) = &want.self_ty
        && let Some(block) = container
    {
        let ok = match block.kind {
            // a blanket impl's type is any type: its trait is named
            ItemKind::Impl if block.name.is_empty() => {
                matches!((&block.trait_name, &want.trait_name), (Some(a), Some(b)) if trait_of(a, b, aliases))
            }
            // its type, and the trait it implements: `impl TryFrom<&PrivateKeyDer<'_>> for
            // KeyPair` is not `impl TryFrom<&[u8]> for KeyPair`
            ItemKind::Impl => {
                same_type(&block.name, ty, want.self_full.as_deref(), aliases)
                    && match (&block.trait_name, &want.trait_name) {
                        (Some(a), Some(b)) => trait_of(a, b, aliases),
                        _ => true,
                    }
            }
            ItemKind::Trait => {
                block.name == *ty
                    || want
                        .trait_name
                        .as_deref()
                        .is_some_and(|t| same_trait(&block.name, t))
            }
            // a function inside a function: no impl block of its own
            _ => true,
        };
        if !ok {
            let of = |t: &Option<String>, ty: &str| match t {
                Some(t) => format!("`impl {t} for {ty}`"),
                None => format!("`{ty}`"),
            };
            return Err(format!(
                "position in a method of {}, not of {}",
                of(&block.trait_name, &block.name),
                of(&want.trait_name, ty)
            ));
        }
    }
    Ok(())
}

/// A type as written in an impl header is the type a context names: the same name, or an
/// alias that stands for the whole type (`Sha256` for sha2's `CoreWrapper<CtVariableCoreWrapper<
/// Sha256VarCore, U32, OidSha256>>`, which `Sha512` is not).
fn same_type(
    written: &str,
    ty: &str,
    full: Option<&str>,
    aliases: &mut dyn FnMut(&str) -> Vec<String>,
) -> bool {
    if written == ty {
        return true;
    }
    // `[u8;?]` (`impl<const N: usize> X for [u8; N]`) is `[u8;32]`
    if written.contains('?') {
        let pat = regex::escape(written).replace(r"\?", r"[^,;\[\]()]+");
        return Regex::new(&format!("^{pat}$")).is_ok_and(|r| r.is_match(ty));
    }
    let Some(full) = full else {
        return false;
    };
    let full = fold_typenum(full);
    aliases(written)
        .iter()
        .any(|t| fold_typenum(&expand_aliases(t, aliases, 3)) == full)
}

/// A trait as written in an impl header is the trait a context names (`same_trait`), also once
/// the aliases among its arguments are replaced (`RandomizedSigner<Signature>` with p521's
/// `type Signature = ecdsa_core::Signature<NistP521>`).
fn trait_of(written: &str, want: &str, aliases: &mut dyn FnMut(&str) -> Vec<String>) -> bool {
    if same_trait(written, want) {
        return true;
    }
    let (head, args) = written.split_at(written.find('<').unwrap_or(written.len()));
    let expanded = format!("{head}{}", expand_aliases(args, aliases, 3));
    expanded != written && same_trait(&fold_typenum(&expanded), &fold_typenum(want))
}

/// A type with the aliases it names replaced by what they stand for, `depth` levels deep (the
/// names followed by arguments are types, not aliases without parameters).
fn expand_aliases(t: &str, aliases: &mut dyn FnMut(&str) -> Vec<String>, depth: usize) -> String {
    let mut out = String::new();
    let mut last = 0;
    for m in re!(r"\b[A-Za-z_]\w*\b").find_iter(t) {
        if t[m.end()..].starts_with('<') {
            continue;
        }
        if let Some(e) = aliases(m.as_str()).first()
            && e != m.as_str()
        {
            out.push_str(&t[last..m.start()]);
            if depth > 1 {
                out.push_str(&expand_aliases(e, aliases, depth - 1));
            } else {
                out.push_str(e);
            }
            last = m.end();
        }
    }
    out.push_str(&t[last..]);
    out
}

/// typenum's unsigned integers as their aliases name them: `UInt<UInt<UTerm,B1>,B0>` is `U2`
/// (rustc prints the type, the source its alias).
fn fold_typenum(t: &str) -> String {
    let mut t = t.replace("UTerm", "U0");
    loop {
        let n = re!(r"UInt<U(\d+),B([01])>")
            .replace_all(&t, |c: &regex::Captures| {
                let v: u128 = c[1].parse().unwrap_or(0);
                format!("U{}", v * 2 + u128::from(&c[2] == "1"))
            })
            .to_string();
        if n == t {
            return t;
        }
        t = n;
    }
}

/// The text of the attribute a position is in, from after its `#[` (or `#![`) to the position:
/// the code before the position, over a few lines, back to the last `#[` with its brackets still
/// open. None when the position is in no attribute.
fn attribute_before(src: &Source, line: usize, offset: usize) -> Option<String> {
    let mut code = String::new();
    for l in (line.saturating_sub(12).max(1)..=line).rev() {
        let chars: Vec<char> = src.lines[l - 1].chars().collect();
        let end = if l == line {
            offset.min(chars.len())
        } else {
            chars.len()
        };
        let part: String = chars[..end]
            .iter()
            .zip(&src.class[l - 1])
            .map(|(&c, k)| if *k == Class::Code { c } else { ' ' })
            .collect();
        code = format!("{part}\n{code}");
        if let Some(i) = code.rfind("#[").or_else(|| code.rfind("#![")) {
            let open = code[i..].find('[').unwrap() + i + 1;
            let inner = &code[open..];
            let depth: i32 = inner
                .chars()
                .map(|c| match c {
                    '[' | '(' => 1,
                    ']' | ')' => -1,
                    _ => 0,
                })
                .sum();
            return (depth >= 0 && !inner.contains(']')).then(|| inner.trim_start().to_string());
        }
    }
    None
}

/// Whether, in an attribute's text up to a position, a `name(` is still open there.
fn open_in(attr: &str, name: &str) -> bool {
    let Some(i) = attr.rfind(&format!("{name}(")).or_else(|| {
        Regex::new(&format!(r"{}\s+\(", regex::escape(name)))
            .unwrap()
            .find_iter(attr)
            .last()
            .map(|m| m.start())
    }) else {
        return false;
    };
    let mut depth = 0i32;
    for c in attr[i..].chars() {
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            _ => {}
        }
    }
    depth >= 1
}

/// The identifier just before a position (whitespace and comments skipped, over a few lines),
/// when the token before it is one: `fn` in `fn seal<..>`, `macro_rules` in `macro_rules! m`.
fn word_before(src: &Source, line: usize, offset: usize) -> Option<String> {
    let mut code = String::new();
    for l in line.saturating_sub(4).max(1)..=line {
        let chars: Vec<char> = src.lines[l - 1].chars().collect();
        let end = if l == line {
            offset.min(chars.len())
        } else {
            chars.len()
        };
        code.extend(
            chars[..end]
                .iter()
                .zip(&src.class[l - 1])
                .map(|(&c, k)| if *k == Class::Comment { ' ' } else { c }),
        );
        code.push(' ');
    }
    let code = code.trim_end();
    let code = code.strip_suffix('!').unwrap_or(code);
    let word: String = code
        .chars()
        .rev()
        .take_while(|&c| is_ident(c))
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    (!word.is_empty()).then_some(word)
}

/// The source from a position on, over the next 63 lines: chars and their classes. A path is
/// read from it with its generic arguments balanced, so the extent only bounds a path rustfmt
/// spread over many lines.
fn rest(src: &Source, line: usize, offset: usize) -> (Vec<char>, Vec<Class>) {
    let mut s = Vec::new();
    let mut k = Vec::new();
    for (n, l) in src.lines.iter().enumerate().skip(line - 1).take(64) {
        if n + 1 != line {
            s.push('\n');
            k.push(Class::Code);
        }
        let from = if n + 1 == line { offset } else { 0 };
        for (c, ch) in l.chars().enumerate().skip(from) {
            s.push(ch);
            k.push(src.class[n].get(c).copied().unwrap_or(Class::Code));
        }
    }
    (s, k)
}

/// How a name is bound in a function's body: by a `let` (or a macro whose expansion lets it),
/// an `if let` / `while let`, a `for`, a `match` arm, a closure's parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BindKind {
    Let,
    Cond,
    For,
    Arm,
    Closure,
    Macro,
}

/// A binding of a name in a function's body (indexes in `Source::code`).
#[derive(Clone, Debug)]
struct Bind {
    name: String,
    kind: BindKind,
    /// the statement or header that binds it (a `let` to its `;`, a `match` to the arm's `=>`)
    stmt: (usize, usize),
    /// its pattern (a closure's parameters)
    pat: (usize, usize),
    /// its initializer, scrutinee or iterator
    init: Option<(usize, usize)>,
    /// where the name is visible: after the `let`'s `;` to the end of its block, the block of an
    /// `if let` or `for`, an arm's expression, a closure's body
    scope: (usize, usize),
}

/// A function's bindings, its parameters' names (`self` for a method's receiver) and its body.
#[derive(Debug, Default)]
struct FnScope {
    binds: Vec<Bind>,
    params: Vec<String>,
    body: (usize, usize),
    /// its blocks, and the bodies of its loops (`for`, `while`, `loop`)
    blocks: Vec<(usize, usize)>,
    loops: Vec<(usize, usize)>,
}

impl FnScope {
    /// The innermost block around `i`.
    fn block_of(&self, i: usize) -> (usize, usize) {
        self.blocks
            .iter()
            .filter(|&&(o, c)| o < i && i < c)
            .max()
            .copied()
            .unwrap_or(self.body)
    }
}

fn word_of(s: &[char], i: usize) -> String {
    s.get(i..)
        .unwrap_or_default()
        .iter()
        .take_while(|c| is_ident(**c))
        .collect()
}

/// Whether an identifier (not a number) starts at `i`.
fn word_start(s: &[char], i: usize) -> bool {
    i < s.len() && is_ident(s[i]) && !s[i].is_ascii_digit() && (i == 0 || !is_ident(s[i - 1]))
}

/// Whether the keyword `k` is at `i`.
fn kw(s: &[char], i: usize, k: &str) -> bool {
    word_start(s, i)
        && s[i..].iter().take(k.len()).copied().eq(k.chars())
        && !s.get(i + k.len()).is_some_and(|c| is_ident(*c))
}

fn skip_blank(s: &[char], mut i: usize) -> usize {
    while i < s.len() && s[i].is_whitespace() {
        i += 1;
    }
    i
}

/// The last non-blank char before `i`.
fn before_blank(s: &[char], i: usize) -> Option<usize> {
    (0..i.min(s.len())).rev().find(|&k| !s[k].is_whitespace())
}

/// The word that ends before `i`, blanks skipped (empty when a symbol does).
fn word_before_at(s: &[char], i: usize) -> String {
    let Some(e) = before_blank(s, i).filter(|&e| is_ident(s[e])) else {
        return String::new();
    };
    let mut b = e + 1;
    while b > 0 && is_ident(s[b - 1]) {
        b -= 1;
    }
    s[b..=e].iter().collect()
}

/// The matching close of the bracket at `open` (`(`, `[`, `{`).
fn close_of_at(s: &[char], open: usize) -> Option<usize> {
    if !matches!(s.get(open), Some('(' | '[' | '{')) {
        return None;
    }
    let mut depth = 0i32;
    for (j, &c) in s.iter().enumerate().skip(open) {
        match c {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(j);
                }
            }
            _ => {}
        }
    }
    None
}

/// The matching open of the bracket at `close` (`)`, `]`, `}`).
fn open_of_at(s: &[char], close: usize) -> Option<usize> {
    if !matches!(s.get(close), Some(')' | ']' | '}')) {
        return None;
    }
    let mut depth = 0i32;
    for j in (0..=close).rev() {
        match s[j] {
            ')' | ']' | '}' => depth += 1,
            '(' | '[' | '{' => {
                depth -= 1;
                if depth == 0 {
                    return Some(j);
                }
            }
            _ => {}
        }
    }
    None
}

/// From `from`, the first index outside the brackets opened after `from` where `stop` holds,
/// or where a bracket opened before `from` closes; `to` when none does before it.
fn scan_to(s: &[char], from: usize, to: usize, stop: impl Fn(usize) -> bool) -> usize {
    let to = to.min(s.len());
    let mut depth = 0i32;
    let mut i = from;
    while i < to {
        if depth == 0 && stop(i) {
            return i;
        }
        match s[i] {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => {
                depth -= 1;
                if depth < 0 {
                    return i;
                }
            }
            _ => {}
        }
        i += 1;
    }
    to
}

/// The `=` of a `let` whose pattern starts at `from`: the first outside brackets that is no
/// `==`, `=>`, `<=`, `>=`, `!=` or compound assignment; None at a `;` first (`let x;`).
fn let_eq_at(s: &[char], from: usize, to: usize) -> Option<usize> {
    let i = scan_to(s, from, to, |i| {
        s[i] == ';'
            || (s[i] == '='
                && !matches!(s.get(i + 1), Some('=' | '>'))
                && !matches!(
                    i.checked_sub(1).map(|p| s[p]),
                    Some('=' | '!' | '<' | '>' | '+' | '-' | '*' | '/' | '%' | '^' | '&' | '|')
                ))
    });
    (s.get(i) == Some(&'=')).then_some(i)
}

/// The names a pattern binds (`(a, b)`, `Some(f)`, `S { f, g: h }`, `ref mut x`, `x @ ..`),
/// its type annotation left out.
fn pattern_names(s: &[char], a: usize, b: usize) -> Vec<String> {
    let end = scan_to(s, a, b, |i| {
        s[i] == ':' && s.get(i + 1) != Some(&':') && (i == 0 || s[i - 1] != ':')
    });
    let mut out = Vec::new();
    let mut i = a;
    while i < end {
        if !word_start(s, i) {
            i += 1;
            continue;
        }
        let w = word_of(s, i);
        let e = i + w.len();
        let first = w.chars().next().unwrap_or('_');
        // (the type annotation's `:` is not the pattern's)
        let next = Some(skip_blank(s, e))
            .filter(|&n| n < end)
            .and_then(|n| s.get(n))
            .copied();
        let path_seg = before_blank(s, i).is_some_and(|p| {
            s[p] == '.' || (s[p] == ':' && p > 0 && s[p - 1] == ':') || s[p] == '\''
        });
        let keyword = matches!(
            w.as_str(),
            "mut" | "ref" | "box" | "true" | "false" | "_" | "if" | "in" | "dyn" | "impl"
        );
        let follows = matches!(next, Some('(' | '{' | '!' | ':' | '<'));
        if !keyword
            && !path_seg
            && !follows
            && (first.is_lowercase() || (first == '_' && w.len() > 1))
        {
            out.push(w);
        }
        i = e;
    }
    out
}

/// The names a parameter list binds (`a: u8, (b, c): (T, T)`, `&mut self`): each parameter's
/// pattern, before its type.
fn params_names(s: &[char], a: usize, b: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut p = a;
    while p < b {
        let e = scan_to(s, p, b, |i| s[i] == ',');
        let colon = scan_to(s, p, e, |i| {
            s[i] == ':' && s.get(i + 1) != Some(&':') && (i == 0 || s[i - 1] != ':')
        });
        if (p..colon).any(|i| kw(s, i, "self")) {
            out.push("self".to_string());
        } else {
            out.extend(pattern_names(s, p, colon));
        }
        p = e + 1;
    }
    out
}

/// Whether a `|` at `k` starts a closure (`|x| ..`, `|| ..`, `move |x|`), not an or-pattern or
/// an operator.
fn closure_at(s: &[char], k: usize) -> bool {
    if s.get(k) != Some(&'|') || s.get(k + 1) == Some(&'=') {
        return false;
    }
    match before_blank(s, k) {
        None => true,
        Some(p) => match s[p] {
            '(' | ',' | '{' | ';' | '[' => true,
            '=' => !matches!(p.checked_sub(1).map(|q| s[q]), Some('=' | '!' | '<' | '>')),
            '>' => p > 0 && s[p - 1] == '=',
            ':' => !(p > 0 && s[p - 1] == ':'),
            c if is_ident(c) => matches!(
                word_before_at(s, k).as_str(),
                "move" | "async" | "return" | "static" | "else"
            ),
            _ => false,
        },
    }
}

/// A closure starting at the `|` at `k` (`closure_at`): its parameters' extent (none for `||`)
/// and its body's.
#[allow(clippy::type_complexity)]
fn closure_parts(
    s: &[char],
    k: usize,
    limit: usize,
) -> Option<(Option<(usize, usize)>, (usize, usize))> {
    let (params, after) = if s.get(k + 1) == Some(&'|') {
        (None, k + 2)
    } else {
        let c = scan_to(s, k + 1, limit, |i| s[i] == '|');
        if s.get(c) != Some(&'|') {
            return None;
        }
        (Some((k + 1, c)), c + 1)
    };
    let mut j = skip_blank(s, after);
    if s.get(j) == Some(&'-') && s.get(j + 1) == Some(&'>') {
        j = scan_to(s, j + 2, limit, |i| s[i] == '{');
    }
    let end = scan_to(s, j, limit, |i| s[i] == ',' || s[i] == ';');
    Some((params, (j, end)))
}

/// Where `k` starts the body of an `async` closure (`async move |d| expr`: at `expr`): that
/// body's extent.
fn async_body_at(s: &[char], k: usize) -> Option<(usize, usize)> {
    let p = before_blank(s, k).filter(|&p| s[p] == '|')?;
    let open = if p > 0 && s[p - 1] == '|' {
        p - 1
    } else {
        (0..p).rev().find(|&o| s[o] == '|')?
    };
    let asynch = match word_before_at(s, open).as_str() {
        "async" => true,
        "move" => {
            let m = before_blank(s, open)?;
            word_before_at(s, m + 1 - 4) == "async"
        }
        _ => false,
    };
    if !asynch || !closure_at(s, open) {
        return None;
    }
    let (_, (j, end)) = closure_parts(s, open, s.len())?;
    (j == k).then_some((k, end))
}

/// The extent of the closure or `async` block starting at `k` (`|x| ..`, `move || ..`, `async
/// move { .. }`, an `async fn`'s body `{ .. }`): from its first token to its body's end.
fn closure_span(s: &[char], k: usize) -> Option<(usize, usize)> {
    let mut i = k;
    while ["async", "move", "static"].iter().any(|w| kw(s, i, w)) {
        i = skip_blank(s, i + word_of(s, i).len());
    }
    match s.get(i)? {
        '|' => {
            let (_, (_, end)) = closure_parts(s, i, s.len())?;
            Some((k, end))
        }
        '{' => Some((k, close_of_at(s, i)? + 1)),
        _ => None,
    }
}

impl Source {
    /// The bindings and parameters of the function `f`, an item of this file.
    fn fn_scope(&self, f: &Item) -> Rc<FnScope> {
        let (a, b) = self.span(f);
        if let Some(sc) = self.scopes.borrow().get(&a) {
            return sc.clone();
        }
        let sc = Rc::new(scan_fn(self, a, b));
        self.scopes.borrow_mut().insert(a, sc.clone());
        sc
    }
}

/// Reads the bindings of the function at `a..b` of `src.code` (its `fn` keyword to its body's
/// end): those of its body, not of the functions nested in it, which see none of them.
fn scan_fn(src: &Source, a: usize, b: usize) -> FnScope {
    let s = &src.code;
    let mut out = FnScope::default();
    // the signature: `fn name<..>(params) -> T where .. {`
    let name_at = skip_blank(s, a + 2);
    let mut i = skip_blank(s, name_at + word_of(s, name_at).len());
    if s.get(i) == Some(&'<') {
        let mut depth = 0;
        while i < b {
            match s[i] {
                '<' => depth += 1,
                '>' if s[i - 1] != '-' => {
                    depth -= 1;
                    if depth == 0 {
                        i += 1;
                        break;
                    }
                }
                _ => {}
            }
            i += 1;
        }
        i = skip_blank(s, i);
    }
    if s.get(i) == Some(&'(')
        && let Some(close) = close_of_at(s, i)
    {
        out.params = params_names(s, i + 1, close);
        i = close + 1;
    }
    let open = scan_to(s, i, b, |k| s[k] == '{');
    let Some(close) = close_of_at(s, open) else {
        return out;
    };
    out.body = (open, close + 1);
    // the blocks, for a `let`'s scope
    let mut blocks = Vec::new();
    let mut stack = Vec::new();
    for (k, &c) in s.iter().enumerate().take(close + 1).skip(open) {
        match c {
            '{' => stack.push(k),
            '}' => {
                if let Some(o) = stack.pop() {
                    blocks.push((o, k + 1));
                }
            }
            _ => {}
        }
    }
    let block_end = |k: usize| {
        blocks
            .iter()
            .filter(|&&(o, c)| o < k && k < c)
            .max()
            .map_or(close + 1, |&(_, c)| c)
    };
    let nested: Vec<(usize, usize)> = src
        .items
        .iter()
        .filter(|it| it.kind == ItemKind::Fn)
        .map(|it| src.span(it))
        .filter(|&(x, _)| x > open && x < close)
        .collect();
    // the file's macros whose expansion binds a name the invocation gives (`bind!(m)`)
    let letting: Vec<&str> = src
        .items
        .iter()
        .filter(|it| {
            it.kind == ItemKind::Macro && {
                let (x, y) = src.span(it);
                re!(r"\blet\s+(?:mut\s+)?\$").is_match(&src.text(x, y))
            }
        })
        .map(|it| it.name.as_str())
        .collect();
    let binds = &mut out.binds;
    let mut loops = Vec::new();
    let mut push = |pat: (usize, usize), kind, stmt, init, scope| {
        let names = if kind == BindKind::Closure {
            params_names(s, pat.0, pat.1)
        } else {
            pattern_names(s, pat.0, pat.1)
        };
        for name in names {
            binds.push(Bind {
                name,
                kind,
                stmt,
                pat,
                init,
                scope,
            });
        }
    };
    let mut k = open + 1;
    while k < close {
        if let Some(&(_, e)) = nested.iter().find(|&&(x, _)| x == k) {
            k = e;
            continue;
        }
        if closure_at(s, k)
            && let Some((params, body)) = closure_parts(s, k, close)
        {
            let pat = params.unwrap_or((k + 1, k + 1));
            push(pat, BindKind::Closure, (k, body.0), None, body);
            k = body.0.max(k + 1);
            continue;
        }
        if !word_start(s, k) {
            k += 1;
            continue;
        }
        let w = word_of(s, k);
        match w.as_str() {
            "let" => {
                let cond = matches!(word_before_at(s, k).as_str(), "if" | "while")
                    || before_blank(s, k).is_some_and(|p| s[p] == '&' && p > 0 && s[p - 1] == '&');
                let pat = k + 3;
                match let_eq_at(s, pat, close) {
                    None => {
                        // `let x;`: assigned later
                        let semi = scan_to(s, pat, close, |i| s[i] == ';');
                        push(
                            (pat, semi),
                            BindKind::Let,
                            (k, semi + 1),
                            None,
                            (semi + 1, block_end(k)),
                        );
                    }
                    Some(eq) if cond => {
                        let init_end = scan_to(s, eq + 1, close, |i| {
                            s[i] == '{' || (s[i] == '&' && s.get(i + 1) == Some(&'&'))
                        });
                        let blk = scan_to(s, init_end, close, |i| s[i] == '{');
                        let blk_end = close_of_at(s, blk).map_or(close, |c| c + 1);
                        if word_before_at(s, k) == "while" {
                            loops.push((blk, blk_end));
                        }
                        push(
                            (pat, eq),
                            BindKind::Cond,
                            (k, blk),
                            Some((eq + 1, init_end)),
                            (blk, blk_end),
                        );
                    }
                    Some(eq) => {
                        let init_end = scan_to(s, eq + 1, close, |i| {
                            s[i] == ';'
                                || (kw(s, i, "else")
                                    && before_blank(s, i).is_some_and(|p| s[p] != '}'))
                        });
                        let semi = scan_to(s, eq + 1, close, |i| s[i] == ';');
                        push(
                            (pat, eq),
                            BindKind::Let,
                            (k, semi + 1),
                            Some((eq + 1, init_end)),
                            (semi + 1, block_end(k)),
                        );
                    }
                }
            }
            "for" if s.get(skip_blank(s, k + 3)) != Some(&'<') => {
                let p = k + 3;
                let pin = scan_to(s, p, close, |i| {
                    kw(s, i, "in") || s[i] == '{' || s[i] == ';'
                });
                if kw(s, pin, "in") {
                    let blk = scan_to(s, pin + 2, close, |i| s[i] == '{');
                    if let Some(bc) = close_of_at(s, blk) {
                        loops.push((blk, bc + 1));
                        push(
                            (p, pin),
                            BindKind::For,
                            (k, blk),
                            Some((pin + 2, blk)),
                            (blk, bc + 1),
                        );
                    }
                }
            }
            "match" if before_blank(s, k).is_none_or(|p| s[p] != '.') => {
                let blk = scan_to(s, k + 5, close, |i| s[i] == '{');
                if let Some(mc) = close_of_at(s, blk) {
                    let scrut = (k + 5, blk);
                    let mut arm = blk + 1;
                    loop {
                        arm = skip_blank(s, arm);
                        if arm >= mc {
                            break;
                        }
                        let arrow =
                            scan_to(s, arm, mc, |i| s[i] == '=' && s.get(i + 1) == Some(&'>'));
                        if arrow >= mc {
                            break;
                        }
                        let pend = scan_to(s, arm, arrow, |i| kw(s, i, "if"));
                        let b0 = skip_blank(s, arrow + 2);
                        let (arm_end, next) = if s.get(b0) == Some(&'{') {
                            let e = close_of_at(s, b0).map_or(mc, |c| c + 1);
                            let n2 = skip_blank(s, e);
                            match s.get(n2) {
                                Some('.' | '?') => {
                                    let e = scan_to(s, b0, mc, |i| s[i] == ',');
                                    (e, e + 1)
                                }
                                Some(',') => (e, n2 + 1),
                                _ => (e, e),
                            }
                        } else {
                            let e = scan_to(s, b0, mc, |i| s[i] == ',');
                            (e, e + 1)
                        };
                        push(
                            (arm, pend),
                            BindKind::Arm,
                            (k, arrow + 2),
                            Some(scrut),
                            (arrow + 2, arm_end),
                        );
                        arm = next.max(arm + 1);
                    }
                }
            }
            _ if letting.contains(&w.as_str())
                && s.get(skip_blank(s, k + w.len())) == Some(&'!') =>
            {
                let ob = skip_blank(s, skip_blank(s, k + w.len()) + 1);
                if let Some(cb) = close_of_at(s, ob) {
                    let n2 = skip_blank(s, cb + 1);
                    let end = if s.get(n2) == Some(&';') {
                        n2 + 1
                    } else {
                        cb + 1
                    };
                    push(
                        (ob + 1, cb),
                        BindKind::Macro,
                        (k, end),
                        Some((k, cb + 1)),
                        (end, block_end(k)),
                    );
                }
            }
            "while" | "loop" if s.get(skip_blank(s, k + w.len())) != Some(&'!') => {
                // (a `while let`'s block is pushed with its binding)
                let n = skip_blank(s, k + w.len());
                if !kw(s, n, "let") {
                    let blk = scan_to(s, n, close, |i| s[i] == '{');
                    if let Some(bc) = close_of_at(s, blk) {
                        loops.push((blk, bc + 1));
                    }
                }
            }
            _ => {}
        }
        k += w.len();
    }
    out.blocks = blocks;
    out.loops = loops;
    out
}

/// What a name read at `at` (an index in `code`) is.
enum Found {
    /// bound in the function around it (the nearest binding whose scope holds it)
    Bind(Bind),
    /// a parameter of the function around it, by the function's name
    Param(String),
    /// a static or const (by its index in `items`): the function's own first
    Item(usize),
}

fn lookup(src: &Source, at: usize, name: &str) -> Option<Found> {
    let p = src.pos(at);
    let f = src.enclosing(p, &[ItemKind::Fn]);
    if let Some(f) = f {
        let sc = src.fn_scope(f);
        if let Some(b) = sc
            .binds
            .iter()
            .filter(|b| b.name == name && b.scope.0 <= at && at < b.scope.1)
            .max_by_key(|b| (b.scope.0, b.stmt.0))
        {
            return Some(Found::Bind(b.clone()));
        }
        if sc.params.iter().any(|n| n == name) && at >= sc.body.0 {
            return Some(Found::Param(f.name.clone()));
        }
    }
    src.items
        .iter()
        .enumerate()
        .filter(|(_, i)| i.kind == ItemKind::Static && i.name == name)
        .min_by_key(|(_, i)| !f.is_some_and(|f| f.contains(i.start)))
        .map(|(k, _)| Found::Item(k))
}

/// The receiver of a method called after the `.` at `dot`: the variable (or path) its
/// expression starts with (`ho` of `ho.run(..)`, `keys` of `keys["a"].seal(..)`), and the
/// expression's extent.
fn receiver_at(s: &[char], dot: usize) -> Option<(usize, String, usize)> {
    let mut j = dot;
    let mut root = None;
    while let Some(p) = before_blank(s, j) {
        match s[p] {
            ')' | ']' => j = open_of_at(s, p)?,
            '?' => j = p,
            c if is_ident(c) => {
                let mut b = p + 1;
                while b > 0 && is_ident(s[b - 1]) {
                    b -= 1;
                }
                root = Some(b);
                match before_blank(s, b) {
                    Some(q) if s[q] == '.' => j = q,
                    Some(q) if s[q] == ':' && q > 0 && s[q - 1] == ':' => j = q - 1,
                    _ => break,
                }
            }
            _ => break,
        }
    }
    let r = root?;
    Some((r, word_of(s, r), dot))
}

/// The type of the value a method called at `i` (`E1.ext()`, `W(S1).alg()`, `g.alg()` with `let
/// g = &W(S2);`, `p.b.ext()` with `p` a `Pair` whose `b` is an `E2`, `mk1().ext()`, `e.ext()` with
/// `let e = E1.upgrade();`) is called on, when the code says which type of the file it is: `None`
/// when it does not (a parameter of a type parameter, a trait object, a value of another crate's
/// type).
fn receiver_type(src: &Source, i: usize) -> Option<String> {
    let s = &src.code;
    let dot = before_blank(s, i).filter(|&d| s[d] == '.')?;
    let (r, _, _) = receiver_at(s, dot)?;
    let ty = type_name(&deref_type(&expr_type(src, r, dot, 5)?));
    src.items
        .iter()
        .any(|it| it.kind == ItemKind::TypeDef && it.name == ty)
        .then_some(ty)
}

/// The type arguments of a generic function's instance as a context names it (`g2::pass::<g2::A>`:
/// `[g2::A]`); `None` for a method, a closure or an item without them.
fn instance_args(path: &str) -> Option<Vec<String>> {
    let p = path.trim();
    if p.starts_with('<') || !p.ends_with('>') {
        return None;
    }
    let chars: Vec<char> = p.chars().collect();
    let mut depth = 0i32;
    let mut open = None;
    for k in (0..chars.len()).rev() {
        match chars[k] {
            '>' if k == 0 || chars[k - 1] != '-' => depth += 1,
            '<' => {
                depth -= 1;
                if depth == 0 {
                    open = Some(k);
                    break;
                }
            }
            _ => {}
        }
    }
    let o = open?;
    if o < 2 || chars[o - 1] != ':' || chars[o - 2] != ':' {
        return None;
    }
    // the segment before: a function's name, not a type's
    let before: String = chars[..o - 2].iter().collect();
    let name = before.rsplit("::").next().unwrap_or("");
    if !name.starts_with(|c: char| c.is_lowercase() || c == '_') {
        return None;
    }
    let inner: String = chars[o + 1..chars.len() - 1].iter().collect();
    // (`<..>`: arguments the context leaves out)
    if inner.contains("..") {
        return None;
    }
    Some(
        split_top(&inner)
            .into_iter()
            .map(|a| a.trim().to_string())
            .collect(),
    )
}

/// The type arguments the call of the file's generic function `name` at `ci` gives it, by its
/// type parameters: written (`pass::<Last>(..)`), or the type of the argument passed for a
/// parameter of that type (`pass(&B, ..)` for `fn pass<T>(t: &T, ..)`: `B`, a type of the file);
/// `None` for one not known. `None` when no such call is there (a method, a macro).
fn call_type_args(src: &Source, ci: usize, name: &str) -> Option<Vec<Option<String>>> {
    let s = &src.code;
    if before_blank(s, ci).is_some_and(|p| s[p] == '.') {
        return None;
    }
    // the path at `ci` up to `name`
    let mut i = ci;
    let mut prefix = Vec::new();
    loop {
        if !word_start(s, i) {
            return None;
        }
        let w = word_of(s, i);
        i += w.chars().count();
        if w == name {
            break;
        }
        prefix.push(w);
        let j = skip_blank(s, i);
        if !(s.get(j) == Some(&':') && s.get(j + 1) == Some(&':')) {
            return None;
        }
        i = skip_blank(s, j + 2);
    }
    let j = skip_blank(s, i);
    if s.get(j) == Some(&':') && s.get(j + 1) == Some(&':') {
        let o = skip_blank(s, j + 2);
        if s.get(o) != Some(&'<') {
            return None;
        }
        let cls = vec![Class::Code; s.len() - o];
        let e = skip_angle(&s[o..], &cls, 0)?;
        // (a type parameter of the caller, `labeled_extract::<Kdf>` in a generic function, is
        // whatever its own instance gives: not compared)
        let mut params: Vec<String> = Vec::new();
        if let Some(f) = src.enclosing(src.pos(ci), &[ItemKind::Fn]) {
            params.extend(fn_sig(src, f).generics);
            if let Some(b) = impl_of(src, f) {
                let (ba, bb) = src.span(b);
                let h = src.text(ba, scan_to(s, ba, bb, |k| s[k] == '{'));
                if let Some(r) = h
                    .trim_start()
                    .strip_prefix("impl")
                    .filter(|r| r.trim_start().starts_with('<'))
                {
                    params.extend(
                        re!(r"[<,]\s*(\w+)\s*[:,>]")
                            .captures_iter(r)
                            .map(|x| x[1].to_string()),
                    );
                }
            }
        }
        return Some(
            split_top(&src.text(o + 1, o + e - 1))
                .into_iter()
                .map(|a| {
                    Some(a.trim().to_string())
                        .filter(|a| a != "_" && !params.contains(&type_name(a)))
                })
                .collect(),
        );
    }
    if s.get(j) != Some(&'(') {
        return None;
    }
    let close = close_of_at(s, j)?;
    let f = free_fn_called(src, ci, name, &prefix)?;
    let sig = fn_sig(src, f);
    if sig.generics.is_empty() {
        return None;
    }
    // the arguments' extents
    let mut args = Vec::new();
    let mut a = j + 1;
    while a < close {
        let e = scan_to(s, a, close, |k| s[k] == ',');
        args.push((a, e));
        a = e + 1;
    }
    Some(
        sig.generics
            .iter()
            .map(|g| {
                let p = sig
                    .params
                    .iter()
                    .position(|(_, t)| type_name(&deref_type(t)) == *g && deref_type(t) == *g)?;
                let &(x, y) = args.get(p)?;
                let t = type_name(&deref_type(&expr_type(src, x, y, 4)?));
                src.items
                    .iter()
                    .any(|it| it.kind == ItemKind::TypeDef && it.name == t)
                    .then_some(t)
            })
            .collect(),
    )
}

/// A type as a method or field is looked up on: references, `mut`, lifetimes and the smart
/// pointers a method call sees through (`Box`, `Rc`, `Arc`) dropped, a path cut to its last
/// segment with its arguments (`&'a mut Box<m::Vec<E2>>` -> `Vec<E2>`). A trait object (`dyn`,
/// `impl`) is no type of the file: empty.
fn deref_type(t: &str) -> String {
    let mut t = t.trim().to_string();
    loop {
        let before = t.clone();
        t = t.trim_start_matches('&').trim().to_string();
        t = re!(r"^'\w+\s*").replace(&t, "").trim().to_string();
        if let Some(r) = t.strip_prefix("mut ") {
            t = r.trim().to_string();
        }
        if let Some(m) = re!(r"^(?:\w+\s*::\s*)*(?:Box|Rc|Arc)\s*<(.*)>$").captures(&t) {
            t = m[1].trim().to_string();
        }
        if t == before {
            break;
        }
    }
    if t.starts_with("dyn ") || t.starts_with("impl ") {
        return String::new();
    }
    // the last segment of the path, outside its arguments
    let chars: Vec<char> = t.chars().collect();
    let (mut depth, mut cut) = (0i32, 0);
    for (k, &c) in chars.iter().enumerate() {
        match c {
            '<' | '(' | '[' => depth += 1,
            '>' | ')' | ']' => depth -= 1,
            ':' if depth == 0 && chars.get(k + 1) == Some(&':') => cut = k + 2,
            _ => {}
        }
    }
    chars[cut.min(chars.len())..]
        .iter()
        .collect::<String>()
        .trim()
        .to_string()
}

/// The arguments of a type (`Vec<E2>`: `[E2]`; `HashMap<K, V>`: `[K, V]`).
fn type_args(t: &str) -> Vec<String> {
    let t = t.trim();
    match (t.find('<'), t.ends_with('>')) {
        (Some(o), true) => split_top(&t[o + 1..t.len() - 1])
            .into_iter()
            .map(|a| a.trim().to_string())
            .filter(|a| !a.starts_with('\''))
            .collect(),
        _ => Vec::new(),
    }
}

/// The type of an element of a value of type `t` read by an index (`Vec<X>`, `[X; N]`, `&[X]`,
/// `VecDeque<X>`: `X`).
fn elem_type(t: &str) -> Option<String> {
    let t = deref_type(t);
    if let Some(inner) = t.strip_prefix('[').and_then(|x| x.strip_suffix(']')) {
        return split_top(inner.split(';').next().unwrap_or(inner))
            .first()
            .map(|x| x.trim().to_string());
    }
    let base = type_name(&t);
    matches!(base.as_str(), "Vec" | "VecDeque" | "SmallVec" | "ArrayVec")
        .then(|| type_args(&t).into_iter().next())
        .flatten()
}

/// A function's signature as written: its type parameters, its parameters (pattern, type; a
/// method's receiver as `self`, of type `Self`) and its return type.
struct FnSig {
    generics: Vec<String>,
    params: Vec<(String, String)>,
    ret: Option<String>,
}

fn fn_sig(src: &Source, f: &Item) -> FnSig {
    let s = &src.code;
    let (a, b) = src.span(f);
    let mut out = FnSig {
        generics: Vec::new(),
        params: Vec::new(),
        ret: None,
    };
    let name_at = skip_blank(s, a + 2);
    let mut i = skip_blank(s, name_at + word_of(s, name_at).len());
    if s.get(i) == Some(&'<') {
        let cls = vec![Class::Code; s.len() - i];
        let Some(e) = skip_angle(&s[i..], &cls, 0) else {
            return out;
        };
        out.generics = split_top(&src.text(i + 1, i + e - 1))
            .iter()
            .filter_map(|g| {
                let g = g.trim().trim_start_matches("const ").trim();
                let n: String = g.chars().take_while(|c| is_ident(*c)).collect();
                (!n.is_empty() && !g.starts_with('\'')).then_some(n)
            })
            .collect();
        i = skip_blank(s, i + e);
    }
    let Some(close) = (s.get(i) == Some(&'('))
        .then(|| close_of_at(s, i))
        .flatten()
    else {
        return out;
    };
    for p in split_top(&src.text(i + 1, close)) {
        let p = p.trim();
        if p.is_empty() {
            continue;
        }
        let pc: Vec<char> = p.chars().collect();
        let colon = (0..pc.len())
            .find(|&k| pc[k] == ':' && pc.get(k + 1) != Some(&':') && (k == 0 || pc[k - 1] != ':'));
        match colon {
            Some(k) => {
                let pat: String = pc[..k].iter().collect();
                let ty: String = pc[k + 1..].iter().collect();
                if re!(r"\bself\b").is_match(&pat) {
                    out.params.push(("self".into(), ty.trim().to_string()));
                } else {
                    out.params
                        .push((pat.trim().to_string(), ty.trim().to_string()));
                }
            }
            None if re!(r"\bself\b").is_match(p) => out.params.push(("self".into(), "Self".into())),
            None => out.params.push((p.to_string(), String::new())),
        }
    }
    let open = scan_to(s, close + 1, b, |k| s[k] == '{' || s[k] == ';');
    let tail = src.text(close + 1, open);
    if let Some(r) = tail.trim_start().strip_prefix("->") {
        let r = r.split(" where ").next().unwrap_or(r);
        let r = re!(r"\bwhere\b").split(r).next().unwrap_or(r);
        out.ret = Some(r.trim().to_string());
    }
    out
}

/// The impl block (or trait) a function of the file is a method of.
fn impl_of<'a>(src: &'a Source, f: &Item) -> Option<&'a Item> {
    src.items
        .iter()
        .filter(|b| {
            matches!(b.kind, ItemKind::Impl | ItemKind::Trait)
                && b.contains(f.start)
                && b.start != f.start
        })
        .max_by_key(|b| b.start)
}

/// The declared type of field `field` (a name, or a tuple index) of the file's struct `ty`.
fn field_type(src: &Source, ty: &str, field: &str) -> Option<String> {
    let s = &src.code;
    let def = src.items.iter().find(|it| {
        it.kind == ItemKind::TypeDef && it.name == ty && kw(s, src.idx(it.start), "struct")
    })?;
    let at = src.idx(def.start);
    let mut i = skip_blank(s, at + 6);
    i = skip_blank(s, i + word_of(s, i).len());
    if s.get(i) == Some(&'<') {
        let cls = vec![Class::Code; s.len() - i];
        i = skip_blank(s, i + skip_angle(&s[i..], &cls, 0)?);
    }
    let open = scan_to(s, i, s.len(), |k| matches!(s[k], '{' | '(' | ';'));
    let close = close_of_at(s, open)?;
    let fields = split_top(&src.text(open + 1, close));
    if s[open] == '(' {
        let k: usize = field.parse().ok()?;
        let f = fields.get(k)?.trim();
        return Some(f.trim_start_matches("pub").trim().to_string());
    }
    fields.iter().find_map(|f| {
        let f = f.trim();
        let f = re!(r"^(?:#\[[^\]]*\]\s*)*(?:pub(?:\s*\([^)]*\))?\s+)?").replace(f, "");
        let (n, t) = f.split_once(':')?;
        (n.trim() == field).then(|| t.trim().to_string())
    })
}

/// The return type of the file's method or associated function `name` of type `ty` (its impl's,
/// or the default body of a trait it implements), `Self` read as `ty`.
fn method_ret(src: &Source, ty: &str, name: &str) -> Option<String> {
    let fns: Vec<&Item> = src
        .items
        .iter()
        .filter(|f| f.kind == ItemKind::Fn && f.name == name)
        .collect();
    let own = fns
        .iter()
        .find(|f| impl_of(src, f).is_some_and(|b| b.kind == ItemKind::Impl && b.name == ty));
    let f = own.or_else(|| {
        fns.iter().find(|f| {
            impl_of(src, f).is_some_and(|t| {
                t.kind == ItemKind::Trait
                    && src.items.iter().any(|b| {
                        b.kind == ItemKind::Impl
                            && (b.name == ty || b.name.is_empty())
                            && b.trait_name.as_deref().map(type_name) == Some(t.name.clone())
                    })
            })
        })
    })?;
    let ret = fn_sig(src, f).ret?;
    Some(re!(r"\bSelf\b").replace_all(&ret, ty).to_string())
}

/// The type of the expression at `a..b` of `code` (a variable, a path to a value or a function
/// of the file called, a struct literal, `vec![..]`, then fields, tuple fields, indexes, `?` and
/// the file's methods called), as far as the code says: `None` where it does not.
fn expr_type(src: &Source, a: usize, b: usize, depth: usize) -> Option<String> {
    if depth == 0 {
        return None;
    }
    let s = &src.code;
    let b = b.min(s.len());
    let mut i = skip_blank(s, a);
    // references and derefs: a method or field is looked up on what they point to
    loop {
        if s.get(i) == Some(&'&') || s.get(i) == Some(&'*') {
            i = skip_blank(s, i + 1);
            if kw(s, i, "mut") {
                i = skip_blank(s, i + 3);
            }
            continue;
        }
        break;
    }
    if i >= b {
        return None;
    }
    let mut ty: String;
    if s[i] == '(' {
        let c = close_of_at(s, i)?;
        if scan_to(s, i + 1, c, |k| s[k] == ',') < c {
            return None;
        }
        ty = expr_type(src, i + 1, c, depth - 1)?;
        i = c + 1;
    } else if word_start(s, i) {
        let start = i;
        let mut segs: Vec<String> = Vec::new();
        loop {
            let w = word_of(s, i);
            i += w.chars().count();
            segs.push(w);
            let j = skip_blank(s, i);
            if s.get(j) == Some(&':') && s.get(j + 1) == Some(&':') {
                let mut k = skip_blank(s, j + 2);
                if s.get(k) == Some(&'<') {
                    let cls = vec![Class::Code; s.len() - k];
                    k = skip_blank(s, k + skip_angle(&s[k..], &cls, 0)?);
                    i = k;
                    if s.get(k) == Some(&':') && s.get(k + 1) == Some(&':') {
                        k = skip_blank(s, k + 2);
                    } else {
                        break;
                    }
                }
                if word_start(s, k) {
                    i = k;
                    continue;
                }
            }
            break;
        }
        let last = segs.last()?.clone();
        let n = skip_blank(s, i);
        let upper = last.starts_with(char::is_uppercase);
        let is_type = |t: &str| {
            src.items
                .iter()
                .any(|it| it.kind == ItemKind::TypeDef && it.name == t)
        };
        let around = |k: usize| -> Option<String> {
            src.enclosing(src.pos(k), &[ItemKind::Impl])
                .map(|b| b.name.clone())
                .filter(|n| !n.is_empty())
        };
        if upper {
            // a struct literal, a tuple struct's or variant's constructor, a unit struct
            if matches!(s.get(n), Some('{' | '(')) {
                i = close_of_at(s, n)? + 1;
            }
            ty = if is_type(&last) {
                last
            } else if segs.len() >= 2 && is_type(&segs[segs.len() - 2]) {
                segs[segs.len() - 2].clone()
            } else if last == "Self" {
                around(start)?
            } else {
                return None;
            };
        } else if s.get(n) == Some(&'!') {
            // `vec![X, ..]`: a `Vec` of the first element's type
            let o = skip_blank(s, n + 1);
            let c = close_of_at(s, o)?;
            if last != "vec" {
                return None;
            }
            let e = scan_to(s, o + 1, c, |k| s[k] == ',' || s[k] == ';');
            ty = format!("Vec<{}>", expr_type(src, o + 1, e, depth - 1)?);
            i = c + 1;
        } else if s.get(n) == Some(&'(') {
            let c = close_of_at(s, n)?;
            i = c + 1;
            if segs.len() >= 2 && segs[segs.len() - 2].starts_with(char::is_uppercase) {
                let q = &segs[segs.len() - 2];
                let q = if q == "Self" {
                    around(start)?
                } else {
                    q.clone()
                };
                ty = method_ret(src, &q, &last)?;
            } else {
                if segs.len() == 1 && matches!(binding(src, start, &last), Some(Bound::Let { .. }))
                {
                    // a closure or pointer held by a variable
                    return None;
                }
                let f = free_fn_called(src, start, &last, &segs[..segs.len() - 1])?;
                let sig = fn_sig(src, f);
                let r = sig.ret?;
                if sig
                    .generics
                    .iter()
                    .any(|g| re!(r"\w+").find_iter(&r).any(|m| m.as_str() == g))
                {
                    return None;
                }
                ty = r;
            }
        } else if segs.len() == 1 && last == "self" {
            ty = around(start)?;
        } else if segs.len() == 1 {
            ty = match binding(src, start, &last)? {
                Bound::Let { .. } => {
                    let Some(Found::Bind(bd)) = lookup(src, start, &last) else {
                        return None;
                    };
                    // the annotation (`let x: T = ..`), else the initializer's type, for a
                    // binding of the whole value (not a pattern's part)
                    let pat = src.text(bd.pat.0, bd.pat.1);
                    let (p, annot) = match pat.split_once(':') {
                        Some((p, t)) if !t.starts_with(':') => (p.trim().to_string(), Some(t)),
                        _ => (pat.trim().to_string(), None),
                    };
                    let p = p.trim_start_matches("mut ").trim();
                    if p != last || !matches!(bd.kind, BindKind::Let) {
                        return None;
                    }
                    match annot {
                        Some(t) => t.trim().to_string(),
                        None => {
                            let (x, y) = bd.init?;
                            expr_type(src, x, y, depth - 1)?
                        }
                    }
                }
                Bound::Param { .. } => {
                    let f = src.enclosing(src.pos(start), &[ItemKind::Fn])?;
                    let sig = fn_sig(src, f);
                    let t = sig
                        .params
                        .iter()
                        .find(|(p, _)| p.trim_start_matches("mut ").trim() == last)?;
                    let base = type_name(&deref_type(&t.1));
                    if sig.generics.contains(&base) {
                        return None;
                    }
                    t.1.clone()
                }
                _ => return None,
            };
        } else {
            return None;
        }
    } else {
        return None;
    }
    // fields, tuple fields, indexes, `?`, method calls
    loop {
        let j = skip_blank(s, i);
        if j >= b {
            break;
        }
        match s[j] {
            '.' => {
                let k = skip_blank(s, j + 1);
                let w = word_of(s, k);
                if w.is_empty() {
                    return None;
                }
                let mut n = skip_blank(s, k + w.chars().count());
                if s.get(n) == Some(&':') && s.get(n + 1) == Some(&':') {
                    let o = skip_blank(s, n + 2);
                    let cls = vec![Class::Code; s.len() - o];
                    n = skip_blank(s, o + skip_angle(&s[o..], &cls, 0)?);
                }
                let base = type_name(&deref_type(&ty));
                if s.get(n) == Some(&'(') {
                    i = close_of_at(s, n)? + 1;
                    ty = match w.as_str() {
                        // what these return is the value itself, as far as a method sees
                        "clone" | "as_ref" | "as_mut" | "borrow" | "borrow_mut" | "to_owned"
                        | "deref" | "deref_mut" | "by_ref" => ty,
                        "unwrap" | "expect" | "unwrap_or_default" => {
                            type_args(&deref_type(&ty)).into_iter().next()?
                        }
                        _ => method_ret(src, &base, &w)?,
                    };
                } else {
                    // a field, or a tuple field (`.0`)
                    i = k + w.chars().count();
                    ty = field_type(src, &base, &w)?;
                }
            }
            '[' => {
                i = close_of_at(s, j)? + 1;
                ty = elem_type(&ty)?;
            }
            '?' => {
                i = j + 1;
                ty = type_args(&deref_type(&ty)).into_iter().next()?;
            }
            _ => break,
        }
    }
    Some(ty)
}

/// Is a method of item `n` (an instantiation chain's) called on a `t`: `<T as Tr>::m` on a `T`, a
/// trait's method (`app::Tr::m`) on a type implementing the trait (directly or by a blanket
/// impl), an inherent method on its type?
fn receiver_fits(src: &Source, n: &InItem, t: &str) -> bool {
    let Some(st) = n.self_ty.as_deref() else {
        return true;
    };
    if n.trait_name.is_some()
        || !src
            .items
            .iter()
            .any(|i| i.kind == ItemKind::Trait && i.name == st)
    {
        return st == t;
    }
    let text = src.lines.join("\n");
    Regex::new(&format!(
        r"\bimpl\b[^{{;]*\b{}\b[^{{;]*\bfor\s+(?:&\s*)?(?:{}\b|[A-Z]\s*(?:\{{|where\b))",
        regex::escape(st),
        regex::escape(t)
    ))
    .is_ok_and(|r| r.is_match(&text))
}

/// What `names_read` has followed: spans, and bindings with the field read of them.
type Seen = HashSet<(usize, usize, String)>;

/// What some code reads, followed (`names_read`).
#[derive(Default, Debug)]
struct Reads {
    /// the upper-case names written (an import alias as its item's), in the code and in what
    /// it reads
    names: BTreeSet<String>,
    /// it reads a value from elsewhere: a parameter of the function, a closure's
    open: bool,
    /// it reads a constant of another file or crate, which is no descriptor of the knowledge
    /// base, whose initializer was not read (`Files::resolve_foreign` reads those of the build's
    /// packages)
    foreign: bool,
    /// those constants: the path written before the name (or the import's), the name, and the
    /// field read of it (`dep::TABLE[i].h`)
    foreign_items: Vec<(Vec<String>, String, Option<String>)>,
    /// the type names written (`Ed25519KeyPair`)
    types: BTreeSet<String>,
    /// a variable it reads was lent whole as `&mut` to a call whose stores are not read
    /// (`mem::swap`): what its binding names may have been replaced
    replaced: bool,
    /// a variable it reads was lent as `&mut` to another crate's function, which may write it
    lent: bool,
    /// it reads a field of a variable or static (`v[0].h`): a value of the field's type, which a
    /// `type-join` member may be, wherever the program stores it
    fields: bool,
    /// (an input) a store through another binding that points to the variable read, on every
    /// way to the read (`let r = &mut a; *r = v;`), replaces what it held: for a claim that the
    /// values found are all (no unknown beside them). Otherwise such a store may or may not be
    /// the one that reaches the read: both are read.
    strict: bool,
    /// (an input) the type arguments of the generic function's instance the code is in (`T` ->
    /// `ilib::CFast` in `hash_c::<ilib::CFast>`)
    inst: Vec<(String, String)>,
    /// the associated items of those types it reads (`T::ALG`: `(ilib::CFast, ALG)`), which
    /// `Files::resolve_assoc` reads: the type's impl's, or the trait's default
    assoc: Vec<(String, String)>,
}

fn is_keyword(w: &str) -> bool {
    matches!(
        w,
        "let"
            | "mut"
            | "ref"
            | "if"
            | "else"
            | "match"
            | "for"
            | "in"
            | "while"
            | "loop"
            | "return"
            | "as"
            | "move"
            | "async"
            | "await"
            | "unsafe"
            | "true"
            | "false"
            | "break"
            | "continue"
            | "where"
            | "fn"
            | "const"
            | "static"
            | "dyn"
            | "impl"
            | "crate"
            | "super"
            | "box"
    )
}

/// The traits of the `dyn` types a type names (`Box<dyn Pick>`: `Pick`; `&(dyn Konst + Sync)`:
/// `Konst`, `Sync`), by their last segment.
fn dyn_traits(t: &str) -> Vec<String> {
    let mut out = Vec::new();
    for m in re!(
        r"\bdyn\s+([\w:]+(?:<[^<>]*(?:<[^<>]*>[^<>]*)*>)?(?:\s*\+\s*(?:[\w:]+(?:<[^<>]*>)?|'\w+))*)"
    )
    .captures_iter(t)
    {
        for b in m[1].split('+') {
            let b = b.trim();
            if !b.is_empty() && !b.starts_with('\'') {
                out.push(type_name(b));
            }
        }
    }
    out
}

/// The type an annotation gives the part of a value a projection names (`(&Fast, &dyn Tr)` and
/// `[1]`: `&dyn Tr`; `[&dyn Tr; 2]` and an element: `&dyn Tr`), innermost projection last; the
/// whole type where it says no more.
fn project_type(t: &str, proj: &[Option<usize>]) -> String {
    let mut t = t.trim().to_string();
    for p in proj.iter().rev() {
        let inner = t.trim_start_matches('&').trim();
        let inner = inner.strip_prefix("mut ").unwrap_or(inner).trim();
        t = match p {
            Some(k) if inner.starts_with('(') && inner.ends_with(')') => {
                match split_top(&inner[1..inner.len() - 1]).get(*k) {
                    Some(e) => e.trim().to_string(),
                    None => return t,
                }
            }
            None => match elem_type(inner) {
                Some(e) => e,
                None => return t,
            },
            _ => return t,
        };
    }
    t
}

/// Where the path whose last segment starts at `wb` starts (`Box::new`: at `Box`).
fn path_start(s: &[char], wb: usize) -> usize {
    let mut st = wb;
    while let Some(c) = before_blank(s, st).filter(|&c| s[c] == ':' && c > 0 && s[c - 1] == ':') {
        let Some(e2) = before_blank(s, c - 1).filter(|&e2| is_ident(s[e2])) else {
            break;
        };
        let mut b = e2 + 1;
        while b > 0 && is_ident(s[b - 1]) {
            b -= 1;
        }
        st = b;
    }
    st
}

/// The call whose arguments the bracket at `ob` opens: the start of its callee's last segment
/// and that name (`f`, `m::f::<T>`, `.m`), skipping a turbofish.
fn callee_before(s: &[char], ob: usize) -> Option<(usize, String)> {
    let mut e = before_blank(s, ob)?;
    if s[e] == '>' {
        // `::<..>`: back to its `<`, then past the `::`
        let mut depth = 0;
        let mut k = e + 1;
        loop {
            k = k.checked_sub(1)?;
            match s[k] {
                '>' => depth += 1,
                '<' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
        }
        let c = before_blank(s, k)?;
        if s[c] != ':' || c == 0 || s[c - 1] != ':' {
            return None;
        }
        e = before_blank(s, c - 1)?;
    }
    if !is_ident(s[e]) {
        return None;
    }
    let mut b = e + 1;
    while b > 0 && is_ident(s[b - 1]) {
        b -= 1;
    }
    Some((b, s[b..=e].iter().collect()))
}

/// The traits the value at `i` (`Fast`, `x`, `W::<A>(..)`, `3u8`), made a pointer there (`&x`,
/// `&mut x`, `Box::new(x)`), becomes a trait object of: the `dyn` type of the context the
/// pointer is in, from the inside out: an `as` cast after it, the parameter of the function or
/// method it is passed to (`foreign` reads another crate's: path written, name, argument index ->
/// the parameter's type), the field of the struct literal it initializes, the variable whose
/// method stores it (`m.insert(k, b)` with `m` declared with `dyn`), the annotation of the `let`,
/// `static` or `const` whose value it is (the tuple element or array element it is), the return
/// type of the function whose result it is (its tail or `return`). Through tuples, arrays,
/// blocks, `if`s, `match`es, `Some`/`Ok`/`Err` and `Box::new`/`Rc::new`/`Arc::new`. None when
/// it becomes none there (`let probe = &Fast;`, `label(&Fast)` taking another trait's object
/// returns that trait).
fn coercion_traits(src: &Source, i: usize, foreign: &mut ForeignParam<'_>) -> Option<Vec<String>> {
    let s = &src.code;
    let some = |v: Vec<String>| (!v.is_empty()).then_some(v);
    // the value: a path (with turbofish), a struct literal or constructor's arguments
    let mut e = i;
    loop {
        e += word_of(s, e).chars().count();
        let j = skip_blank(s, e);
        if s.get(j) == Some(&':') && s.get(j + 1) == Some(&':') {
            let k = skip_blank(s, j + 2);
            if s.get(k) == Some(&'<') {
                let cls = vec![Class::Code; s.len() - k];
                e = k + skip_angle(&s[k..], &cls, 0)?;
                let j2 = skip_blank(s, e);
                if s.get(j2) == Some(&':')
                    && s.get(j2 + 1) == Some(&':')
                    && word_start(s, skip_blank(s, j2 + 2))
                {
                    e = skip_blank(s, j2 + 2);
                    continue;
                }
                break;
            }
            if word_start(s, k) {
                e = k;
                continue;
            }
        }
        break;
    }
    let j = skip_blank(s, e);
    if matches!(s.get(j), Some('{' | '(')) && s[i].is_uppercase() {
        e = close_of_at(s, j)? + 1;
    }
    let (mut ps, mut pe) = (i, e);
    // the pointer made of it
    if let Some(p) = before_blank(s, ps) {
        if s[p] == '&' {
            ps = p;
        } else if word_before_at(s, ps) == "mut"
            && let Some(a) = before_blank(s, p + 1 - 3).filter(|&a| s[a] == '&')
        {
            ps = a;
        } else if s[p] == '('
            && let Some((wb, w)) = callee_before(s, p)
            && matches!(w.as_str(), "new" | "pin")
        {
            let path = path_before(s, wb);
            if path
                .last()
                .is_some_and(|q| matches!(q.as_str(), "Box" | "Rc" | "Arc" | "Pin"))
            {
                let st = path_start(s, wb);
                ps = st;
                pe = close_of_at(s, p)? + 1;
            }
        }
    }
    // the item: a function's body or a static's value, not past it
    let item = src.enclosing(src.pos(i), &[ItemKind::Fn, ItemKind::Static])?;
    let (fa, fb) = src.span(item);
    let floor = if item.kind == ItemKind::Fn {
        scan_to(s, fa, fb, |k| s[k] == '{')
    } else {
        fa
    };
    // the first index of its body or value
    let lo = if item.kind == ItemKind::Fn {
        floor + 1
    } else {
        fa
    };
    let mut proj: Vec<Option<usize>> = Vec::new();
    for _ in 0..24 {
        // `as T`
        let n = skip_blank(s, pe);
        if kw(s, n, "as") {
            let t_end = scan_to(s, n + 2, fb, |k| matches!(s[k], ',' | ';' | '=' | '{'));
            return some(dyn_traits(&src.text(n + 2, t_end)));
        }
        // back to the bracket around it, the statement's start, a `=` of its statement
        let mut depth = 0i32;
        let mut k = ps;
        let mut eq = None;
        // (where the statement starts when no bracket is around it)
        let mut st = lo;
        let stop = loop {
            if k <= lo {
                break None;
            }
            k -= 1;
            if s[k] == ';' && depth == 0 {
                st = k + 1;
                break None;
            }
            match s[k] {
                ')' | ']' | '}' => depth += 1,
                '(' | '[' | '{' => {
                    if depth == 0 {
                        break Some(k);
                    }
                    depth -= 1;
                }
                '=' if depth == 0
                    && eq.is_none()
                    && !matches!(s.get(k + 1), Some('=' | '>'))
                    && !matches!(
                        k.checked_sub(1).map(|q| s[q]),
                        Some('=' | '!' | '<' | '>' | '+' | '-' | '*' | '/' | '%' | '^' | '&' | '|')
                    ) =>
                {
                    eq = Some(k)
                }
                _ => {}
            }
        };
        if let Some(eq) = eq {
            // the value of a `let`, `static` or `const`: its annotation
            let st = stop.map_or(st, |b| b + 1);
            let head = src.text(st, eq);
            let head = head.trim();
            let head = re!(r"^(?:pub(?:\s*\([^)]*\))?\s+)?").replace(head, "");
            if !re!(r"^(?:let|static|const)\b").is_match(&head) {
                return None;
            }
            let hc: Vec<char> = head.chars().collect();
            let colon = (0..hc.len()).find(|&c| {
                hc[c] == ':' && hc.get(c + 1) != Some(&':') && (c == 0 || hc[c - 1] != ':')
            })?;
            let t: String = hc[colon + 1..].iter().collect();
            return some(dyn_traits(&project_type(&t, &proj)));
        }
        let Some(ob) = stop else {
            // a statement's start: its function's result (a tail expression, `return`)
            let st = skip_blank(s, st);
            if item.kind != ItemKind::Fn {
                return None;
            }
            let body_end = close_of_at(s, floor)?;
            let tail = kw(s, st, "return") || scan_to(s, st, body_end, |m| s[m] == ';') >= body_end;
            if !tail {
                return None;
            }
            let ret = fn_sig(src, item).ret?;
            return some(dyn_traits(&ret));
        };
        let cb = close_of_at(s, ob)?;
        // its element index
        let idx = (ob + 1..ps)
            .filter(|&m| s[m] == ',' && scan_to(s, ob + 1, m + 1, |q| q == m) == m)
            .count();
        match s[ob] {
            '(' => match callee_before(s, ob)
                .filter(|(_, w)| !is_keyword(w) && w != "match" && w != "if")
            {
                None => {
                    // a tuple (or parentheses)
                    if scan_to(s, ob + 1, cb, |m| s[m] == ',') < cb {
                        proj.push(Some(idx));
                    }
                }
                Some((wb, w)) => {
                    let path = path_before(s, wb);
                    let method = before_blank(s, wb).is_some_and(|d| s[d] == '.');
                    let wrapper = matches!(w.as_str(), "Some" | "Ok" | "Err")
                        || (matches!(w.as_str(), "new" | "pin" | "from")
                            && path.last().is_some_and(|q| {
                                matches!(q.as_str(), "Box" | "Rc" | "Arc" | "Pin")
                            }));
                    if wrapper {
                        let st = path_start(s, wb);
                        ps = st;
                        pe = cb + 1;
                        continue;
                    }
                    if w.starts_with(char::is_uppercase) {
                        // a constructor: what is coerced is the value it makes
                        return None;
                    }
                    if method {
                        let d = before_blank(s, wb)?;
                        // a store into a variable declared with a trait object (`m.insert(k, b)`)
                        if let Some((r, recv, _)) = receiver_at(s, d)
                            && recv.chars().all(is_ident)
                            && let Some(Bound::Let { first, last, .. }) = binding(src, r, &recv)
                        {
                            let decl: String = (first..=last)
                                .map(|l| src.lines[l - 1].as_str())
                                .collect::<Vec<_>>()
                                .join("\n");
                            let t = dyn_traits(&decl);
                            if !t.is_empty() {
                                return Some(t);
                            }
                        }
                        // the file's method of that name: its parameter after `self`
                        let ts: Vec<String> = src
                            .items
                            .iter()
                            .filter(|f| f.kind == ItemKind::Fn && f.name == w)
                            .filter_map(|f| {
                                let sig = fn_sig(src, f);
                                let k = idx
                                    + usize::from(
                                        sig.params.first().is_some_and(|p| p.0 == "self"),
                                    );
                                sig.params.get(k).map(|p| dyn_traits(&p.1))
                            })
                            .flatten()
                            .collect();
                        return some(ts);
                    }
                    let ty = match free_fn_called(src, wb, &w, &path) {
                        Some(f) => fn_sig(src, f).params.get(idx).map(|p| p.1.clone()),
                        None => foreign(&path, &w, idx),
                    };
                    return some(dyn_traits(&ty?));
                }
            },
            '[' => {
                // an array literal (`[&A, &B]`, `vec![..]`), not an index
                let p = before_blank(s, ob);
                if p.is_some_and(|p| is_ident(s[p]) || matches!(s[p], ')' | ']')) {
                    return None;
                }
                proj.push(None);
                if let Some(pb) = p.filter(|&pb| s[pb] == '!') {
                    let we = before_blank(s, pb)?;
                    let mut wb = we + 1;
                    while wb > 0 && is_ident(s[wb - 1]) {
                        wb -= 1;
                    }
                    ps = path_start(s, wb);
                    pe = cb + 1;
                    continue;
                }
            }
            '{' => {
                // a field of a struct literal (`S { inner: Box::new(X) }`)
                let head = word_before_at(s, ob);
                let colon =
                    before_blank(s, ps).filter(|&c| s[c] == ':' && (c == 0 || s[c - 1] != ':'));
                if head.starts_with(char::is_uppercase)
                    && let Some(c) = colon
                {
                    let field = word_before_at(s, c);
                    if let Some(t) = field_type(src, &head, &field) {
                        return some(dyn_traits(&t));
                    }
                    let ts: Vec<String> = src
                        .lines
                        .iter()
                        .filter_map(|l| {
                            Regex::new(&format!(
                                r"\b{}\s*:\s*([^,;=]*\bdyn\b[^,;=]*)",
                                regex::escape(&field)
                            ))
                            .ok()?
                            .captures(l)
                            .map(|m| dyn_traits(&m[1]))
                        })
                        .flatten()
                        .collect();
                    return some(ts);
                }
                // a block, an `if`'s or a `match`'s: the value of the expression around it
            }
            _ => return None,
        }
        ps = ob;
        pe = cb + 1;
    }
    None
}

/// The parameters of a parameter list, split at its top-level commas.
fn split_top(t: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut cur = String::new();
    for c in t.chars() {
        match c {
            '(' | '[' | '{' | '<' => depth += 1,
            ')' | ']' | '}' | '>' => depth -= 1,
            ',' if depth == 0 => {
                out.push(std::mem::take(&mut cur));
                continue;
            }
            _ => {}
        }
        cur.push(c);
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    out
}

/// What the call at `p` reads: its callee (a path, or an expression through a pointer), its
/// arguments and its receiver, followed through variables, statics and the file's functions
/// (`names_read`); `None` when no call starts there. `strict`: see `Reads::strict`.
fn call_reads(
    src: &Source,
    kb: &Kb,
    p: usize,
    strict: bool,
    inst: &[(String, String)],
    alg: Option<usize>,
) -> Option<Reads> {
    let s = &src.code;
    let mut seen = HashSet::new();
    let mut call = Reads {
        strict,
        inst: inst.to_vec(),
        ..Reads::default()
    };
    // the call: its callee (a path, or an expression through a pointer: `(h.f)`, `FNS[i]`,
    // `get()`), then its arguments; the receiver of a method
    let mut j = p;
    let mut groups = Vec::new();
    loop {
        j = skip_blank(s, j);
        if word_start(s, j) {
            j += word_of(s, j).len();
        } else if s.get(j) == Some(&':') && s.get(j + 1) == Some(&':') {
            j += 2;
        } else if s.get(j) == Some(&'<') && groups.is_empty() {
            let cls = vec![Class::Code; s.len() - j];
            match skip_angle(&s[j..], &cls, 0) {
                Some(e) => j += e,
                None => break,
            }
        } else if matches!(s.get(j), Some('(' | '[')) || (s.get(j) == Some(&'*') && j == p) {
            if s[j] == '*' {
                j += 1;
                continue;
            }
            let Some(c) = close_of_at(s, j) else { break };
            groups.push((j, c));
            j = c + 1;
        } else {
            break;
        }
    }
    if !groups.iter().any(|&(o, _)| s[o] == '(') {
        return None;
    }
    let receiver = before_blank(s, p)
        .filter(|&d| s[d] == '.')
        .and_then(|dot| receiver_at(s, dot).map(|(r, _, _)| (r, dot)));
    // the argument that carries the algorithm (`alg`, the knowledge base's: the receiver is 0 of
    // a method): only that one is read, beside the callee's own groups (`FNS[i]`), where the
    // call has it; the data argument is no value of the algorithm
    let args = groups.iter().rev().find(|&&(o, _)| s[o] == '(').copied();
    let target: Option<Option<(usize, usize)>> = match (alg, receiver, args) {
        (Some(0), Some(_), _) => Some(None),
        (Some(k), Some(_), Some((o, c))) => list_elems(s, o + 1, c).get(k - 1).map(|&a| Some(a)),
        (Some(k), None, Some((o, c))) => list_elems(s, o + 1, c).get(k).map(|&a| Some(a)),
        _ => None,
    };
    match target {
        Some(arg) => {
            for &(o, c) in groups.iter().filter(|&&g| Some(g) != args) {
                names_read(src, kb, o + 1, c, 4, &mut seen, &mut call, true);
            }
            match (arg, receiver) {
                (Some((x, y)), _) => {
                    for (x, y) in value_parts(s, x, y) {
                        names_read(src, kb, x, y, 4, &mut seen, &mut call, true);
                    }
                }
                (None, Some((r, dot))) => {
                    names_read(src, kb, r, dot, 4, &mut seen, &mut call, true)
                }
                (None, None) => {}
            }
        }
        None => {
            for &(o, c) in &groups {
                names_read(src, kb, o + 1, c, 4, &mut seen, &mut call, true);
            }
            if let Some((r, dot)) = receiver {
                names_read(src, kb, r, dot, 4, &mut seen, &mut call, true);
            }
        }
    }
    Some(call)
}

/// The traits of the trait objects the call at `p` calls methods on (`digest(g.alg(), d)` with
/// `g: Box<dyn Gen>`: `Gen`), in its arguments and receiver: None where it calls none, or one on
/// a value whose type the code does not say (a type parameter's, a call's not followed).
fn call_dyn_receivers(src: &Source, p: usize) -> Option<Vec<String>> {
    let s = &src.code;
    let mut j = p;
    let end = loop {
        j = skip_blank(s, j);
        if word_start(s, j) {
            j += word_of(s, j).chars().count();
        } else if s.get(j) == Some(&':') && s.get(j + 1) == Some(&':') {
            j += 2;
        } else if s.get(j) == Some(&'<') {
            let cls = vec![Class::Code; s.len() - j];
            j += skip_angle(&s[j..], &cls, 0)?;
        } else if s.get(j) == Some(&'(') {
            break close_of_at(s, j)?;
        } else {
            return None;
        }
    };
    let start = before_blank(s, p)
        .filter(|&d| s[d] == '.')
        .and_then(|dot| receiver_at(s, dot).map(|(r, _, _)| r))
        .unwrap_or(p);
    let (mut out, mut any) = (Vec::new(), false);
    for k in start..end {
        if s[k] != '.' {
            continue;
        }
        let m = skip_blank(s, k + 1);
        let w = word_of(s, m);
        if w.is_empty() || s.get(skip_blank(s, m + w.chars().count())) != Some(&'(') {
            continue;
        }
        let (r, _, _) = receiver_at(s, k)?;
        let t = expr_type(src, r, k, 5)?;
        any = true;
        out.extend(dyn_traits(&t));
    }
    any.then_some(out)
}

/// The value argument of a call of `symbol` that carries the algorithm, from the knowledge
/// base's operation the symbol is (`ring::digest::digest`: 0; the receiver is 0 of a method);
/// None for another call, or an algorithm that is the call's type.
fn alg_arg(kb: &Kb, symbol: &str) -> Option<usize> {
    let sym = strip_generics(symbol);
    let (krate, rest) = sym.split_once("::")?;
    kb.operations
        .iter()
        .find(|e| e.krates.iter().any(|k| k == krate) && e.pattern.is_match(rest) && !e.self_type)
        .map(|e| e.algorithm)
}

/// The path written before the word at `start` (`dep::inner::` before `X`: `[dep, inner]`).
fn path_before(s: &[char], start: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut at = start;
    while let Some(p) = before_blank(s, at)
        && s[p] == ':'
        && p > 0
        && s[p - 1] == ':'
    {
        let Some(e) = before_blank(s, p - 1) else {
            break;
        };
        if !is_ident(s[e]) {
            break;
        }
        let mut b = e;
        while b > 0 && is_ident(s[b - 1]) {
            b -= 1;
        }
        out.push(s[b..=e].iter().collect::<String>());
        at = b;
    }
    out.reverse();
    out
}

/// Follows what the code at `a..b` reads (`depth` steps): the upper-case names it writes, the
/// statics and consts it names (their initializers), the file's functions it calls (their
/// bodies: a `const fn`'s value), the variables it reads (their initializers, scrutinees or
/// iterators, and the statements of the function that store into them: `v = ..`, `v.f = ..`,
/// `m.insert(..)`). With `own`, the code is the function's own: a parameter it reads is a value
/// from elsewhere (`open`).
#[allow(clippy::too_many_arguments)]
fn names_read(
    src: &Source,
    kb: &Kb,
    a: usize,
    b: usize,
    depth: usize,
    seen: &mut Seen,
    r: &mut Reads,
    own: bool,
) {
    let s = &src.code;
    let mut i = a;
    while i < b.min(s.len()) {
        // an index picks an element (`TABLE[i]`): it is no value read
        if s[i] == '['
            && before_blank(s, i)
                .is_some_and(|p| p >= a && (is_ident(s[p]) || matches!(s[p], ')' | ']')))
            && let Some(c) = close_of_at(s, i)
        {
            i = c + 1;
            continue;
        }
        if !word_start(s, i) {
            i += 1;
            continue;
        }
        let start = i;
        let w = word_of(s, i);
        i += w.len();
        let prev = before_blank(s, start);
        let after_dot = prev.is_some_and(|p| s[p] == '.');
        let after_colons = prev.is_some_and(|p| s[p] == ':' && p > 0 && s[p - 1] == ':');
        let n = skip_blank(s, i);
        let path_head = s.get(n) == Some(&':') && s.get(n + 1) == Some(&':');
        let call =
            s.get(n) == Some(&'(') || (path_head && s.get(skip_blank(s, n + 2)) == Some(&'<'));
        if call
            && !after_dot
            && matches!(w.as_str(), "replace" | "take" | "swap")
            && !src
                .items
                .iter()
                .any(|it| it.kind == ItemKind::Fn && it.name == w)
            && let Some(close) = close_of_at(s, n)
        {
            // `mem::replace(&mut x, v)`, `mem::take(&mut x)`: x's value before; `swap`: none
            if w != "swap" {
                let comma = scan_to(s, n + 1, close, |k| s[k] == ',');
                names_read(src, kb, n + 1, comma, depth, seen, r, own);
            }
            i = close + 1;
            continue;
        }
        if after_dot
            && call
            && depth > 0
            && src
                .items
                .iter()
                .any(|it| it.kind == ItemKind::Fn && it.name == w)
        {
            // a method of the file's (`q.pick()` on a `Plain`): what its body names; on a
            // value whose type the code does not say, or whose method another crate gives
            // (a trait's default body), what it returns is not read
            match exact_method(src, &start, &w) {
                Some(f) => {
                    let (fa, fb) = src.span(f);
                    let fa = scan_to(s, fa, fb, |k| s[k] == '{');
                    if seen.insert((fa, fb, String::new())) {
                        names_read(src, kb, fa, fb, depth - 1, seen, r, false);
                    }
                }
                None => r.lent = true,
            }
            continue;
        }
        if after_dot || s.get(n) == Some(&'!') {
            // a field or a method, a macro
            continue;
        }
        // `T::ALG` in an instance whose `T` is known: that type's `ALG`
        if path_head
            && !after_colons
            && let Some((_, ty)) = r.inst.iter().find(|(p, _)| *p == w).cloned()
        {
            let k = skip_blank(s, n + 2);
            let item = word_of(s, k);
            if item.starts_with(char::is_uppercase)
                && s.get(skip_blank(s, k + item.chars().count())) != Some(&'(')
            {
                if !r.assoc.contains(&(ty.clone(), item.clone())) {
                    r.assoc.push((ty, item.clone()));
                }
                i = k + item.chars().count();
            }
            continue;
        }
        let first = w.chars().next().unwrap_or('_');
        let upper = first.is_uppercase()
            && w.chars()
                .all(|c| c.is_uppercase() || c.is_ascii_digit() || c == '_');
        if first.is_uppercase() && !upper {
            r.types.insert(w);
            continue;
        }
        if upper {
            // (`D::digest`: a type parameter's path)
            if path_head {
                continue;
            }
            // an import alias: its item
            let w0 = w.clone();
            let item = src
                .binds
                .iter()
                .find(|bd| bd.name == w)
                .and_then(|bd| bd.path.last().cloned())
                .unwrap_or(w);
            // (a definition's own name, `const X: ..`, `static mut X`, is no read of it)
            let before = word_before_at(s, start);
            if matches!(before.as_str(), "const" | "static")
                || (matches!(before.as_str(), "mut" | "ref")
                    && before_blank(s, start)
                        .is_some_and(|p| word_before_at(s, p + 1 - before.len()) == "static"))
            {
                continue;
            }
            let mut statics: Vec<&Item> = src
                .items
                .iter()
                .filter(|it| it.kind == ItemKind::Static && it.name == item)
                .collect();
            // of several of that name in the file's modules, those of the module the path
            // written (or the import) leads to from the read's (`twin::CALG` beside `CALG`)
            if statics.len() > 1 {
                let here = modules_at(src, src.pos(start));
                let prefix = match src.binds.iter().find(|bd| bd.name == w0) {
                    Some(bd) => bd.path[..bd.path.len().saturating_sub(1)].to_vec(),
                    None => path_before(s, start),
                };
                let want: Option<Vec<String>> = match prefix.first().map(String::as_str) {
                    Some("crate" | "$crate") => None,
                    Some("self") => Some(here.iter().chain(&prefix[1..]).cloned().collect()),
                    Some("super") => {
                        let k = prefix.iter().take_while(|g| *g == "super").count();
                        Some(
                            here[..here.len().saturating_sub(k)]
                                .iter()
                                .chain(&prefix[k..])
                                .cloned()
                                .collect(),
                        )
                    }
                    _ => Some(here.iter().chain(&prefix).cloned().collect()),
                };
                if let Some(want) = want {
                    let pick: Vec<&Item> = statics
                        .iter()
                        .copied()
                        .filter(|it| modules_at(src, it.start) == want)
                        .collect();
                    if !pick.is_empty() {
                        statics = pick;
                    }
                }
            }
            if !statics.is_empty() {
                // a field of its elements (`TABLE[i].h`): the values its literals give it
                let field = field_read(s, i);
                r.fields |= field.is_some();
                for it in statics {
                    let sp = src.span(it);
                    let key = (sp.0, sp.1, field.clone().unwrap_or_default());
                    if depth > 0 && seen.insert(key) {
                        let parts = field
                            .as_deref()
                            .map(|f| {
                                project(
                                    src,
                                    sp.0,
                                    sp.1,
                                    &f.split('.').collect::<Vec<_>>(),
                                    8,
                                    &mut r.names,
                                )
                            })
                            .unwrap_or(vec![sp]);
                        for (x, y) in parts {
                            names_read(src, kb, x, y, depth - 1, seen, r, false);
                        }
                    }
                }
            } else if item.len() == 1 || src.locals.contains(&item) {
                // a type parameter (`h::<T>`), a type of the file (`struct S1;`)
                r.types.insert(item);
                continue;
            } else if !kb.statics.iter().any(|e| e.pattern.is_match(&item)) {
                r.foreign = true;
                let prefix = match src.binds.iter().find(|bd| bd.name == w0) {
                    Some(bd) => bd.path[..bd.path.len().saturating_sub(1)].to_vec(),
                    None => path_before(s, start),
                };
                let key = (prefix, item.clone(), field_read(s, i));
                if !r.foreign_items.contains(&key) {
                    r.foreign_items.push(key);
                }
            }
            r.names.insert(item);
            continue;
        }
        if after_colons || path_head || is_keyword(&w) || !(first.is_lowercase() || first == '_') {
            continue;
        }
        let found = lookup(src, start, &w);
        // (a function item passed as a value, `o.map(fixed)`: what it returns, as a call)
        let fn_item = !call
            && found.is_none()
            && src
                .items
                .iter()
                .any(|it| it.kind == ItemKind::Fn && it.name == w);
        if (call && !matches!(found, Some(Found::Bind(_)))) || fn_item {
            // the file's function: what its body names
            for f in src
                .items
                .iter()
                .filter(|it| it.kind == ItemKind::Fn && it.name == w)
            {
                let sp = src.span(f);
                if depth > 0 && seen.insert((sp.0, sp.1, String::new())) {
                    names_read(src, kb, sp.0, sp.1, depth - 1, seen, r, false);
                }
            }
            continue;
        }
        match found {
            Some(Found::Bind(bd)) if bd.kind == BindKind::Closure => r.open |= own,
            Some(Found::Bind(bd)) => {
                if depth == 0 {
                    continue;
                }
                // the stores that may reach the read: before it, or in a loop around both; one
                // into the place read, in a block around the read, replaces what was there
                let sc = src
                    .enclosing(src.pos(start), &[ItemKind::Fn])
                    .map(|f| src.fn_scope(f));
                let place = read_place(s, start).0;
                let field = field_read(s, i);
                r.fields |= field.is_some();
                let in_loop = |w: usize| {
                    sc.as_ref().is_some_and(|sc| {
                        sc.loops
                            .iter()
                            .any(|&(o, c)| o <= w && w < c && o <= start && start < c)
                    })
                };
                let writes: Vec<(usize, usize, usize)> = writes_to(src, &bd)
                    .into_iter()
                    .filter(|w| w.0 < start || in_loop(w.0))
                    .collect();
                let dom = writes
                    .iter()
                    .filter(|w| {
                        w.0 < start
                            && assigned_place(s, (w.0, w.2))
                                .is_some_and(|a| place == a || place.starts_with(&format!("{a}.")))
                            && sc.as_ref().is_some_and(|sc| {
                                let (o, c) = sc.block_of(w.0);
                                o < start && start < c
                            })
                    })
                    .map(|w| (w.0, (w.1, w.2)))
                    .max();
                // or a call of the file's function that replaces it on every way through it
                let dom = match sc
                    .as_ref()
                    .and_then(|sc| call_kills(src, &bd, start, &place, sc))
                {
                    Some(k) if dom.is_none_or(|d| k.0 > d.0) => Some(k),
                    _ => dom,
                };
                let around = |o: usize| {
                    sc.as_ref().is_some_and(|sc| {
                        let (bo, bc) = sc.block_of(o);
                        bo < start && start < bc
                    })
                };
                // stores through another binding pointing to it (`let r = &mut a; *r = v;`):
                // of the place read or of what holds it; one on every way to the read replaces
                // it for a claim that the values are all (`strict`), else it may or may not
                let pstores: Vec<PtrStore> = pointer_stores(src, &bd, start)
                    .into_iter()
                    .filter(|p| {
                        (p.at < start || in_loop(p.at))
                            && (place == p.place
                                || place.starts_with(&format!("{}.", p.place))
                                || place.starts_with(&format!("{}[", p.place))
                                || p.place.starts_with(&format!("{place}.")))
                    })
                    .collect();
                let pdom = pstores
                    .iter()
                    .filter(|p| {
                        r.strict
                            && p.definite
                            && p.at < start
                            && around(p.at)
                            && !p.place.starts_with(&format!("{place}."))
                            && dom.is_none_or(|d| p.at > d.0)
                    })
                    .max_by_key(|p| p.at)
                    .map(|p| (p.at, p.value));
                let dom = pdom.or(dom);
                // lent whole as `&mut` to `mem::swap(&mut a, &mut b)` or `mem::replace(&mut a,
                // v)`: it may hold what the call's other arguments hold; to `mem::take`, a
                // default not read
                // (the last such call in a block around the read replaces it: after it, the
                // variable holds the other argument's value, or the default)
                // (not the call the read is an argument of)
                let swaps: Vec<(usize, usize, String)> = swaps_of(src, &bd, start)
                    .into_iter()
                    .filter(|&(o, c, _)| !(o < start && start < c))
                    .collect();
                let swap = swaps
                    .iter()
                    .rev()
                    .find(|&&(o, _, _)| o < start && dom.is_none_or(|d| o > d.0) && around(o))
                    .cloned();
                // the other argument: `swap`'s other place, `replace`'s value
                let other = |o: usize, c: usize, f: &str| {
                    let comma = scan_to(s, o + 1, c, |k| s[k] == ',');
                    let mine = src.text(o + 1, comma);
                    if f == "replace"
                        || re!(r"\b\w+\b")
                            .find_iter(&mine)
                            .any(|m| m.as_str() == bd.name)
                    {
                        (comma + 1, c)
                    } else {
                        (o + 1, comma)
                    }
                };
                if let Some((o, c, f)) = &swap {
                    match f.as_str() {
                        "take" => {
                            r.open |= own;
                            r.replaced |= own;
                        }
                        _ => {
                            let (x, y) = other(*o, *c, f);
                            names_read(src, kb, x, y, depth - 1, seen, r, own);
                        }
                    }
                }
                // one that may or may not run on the way to the read (in an `if`, in a loop
                // around the read, after the one that replaces it): it may hold the other
                // argument's value too, beside its own
                for (o, c, f) in &swaps {
                    if swap.as_ref().is_some_and(|w| w.0 >= *o) || dom.is_some_and(|d| d.0 > *o) {
                        continue;
                    }
                    if !(*o < start || in_loop(*o)) || f == "take" {
                        continue;
                    }
                    let (x, y) = other(*o, *c, f);
                    names_read(src, kb, x, y, depth - 1, seen, r, own);
                    r.replaced |= own;
                }
                let dom = match &swap {
                    Some((o, _, _)) => Some((*o, (*o, *o))),
                    None => dom,
                };
                if !seen.insert((
                    bd.stmt.0,
                    dom.map_or(bd.stmt.1, |d| d.0),
                    field.clone().unwrap_or_default(),
                )) {
                    continue;
                }
                if dom.is_none()
                    && let Some((x, y)) = bd.init
                {
                    // a `match` arm's variant: what that variant is made with; a field read:
                    // what the literals give that field (`v11[0].h` of `vec![E { h: .. }]`)
                    let parts = variant_parts(src, &bd)
                        .or_else(|| {
                            // where the pattern binds it in the value (`let (p, q) = (..)`,
                            // `let Two { h, l } = ..`; a condition's, loop's or arm's only when
                            // it binds the whole), then the fields read of it
                            let mut path: Vec<String> =
                                match pattern_path(s, bd.pat.0, bd.pat.1, &bd.name) {
                                    Some(p) if bd.kind == BindKind::Let || p.is_empty() => p,
                                    _ => return None,
                                };
                            path.extend(
                                field
                                    .as_deref()
                                    .into_iter()
                                    .flat_map(|f| f.split('.'))
                                    .map(str::to_string),
                            );
                            if path.is_empty() {
                                return None;
                            }
                            let path: Vec<&str> = path.iter().map(String::as_str).collect();
                            Some(project(src, x, y, &path, 8, &mut r.names))
                        })
                        .unwrap_or_else(|| value_parts(s, x, y));
                    for (x, y) in parts {
                        names_read(src, kb, x, y, depth - 1, seen, r, own);
                    }
                }
                if let Some((_, (x, y))) = dom {
                    names_read(src, kb, x, y, depth - 1, seen, r, own);
                }
                // (not a store into another field of it)
                let other_field = |w: &(usize, usize, usize)| {
                    assigned_place(s, (w.0, w.2)).is_some_and(|a| {
                        a.contains('.') && !place.starts_with(&a) && !a.starts_with(&place)
                    })
                };
                for (_, x, y) in writes
                    .into_iter()
                    .filter(|w| dom.is_none_or(|d| w.0 > d.0) && !other_field(w))
                {
                    names_read(src, kb, x, y, depth - 1, seen, r, own);
                }
                for p in pstores.iter().filter(|p| dom.is_none_or(|d| p.at > d.0)) {
                    names_read(src, kb, p.value.0, p.value.1, depth - 1, seen, r, own);
                }
                // what the file's functions it is lent to (`maybe(&mut z, c)`, `b.up()`) may
                // write there; lent to another crate's function, it may hold what that puts
                for (i, f) in lent_to(src, &bd, start) {
                    match f {
                        Some(fi) => {
                            let sp = src.span(fi);
                            if seen.insert((sp.0, sp.1, String::new())) {
                                names_read(src, kb, sp.0, sp.1, depth - 1, seen, r, false);
                            }
                        }
                        None => {
                            let _ = i;
                            r.lent = true;
                        }
                    }
                }
            }
            Some(Found::Param(_)) => r.open |= own,
            Some(Found::Item(k)) => {
                let sp = src.span(&src.items[k]);
                if depth > 0 && seen.insert((sp.0, sp.1, String::new())) {
                    names_read(src, kb, sp.0, sp.1, depth - 1, seen, r, false);
                }
            }
            None => {}
        }
    }
}

/// A store through another binding that may point to a variable read (`pointer_stores`).
struct PtrStore {
    /// where the store's statement starts, and the value it stores
    at: usize,
    value: (usize, usize),
    /// the place of the variable it writes (`a`, `s1.alg`)
    place: String,
    /// the pointer points there on every way: a `let` of the borrow itself, of a struct or tuple
    /// literal holding it, of a reborrow or copy of one that does, the result of the file's
    /// function or method returning it; not one bound by a pattern, a loop, a condition
    definite: bool,
}

/// What the file's function `f` returns of its parameter `param` (its tail expression): the
/// path in the result to it (`""` the parameter, `.r` a field of the struct literal returned,
/// `.0` a tuple's element, `?` an `Option`'s value), the part of it a borrow returned names
/// (`&mut self.alg`: `.alg`), and whether it returns that on every way (no `return` before).
fn returns_part(src: &Source, f: &Item, param: &str) -> Option<(String, String, bool)> {
    let s = &src.code;
    let sc = src.fn_scope(f);
    let (o, c) = sc.body;
    if c < o + 2 {
        return None;
    }
    let mut tail_at = o + 1;
    let mut k = o + 1;
    while k < c - 1 {
        let e = scan_to(s, k, c - 1, |m| s[m] == ';');
        if e >= c - 1 {
            break;
        }
        tail_at = e + 1;
        k = e + 1;
    }
    let tail = src.text(tail_at, c - 1);
    let tail = tail.trim();
    let definite = !(o..c).any(|m| kw(s, m, "return") || s[m] == '?');
    let p = regex::escape(param);
    // `x`, `&mut *x`, `&mut x.f.g`, `&mut self.alg`
    if let Some(m) = Regex::new(&format!(
        r"^(?:&\s*mut\s+\**\s*)?\(?\s*\**{p}\s*\)?((?:\s*\.\s*\w+)*)$"
    ))
    .ok()?
    .captures(tail)
    {
        let sub: String = m[1].chars().filter(|c| !c.is_whitespace()).collect();
        if !sub.is_empty() && !tail.starts_with('&') {
            return None;
        }
        return Some((String::new(), sub, definite));
    }
    if Regex::new(&format!(r"^Some\s*\(\s*{p}\s*\)$"))
        .ok()?
        .is_match(tail)
    {
        return Some(("?".into(), String::new(), definite));
    }
    // `W { r: x, .. }`, `Self { r: x }`
    if let Some(m) = Regex::new(&format!(
        r"^(?:\w+::)*[A-Z]\w*\s*\{{(?:[^{{}}]*,)?\s*(\w+)\s*:\s*{p}\s*(?:,[^{{}}]*)?\}}$"
    ))
    .ok()?
    .captures(tail)
    {
        return Some((format!(".{}", &m[1]), String::new(), definite));
    }
    // `(x, ..)`
    if tail.starts_with('(') && tail.ends_with(')') {
        let parts = split_top(&tail[1..tail.len() - 1]);
        if parts.len() > 1
            && let Some(k) = parts.iter().position(|e| e.trim() == param)
        {
            return Some((format!(".{k}"), String::new(), definite));
        }
    }
    None
}

/// The stores through other bindings of the function that may point to the variable bound by
/// `bd` (or a part of it): `let r = &mut a; *r = v;`, reborrows and copies of such a pointer
/// (`let r1 = &mut *r0;`, `let r2 = r1;`), values holding one (`Holder { r: &mut x }`, `(&mut x,
/// ..)`, `Some(&mut x)`, `[&mut x]`, and the patterns and loops binding what they hold), a
/// pointer the file's function or method returns (`let r = s.slot();`, `let w = wrap(&mut x);`,
/// `*slot_of(&mut s) = v;`), and a field written through a pointer (`r.alg = v`).
fn pointer_stores(src: &Source, bd: &Bind, start: usize) -> Vec<PtrStore> {
    let s = &src.code;
    let Some(f) = src.enclosing(src.pos(start), &[ItemKind::Fn]) else {
        return Vec::new();
    };
    let sc = src.fn_scope(f);
    let is = |k: usize, b: &Bind| matches!(lookup(src, k, &b.name), Some(Found::Bind(x)) if x.stmt == b.stmt && x.name == b.name);
    // (binding, path in it to the pointer, the variable's part it points to, definite)
    let mut aliases: Vec<(Bind, String, String, bool)> = Vec::new();
    // the holder an expression at `e0..e1` of a binding's initializer `x..y` is in: the path to
    // it, and whether the initializer is that holder itself
    let holder = |x: usize, y: usize, e0: usize, e1: usize| -> Option<(String, bool)> {
        let x = skip_blank(s, x);
        let y = before_blank(s, y).map_or(y, |q| q + 1);
        if e0 == x && e1 >= y {
            return Some((String::new(), true));
        }
        // the bracket around it
        let mut depth = 0;
        let mut ob = None;
        let mut k = e0;
        while k > x {
            k -= 1;
            match s[k] {
                ')' | ']' | '}' => depth += 1,
                '(' | '[' | '{' => {
                    if depth == 0 {
                        ob = Some(k);
                        break;
                    }
                    depth -= 1;
                }
                _ => {}
            }
        }
        let ob = ob?;
        let cb = close_of_at(s, ob)?;
        let head = word_before_at(s, ob);
        let whole_from = |from: usize| skip_blank(s, from) == x && cb + 1 >= y;
        let head_at = ob - head.chars().count();
        let head_at =
            before_blank(s, ob).map_or(head_at, |p| p + 1 - head.chars().count().min(p + 1));
        // its element index (top-level commas before it)
        let idx = (ob + 1..e0)
            .filter(|&m| s[m] == ',' && scan_to(s, ob + 1, m + 1, |q| q == m) == m)
            .count();
        match s[ob] {
            '(' if head.is_empty() => Some((format!(".{idx}"), whole_from(ob))),
            '(' if head == "Some" => Some(("?".into(), false)),
            '{' if head.starts_with(char::is_uppercase) => {
                let p = before_blank(s, e0)?;
                if s[p] != ':' {
                    return None;
                }
                let fld = word_before_at(s, p);
                Some((format!(".{fld}"), whole_from(head_at)))
            }
            '[' => Some(("[]".into(), false)),
            '(' => {
                // a call of the file's function returning the pointer
                let fi = free_fn_called(src, head_at, &head, &path_before(s, head_at))?;
                let pn = src.fn_scope(fi).params.get(idx)?.clone();
                let (path, _, def) = returns_part(src, fi, &pn)?;
                Some((path, def && whole_from(head_at)))
            }
            _ => None,
        }
    };
    for _ in 0..12 {
        let mut grew = false;
        for b in &sc.binds {
            if (b.stmt == bd.stmt && b.name == bd.name)
                || aliases
                    .iter()
                    .any(|a| a.0.stmt == b.stmt && a.0.name == b.name)
            {
                continue;
            }
            let Some((x, y)) = b.init else { continue };
            let simple = b.kind == BindKind::Let && {
                let p = src.text(b.pat.0, b.pat.1);
                let p = p.split(':').next().unwrap_or("").trim();
                p.trim_start_matches("mut ").trim() == b.name
            };
            let mut found: Option<(String, String, bool)> = None;
            for k in x..y.min(s.len()) {
                if found.is_some() {
                    break;
                }
                // `&mut NAME..`
                if kw(s, k, &bd.name) && is(k, bd) {
                    let (pl, end) = read_place(s, k);
                    let sub = pl[bd.name.len()..].to_string();
                    let borrow = (word_before_at(s, k) == "mut")
                        .then(|| before_blank(s, k).and_then(|m| before_blank(s, m + 1 - 3)))
                        .flatten()
                        .filter(|&a| s[a] == '&');
                    if let Some(a) = borrow {
                        match holder(x, y, a, end) {
                            Some((path, whole)) => {
                                found = Some((path, sub, whole && simple));
                            }
                            None => found = Some(("*".into(), String::new(), false)),
                        }
                    } else if s.get(skip_blank(s, end)) == Some(&'.') {
                        // `NAME.m()`: the file's method returning a borrow of a part of it
                        let m = skip_blank(s, skip_blank(s, end) + 1);
                        let name = word_of(s, m);
                        if s.get(skip_blank(s, m + name.chars().count())) == Some(&'(')
                            && let Some(fi) = method_for(src, &m, &name)
                            && let Some((path, sub2, def)) = returns_part(src, fi, "self")
                        {
                            let c = close_of_at(s, skip_blank(s, m + name.chars().count()));
                            let whole = c.is_some_and(|c| skip_blank(s, c + 1) >= y)
                                && k == skip_blank(s, x);
                            found = Some((path, format!("{sub}{sub2}"), def && whole && simple));
                        }
                    }
                    continue;
                }
                // a pointer already found: a copy, a reborrow, a part of a holder
                if !word_start(s, k)
                    || before_blank(s, k).is_some_and(|p| s[p] == '.' || s[p] == ':')
                {
                    continue;
                }
                let Some(a) = aliases.iter().find(|a| kw(s, k, &a.0.name) && is(k, &a.0)) else {
                    continue;
                };
                let (pl, end) = read_place(s, k);
                let acc = pl[a.0.name.len()..].to_string();
                let rest = if a.1 == "*" {
                    "*".to_string()
                } else if let Some(r) = a.1.strip_prefix(acc.as_str()) {
                    r.to_string()
                } else {
                    continue;
                };
                // (`&mut *r0`, `&mut **r0`, `r0`)
                let mut e0 = k;
                while let Some(p) = before_blank(s, e0).filter(|&p| s[p] == '*') {
                    e0 = p;
                }
                if word_before_at(s, e0) == "mut"
                    && let Some(m) = before_blank(s, e0)
                    && let Some(amp) = before_blank(s, m + 1 - 3).filter(|&q| s[q] == '&')
                {
                    e0 = amp;
                } else if let Some(amp) = before_blank(s, e0).filter(|&q| s[q] == '&') {
                    e0 = amp;
                }
                match holder(x, y, e0, end) {
                    Some((path, whole)) if rest != "*" => {
                        found =
                            Some((format!("{path}{rest}"), a.2.clone(), whole && simple && a.3));
                    }
                    _ => found = Some(("*".into(), a.2.clone(), false)),
                }
            }
            if let Some((path, sub, def)) = found {
                let path = if simple { path } else { "*".to_string() };
                aliases.push((b.clone(), path, sub, def));
                grew = true;
            }
        }
        if !grew {
            break;
        }
    }
    let mut out = Vec::new();
    let assign_at = |end: usize| {
        let j = skip_blank(s, end);
        (s.get(j) == Some(&'=') && !matches!(s.get(j + 1), Some('=' | '>'))).then_some(j)
    };
    let stmt_start = |k: usize| before_blank(s, k).is_none_or(|p| matches!(s[p], ';' | '{' | '}'));
    for (b, path, sub, def) in &aliases {
        let mut stores = Vec::new();
        let mut retargeted = false;
        let mut i = b.scope.0;
        while i < b.scope.1.min(s.len()) {
            if !kw(s, i, &b.name) || !is(i, b) {
                i += 1;
                continue;
            }
            let mut st = i;
            let mut derefs = 0;
            while let Some(p) = before_blank(s, st).filter(|&p| s[p] == '*') {
                st = p;
                derefs += 1;
            }
            let (pl, end) = read_place(s, i);
            let acc = pl[b.name.len()..].to_string();
            i = end.max(i + 1);
            if !stmt_start(st) {
                continue;
            }
            let Some(eq) = assign_at(end) else { continue };
            let e = scan_to(s, eq + 1, b.scope.1, |m| s[m] == ';');
            let place = if derefs == 0 && acc.is_empty() {
                retargeted = true;
                continue;
            } else if path == "*" || path.starts_with('?') || path.starts_with("[]") {
                bd.name.clone()
            } else if derefs >= 1 && acc == *path {
                format!("{}{sub}", bd.name)
            } else if derefs == 0 && path.is_empty() && acc.starts_with('.') {
                format!("{}{sub}{acc}", bd.name)
            } else {
                continue;
            };
            stores.push((st, (eq + 1, e), place));
        }
        for (at, value, place) in stores {
            out.push(PtrStore {
                at,
                value,
                place,
                definite: *def && !retargeted && path != "*",
            });
        }
    }
    // `*f(.., &mut v.x, ..) = x;` with the file's `f` returning that borrow
    let (from, to) = bd.scope;
    let mut i = from;
    while i < to.min(s.len()) {
        if s[i] != '*' || !stmt_start(i) {
            i += 1;
            continue;
        }
        let w0 = skip_blank(s, i + 1);
        let mut j = w0;
        while j < to && (is_ident(s[j]) || s[j] == ':') {
            j += 1;
        }
        let name = src.text(w0, j);
        let name = name.rsplit("::").next().unwrap_or("").to_string();
        let open = skip_blank(s, j);
        if s.get(open) != Some(&'(') || name.is_empty() {
            i += 1;
            continue;
        }
        let Some(close) = close_of_at(s, open) else {
            i += 1;
            continue;
        };
        if let Some(eq) = assign_at(close + 1)
            && let Some(fi) =
                free_fn_called(src, w0, &name, &path_before(s, open - name.chars().count()))
        {
            let mut a = open + 1;
            let mut idx = 0;
            while a < close {
                let e2 = scan_to(s, a, close, |m| s[m] == ',');
                let k = skip_blank(s, a);
                let n = if s.get(k) == Some(&'&') {
                    skip_blank(s, k + 1)
                } else {
                    k
                };
                let n = if kw(s, n, "mut") {
                    skip_blank(s, n + 3)
                } else {
                    n
                };
                if kw(s, n, &bd.name)
                    && is(n, bd)
                    && let Some(pn) = src.fn_scope(fi).params.get(idx)
                    && let Some((path, sub, def)) = returns_part(src, fi, pn)
                    && path.is_empty()
                {
                    let (pl, _) = read_place(s, n);
                    let e = scan_to(s, eq + 1, to, |m| s[m] == ';');
                    out.push(PtrStore {
                        at: i,
                        value: (eq + 1, e),
                        place: format!("{pl}{sub}"),
                        definite: def,
                    });
                }
                idx += 1;
                a = e2 + 1;
            }
            i = close + 1;
            continue;
        }
        i += 1;
    }
    out
}

/// The `swap`, `take` and `replace` calls the variable bound by `bd` is lent to whole as `&mut`
/// in its scope (before the read at `start`, or after it in a loop around both: the caller
/// tells): their argument lists (brackets) and names.
fn swaps_of(src: &Source, bd: &Bind, start: usize) -> Vec<(usize, usize, String)> {
    let s = &src.code;
    let mut out = Vec::new();
    let _ = start;
    for i in bd.scope.0..bd.scope.1.min(s.len()) {
        if kw(s, i, &bd.name)
            && matches!(lookup(src, i, &bd.name), Some(Found::Bind(b)) if b.stmt == bd.stmt)
            && word_before_at(s, i) == "mut"
            && before_blank(s, i)
                .and_then(|m| before_blank(s, m + 1 - 3))
                .is_some_and(|a| s[a] == '&')
            && !matches!(
                s.get(skip_blank(s, i + bd.name.chars().count())),
                Some('.' | '[')
            )
            && swapping_call(src, i)
        {
            let mut depth = 0;
            let mut j = i;
            while j > 0 {
                j -= 1;
                match s[j] {
                    ')' | ']' | '}' => depth += 1,
                    '(' if depth == 0 => break,
                    '(' | '[' | '{' => depth -= 1,
                    _ => {}
                }
            }
            if let Some(c) = close_of_at(s, j) {
                out.push((j, c, word_before_at(s, j)));
            }
        }
    }
    out
}

/// Is the argument at `i` passed to `swap`, `take` or `replace` that is not the file's own
/// function (`mem::swap(&mut a, &mut b)`)?
fn swapping_call(src: &Source, i: usize) -> bool {
    let s = &src.code;
    let mut depth = 0;
    let mut j = i;
    let open = loop {
        if j == 0 {
            return false;
        }
        j -= 1;
        match s[j] {
            ')' | ']' | '}' => depth += 1,
            '(' if depth == 0 => break j,
            '(' | '[' | '{' => {
                if depth == 0 {
                    return false;
                }
                depth -= 1;
            }
            ';' if depth == 0 => return false,
            _ => {}
        }
    };
    let f = word_before_at(s, open);
    let fb = open - f.chars().count();
    let own = before_blank(s, fb).is_none_or(|p| s[p] != ':' && s[p] != '.')
        && src
            .items
            .iter()
            .any(|x| x.kind == ItemKind::Fn && x.name == f);
    matches!(f.as_str(), "swap" | "take" | "replace") && !own
}

/// A call before the read at `start`, in a block around it, that replaces the place read on
/// every way through it: of the file's function the variable is passed to by `&mut`
/// (`outer(&mut a7)`), or the file's method called on it (`c4.upgrade()`), whose body assigns
/// that place at its top level (`*slot = ..`, `self.alg = ..`), itself or through such a call,
/// with no `return` or `?` before: where the call is, and the value assigned.
fn call_kills(
    src: &Source,
    bd: &Bind,
    start: usize,
    place: &str,
    sc: &FnScope,
) -> Option<(usize, (usize, usize))> {
    let s = &src.code;
    let mut best = None;
    let mut i = bd.scope.0;
    while i < start {
        if !kw(s, i, &bd.name)
            || !matches!(lookup(src, i, &bd.name), Some(Found::Bind(b)) if b.stmt == bd.stmt)
        {
            i += 1;
            continue;
        }
        let arg = read_place(s, i).0;
        // `f(.., &mut v.x, ..)`
        let by_mut = word_before_at(s, i) == "mut"
            && before_blank(s, i)
                .and_then(|m| before_blank(s, m + 1 - 3))
                .is_some_and(|a| s[a] == '&');
        let mut kills: Vec<(String, (usize, usize))> = Vec::new();
        let mut at = i;
        if by_mut {
            // the call it is an argument of
            let mut depth = 0;
            let mut j = i;
            let open = loop {
                if j == 0 {
                    break None;
                }
                j -= 1;
                match s[j] {
                    ')' | ']' | '}' => depth += 1,
                    '(' if depth == 0 => break Some(j),
                    '(' | '[' | '{' => {
                        if depth == 0 {
                            break None;
                        }
                        depth -= 1;
                    }
                    ';' if depth == 0 => break None,
                    _ => {}
                }
            };
            if let Some(open) = open {
                let f = word_before_at(s, open);
                let fb = open - f.len();
                let free = before_blank(s, fb).is_none_or(|p| s[p] != '.');
                let idx = (open + 1..i)
                    .filter(|&k| s[k] == ',' && scan_to(s, open + 1, k + 1, |m| m == k) == k)
                    .count();
                if free && let Some(fi) = free_fn_called(src, fb, &f, &path_before(s, fb)) {
                    let fs = src.fn_scope(fi);
                    if let Some(pn) = fs.params.get(idx) {
                        kills = body_assigns(src, fi, pn, 3)
                            .into_iter()
                            .map(|(sub, v)| (format!("{arg}{sub}"), v))
                            .collect();
                        at = open;
                    }
                }
            }
        } else {
            // `v.m(..)`, a method of the file's taking `self`
            let d = skip_blank(s, i + arg.chars().count());
            let m = skip_blank(s, d + 1);
            let name = word_of(s, m);
            if s.get(d) == Some(&'.')
                && s.get(skip_blank(s, m + name.len())) == Some(&'(')
                && let Some(fi) = method_for(src, &m, &name)
            {
                kills = body_assigns(src, fi, "self", 3)
                    .into_iter()
                    .map(|(sub, v)| (format!("{arg}{sub}"), v))
                    .collect();
                at = m;
            }
        }
        let (o, c) = sc.block_of(at);
        if o < start && start < c {
            for (k, v) in kills {
                if place == k || place.starts_with(&format!("{k}.")) {
                    best = Some((at, v));
                }
            }
        }
        i += bd.name.len();
    }
    best
}

/// What the body of the function `f` assigns through its parameter `param` at its top level,
/// before any `return` or `?`: the place under the parameter (`""` for `*slot = ..`, `.alg` for
/// `self.alg = ..`) and the value, also through the file's functions it passes the parameter
/// to there (`inner(slot)`, `self.set()`).
fn body_assigns(
    src: &Source,
    f: &Item,
    param: &str,
    depth: usize,
) -> Vec<(String, (usize, usize))> {
    let s = &src.code;
    let sc = src.fn_scope(f);
    let (b0, b1) = sc.body;
    // a parameter the body points elsewhere (`slot = other;`, `mem::swap(&mut slot, ..)`):
    // what it writes through it is not the caller's place
    let body = src.text(b0, b1);
    if param != "self"
        && Regex::new(&format!(
            r"(?:^|[;{{}}]\s*){p}\s*=[^=]|&\s*mut\s+{p}\b",
            p = regex::escape(param)
        ))
        .is_ok_and(|r| r.is_match(&body))
    {
        return Vec::new();
    }
    // a way out before the end
    let exit = (b0..b1)
        .find(|&k| kw(s, k, "return") || (s[k] == '?' && k > 0 && !s[k - 1].is_whitespace()));
    let mut out = Vec::new();
    // the places under the parameter a local reborrows (`let r = &mut self.alg;`)
    let mut aliases: HashMap<String, String> = HashMap::new();
    let under = |x: &str, aliases: &HashMap<String, String>| -> Option<String> {
        let x = x
            .trim()
            .trim_start_matches("&mut")
            .trim()
            .trim_start_matches('*')
            .trim();
        let (head, rest) = x.split_once('.').map_or((x, ""), |(h, r)| (h, r));
        let rest = if rest.is_empty() {
            String::new()
        } else {
            format!(".{rest}")
        };
        if head == param {
            Some(rest)
        } else {
            aliases.get(head).map(|a| format!("{a}{rest}"))
        }
    };
    let mut k = b0 + 1;
    while k < b1.saturating_sub(1) && exit.is_none_or(|e| k < e) {
        let e = scan_to(s, k, b1 - 1, |m| s[m] == ';');
        let st = skip_blank(s, k);
        let st = if s.get(st) == Some(&'*') {
            skip_blank(s, st + 1)
        } else {
            st
        };
        if exit.is_some_and(|x| x < e) {
            break;
        }
        let stmt = src.text(st, e);
        // `std::mem::replace(slot, v)`
        let replace = re!(r"\bmem\s*::\s*replace\s*\(").find(&stmt).and_then(|m| {
            let open = st + stmt[..m.end()].chars().count() - 1;
            let c = close_of_at(s, open)?;
            let comma = scan_to(s, open + 1, c, |x| s[x] == ',');
            Some((under(&src.text(open + 1, comma), &aliases)?, (comma + 1, c)))
        });
        if let Some(r) = replace {
            out.push(r);
        } else if kw(s, st, "let")
            && let Some(m) = re!(r"^let\s+(?:mut\s+)?(\w+)\s*(?::[^=]*)?=\s*&\s*mut\s+([\w.]+)\s*$")
                .captures(stmt.trim())
            && let Some(sub) = under(&m[2], &aliases)
        {
            aliases.insert(m[1].to_string(), sub);
        } else if let Some(pl) = assigned_place(s, (st, e))
            && let Some(sub) = under(&pl, &aliases)
        {
            let v = scan_to(s, st, e, |m| s[m] == '=') + 1;
            out.push((sub, (v, e)));
        } else if depth > 0 {
            // `g(.., param, ..)`, `self.m(..)`
            let w = word_of(s, st);
            let n = skip_blank(s, st + w.len());
            if kw(s, st, param) && s.get(n) == Some(&'.') {
                let m = skip_blank(s, n + 1);
                let name = word_of(s, m);
                // (the method it calls: the only one of that name, or `self`'s, in the impl
                // around; on a value of a type parameter, several types' may run: not followed)
                let methods: Vec<&Item> = src
                    .items
                    .iter()
                    .filter(|x| {
                        x.kind == ItemKind::Fn
                            && x.name == name
                            && src.fn_scope(x).params.first().is_some_and(|p| p == "self")
                    })
                    .collect();
                let own_impl = src.items.iter().find(|b| {
                    b.kind == ItemKind::Impl && b.contains(f.start) && b.start != f.start
                });
                let g = match methods.as_slice() {
                    [one] => Some(*one),
                    _ if param == "self" => {
                        own_impl.and_then(|b| methods.iter().copied().find(|g| b.contains(g.start)))
                    }
                    _ => None,
                };
                if let Some(g) = g {
                    out.extend(body_assigns(src, g, "self", depth - 1));
                }
            } else if !w.is_empty()
                && s.get(n) == Some(&'(')
                && let Some(c) = close_of_at(s, n)
                && let Some(g) = src
                    .items
                    .iter()
                    .find(|x| x.kind == ItemKind::Fn && x.name == w)
            {
                let mut a = n + 1;
                let mut idx = 0;
                while a < c {
                    let e2 = scan_to(s, a, c, |m| s[m] == ',');
                    let arg = src.text(a, e2);
                    let arg = arg
                        .trim()
                        .trim_start_matches("&mut")
                        .trim()
                        .trim_start_matches('*')
                        .trim();
                    if arg == param
                        && let Some(pn) = src.fn_scope(g).params.get(idx)
                    {
                        out.extend(body_assigns(src, g, pn, depth - 1));
                    }
                    idx += 1;
                    a = e2 + 1;
                }
            }
        }
        k = e + 1;
    }
    out
}

/// The place a read at `start` reads: the variable and the fields and literal indexes after it
/// (`c9.alg`, `t.0`, `v10[0]`), and where it ends.
fn read_place(s: &[char], start: usize) -> (String, usize) {
    let mut out = word_of(s, start);
    let mut j = start + out.len();
    loop {
        let d = skip_blank(s, j);
        match s.get(d) {
            Some('.') => {
                let f = skip_blank(s, d + 1);
                let w = word_of(s, f);
                if w.is_empty() || s.get(skip_blank(s, f + w.len())) == Some(&'(') {
                    break;
                }
                out.push('.');
                out.push_str(&w);
                j = f + w.len();
            }
            Some('[') => {
                let Some(c) = close_of_at(s, d) else { break };
                let k: String = s[d + 1..c].iter().filter(|c| !c.is_whitespace()).collect();
                if k.is_empty() || !k.chars().all(|c| c.is_ascii_digit()) {
                    break;
                }
                out.push_str(&format!("[{k}]"));
                j = c + 1;
            }
            _ => break,
        }
    }
    (out, j)
}

/// The fields read after a variable or static ending at `end`, past its indexes, as a path
/// (`TABLE[i].h`: `h`; `NESTED.inner.h`: `inner.h`; `TS.1.h`: `1.h`), not a method called.
fn field_read(s: &[char], end: usize) -> Option<String> {
    let mut out: Vec<String> = Vec::new();
    let mut j = skip_blank(s, end);
    loop {
        while s.get(j) == Some(&'[') {
            j = skip_blank(s, close_of_at(s, j)? + 1);
        }
        if s.get(j) != Some(&'.') {
            break;
        }
        let f = skip_blank(s, j + 1);
        let w = word_of(s, f);
        let n = skip_blank(s, f + w.chars().count());
        if w.is_empty() || matches!(s.get(n), Some('(' | ':')) {
            break;
        }
        j = n;
        out.push(w);
    }
    (!out.is_empty()).then(|| out.join("."))
}

/// Where a pattern at `a..b` binds `name` in the value it matches, as a path of fields (`(x, _)`:
/// `0`; `[a, b]`: `[1]` for `b`; `Two { h, l }`: `l`; `((x, _), y)`: `0.0` for `x`; `S(a, b)`:
/// `1`); empty for the pattern itself (`x`, `mut x`, `x @ ..`); None where it does not say (a
/// rest `..` before it, an or-pattern).
fn pattern_path(s: &[char], a: usize, b: usize, name: &str) -> Option<Vec<String>> {
    let mut a = skip_blank(s, a);
    let mut b = b.min(s.len());
    // (its type annotation: not the pattern's)
    let colon = scan_to(s, a, b, |k| {
        s[k] == ':' && s.get(k + 1) != Some(&':') && (k == 0 || s[k - 1] != ':')
    });
    b = colon.min(b);
    while b > a && s[b - 1].is_whitespace() {
        b -= 1;
    }
    loop {
        if s.get(a) == Some(&'&') {
            a = skip_blank(s, a + 1);
        } else if kw(s, a, "mut") || kw(s, a, "ref") {
            a = skip_blank(s, a + 3);
        } else {
            break;
        }
    }
    if a >= b {
        return None;
    }
    if word_start(s, a) && word_of(s, a) == name {
        let e = skip_blank(s, a + name.chars().count());
        return (e >= b || s.get(e) == Some(&'@')).then(Vec::new);
    }
    let elems_in = |o: usize, c: usize| list_elems(s, o + 1, c);
    let rest_before = |els: &[(usize, usize)], k: usize| {
        els[..k].iter().any(|&(x, y)| src_text_is(s, x, y, ".."))
    };
    let mut head_end = a;
    while head_end < b && (is_ident(s[head_end]) || s[head_end] == ':') {
        head_end += 1;
    }
    let o = skip_blank(s, head_end);
    let c = close_of_at(s, o)?;
    if skip_blank(s, c + 1) < b {
        return None;
    }
    let els = elems_in(o, c);
    for (k, &(x, y)) in els.iter().enumerate() {
        match s[o] {
            '(' | '[' => {
                if let Some(mut p) = pattern_path(s, x, y, name) {
                    if rest_before(&els, k) {
                        return None;
                    }
                    let step = if s[o] == '[' {
                        format!("[{k}]")
                    } else {
                        k.to_string()
                    };
                    p.insert(0, step);
                    return Some(p);
                }
            }
            '{' => {
                let x0 = skip_blank(s, x);
                let fname = word_of(s, x0);
                let n = skip_blank(s, x0 + fname.chars().count());
                let sub = if s.get(n) == Some(&':') {
                    pattern_path(s, n + 1, y, name)
                } else {
                    pattern_path(s, x, y, name)
                };
                if let Some(mut p) = sub {
                    p.insert(0, fname);
                    return Some(p);
                }
            }
            _ => return None,
        }
    }
    None
}

/// Whether the code at `a..b` is `t`, blanks aside.
fn src_text_is(s: &[char], a: usize, b: usize, t: &str) -> bool {
    s[a..b.min(s.len())]
        .iter()
        .filter(|c| !c.is_whitespace())
        .copied()
        .eq(t.chars())
}

/// The parts of an expression at `a..b` that give its value, through the `Option` and `Result`
/// combinators a closure decides (`o.map_or(&SHA512, |_| &SHA1)`: the default and the closure's
/// body, not `o`'s value unless the closure reads its parameter; `.map(f)`, `.and_then(f)`,
/// `.map_or_else(d, f)` likewise; `.unwrap_or(d)` adds `d`); the whole where it says no more.
fn value_parts(s: &[char], a: usize, b: usize) -> Vec<(usize, usize)> {
    let b = b.min(s.len());
    let mut end = b;
    while end > a && s[end - 1].is_whitespace() {
        end -= 1;
    }
    let mut extra = Vec::new();
    // trailing calls keeping the value (`.unwrap()`, `.copied()`, `?`), or adding one
    loop {
        if end > a && s[end - 1] == '?' {
            end -= 1;
            continue;
        }
        if end == 0 || s[end - 1] != ')' {
            break;
        }
        let Some(o) = open_of_at(s, end - 1) else {
            break;
        };
        let name = word_before_at(s, o);
        let nb = before_blank(s, o).map_or(o, |p| p + 1 - name.chars().count().min(p + 1));
        let Some(dot) = before_blank(s, nb).filter(|&d| s[d] == '.' && d > a) else {
            break;
        };
        match name.as_str() {
            "unwrap" | "expect" | "copied" | "cloned" | "unwrap_or_default" | "as_ref"
            | "as_deref" => end = dot,
            "unwrap_or" | "or" => {
                extra.push((o + 1, end - 1));
                end = dot;
            }
            "unwrap_or_else" | "or_else" => {
                extra.extend(closure_value(s, o + 1, end - 1).unwrap_or(vec![(o + 1, end - 1)]));
                end = dot;
            }
            "map" | "and_then" | "map_or" | "map_or_else" => {
                let args = list_elems(s, o + 1, end - 1);
                let f = args.last().copied();
                let Some(f) = f else { break };
                let Some(body) = closure_value(s, f.0, f.1) else {
                    // a function item: what it makes of the receiver's value
                    return [(a, b)].into_iter().chain(extra).collect();
                };
                let mut out = body;
                if let Some(&d) = args.first().filter(|_| args.len() == 2) {
                    out.extend(closure_value(s, d.0, d.1).unwrap_or(vec![d]));
                }
                // a closure reading its parameter: what it makes of the receiver's value
                if closure_reads_param(s, f.0, f.1) {
                    out.push((a, dot));
                }
                out.extend(extra);
                return out;
            }
            _ => break,
        }
    }
    [(a, b)].into_iter().chain(extra).collect()
}

/// The body of a closure written at `a..b` (`|_| &SHA1`, `|| x`), None for another expression.
fn closure_value(s: &[char], a: usize, b: usize) -> Option<Vec<(usize, usize)>> {
    let k = skip_blank(s, a);
    let k = if kw(s, k, "move") {
        skip_blank(s, k + 4)
    } else {
        k
    };
    if !closure_at(s, k) {
        return None;
    }
    let (_, (x, y)) = closure_parts(s, k, b)?;
    Some(vec![(x, y.min(b))])
}

/// Whether the closure written at `a..b` reads one of its parameters in its body.
fn closure_reads_param(s: &[char], a: usize, b: usize) -> bool {
    let k = skip_blank(s, a);
    let k = if kw(s, k, "move") {
        skip_blank(s, k + 4)
    } else {
        k
    };
    let Some((Some((pa, pb)), (x, y))) = closure_parts(s, k, b) else {
        return false;
    };
    let names = params_names(s, pa, pb);
    (x..y.min(b)).any(|i| names.iter().any(|n| n != "_" && kw(s, i, n)))
}

/// The top-level elements of a list at `a..b` (between brackets): their extents.
fn list_elems(s: &[char], a: usize, b: usize) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut x = a;
    while x < b {
        let e = scan_to(s, x, b, |k| s[k] == ',');
        if s[x..e].iter().any(|c| !c.is_whitespace()) {
            out.push((x, e));
        }
        x = e + 1;
    }
    out
}

/// What the code at `a..b` (an expression, or a static's or const's item) gives the field path
/// `fields` (`h`, `inner.h`, `1`, `0.1`) of the value it makes: the field's value in a struct
/// literal (through `..base`), a tuple literal's element, through each element of an array
/// literal or `vec![..]`, and through a constant or static of the file it names (`[BASE, ..]`,
/// `Outer { inner: BASE }`, `FIX`, `&FIX`); the whole code where it says no more (a call, a
/// `const fn`, another crate's constant); nothing where a literal has no such field. `via`
/// collects the constants and statics passed through.
fn project(
    src: &Source,
    a: usize,
    b: usize,
    fields: &[&str],
    depth: usize,
    via: &mut BTreeSet<String>,
) -> Vec<(usize, usize)> {
    let s = &src.code;
    let mut a = skip_blank(s, a);
    let mut b = b.min(s.len());
    if fields.is_empty() || depth == 0 || a >= b {
        return vec![(a, b)];
    }
    // an item: its initializer
    if (kw(s, a, "static") || kw(s, a, "const"))
        && let Some(eq) = let_eq_at(s, a, b)
    {
        a = skip_blank(s, eq + 1);
    }
    while b > a && (s[b - 1].is_whitespace() || s[b - 1] == ';') {
        b -= 1;
    }
    while a < b && s[a] == '&' {
        a = skip_blank(s, a + 1);
        if kw(s, a, "mut") {
            a = skip_blank(s, a + 3);
        }
    }
    if a >= b {
        return Vec::new();
    }
    let (f, rest) = (fields[0], &fields[1..]);
    let index: Option<usize> = f.parse().ok();
    let whole = |o: usize| close_of_at(s, o) == Some(b - 1);
    match s[a] {
        '(' if whole(a) => {
            let elems = list_elems(s, a + 1, b - 1);
            let tuple = scan_to(s, a + 1, b - 1, |k| s[k] == ',') < b - 1;
            if !tuple {
                return project(src, a + 1, b - 1, fields, depth - 1, via);
            }
            match index.and_then(|k| elems.get(k)) {
                Some(&(x, y)) => project(src, x, y, rest, depth - 1, via),
                None => Vec::new(),
            }
        }
        '[' if whole(a) => {
            let semi = scan_to(s, a + 1, b - 1, |k| s[k] == ';');
            let elems = if semi < b - 1 {
                vec![(a + 1, semi)]
            } else {
                list_elems(s, a + 1, b - 1)
            };
            // a slice pattern's element (`[k]`): that one; a field: each element's
            if let Some(k) = f
                .strip_prefix('[')
                .and_then(|x| x.strip_suffix(']'))
                .and_then(|x| x.parse::<usize>().ok())
            {
                let el = if semi < b - 1 {
                    elems.first()
                } else {
                    elems.get(k)
                };
                return match el {
                    Some(&(x, y)) => project(src, x, y, rest, depth - 1, via),
                    None => Vec::new(),
                };
            }
            elems
                .into_iter()
                .flat_map(|(x, y)| project(src, x, y, fields, depth - 1, via))
                .collect()
        }
        _ if word_start(s, a) => {
            // a path
            let mut e = a;
            let mut last;
            loop {
                last = word_of(s, e);
                e += last.chars().count();
                let j = skip_blank(s, e);
                if s.get(j) == Some(&':')
                    && s.get(j + 1) == Some(&':')
                    && word_start(s, skip_blank(s, j + 2))
                {
                    e = skip_blank(s, j + 2);
                    continue;
                }
                break;
            }
            let n = skip_blank(s, e);
            // `vec![..]`
            if last == "vec" && s.get(n) == Some(&'!') {
                let o = skip_blank(s, n + 1);
                if s.get(o) == Some(&'[') && whole(o) {
                    return project(src, o, b, fields, depth - 1, via);
                }
                return vec![(a, b)];
            }
            // a constant or static of the file, or an element of one (`TABLE[i]`: each)
            let indexed = s.get(n) == Some(&'[')
                && close_of_at(s, n).is_some_and(|c| skip_blank(s, c + 1) >= b);
            if (n >= b || indexed)
                && last.chars().next().is_some_and(char::is_uppercase)
                && last
                    .chars()
                    .all(|c| c.is_uppercase() || c.is_ascii_digit() || c == '_')
            {
                let items: Vec<&Item> = src
                    .items
                    .iter()
                    .filter(|it| it.kind == ItemKind::Static && it.name == last)
                    .collect();
                if items.is_empty() {
                    return vec![(a, b)];
                }
                via.insert(last.clone());
                return items
                    .into_iter()
                    .flat_map(|it| {
                        let (x, y) = src.span(it);
                        project(src, x, y, fields, depth - 1, via)
                    })
                    .collect();
            }
            match s.get(n) {
                // a struct literal: the field's value, or its base's
                Some('{') if whole(n) && index.is_none() => {
                    let mut vals = Vec::new();
                    let mut base = None;
                    for (x, y) in list_elems(s, n + 1, b - 1) {
                        let x = skip_blank(s, x);
                        if s.get(x) == Some(&'.') && s.get(x + 1) == Some(&'.') {
                            base = Some((x + 2, y));
                        } else if kw(s, x, f) {
                            let c = skip_blank(s, x + f.len());
                            if s.get(c) == Some(&':') {
                                vals.push((c + 1, y));
                            } else if c >= y {
                                // shorthand `S { h }`
                                vals.push((x, y));
                            }
                        }
                    }
                    if vals.is_empty()
                        && let Some((x, y)) = base
                    {
                        return project(src, x, y, fields, depth - 1, via);
                    }
                    vals.into_iter()
                        .flat_map(|(x, y)| project(src, x, y, rest, depth - 1, via))
                        .collect()
                }
                // a call of the file's function (`make()`, a `const fn`): what its tail
                // expression gives, where it has no other way out
                Some('(')
                    if whole(n) && last.starts_with(|c: char| c.is_lowercase() || c == '_') =>
                {
                    let Some(f) =
                        free_fn_called(src, a, &last, &path_before(s, e - last.chars().count()))
                    else {
                        return vec![(a, b)];
                    };
                    let (o, c) = src.fn_scope(f).body;
                    if c < o + 2 || (o..c).any(|m| kw(s, m, "return") || s[m] == '?') {
                        return vec![(a, b)];
                    }
                    let mut tail = o + 1;
                    let mut k = o + 1;
                    while k < c - 1 {
                        let e2 = scan_to(s, k, c - 1, |m| s[m] == ';');
                        if e2 >= c - 1 {
                            break;
                        }
                        tail = e2 + 1;
                        k = e2 + 1;
                    }
                    project(src, tail, c - 1, fields, depth - 1, via)
                }
                // a tuple struct's constructor: its element
                Some('(') if whole(n) && last.starts_with(char::is_uppercase) => {
                    match index.and_then(|k| list_elems(s, n + 1, b - 1).get(k).copied()) {
                        Some((x, y)) => project(src, x, y, rest, depth - 1, via),
                        None => vec![(a, b)],
                    }
                }
                _ => vec![(a, b)],
            }
        }
        _ => vec![(a, b)],
    }
}

/// The place a statement (`writes_to`) assigns (`c9.alg = ..`, `v10[0] = ..`), if it is an
/// assignment.
fn assigned_place(s: &[char], w: (usize, usize)) -> Option<String> {
    let (place, end) = read_place(s, w.0);
    let j = skip_blank(s, end);
    (j < w.1 && s.get(j) == Some(&'=') && !matches!(s.get(j + 1), Some('=' | '>'))).then_some(place)
}

/// For a `match` arm binding a field of a variant (`Pick::A(x) => ..`) of a variable (`match
/// p`): the arguments of that variant's constructions in what the variable holds (`Pick::A(&
/// SHA384)`), where it has some.
fn variant_parts(src: &Source, bd: &Bind) -> Option<Vec<(usize, usize)>> {
    if bd.kind != BindKind::Arm {
        return None;
    }
    let s = &src.code;
    let (a, b) = bd.pat;
    let at = (a..b).find(|&i| kw(s, i, &bd.name))?;
    let mut depth = 0;
    let mut j = at;
    let open = loop {
        if j <= a {
            return None;
        }
        j -= 1;
        match s[j] {
            ')' => depth += 1,
            '(' if depth == 0 => break j,
            '(' => depth -= 1,
            _ => {}
        }
    };
    let v = word_before_at(s, open);
    if !v.chars().next()?.is_uppercase() {
        return None;
    }
    let (x, y) = bd.init?;
    let var = src.text(x, y).trim().to_string();
    if var.is_empty() || !var.chars().all(is_ident) {
        return None;
    }
    let k = (x..y).find(|&i| kw(s, i, &var))?;
    let Some(Found::Bind(vb)) = lookup(src, k, &var) else {
        return None;
    };
    let mut texts: Vec<(usize, usize)> = vb.init.into_iter().collect();
    texts.extend(writes_to(src, &vb).into_iter().map(|w| (w.1, w.2)));
    let mut out = Vec::new();
    for (p, q) in texts {
        for i in p..q {
            if kw(s, i, &v) {
                let o = skip_blank(s, i + v.len());
                if s.get(o) == Some(&'(')
                    && let Some(c) = close_of_at(s, o)
                {
                    out.push((o + 1, c));
                }
            }
        }
    }
    (!out.is_empty()).then_some(out)
}

/// The statements of its scope that store into a variable: those that start with it
/// (`v = ..;`, `v.f = ..;`, `*v = ..;`, `m.insert(k, ..);`, `m.entry(k).or_insert(..);`), the
/// variable read there being this binding: where each starts, where what it stores starts
/// (the value assigned, the method's arguments), and its end.
fn writes_to(src: &Source, bd: &Bind) -> Vec<(usize, usize, usize)> {
    let s = &src.code;
    let mut out = Vec::new();
    let (from, to) = bd.scope;
    let mut i = from;
    while i < to.min(s.len()) {
        if !kw(s, i, &bd.name) {
            i += 1;
            continue;
        }
        let mut p = before_blank(s, i);
        if p.is_some_and(|p| s[p] == '*') {
            p = before_blank(s, p.unwrap_or(0));
        }
        let starts = p.is_none_or(|p| matches!(s[p], ';' | '{' | '}'));
        if starts && matches!(lookup(src, i, &bd.name), Some(Found::Bind(b)) if b.stmt == bd.stmt) {
            let e = scan_to(s, i, to, |k| s[k] == ';');
            // what it stores: an assignment's value, a method's arguments
            let from = match assigned_place(s, (i, e)) {
                Some(_) => scan_to(s, i, e, |k| s[k] == '=') + 1,
                None => i + bd.name.len(),
            };
            out.push((i, from, e));
            i = e.max(i + 1);
            continue;
        }
        i += bd.name.len();
    }
    // `*f(.., &mut v, ..) = x;`: a store through the borrow a call returns, which may be `v`
    let lent = Regex::new(&format!(r"&\s*mut\s+{}\b", regex::escape(&bd.name))).ok();
    let mut i = from;
    while i < to.min(s.len()) {
        if s[i] != '*' || !before_blank(s, i).is_none_or(|p| matches!(s[p], ';' | '{' | '}')) {
            i += 1;
            continue;
        }
        let mut j = skip_blank(s, i + 1);
        while j < to && (is_ident(s[j]) || s[j] == ':') {
            j += 1;
        }
        j = skip_blank(s, j);
        if s.get(j) == Some(&'<') {
            let cls = vec![Class::Code; s.len() - j];
            match skip_angle(&s[j..], &cls, 0) {
                Some(e) => j = skip_blank(s, j + e),
                None => {
                    i += 1;
                    continue;
                }
            }
        }
        if s.get(j) != Some(&'(') {
            i += 1;
            continue;
        }
        let Some(close) = close_of_at(s, j) else {
            i += 1;
            continue;
        };
        let eq = skip_blank(s, close + 1);
        if s.get(eq) == Some(&'=')
            && s.get(eq + 1) != Some(&'=')
            && lent
                .as_ref()
                .is_some_and(|r| r.is_match(&src.text(j, close)))
        {
            let e = scan_to(s, eq, to, |k| s[k] == ';');
            out.push((i, eq + 1, e));
            i = e.max(i + 1);
            continue;
        }
        i += 1;
    }
    out.sort();
    out
}

/// A token of a macro's matcher or invocation.
#[derive(Clone, Debug, PartialEq)]
enum Tok {
    Word(String),
    Punct(char),
    Lit(String),
    Group(char, Vec<Tok>),
}

impl Tok {
    fn text(&self) -> String {
        match self {
            Tok::Word(w) | Tok::Lit(w) => w.clone(),
            Tok::Punct(c) => c.to_string(),
            Tok::Group(d, inner) => {
                let close = match d {
                    '(' => ')',
                    '[' => ']',
                    _ => '}',
                };
                format!("{d}{}{close}", toks_text(inner))
            }
        }
    }
}

fn toks_text(t: &[Tok]) -> String {
    t.iter().map(Tok::text).collect::<Vec<_>>().join(" ")
}

/// The tokens of `text`: comments skipped, literals whole, brackets as groups.
fn tokens(text: &str) -> Vec<Tok> {
    fn go(chars: &[char], cls: &[Class], i: &mut usize, close: Option<char>) -> Vec<Tok> {
        let mut out = Vec::new();
        while *i < chars.len() {
            let c = chars[*i];
            match cls[*i] {
                Class::Comment => {
                    *i += 1;
                    continue;
                }
                Class::Literal => {
                    let s = *i;
                    while *i < chars.len() && cls[*i] == Class::Literal {
                        *i += 1;
                    }
                    out.push(Tok::Lit(chars[s..*i].iter().collect()));
                    continue;
                }
                Class::Code => {}
            }
            if c.is_whitespace() {
                *i += 1;
                continue;
            }
            if Some(c) == close {
                *i += 1;
                return out;
            }
            let s = *i;
            match c {
                '(' | '[' | '{' => {
                    let cl = match c {
                        '(' => ')',
                        '[' => ']',
                        _ => '}',
                    };
                    *i += 1;
                    let inner = go(chars, cls, i, Some(cl));
                    out.push(Tok::Group(c, inner));
                }
                _ if is_ident(c) => {
                    while *i < chars.len() && is_ident(chars[*i]) && cls[*i] == Class::Code {
                        *i += 1;
                    }
                    let w: String = chars[s..*i].iter().collect();
                    out.push(if c.is_ascii_digit() {
                        Tok::Lit(w)
                    } else {
                        Tok::Word(w)
                    });
                }
                _ => {
                    out.push(Tok::Punct(c));
                    *i += 1;
                }
            }
        }
        out
    }
    let chars: Vec<char> = text.chars().collect();
    let cls = classify(text);
    let mut i = 0;
    go(&chars, &cls, &mut i, None)
}

/// The metavariables a rule's matcher binds, and the tokens each binds.
type Metavars = Vec<(String, Vec<Tok>)>;

/// An element of a macro rule's matcher.
#[derive(Clone, Debug)]
enum El {
    Lit(Tok),
    /// `$name:fragment`
    Var(String, String),
    Group(char, Vec<El>),
    /// `$( .. ) sep? op`: the elements repeated, the separator, and `*`, `+` or `?`
    Rep(Vec<El>, Option<Tok>, char),
}

/// A matcher's elements; None for one not read (a `$` followed by anything else).
fn matcher_els(toks: &[Tok]) -> Option<Vec<El>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < toks.len() {
        match &toks[i] {
            Tok::Punct('$') => match (toks.get(i + 1), toks.get(i + 2), toks.get(i + 3)) {
                (Some(Tok::Word(n)), Some(Tok::Punct(':')), Some(Tok::Word(f))) => {
                    out.push(El::Var(n.clone(), f.clone()));
                    i += 4;
                    continue;
                }
                // a repetition: `$( .. ),*`, `$( .. )+`, `$( .. )?`
                (Some(Tok::Group('(', inner)), Some(a), b) => {
                    let inner = matcher_els(inner)?;
                    let op = |t: &Tok| match t {
                        Tok::Punct(c @ ('*' | '+' | '?')) => Some(*c),
                        _ => None,
                    };
                    match (op(a), b.and_then(op)) {
                        (Some(o), _) => {
                            out.push(El::Rep(inner, None, o));
                            i += 3;
                        }
                        (None, Some(o)) => {
                            out.push(El::Rep(inner, Some(a.clone()), o));
                            i += 4;
                        }
                        _ => return None,
                    }
                    continue;
                }
                _ => return None,
            },
            Tok::Group(d, inner) => out.push(El::Group(*d, matcher_els(inner)?)),
            t => out.push(El::Lit(t.clone())),
        }
        i += 1;
    }
    Some(out)
}

/// Whether tokens `t` are a fragment of kind `frag` (`ident`, `literal`, `expr`, ..): an
/// expression, type or path runs to the next `,`, `;` or `=>`.
fn frag_ok(frag: &str, t: &[Tok]) -> bool {
    match frag {
        "ident" => matches!(t, [Tok::Word(w)] if w != "_"),
        "literal" => {
            matches!(t, [Tok::Lit(_)] | [Tok::Punct('-'), Tok::Lit(_)])
                || matches!(t, [Tok::Word(w)] if w == "true" || w == "false")
        }
        "lifetime" => matches!(t, [Tok::Punct('\''), Tok::Word(_)]),
        "tt" => t.len() == 1,
        "block" => matches!(t, [Tok::Group('{', _)]),
        _ => {
            !t.is_empty()
                && !t.iter().enumerate().any(|(k, x)| {
                    matches!(x, Tok::Punct(';' | ','))
                        || (matches!(x, Tok::Punct('='))
                            && matches!(t.get(k + 1), Some(Tok::Punct('>'))))
                })
        }
    }
}

/// Matches an invocation's tokens against a matcher, binding its metavariables.
fn match_els(p: &[El], t: &[Tok], out: &mut Metavars) -> bool {
    let Some(first) = p.first() else {
        return t.is_empty();
    };
    match first {
        El::Lit(x) => t.first() == Some(x) && match_els(&p[1..], &t[1..], out),
        El::Group(d, inner) => {
            let n = out.len();
            let ok = matches!(t.first(), Some(Tok::Group(d2, sub)) if d2 == d && match_els(inner, sub, out))
                && match_els(&p[1..], &t[1..], out);
            if !ok {
                out.truncate(n);
            }
            ok
        }
        // a repetition: its elements `n` times (separated), then the rest
        El::Rep(inner, sep, op) => {
            let (min, max) = match op {
                '?' => (0, 1),
                '+' => (1, t.len().max(1)),
                _ => (0, t.len()),
            };
            for n in (min..=max).rev() {
                let mut expanded: Vec<El> = Vec::new();
                for k in 0..n {
                    if k > 0
                        && let Some(sp) = sep
                    {
                        expanded.push(El::Lit(sp.clone()));
                    }
                    expanded.extend(inner.iter().cloned());
                }
                expanded.extend(p[1..].iter().cloned());
                let m = out.len();
                if match_els(&expanded, t, out) {
                    return true;
                }
                out.truncate(m);
            }
            false
        }
        El::Var(name, frag) => {
            let max = if matches!(frag.as_str(), "ident" | "tt" | "block") {
                t.len().min(1)
            } else {
                t.len()
            };
            for k in (1..=max).rev() {
                if !frag_ok(frag, &t[..k]) {
                    continue;
                }
                let n = out.len();
                out.push((name.clone(), t[..k].to_vec()));
                if match_els(&p[1..], &t[k..], out) {
                    return true;
                }
                out.truncate(n);
            }
            frag == "vis" && match_els(&p[1..], t, out)
        }
    }
}

/// A rule of a `macro_rules!`: its matcher (None when not read) and its transcriber's extent in
/// `code`, inside its brackets.
struct Rule {
    matcher: Option<Vec<El>>,
    body: (usize, usize),
}

fn rules_of(src: &Source, m: &Item) -> Vec<Rule> {
    let s = &src.code;
    let (b, e) = src.span(m);
    let mut out = Vec::new();
    let mut k = b + 1;
    while k < e {
        k = skip_blank(s, k);
        if !matches!(s.get(k), Some('(' | '[' | '{')) {
            break;
        }
        let Some(mc) = close_of_at(s, k) else { break };
        let arrow = skip_blank(s, mc + 1);
        if !(s.get(arrow) == Some(&'=') && s.get(arrow + 1) == Some(&'>')) {
            break;
        }
        let t = skip_blank(s, arrow + 2);
        let Some(tc) = close_of_at(s, t) else { break };
        out.push(Rule {
            matcher: matcher_els(&tokens(&src.orig(k + 1, mc))),
            body: (t + 1, tc),
        });
        k = skip_blank(s, tc + 1);
        if s.get(k) == Some(&';') {
            k += 1;
        }
    }
    out
}

/// The arguments of the macro invocation at `at`: its name and the tokens inside its brackets.
fn invocation_args(src: &Source, at: (usize, usize)) -> Option<(String, Vec<Tok>)> {
    let (name, text) = invocation_text(src, at)?;
    let toks = tokens(&text);
    let k = toks.iter().position(|t| *t == Tok::Punct('!'))?;
    match toks.get(k + 1)? {
        Tok::Group(_, inner) => Some((name, inner.clone())),
        _ => None,
    }
}

/// The rule of `macro_rules! m` the invocation `args` matches (the first that does, as rustc
/// picks it), with the metavariables it binds; None when a rule before it is not read.
fn rule_for(src: &Source, m: &Item, args: &[Tok]) -> Option<(Rule, Metavars)> {
    for r in rules_of(src, m) {
        let mut out = Vec::new();
        if match_els(r.matcher.as_ref()?, args, &mut out) {
            return Some((r, out));
        }
    }
    None
}

/// What the invocation at `at` of the file's `macro_rules!` expands to: the transcriber of the
/// rule it matches with its metavariables replaced; None when that is not known.
fn expansion(src: &Source, at: (usize, usize)) -> Option<String> {
    // (an invocation is cited by every step of long instantiation chains: once per source)
    thread_local! {
        static EXPANSIONS: std::cell::RefCell<HashMap<(usize, usize, usize), Option<String>>> =
            std::cell::RefCell::new(HashMap::new());
    }
    let key = (src as *const Source as usize, at.0, at.1);
    if let Some(e) = EXPANSIONS.with(|c| c.borrow().get(&key).cloned()) {
        return e;
    }
    let e = expansion_uncached(src, at);
    EXPANSIONS.with(|c| c.borrow_mut().insert(key, e.clone()));
    e
}

fn expansion_uncached(src: &Source, at: (usize, usize)) -> Option<String> {
    let (name, args) = invocation_args(src, at)?;
    let m = src
        .items
        .iter()
        .find(|i| i.kind == ItemKind::Macro && i.name == name)?;
    let (r, binds) = rule_for(src, m, &args)?;
    let mut text = src.orig(r.body.0, r.body.1);
    // longer names first (`$alg` before `$a`)
    let mut binds = binds;
    binds.sort_by_key(|(n, _)| std::cmp::Reverse(n.len()));
    for (n, t) in binds {
        text = text.replace(&format!("${n}"), &toks_text(&t));
    }
    Some(text)
}

thread_local! {
    /// Set by a check that could tell its position only within a range of identical candidates:
    /// invocations of one macro that make the same item as far as the context says.
    static RANGED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Which macro invocation makes an item: this one only, this one among others the context
/// cannot tell apart (a range), or another one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Pick {
    Exact,
    Range,
    No,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn items_and_their_names() {
        let src = Source::new(
            "impl<T: AsRef<[u8]>> Sealer<T> {\n    fn seal(&self) -> impl Fn() -> u8 {\n        || 1\n    }\n}\nimpl TryFrom<&PrivateKeyDer<'_>> for KeyPair {\n    fn try_from(k: &PrivateKeyDer) -> Self { todo!() }\n}\nstatic S: &'static str = \"fn x() {\";\nmacro_rules! m {\n    () => { fn inner() {} };\n}\n",
            true,
            false,
        );
        let at = |l, c| {
            src.enclosing((l, c), &[ItemKind::Fn, ItemKind::Static])
                .map(|i| i.name.clone())
        };
        assert_eq!(at(3, 8).as_deref(), Some("seal"));
        assert_eq!(at(7, 45).as_deref(), Some("try_from"));
        assert_eq!(at(9, 30).as_deref(), Some("S"));
        let imp = src.enclosing((3, 8), &[ItemKind::Impl]).unwrap();
        assert_eq!(imp.name, "Sealer");
        let tf = src.enclosing((7, 45), &[ItemKind::Impl]).unwrap();
        assert_eq!(
            (tf.name.as_str(), tf.trait_name.as_deref()),
            ("KeyPair", Some("TryFrom<&PrivateKeyDer>"))
        );
        assert!(src.enclosing((11, 12), &[ItemKind::Macro]).is_some());
        // a `where` clause on its own line (hpke's `impl<D> LabeledExpand for Hkdf<D>`)
        let w = Source::new(
            "impl<D> Expand for Hkdf<D>\nwhere\n    D: BlockSizeUser,\n{\n    fn f() {}\n}\n",
            true,
            false,
        );
        let imp = w.enclosing((5, 8), &[ItemKind::Impl]).unwrap();
        assert_eq!(
            (imp.name.as_str(), imp.trait_name.as_deref()),
            ("Hkdf", Some("Expand"))
        );
        assert!(src.enclosing((9, 30), &[ItemKind::Macro]).is_none());
    }

    #[test]
    fn the_item_a_context_names() {
        let i = in_item("<rcgen::KeyPair as core::convert::TryFrom<&rustls_pki_types::PrivateKeyDer<'_>>>::try_from").unwrap();
        assert_eq!(i.name, "try_from");
        assert_eq!(i.self_ty.as_deref(), Some("KeyPair"));
        assert_eq!(i.trait_name.as_deref(), Some("TryFrom<&PrivateKeyDer>"));
        let i = in_item("r1::Jar::<J>::seal::{closure#0}").unwrap();
        assert_eq!(
            (i.name.as_str(), i.self_ty.as_deref()),
            ("seal", Some("Jar"))
        );
        let i = in_item("v4_public::<impl rusty_paseto::core::Paseto<'_, V4, Public>>::try_sign")
            .unwrap();
        assert_eq!(
            (i.name.as_str(), i.self_ty.as_deref()),
            ("try_sign", Some("Paseto"))
        );
        let i = in_item("t1::xchacha").unwrap();
        assert_eq!((i.name.as_str(), i.self_ty), ("xchacha", None));
        assert!(same_trait("TryFrom", "TryFrom<&PrivateKeyDer>"));
        assert!(!same_trait("TryFrom<&[u8]>", "TryFrom<&PrivateKeyDer>"));
    }

    fn code_at(src: &str, needle: &str) -> bool {
        let (code, _) = lex(src);
        let line = src.lines().position(|l| l.contains(needle)).unwrap();
        let byte = src.lines().nth(line).unwrap().find(needle).unwrap();
        let col = src.lines().nth(line).unwrap()[..byte].chars().count();
        code[line][col] == Class::Code
    }

    #[test]
    fn lexer_classifies_literals_and_comments() {
        let src = "fn main() { let q = '\\''; let A = 1; let r = '\"'; let B = 2;\n let s = \"x\\\" C\"; let D = 3; let t = r#\"E\"# ; let F = 4;\n let l: &'static str = \"z\"; let G = 5; /* c /* n */ H */ let I = 6; let u = b'\\\\'; let J = 7; // K\n}";
        assert!(code_at(src, "A ="));
        assert!(code_at(src, "B ="));
        assert!(!code_at(src, "C\""));
        assert!(code_at(src, "D ="));
        assert!(!code_at(src, "E\""));
        assert!(code_at(src, "F ="));
        assert!(code_at(src, "G ="));
        assert!(!code_at(src, "H */"));
        assert!(code_at(src, "I ="));
        assert!(code_at(src, "J ="));
        assert!(!code_at(src, "K"));
    }

    fn generics_of(at: &str) -> Vec<String> {
        let s: Vec<char> = at.chars().collect();
        path_and_generics(&s, &classify(at)).unwrap().2
    }

    #[test]
    fn paths() {
        assert_eq!(
            path_at("Hmac::<Sha256>::new_from_slice(k)").unwrap().1,
            "new_from_slice"
        );
        assert_eq!(
            path_at("<Hmac<Sha256> as Mac>::new_from_slice(k)")
                .unwrap()
                .1,
            "new_from_slice"
        );
        assert_eq!(path_at("seal::<Aes256Gcm>(&k)").unwrap().1, "seal");
        assert_eq!(
            path_at("Vec::<u8>::new(); let h = Hmac::<Sha256>::new_from_slice(k)")
                .unwrap()
                .1,
            "new"
        );
        assert_eq!(
            path_at("ring::digest::SHA256.output_len()").unwrap().1,
            "SHA256"
        );
        assert_eq!(
            path_at("Foo::<[u8; 32], fn() -> u8>::bar()").unwrap().1,
            "bar"
        );
        assert_eq!(
            path_at("Hmac::<\n        Sha256,\n    >::new_from_slice(b)")
                .unwrap()
                .1,
            "new_from_slice"
        );
        assert_eq!(
            path_at("<sha2::Sha512 as Digest>\n        ::digest(b)")
                .unwrap()
                .1,
            "digest"
        );
        assert_eq!(
            path_at("hash(b);\n}\nfn x() { a::digest() }").unwrap().1,
            "hash"
        );
        assert_eq!(generics_of("Hmac::<sha2::Sha256>::new(k)"), vec!["sha2"]);
        assert_eq!(generics_of("SimpleHkdfExtract::<Kdf>::new(s)"), vec!["Kdf"]);
        assert_eq!(generics_of("Foo::<'static, [u8; 32]>::new(s)"), vec!["u8"]);
        // a crate named from the root
        assert_eq!(
            path_at("::sha2::Sha256::digest(d)").unwrap(),
            (vec!["sha2".into(), "Sha256".into()], "digest".into())
        );
    }

    #[test]
    fn raw_identifiers_are_read_without_their_prefix() {
        assert_eq!(path_at("Sha256::r#digest(b\"r\")").unwrap().1, "digest");
        assert_eq!(path_at("r#digest(b)").unwrap().1, "digest");
        assert_eq!(generics_of("Hmac::<r#Sha256>::new(k)"), vec!["Sha256"]);
        // `#digest` (a shifted position) is no path
        assert!(path_at("#digest(b)").is_none());
    }

    #[test]
    fn comments_between_path_segments_are_skipped() {
        assert_eq!(
            path_at("sha2::Sha256 // first\n        ::digest(d);")
                .unwrap()
                .1,
            "digest"
        );
        assert_eq!(
            path_at("sha2::/* the type */Sha256::digest(d)").unwrap().1,
            "digest"
        );
        // a comment in the generic arguments names no type
        assert_eq!(
            generics_of("Hmac::<Sha256 /* not Sha1 */>::new(k)"),
            vec!["Sha256"]
        );
        // a literal is not skipped: the path ends before it
        assert_eq!(
            path_at("sha2::Sha256 \"x\" ::digest(d)").unwrap().1,
            "Sha256"
        );
    }

    fn col(src: &Source, line: usize, needle: &str) -> usize {
        let l = &src.lines[line - 1];
        l[..l.find(needle).unwrap()].chars().count()
    }

    #[test]
    fn a_token_may_follow_a_single_colon_not_a_path_separator() {
        let src = Source::new(
            "let w = W { n:Sha256::digest(data).len() };\nlet h = sha2::Sha256::digest(d);\nlet g = sha2::\n    Sha256::digest(d);\nlet r = Sha256::r#digest(d);\nlet c = sha2:: /* c */ Sha256::digest(d);",
            true,
            false,
        );
        assert!(token_start(&src, 1, col(&src, 1, "Sha256")));
        assert!(token_start(&src, 2, col(&src, 2, "sha2")));
        assert!(!token_start(&src, 2, col(&src, 2, "Sha256")));
        assert!(!token_start(&src, 2, col(&src, 2, "digest")));
        assert!(!token_start(&src, 2, col(&src, 2, "ha2")));
        // after `::` on the line before, or after a comment
        assert!(!token_start(&src, 4, col(&src, 4, "Sha256")));
        assert!(!token_start(&src, 6, col(&src, 6, "Sha256")));
        // the identifier of `r#digest` is not a token of its own
        assert!(!token_start(&src, 5, col(&src, 5, "digest")));
        assert!(token_start(&src, 5, col(&src, 5, "Sha256")));
    }

    #[test]
    fn tags_are_read_from_the_head_of_the_context_only() {
        let c = split_context(
            "[reachable] [call] in p3::comment; use: digest; line: `let d = Sha256::digest(data); // see [derive Foo] and [macro bar!]`; code: `Sha256::digest`",
        );
        assert_eq!(c.tags, "[reachable] [call] ");
        assert!(!re!(r"\[macro ([\w:]+!)\]").is_match(c.tags));
        assert!(!re!(r"\[derive ([\w:]+)\]").is_match(c.tags));
        assert_eq!(c.details, "[reachable] [call] in p3::comment; use: digest");
        assert_eq!(
            c.line,
            Some("let d = Sha256::digest(data); // see [derive Foo] and [macro bar!]")
        );
        assert_eq!(c.code, Some("Sha256::digest"));
        let c = split_context(
            "[present] [call] [macro sha2::m!] in x; part of SHA-256; line: `m!(a); // ; part of MD5`",
        );
        assert_eq!(c.tags, "[present] [call] [macro sha2::m!] ");
        assert_eq!(
            &re!(r"; part of ([^\s;(]+)").captures(c.details).unwrap()[1],
            "SHA-256"
        );
        assert_eq!(c.code, None);
    }

    #[test]
    fn crlf_lines_compare_without_the_carriage_return() {
        let lock = "[[package]]\r\nname = \"sha2\"\r\nversion = \"0.10.9\"\r\n";
        let src = Source::new(lock, false, false);
        assert_eq!(src.lines[1], "name = \"sha2\"");
        let ctx = "[manifest] locked sha2 0.10.9; reached via p -> sha2";
        let c = "pkg:cargo/sha2@0.10.9";
        assert_eq!(check_lock(&src.lines, 2, 0, "sha2", ctx, c), Ok(()));
        assert!(check_lock(&src.lines, 2, 1, "sha2", ctx, c).is_err());
        assert!(check_lock(&src.lines, 3, 0, "sha2", ctx, c).is_err());
        assert!(
            check_lock(
                &src.lines,
                2,
                0,
                "sha2",
                "[manifest] locked sha2 0.11.0; x",
                c
            )
            .is_err()
        );
        assert!(check_lock(&src.lines, 2, 0, "sha2", "[manifest] something", c).is_err());
        // the evidence of another version of the package, or of another package
        assert!(check_lock(&src.lines, 2, 0, "sha2", ctx, "pkg:cargo/sha2@0.11.0").is_err());
        assert!(check_lock(&src.lines, 2, 0, "sha2", ctx, "pkg:cargo/sha1@0.10.6").is_err());
        let rs = Source::new(
            "use sha2::Sha256;\r\nfn f() { Sha256::digest(b) }\r\n",
            true,
            false,
        );
        assert_eq!(rs.lines[1], "fn f() { Sha256::digest(b) }");
        assert_eq!(rs.class[1].len(), rs.lines[1].chars().count());
        let toml = Source::new(
            "[package]\r\nname = \"p\"\r\n[dependencies]\r\nsha2 = \"0.10\"\r\n",
            false,
            true,
        );
        assert_eq!(
            check_toml(
                &toml.toml,
                &toml.lines[3],
                4,
                0,
                "sha2",
                "[manifest] declared by p (dependencies)",
                "pkg:cargo/sha2@0.10.9"
            ),
            Ok(())
        );
    }

    const MANIFEST: &str = r#"[package]
name = "t4"
version = "0.1.0"
links = "native"

# sha1 is mentioned in this comment
[dependencies]
hashing = { package = "sha2", version = "0.10" }
md5.version = "0.7"
"sha1" = "0.10"
x = """
[dev-dependencies]
ring = 1
"""

[dependencies.hmac]
version = "0.12"

[ target . 'cfg(target_os="linux")' . dependencies ]
blake3 = "1"

[dev-dependencies]
hmac = "0.12"

[build-dependencies]
md5 = "0.7"

[workspace.dependencies]
ring = "0.17"
"#;

    /// The package each key of MANIFEST declares, as the CBOM names it.
    fn component(symbol: &str) -> &'static str {
        match symbol {
            "hashing" => "pkg:cargo/sha2@0.10.9",
            "md5" => "pkg:cargo/md5@0.7.0",
            "sha1" => "pkg:cargo/sha1@0.10.6",
            "hmac" => "pkg:cargo/hmac@0.12.1",
            "blake3" => "pkg:cargo/blake3@1.8.5",
            "ring" => "pkg:cargo/ring@0.17.14",
            "links" => "pkg:cargo/t4@0.1.0",
            _ => "pkg:cargo/other@1.0.0",
        }
    }

    fn toml_check(line: usize, col: usize, symbol: &str, ctx: &str) -> Result<(), String> {
        toml_check_of(line, col, symbol, ctx, component(symbol))
    }

    fn toml_check_of(
        line: usize,
        col: usize,
        symbol: &str,
        ctx: &str,
        component: &str,
    ) -> Result<(), String> {
        let src = Source::new(MANIFEST, false, true);
        check_toml(
            &src.toml,
            &src.lines[line - 1],
            line,
            col,
            symbol,
            ctx,
            component,
        )
    }

    #[test]
    fn manifest_keys_are_read_with_their_tables() {
        let dep = "[manifest] declared by t4 (dependencies)";
        let dev = "[manifest] declared by t4 (dev-dependencies)";
        let build = "[manifest] declared by t4 (build-dependencies); default-features = false";
        // every form the generator cites
        assert_eq!(toml_check(8, 0, "hashing", dep), Ok(()));
        assert_eq!(toml_check(9, 0, "md5", dep), Ok(()));
        assert_eq!(toml_check(10, 0, "sha1", dep), Ok(()));
        assert_eq!(toml_check(16, 14, "hmac", dep), Ok(()));
        assert_eq!(toml_check(20, 0, "blake3", dep), Ok(()));
        assert_eq!(toml_check(23, 0, "hmac", dev), Ok(()));
        assert_eq!(toml_check(26, 0, "md5", build), Ok(()));
        // a quoted key at its opening quote only
        assert!(toml_check(10, 1, "sha1", dep).is_err());
        // a comment, a multi-line string, a value, keys inside a dependency's table
        assert!(toml_check(6, 2, "sha1", dep).is_err());
        assert!(toml_check(12, 0, "dev-dependencies", dep).is_err());
        assert!(toml_check(13, 0, "ring", dev).is_err());
        assert!(toml_check(8, 22, "sha2", dep).is_err());
        assert!(toml_check(8, 12, "package", dep).is_err());
        assert!(toml_check(9, 4, "version", dep).is_err());
        // positions swapped between tables
        assert!(toml_check(23, 0, "hmac", dep).is_err());
        assert!(toml_check(16, 14, "hmac", dev).is_err());
        assert!(toml_check(26, 0, "md5", dep).is_err());
        assert!(toml_check(9, 0, "md5", build).is_err());
        // [workspace.dependencies] is not where a member declares a dependency
        assert!(toml_check(29, 0, "ring", dep).is_err());
        // another package's manifest
        assert!(toml_check(8, 0, "hashing", "[manifest] declared by t5 (dependencies)").is_err());
        // links
        let links =
            "[manifest] native library `native`; code behind the FFI boundary is not analysed";
        assert_eq!(toml_check(4, 0, "links", links), Ok(()));
        assert!(toml_check(4, 0, "links", "[manifest] native library `other`; x").is_err());
        assert!(toml_check(4, 0, "links", "[manifest] unheard of").is_err());
        assert!(toml_check_of(4, 0, "links", links, "pkg:cargo/ring@0.17.14").is_err());
        // a key declaring another package, or a version the requirement excludes
        assert!(toml_check_of(10, 0, "sha1", dep, "pkg:cargo/ring@0.17.14").is_err());
        assert!(toml_check_of(8, 0, "hashing", dep, "pkg:cargo/sha2@0.11.0").is_err());
        assert!(toml_check_of(16, 14, "hmac", dep, "pkg:cargo/hmac@0.13.0").is_err());
        assert!(toml_check_of(9, 0, "md5", dep, "pkg:cargo/md5@0.8.0").is_err());
        // a root dotted key into the table
        let root = Source::new(
            "dependencies.zeta = \"1\"\n[package]\nname = \"t4\"\n",
            false,
            true,
        );
        assert_eq!(
            check_toml(
                &root.toml,
                &root.lines[0],
                1,
                13,
                "zeta",
                dep,
                "pkg:cargo/zeta@1.2.0"
            ),
            Ok(())
        );
    }

    #[test]
    fn merged_parents_are_strictly_more_specific_names() {
        assert!(extends("Argon2id-19456-2-1", "Argon2", Some("Argon2")));
        assert!(extends(
            "PBKDF2-SHA-256-1000-32",
            "PBKDF2-SHA-256",
            Some("PBKDF2")
        ));
        assert!(!extends("SHA-256", "SHA-256", Some("SHA-2")));
        assert!(!extends("SHA-2560", "SHA-256", Some("SHA-2")));
        assert!(!extends("Argon2id-19456-2-1", "Argon2", Some("Argon")));
        assert!(!extends("SHA-512", "SHA-256", Some("SHA-2")));
    }

    #[test]
    fn imports_of_one_name_from_several_crates() {
        let src = Source::new(
            "use sha2::Digest;\n#[cfg(feature = \"legacy\")]\nuse sha1::Sha1 as Hasher;\n#[cfg(not(feature = \"legacy\"))]\nuse sha2::Sha256 as Hasher;\nuse aes_gcm::{aead::{KeyInit, Aead as A}, Aes256Gcm, self as gcm};\nuse crate::local::Thing;\nextern crate ring as r;\nuse other::*;\nfn f<D: Digest, const N: usize>() {}\nstruct Wrapper;",
            true,
            false,
        );
        let roots =
            |n: &str| import_roots(&src.binds, n).map(|r| r.into_iter().collect::<Vec<_>>());
        assert_eq!(roots("Hasher"), Some(vec!["sha1".into(), "sha2".into()]));
        assert_eq!(roots("Aes256Gcm"), Some(vec!["aes_gcm".into()]));
        assert_eq!(roots("KeyInit"), Some(vec!["aes_gcm".into()]));
        assert_eq!(roots("A"), Some(vec!["aes_gcm".into()]));
        assert_eq!(roots("gcm"), Some(vec!["aes_gcm".into()]));
        assert_eq!(roots("r"), Some(vec!["ring".into()]));
        assert_eq!(roots("Thing"), None);
        // not imported: the crate of that name, if any
        assert_eq!(roots("sha2"), Some(vec!["sha2".into()]));
        let renamed = |ident: &str| {
            src.binds
                .iter()
                .filter(|b| b.path.last().is_some_and(|l| l == ident) && b.name != ident)
                .map(|b| b.name.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(renamed("Sha256"), vec!["Hasher"]);
        assert_eq!(renamed("Aead"), vec!["A"]);
        for local in ["D", "N", "Wrapper"] {
            assert!(src.locals.contains(local), "{local}");
        }
        assert!(!src.locals.contains("Hasher"));
    }

    /// The first line of the binding of `name` read where `at` is written (0 for a parameter).
    fn bound_line(src: &Source, at: &str, name: &str) -> Option<usize> {
        let l = src.lines.iter().position(|l| l.contains(at))? + 1;
        let c = src.lines[l - 1].find(at)?;
        match binding(src, src.idx((l, c)), name)? {
            Bound::Let { first, .. } => Some(first),
            Bound::Param { .. } => Some(0),
            _ => None,
        }
    }

    #[test]
    fn bindings_are_read_in_their_scope() {
        let src = Source::new(
            "fn main() {\n    let h = a;\n    {\n        let h = b;\n        h(1); // in\n    }\n    h(2); // out\n    fn inner() {\n        let g = c;\n        g(3); // inner\n    }\n    let g = d;\n    g(4); // outer g\n    let f = e;\n    let f = f;\n    f(5); // copy\n    let k = |x: u8| x;\n    k(6); // closure\n}\n",
            true,
            false,
        );
        assert_eq!(bound_line(&src, "h(1)", "h"), Some(4));
        assert_eq!(bound_line(&src, "h(2)", "h"), Some(2));
        assert_eq!(bound_line(&src, "g(3)", "g"), Some(9));
        assert_eq!(bound_line(&src, "g(4)", "g"), Some(12));
        assert_eq!(bound_line(&src, "f(5)", "f"), Some(15));
        // the self-copy's own value: the `f` before it
        let l15 = src.lines[14].find("= f").unwrap() + 2;
        assert_eq!(
            match binding(&src, src.idx((15, l15)), "f") {
                Some(Bound::Let { first, .. }) => Some(first),
                _ => None,
            },
            Some(14)
        );
        // a closure's parameter is visible in its body only
        let x = src.lines[16].rfind('x').unwrap();
        assert!(matches!(
            binding(&src, src.idx((17, x)), "x"),
            Some(Bound::ClosureParam)
        ));
        assert!(binding(&src, src.idx((18, 4)), "x").is_none());
    }

    #[test]
    fn a_macro_invocation_matches_its_first_rule() {
        let src = Source::new(
            "macro_rules! sel {\n    ($m:ident, 256) => { mod $m { fn a() {} } };\n    ($m:ident, 384) => { mod $m { fn b() {} } };\n}\nmacro_rules! semi {\n    ($f:ident; $alg:ident) => { fn $f() { x::$alg } };\n}\nsel!(gamma, 384);\nsemi!(s1; SHA512);\n",
            true,
            false,
        );
        let m = src.items.iter().find(|i| i.name == "sel").unwrap();
        let (_, args) = invocation_args(&src, (8, 0)).unwrap();
        let (r, binds) = rule_for(&src, m, &args).unwrap();
        assert_eq!(src.pos(r.body.0).0, 3);
        assert_eq!(binds[0].0, "m");
        let m = src.items.iter().find(|i| i.name == "semi").unwrap();
        let (_, args) = invocation_args(&src, (9, 0)).unwrap();
        let (_, binds) = rule_for(&src, m, &args).unwrap();
        assert_eq!(
            binds
                .iter()
                .map(|(n, t)| format!("{n}={}", toks_text(t)))
                .collect::<Vec<_>>(),
            ["f=s1", "alg=SHA512"]
        );
        assert!(
            expansion(&src, (9, 0))
                .unwrap()
                .contains("fn s1() { x::SHA512 }")
        );
    }

    #[test]
    fn closures_have_extents() {
        let s: Vec<char> = "run2(|x| a(x).len(), move |y| { b(y) }, async move |z| c(z));"
            .chars()
            .collect();
        let text: String = s.iter().collect();
        let first = text.find('|').unwrap();
        let (a, b) = closure_span(&s, first).unwrap();
        assert_eq!(&text[a..b], "|x| a(x).len()");
        let mv = text.find("move |y|").unwrap();
        let (a, b) = closure_span(&s, mv).unwrap();
        assert_eq!(&text[a..b], "move |y| { b(y) }");
        let body = text.find("c(z)").unwrap();
        let (a, b) = async_body_at(&s, body).unwrap();
        assert_eq!(&text[a..b], "c(z)");
        assert!(async_body_at(&s, text.find("a(x)").unwrap()).is_none());
    }
}
