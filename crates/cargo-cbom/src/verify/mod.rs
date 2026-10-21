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
//!   (..)`, `let Two { h, l } = ..`, also over a variable bound by a `let` of the whole value and
//!   not stored into after, `let (_, (_, a)) = t;`, and after a rest, `let [_, .., c] = ..`;
//!   both `#[cfg(..)]` siblings `let a = ..;`), the stores into them that may reach the call (an
//!   assignment, one whose value reads the variable keeping the value before, a `mem::swap` /
//!   `mem::replace` with another argument in a block around the read, of the variable or of the
//!   field read, `mem::swap(&mut s.a, &mut s.b)`, one on some ways only as a value beside the one
//!   before, a store through another binding that may point to the variable: `let r = &mut a; *r
//!   = v`, reborrows, copies, holders, `*f(&mut v) = x`, a method's returned borrow, `*s.a_mut()
//!   = x` into the field it borrows), a store or a call of the file's function that replaces the
//!   place read on every way to it; an `Option` combinator's function (`o.map_or(&SHA512, |_|
//!   &SHA1)`, `o.map(fixed)`: the default and the function's value, not `o`'s unless the closure
//!   or the file's function reads its parameter); a `replace` or `take` method's value is the
//!   receiver's old one, not its argument; the file's functions and methods it calls, the method of a
//!   value of one of the file's types; the statics, consts and `const fn`s named, projected
//!   through the fields, tuple elements and array elements read (`TABLE[i].h`, `NESTED.inner.h`,
//!   `PAIRS[i].1`, `NAMED[i].1.h` with a literal beside, through a constant an initializer names,
//!   `[BASE, ..]`, a struct update's base `..BASE`, a `const fn`'s parameter it returns, a table
//!   iterated, `for c in TABLE.iter()`), also of other files and packages of the build (by the
//!   module path written, glob imports and `pub use` re-exports, glob ones too, a dependency the
//!   manifest renames; a one-letter name is a type parameter only when no path or `use` gives it;
//!   one not found in a package at hand names nothing); an instance's associated constant
//!   (`T::ALG` in `hash_c::<CFast>`: CFast's, else the trait's default); an index (`[i]`) is no
//!   value read. A call reading a value from elsewhere (a parameter, a variable lent to a call
//!   not followed, a field a method sets) has no claim "in the arguments" of a descriptor its
//!   code does not name; a constant of a crate whose sources are not at hand: named in the
//!   function at least.
//!   No other descriptor of the asset's primitive (nor a type the knowledge base gives one) is
//!   read instead. A claim that the values found are all (no unknown beside them) is held to a
//!   store through a pointer that replaces the place on every way to the call; a member found
//!   beside others not followed may be the value before it; a container's element labelled
//!   `member: container, possible` may be any the container holds (R4.3: one place), whatever a
//!   store into an element replaced;
//! - a member reaching the call from another function (`member: object`, `caller`, `fixed`,
//!   `dyn`, `container`, and `type-join`, `impl` at a call reading no field): where the argument
//!   carrying the algorithm holds no value from elsewhere (a parameter, a variable lent to a
//!   call not followed, a constant of a crate not at hand, a static the program may change), it
//!   names no other descriptor of the primitive (nor a type the knowledge base gives one)
//!   instead (a variable lent as `&mut` into a local binding is lent to code not followed only
//!   when that binding is a method's receiver or a call's argument: stores through it are
//!   followed); a witness function (`member: object, from F`, `caller, passed by F`, `impl,
//!   possible (what F writes)`, `type-join, possible (a value F stores ..)`) of the build's own
//!   packages, not made by the compiler, exists (`<T as Tr>::m`, `Tr::m for T`: T's impl of Tr,
//!   or the trait's default body where T's impl writes no `m`) and can give X: its body names
//!   X, or reads a parameter that can hold it (not an integer, a string, bytes), or, returning or
//!   writing the object, has a result or a `&mut` parameter that can (a writer not replacing what
//!   it writes, on every way, with other descriptors only; any writer of the object, for a
//!   member beside others not followed);
//! - a static table's member ("one of the N in `T`", "stored in `static T`", `member: table`,
//!   `member: static`) is held by the static or const `T` of the package (the fields read, where
//!   the context reads some), and, where the argument carrying the algorithm reads no value from
//!   elsewhere, that code reads `T` and, through the fields it reads, X; a coercion ("`T` is
//!   coerced to `dyn Tr` at F:L") is a pointer made of a `T` (or of a variable bound to one, a
//!   parameter declared of `T` or of a type parameter of its function, a type parameter's value
//!   in a generic function) on that line that becomes an object of `Tr`, or of a trait whose
//!   supertraits include `Tr`, there: by the innermost context it is in (an `as` cast after it,
//!   the parameter of the function it is passed to, also another crate's, the field of the
//!   struct literal or of a field assignment, the field of the file's tuple struct or enum
//!   variant constructed, the variable whose method stores it, the annotation of the `let`,
//!   `static` or `const` whose value, tuple element or array element it is, a closure's return
//!   annotation, the return type of the function whose tail or `return` it is; through blocks'
//!   tails, the file's type aliases and traits imported under another name), also a field of
//!   `self` declared of `T` (`&self.t`), a box's contents (`&*b`), and a closure's parameter
//!   where `T` is named on the line before the closure; in a static's item exactly when the
//!   detail says "in a static";
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
//!   field's declared type, a tuple's element, a function's or method's return type, a derived
//!   `T::default()`, `vec![..]`'s and an array literal's elements, `Some(..)`, through
//!   parentheses and the file's type aliases) is of
//!   the chain's type, or of one implementing the chain's trait; a generic function's instance
//!   (`pass::<A>`) is called with those type arguments, written or given by an argument of a
//!   type of the file (`pass(&B, ..)` is `pass::<B>`); a vtable's detail cites the coercion's
//!   expression from its first token (a cast to a pointer, not `as fn(..)`), also a value made
//!   an object of the method's trait by a function's parameter (`up_dyn(&mut a1)`, a default
//!   body only for a type whose impl does not write it); an `async fn`'s body (`f::{closure#0}`)
//!   is cited on a line calling `f`, or where the future is polled (`as `poll``); a call a macro
//!   invoked in the function
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
//! true, and so is a shifted instantiation detail that lands on another call of the method by the
//! same caller on a value whose type the code says is the instance's (`a2.ext()` with `a2: E2`
//! beside `E2.ext()`): counted apart and printed (`AS TRUE`), not hidden.
//!
//! Known limits:
//! - A cell handed to a function by a shared borrow (`set(&c)` with `fn set(c: &Cell<A>)`,
//!   `RefCell`, `Mutex`) is read as its initializer: stores through it are not followed, so a
//!   claim that the function's value is the only one is rejected (R4.12).
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
//! - Coercions not read: a `match` arm whose type only another arm gives (`E::B =>
//!   Box::new(U)` with `E::A(p) => p`); the closure-parameter rule takes the type named on the
//!   line before the closure for the parameter's.
//! - A receiver whose type the code says only through an `if`/`match` block's value, or a field
//!   of a generic struct whose type is a type parameter, is not typed (a chain moved onto it is
//!   accepted); a generic struct receiver's type arguments are not compared.
//! - Correct positions still rejected: a store through an `Option` holder re-pointed before the
//!   write (`o = Some(&mut g); if let Some(r) = o { *r = v }`), a write through a holder after a
//!   chain of reborrows; a `thread_local!` declared inside a function; a default body run through
//!   `Option::map(Trait::m)`; nested closures of a generic function instantiated twice.
//! - A store through a pointer a struct pattern binds (`let S { a, .. } = &mut s; *a = v`) or a
//!   `Box` holding the pointer is a possible store: the value before is still accepted.
//! - `#[cfg(..)]` is not evaluated (both `#[cfg]` sibling `let`s are read). A shifted position that lands on an identical line that the
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

mod check;
mod files;
mod lex;
mod macros;
mod manifest;
mod members;
mod reads;
mod source;
mod stores;
mod types;

use lex::*;
use macros::*;
use manifest::*;
use reads::*;
use source::*;
use stores::*;
use types::*;

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
        TYPED.with(|t| t.borrow_mut().clear());
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
                    TYPED.with(|t| t.borrow_mut().clear());
                    let ok = files
                        .check_with(i, o.line, o.offset, Some(&shifted))
                        .is_ok();
                    if !ok || RANGED.with(|r| r.get()) {
                        caught += 1;
                    } else if m[0].starts_with("coerced to")
                        || TYPED.with(|t| t.borrow().iter().any(|p| p == part))
                    {
                        // the shifted line coerces the type to the trait too (a value of the type
                        // becomes an object of that trait there, as `check_coercions` reads it),
                        // or the caller calls the method there too on a value the code says is
                        // of the instance's type (`E2.ext()` below `a2.ext()`, `a2` an `E2`):
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
                     more landed on another coercion of the same type or call of the same \
                     instance, as true)"
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

/// The parts of an occurrence's context: the leading `[..]` tags, the details, and the source
/// line and text the generator recorded last.
struct Ctx<'a> {
    tags: &'a str,
    details: &'a str,
    line: Option<&'a str>,
    code: Option<&'a str>,
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

/// A `use` or `extern crate` item, in a source with comments and literals blanked.
static USE_ITEM: std::sync::LazyLock<Regex> =
    std::sync::LazyLock::new(|| Regex::new(r"(?s)\b(?:use|extern\s+crate)\s[^;]*;").unwrap());

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

/// What a name read at `at` (an index in `code`) is.
enum Found {
    /// bound in the function around it (the nearest binding whose scope holds it)
    Bind(Bind),
    /// a parameter of the function around it, by the function's name
    Param(String),
    /// a static or const (by its index in `items`): the function's own first
    Item(usize),
}

/// A function's signature as written: its type parameters, its parameters (pattern, type; a
/// method's receiver as `self`, of type `Self`) and its return type.
struct FnSig {
    generics: Vec<String>,
    params: Vec<(String, String)>,
    ret: Option<String>,
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
    /// (an input) the claim's members are elements of a container, possible (`member:
    /// container, possible`): one container's elements are one place (R4.3), so a store into an
    /// element (`v[0] = x`) does not replace what the container's other stores and its literal
    /// put there
    smashed: bool,
    /// (an input) the type arguments of the generic function's instance the code is in (`T` ->
    /// `ilib::CFast` in `hash_c::<ilib::CFast>`)
    inst: Vec<(String, String)>,
    /// the associated items of those types it reads (`T::ALG`: `(ilib::CFast, ALG)`), which
    /// `Files::resolve_assoc` reads: the type's impl's, or the trait's default
    assoc: Vec<(String, String)>,
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

/// Methods of the standard library's containers that put their arguments in them.
const CONTAINER_STORES: &[&str] = &[
    "push",
    "push_back",
    "push_front",
    "insert",
    "replace",
    "get_or_insert",
];

/// A token of a macro's matcher or invocation.
#[derive(Clone, Debug, PartialEq)]
enum Tok {
    Word(String),
    Punct(char),
    Lit(String),
    Group(char, Vec<Tok>),
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

/// A rule of a `macro_rules!`: its matcher (None when not read) and its transcriber's extent in
/// `code`, inside its brackets.
struct Rule {
    matcher: Option<Vec<El>>,
    body: (usize, usize),
}

thread_local! {
    /// Set by a check that could tell its position only within a range of identical candidates:
    /// invocations of one macro that make the same item as far as the context says.
    static RANGED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// The instantiation details a check confirmed by the receiver's type the code says, which
    /// is the instance's (`instantiated by main at src/main.rs:24:22 as `ext`` for `E2.ext()`).
    static TYPED: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
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
