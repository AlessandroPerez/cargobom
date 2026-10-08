//! Facts written by `rcbom-driver` (one JSON file per compiled crate) and read by
//! `rcbom-analysis`. The driver is knowledge-base agnostic apart from a crate filter: it reports
//! every place where code names a function, type or static of a crate the knowledge base knows,
//! with the source position of that name. Matching against the knowledge base happens on the
//! stable side, on these structured facts, never on printed MIR.

use serde::{Deserialize, Serialize};

/// Bumped whenever the shape below changes; the analysis refuses mismatched facts.
pub const FACTS_VERSION: u32 = 7;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CrateFacts {
    pub facts_version: u32,
    pub krate: CrateInfo,
    /// Places in this crate's own source, scanned per item without following calls.
    /// For fn items without generics, the body is monomorphic; for generic ones, only calls
    /// whose generic arguments are already concrete are kept.
    pub sites: Vec<Site>,
    /// Edges of the data graph that have no source position of their own: statics an
    /// initializer reaches only through evaluation (`static T: Table = make_table();` with
    /// `const fn make_table()` naming `&SHA256`).
    #[serde(default)]
    pub data_edges: Vec<DataEdge>,
    /// Present when this crate has an entry point (a binary): the instance graph walked from
    /// `main` across all crates whose MIR is available. Sites found there are `Reachable`.
    pub reach: Option<Reach>,
}

/// `owner` (a static) holds a pointer to `target` in its evaluated value.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DataEdge {
    pub owner: Owner,
    pub target: DefRef,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CrateInfo {
    /// Crate name as rustc sees it (`age_core`).
    pub name: String,
    /// `StableCrateId` of this compilation, used to tell two versions of one crate apart.
    pub stable_id: String,
    /// Cargo package name and version (`age-core`, `0.11.0`), from the env cargo sets for rustc.
    pub package: String,
    pub version: String,
    pub manifest_dir: String,
    /// rustc's working directory; relative span paths are relative to it.
    pub cwd: String,
    /// `CARGO_PRIMARY_PACKAGE`: a workspace member the user asked to build.
    pub primary: bool,
    pub crate_types: Vec<String>,
    /// Cargo's unit id for this compilation (`-C extra-filename`, e.g. `-1a2b3c4d5e6f7a8b`):
    /// the facts file is `<name><unit>.json`, and `cargo cbom` keeps only the units of the
    /// current build.
    #[serde(default)]
    pub unit: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CrateRef {
    pub name: String,
    pub stable_id: String,
}

/// A source position. `line` and `col` are 1-based; `col` counts characters, as rustc does.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Loc {
    pub file: String,
    pub line: usize,
    pub col: usize,
    pub end_line: usize,
    pub end_col: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Tier {
    /// The code exists in a compiled crate.
    Present,
    /// The code is in the instance graph from an entry point of a workspace binary.
    Reachable,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OwnerKind {
    Fn,
    Static,
}

/// The item whose body contains the site.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Owner {
    pub kind: OwnerKind,
    /// Human-readable path, with generic arguments for monomorphized instances.
    pub name: String,
    /// For statics, the def-path hash (matches `DefRef::id`); for fns, the mangled name.
    pub id: String,
    pub krate: CrateRef,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DefRef {
    pub krate: CrateRef,
    /// Defining path, crate-qualified, independent of re-exports and of the crate that
    /// observed it (`ring::aead::algorithm::AES_256_GCM`).
    pub path: String,
    /// Def-path hash, stable across compilation sessions of the same crate.
    pub id: String,
}

/// A type, reduced to what knowledge-base matching needs. Type aliases are gone: `Aes256Gcm`
/// arrives as `AesGcm<Aes256, UInt<..>>`, with every generic argument, defaults included.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TyTree {
    /// `krate` identifies the exact crate (two versions of sha2 are two crates), so the
    /// knowledge base's version ranges can be applied.
    Adt {
        krate: CrateRef,
        path: String,
        args: Vec<TyTree>,
    },
    Ref(Box<TyTree>),
    Slice(Box<TyTree>),
    Array(Box<TyTree>, Option<u64>),
    Tuple(Vec<TyTree>),
    /// A const generic argument, evaluated when possible.
    Const(Option<u64>),
    /// `dyn Trait`: the principal trait's path.
    Dyn(Vec<String>),
    /// A generic parameter: the site is not monomorphic.
    Param(String),
    Other(String),
}

// `Call` carries the call's arguments and origins and is much larger than the other variants;
// facts are written once and read once, so boxing would only add indirection to the JSON model.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Target {
    /// A call `callee::<args>(..)`. `callee` is the function as named at the call site (a trait
    /// method stays the trait method). `self_ty` is the type the method belongs to: `Self` of a
    /// trait method, the instantiated self type of an inherent impl (`Hkdf<Sha256, Hmac<..>>`
    /// for `Hkdf::<Sha256>::new`, whose own generic arguments are only `[H, I]`). `args` are
    /// the remaining generic arguments. `method` is the callee's own name. `const_args` has
    /// one entry per value argument: its value when it is an integer constant (`1_000` in
    /// `pbkdf2_hmac::<Sha256>(pw, salt, 1_000, out)`), else `None`.
    Call {
        callee: DefRef,
        method: String,
        self_ty: Option<TyTree>,
        args: Vec<TyTree>,
        const_args: Vec<Option<i128>>,
        /// Where each value argument comes from, within the enclosing body.
        arg_origins: Vec<Origin>,
        /// For each value argument, the length of the array behind it when its type says so
        /// (`&mut [0u8; 32]` passed as `&mut [u8]`).
        arg_lens: Vec<Option<u64>>,
    },
    /// A reference to a named `const` item, e.g. `&aws_lc_rs::aead::AES_256_GCM`: aws-lc-rs
    /// defines its algorithms as consts, which are copied by value and have no allocation.
    Const { def: DefRef },
    /// A reference to a static, e.g. `&ring::aead::AES_256_GCM`.
    Static { def: DefRef },
}

/// Origin of a value inside one function body, as a bounded tree over def-use chains.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Origin {
    /// A compile-time constant: an integer `value`, or literal data of `len` elements
    /// (`[0u8; 12]`, `b"saltysalt"`).
    Const {
        value: Option<i128>,
        len: Option<u64>,
        span: Option<Loc>,
    },
    /// A named static or const item (`&ring::aead::AES_256_GCM`).
    Data {
        def: DefRef,
    },
    /// Argument `index` of the enclosing function.
    Param {
        index: usize,
    },
    /// The result of a call; `args` are the origins of its value arguments. `callee` is the
    /// defining path; `self_ty` the path of the type a method belongs to, when it is an ADT
    /// (`argon2::Argon2` for `<Argon2 as Default>::default`).
    Call {
        callee: String,
        krate: String,
        #[serde(default)]
        self_ty: Option<String>,
        args: Vec<Origin>,
        /// Where the callee is named, as for a site: the analysis finds the site of this very
        /// call (`Oaep::new_with_label::<Sha256, _>(..)` passed to `encrypt`) and what it
        /// matched.
        #[serde(default)]
        span: Option<Loc>,
    },
    /// A value of a type without fields (`rand::rngs::OsRng`, `Option::None`): no data, but the
    /// type itself may say where values come from.
    Unit {
        path: String,
        krate: String,
    },
    /// Several definitions reach the value.
    Any(Vec<Origin>),
    /// A bound of the search was hit here (depth, width or size): the origin is incomplete.
    Truncated,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Site {
    pub tier: Tier,
    pub owner: Owner,
    /// Where the name appears. For code produced by a macro, this is the outermost macro call
    /// site in the user's source, and `expansion` keeps the position inside the macro.
    pub span: Loc,
    /// The source text of `span` when it is on one line and not inside a macro expansion
    /// (`Sha512_256::digest`, `seal_in_place_append_tag`, `aead::AES_256_GCM`).
    #[serde(default)]
    pub text: Option<String>,
    /// The source line holding the position (for code from a macro, the line of the outermost
    /// call), without its leading and trailing whitespace. Two sites on neighbouring lines can
    /// have the same `text` at the same column (`Ec(kp) => kp.public_key()` above
    /// `Ed(kp) => kp.public_key()`); their lines tell them apart.
    #[serde(default)]
    pub line_text: Option<String>,
    pub expansion: Option<Expansion>,
    pub target: Target,
    /// For sites inside a monomorphized generic instance: the calls that created the
    /// instance, innermost first (`seal::<Aes256Gcm>` called at src/main.rs:23).
    pub via: Vec<ViaStep>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MacroKind {
    /// `name!(..)`: the position is the macro's name at the call.
    Bang,
    /// `#[derive(Name)]`: the position is `Name` inside the derive list.
    Derive,
    /// `#[name]`: the position is the attribute.
    Attr,
    /// A compiler rewrite (`?`, `for`, `async`): the position is ordinary code.
    Desugaring,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Expansion {
    pub kind: MacroKind,
    /// The macro's name as rustc records it (`hash_all`, `ml::sha512_of`, `Clone`); empty for
    /// desugarings.
    pub macro_name: String,
    pub def_site: Loc,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ViaStep {
    pub caller: String,
    pub span: Loc,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Reach {
    pub roots: Vec<String>,
    pub instances: usize,
    /// The walk stopped at the instance limit; the reachable tier is incomplete.
    pub truncated: bool,
    /// Statics referenced from reachable code. Statics they refer to in turn are closed over
    /// by the analysis, using the static-owned sites of every crate.
    pub statics: Vec<DefRef>,
    /// Owner ids of the reached function instances (mangled names), and the def-path hashes
    /// of their definitions: sites found by the per-item scan inside one of them, generic or
    /// not, are reachable too.
    pub fns: Vec<String>,
}
