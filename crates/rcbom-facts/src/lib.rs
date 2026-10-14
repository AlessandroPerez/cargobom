//! Facts written by `rcbom-driver` (one JSON file per compiled crate) and read by
//! `rcbom-analysis`. The driver is knowledge-base agnostic apart from a crate filter: it reports
//! every place where code names a function, type or static of a crate the knowledge base knows,
//! with the source position of that name. Matching against the knowledge base happens on the
//! stable side, on these structured facts, never on printed MIR.

use serde::{Deserialize, Serialize};

/// Bumped whenever the shape below changes; the analysis refuses mismatched facts.
pub const FACTS_VERSION: u32 = 19;

/// How the links name a static's initializer as the owner of what it stores and calls
/// (`FieldStore::func`, `LocalCall::caller`): `static <path> <id>`, so that a value stored there
/// reaches a call only when the static is reachable.
pub fn static_owner(path: &str, id: &str) -> String {
    format!("static {path} {id}")
}

/// The path and id of the static an owner names (`static_owner`).
pub fn owner_static(owner: &str) -> Option<(&str, &str)> {
    owner.strip_prefix("static ")?.rsplit_once(' ')
}

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
    /// How values reach a call from other functions, for the values that can carry an
    /// algorithm or a key (types of knowledge-base crates): what this crate stores in struct
    /// fields, what its functions return, what it passes to functions, and what its statics
    /// hold at run time.
    #[serde(default)]
    pub links: Links,
    /// The field names of this crate's structs, by path as `Origin::Field` names them, when the
    /// knowledge base describes the crate: a boundary model names a field (`Header.alg`), whose
    /// index changes between versions (`Validation.algorithms` is field 8 in jsonwebtoken 9.2,
    /// 9 in 9.3).
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub fields: std::collections::BTreeMap<String, Vec<String>>,
    /// The variants of this crate's field-less enums (name, discriminant), by path, when the
    /// knowledge base describes the crate: a constant of one is its discriminant
    /// (`const ALG: Algorithm = Algorithm::ES384` is `Data { value: 4 }`).
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub variants: std::collections::BTreeMap<String, Vec<(String, i128)>>,
}

/// Value flow across the functions of a crate (see `CrateFacts::links`). Flow-insensitive: a
/// field holds any value stored in it anywhere, a parameter any argument passed for it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Links {
    /// `S { f: v }`, `x.f = v`, in function bodies and static initializers.
    pub fields: Vec<FieldStore>,
    /// What a function returns.
    pub returns: Vec<Returned>,
    /// A call of a function outside the knowledge-base crates and the standard library, with
    /// its arguments' origins (`Unknown` for arguments that cannot carry one).
    pub calls: Vec<LocalCall>,
    /// Values a static holds at run time: a `LazyLock`'s or `OnceLock`'s initializer, what
    /// `OnceLock::set` or a write to a `static mut` puts there.
    pub statics: Vec<StaticValue>,
    /// What a function writes through a parameter (`fn set(slot: &mut &Algorithm) { *slot =
    /// &SHA512 }`, `*l.write().unwrap() = a`): `Origin::Written` at its calls.
    #[serde(default)]
    pub writes: Vec<ParamWrite>,
    /// The types the walked code coerces to a trait object (`Box::new(Blob) as Box<dyn
    /// Source>`, a `&'static dyn Trait` in a constant): the implementations a call through
    /// `dyn Source` (an `Origin::Call` whose `self_ty` is `dyn <trait>`) may run.
    #[serde(default)]
    pub coercions: Vec<Coercion>,
}

/// Type `ty` (an ADT's defining path with its type arguments, `app::W<app::A>`, or the type as
/// rustc prints it) is coerced to `dyn trait_path` at `at` (a constant's or a static's: its
/// item). `methods`: for each method of the trait object (the trait's, its supertraits'), by
/// defining path, the body a call through it runs for `ty`, as the links name it (the type's
/// implementation, or the trait's default body: `Origin::Call::runs`).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Coercion {
    pub trait_path: String,
    pub ty: String,
    pub at: Option<Loc>,
    /// The coercion is written in a static's value (not a constant's, nor a function's).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub in_static: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<(String, String)>,
}

/// Function `func` writes `value` through its parameter `index`; `value` names its parameters.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ParamWrite {
    pub func: String,
    pub index: usize,
    pub value: Origin,
}

impl Links {
    /// Adds `other`'s records, without duplicates.
    pub fn merge(&mut self, other: Links) {
        for f in other.fields {
            if !self.fields.contains(&f) {
                self.fields.push(f);
            }
        }
        for r in other.returns {
            if !self.returns.contains(&r) {
                self.returns.push(r);
            }
        }
        for c in other.calls {
            if !self.calls.contains(&c) {
                self.calls.push(c);
            }
        }
        for w in other.writes {
            if !self.writes.contains(&w) {
                self.writes.push(w);
            }
        }
        for s in other.statics {
            match self.statics.iter_mut().find(|x| x.def.id == s.def.id) {
                Some(x) => {
                    x.mutable |= s.mutable;
                    for v in s.values {
                        if !x.values.contains(&v) {
                            x.values.push(v);
                        }
                    }
                }
                None => self.statics.push(s),
            }
        }
    }
}

/// A value stored in a struct field (or a field of a struct inside it), or in a field of an
/// enum variant built by the program (`KeyPairKind::Ec(kp)`).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FieldStore {
    /// Defining path of the struct, or of the enum variant (`rcgen::key_pair::KeyPairKind::Ec`).
    pub adt: String,
    /// The field, then the fields inside it (`c.aead.alg`: `aead`'s index, then `alg`'s).
    pub path: Vec<usize>,
    pub value: Origin,
    /// Defining path of the function storing it, whose parameters `value` names; empty in a
    /// static's initializer.
    pub func: String,
    /// Stored through a reference (`self.alg = v` in a `&mut self` method): the struct written
    /// may be a part of another one.
    pub via_ref: bool,
    /// The struct's type arguments, when it has some and they are known (`Wrapper<&ring::
    /// digest::Algorithm>` is not `Wrapper<&ring::aead::Algorithm>`); a read of other
    /// arguments does not see the store.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args: Option<String>,
}

/// The name under which a method implementing a trait records what it returns, besides its
/// own path: the trait's method and the `Self` type a call names (`Origin::Call`'s `callee`
/// and `self_ty`).
pub fn impl_key(trait_method: &str, self_ty: &str) -> String {
    format!("{trait_method} for {self_ty}")
}

/// What a function returns, or a field of it (`path`, as in `FieldStore`).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Returned {
    /// Defining path of the function; for a method implementing a trait's, also recorded
    /// under `impl_key`.
    pub func: String,
    pub path: Vec<usize>,
    pub value: Origin,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LocalCall {
    /// Defining path of the function called.
    pub callee: String,
    /// Defining path of the function calling it, whose parameters `args` name.
    pub caller: String,
    pub args: Vec<Origin>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StaticValue {
    pub def: DefRef,
    /// Its contents change at run time (`static mut`, `LazyLock`, `OnceLock`, a lock, an
    /// atomic): it is not data compiled in.
    pub mutable: bool,
    pub values: Vec<Origin>,
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
    /// The defining path of the function or static, without an instance's generic arguments:
    /// what `LocalCall::callee` and `Returned::func` name.
    #[serde(default)]
    pub path: String,
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
        /// A call through a function pointer or a function held in a place (`let h = digest;
        /// h(&SHA256, d)`): the site is the call's callee expression, and this is where the
        /// function was named.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        through: Option<Loc>,
        /// The function is named here as a value (made a pointer, stored, passed:
        /// `iter.map(Sha256::digest)`), not called: it runs wherever the value is called.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        value: bool,
    },
    /// A call through a function pointer whose function is not named in this body (`(h.f)(..)`,
    /// a parameter, a returned pointer): the site is the call's callee expression; `origin` is
    /// where the pointer comes from, leading to the functions named as values (`Call::value`,
    /// `Origin::Unit::span`). The value arguments as for `Call`.
    Pointer {
        origin: Origin,
        const_args: Vec<Option<i128>>,
        arg_origins: Vec<Origin>,
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
        /// Literal data all of whose bytes are zero (`[0u8; 64]`).
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        zero: bool,
    },
    /// A named static or const item (`&ring::aead::AES_256_GCM`). `value` is an integer
    /// const's value (`const ITERATIONS: u32 = 600_000`), when the compiler can evaluate it.
    Data {
        def: DefRef,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        value: Option<i128>,
        /// An item whose value's bytes are all zero (`const ZERO: [u8; 32] = [0; 32]`).
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        zero: bool,
    },
    /// Argument `index` of the enclosing function, or of `owner` (its defining path) when that
    /// is another: a closure or `async` body reads its parent function's parameter through a
    /// capture (`fn hash_all(alg, ..) { items.map(|d| digest(alg, d)) }`).
    Param {
        index: usize,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        owner: Option<String>,
    },
    /// The result of a call; `args` are the origins of its value arguments. `callee` is the
    /// defining path; `self_ty` the path of the type a method belongs to, when it is an ADT
    /// (`argon2::Argon2` for `<Argon2 as Default>::default`), or `dyn <trait>` for a trait
    /// method called on a trait object (`s.alg()` with `s: &dyn Source`; see `Coercion`).
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
        /// The body the call runs, when the driver resolves it to another than `callee`'s
        /// item: a trait method's implementation for a known `Self` (`<app::Fast as
        /// app::Pick>::alg`) or the trait's default body for it, an instance of a generic
        /// function of the program (`app::pick::<app::Fast>`), whose summaries `Links` records
        /// under that name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        runs: Option<String>,
    },
    /// A value of a type without fields (`rand::rngs::OsRng`, `Option::None`): no data, but the
    /// type itself may say where values come from.
    Unit {
        path: String,
        krate: String,
        /// For an enum variant, its discriminant (`argon2::Algorithm::Argon2i` is 1).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        value: Option<i128>,
        /// For a function item used as a value, where it is named (as its `Call::value` site).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        span: Option<Loc>,
    },
    /// A buffer written through a borrow that `callee` returned (`for c in key.chunks_mut(16) {
    /// rng.fill_bytes(c) }`, a lock guard): what was written is not followed.
    Through {
        callee: String,
    },
    /// Field `field` of a struct `adt` read from a value whose origin is `base` (a parameter,
    /// a call's result, a static): any value the crate stores in that field (`Links::fields`).
    /// For an enum outside the standard library, `adt` is the variant (`match &self.kind {
    /// KeyPairKind::Ec(kp) => .. }`); a standard-library enum's field (`Some(k)`) is the whole
    /// value.
    Field {
        adt: String,
        field: usize,
        base: Box<Origin>,
        /// The struct's type arguments, as `FieldStore::args`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        args: Option<String>,
    },
    /// What function `callee` writes through its parameter `index` (`Links::writes`), its
    /// parameters being `args`: `set_slot(&mut c.alg)` stores it in `c.alg`. For a trait
    /// method the call does not resolve to one body, `self_ty` says how it dispatches: `dyn
    /// <trait>` (the types coerced to the trait object) or `impl <trait>` (a generic `T:
    /// Trait`: any implementation).
    Written {
        callee: String,
        index: usize,
        args: Vec<Origin>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        self_ty: Option<String>,
    },
    /// A write of `value` into field `path` of the value it is a part of (`h.alg =
    /// Algorithm::HS384` after `let mut h = Header::default()`), as a part of an `All`. `strong`:
    /// the write happens on every way from the value's definition to the read, so the field
    /// holds `value`, not what the definition put there.
    Set {
        path: Vec<usize>,
        value: Box<Origin>,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        strong: bool,
    },
    /// Several definitions reach the value: it is one of these.
    Any(Vec<Origin>),
    /// A value built from all of these parts: the elements of an array or the fields of a
    /// struct built here, the operands of an arithmetic operation, a value with some of its
    /// elements written afterwards (`key[31] = 1`).
    All(Vec<Origin>),
    /// The value depends on its own earlier value (`ctr += 1` in a loop): it changes with
    /// each iteration; the other alternatives say where it starts.
    Loop,
    /// A bound of the search was hit here (depth, width or size): the origin is incomplete.
    Truncated,
    Unknown,
}

impl Origin {
    /// The origin with its parameters that name no owner made parameters of `owner`: a value
    /// a closure captured, as its parent function computes it.
    pub fn params_of(self, owner: &str) -> Origin {
        match self {
            Origin::Param { index, owner: None } => Origin::Param {
                index,
                owner: Some(owner.to_string()),
            },
            Origin::Call {
                callee,
                krate,
                self_ty,
                args,
                span,
                runs,
            } => Origin::Call {
                callee,
                krate,
                self_ty,
                args: args.into_iter().map(|a| a.params_of(owner)).collect(),
                span,
                runs,
            },
            Origin::Field {
                adt,
                field,
                base,
                args,
            } => Origin::Field {
                adt,
                field,
                base: Box::new(base.params_of(owner)),
                args,
            },
            Origin::Written {
                callee,
                index,
                args,
                self_ty,
            } => Origin::Written {
                callee,
                index,
                args: args.into_iter().map(|a| a.params_of(owner)).collect(),
                self_ty,
            },
            Origin::Any(v) => Origin::Any(v.into_iter().map(|a| a.params_of(owner)).collect()),
            Origin::All(v) => Origin::All(v.into_iter().map(|a| a.params_of(owner)).collect()),
            Origin::Set {
                path,
                value,
                strong,
            } => Origin::Set {
                path,
                value: Box::new(value.params_of(owner)),
                strong,
            },
            o => o,
        }
    }

    /// The origin with what lies more than `depth` origins down cut (`Truncated`): facts are
    /// read back by a parser with a nesting bound (serde_json's 128 levels, up to 3 per
    /// origin), whatever bounds the search that built them.
    pub fn capped(self, depth: usize) -> Origin {
        if depth == 0 {
            return Origin::Truncated;
        }
        let cap = |v: Vec<Origin>| v.into_iter().map(|a| a.capped(depth - 1)).collect();
        match self {
            Origin::Call {
                callee,
                krate,
                self_ty,
                args,
                span,
                runs,
            } => Origin::Call {
                callee,
                krate,
                self_ty,
                args: cap(args),
                span,
                runs,
            },
            Origin::Field {
                adt,
                field,
                base,
                args,
            } => Origin::Field {
                adt,
                field,
                base: Box::new(base.capped(depth - 1)),
                args,
            },
            Origin::Written {
                callee,
                index,
                args,
                self_ty,
            } => Origin::Written {
                callee,
                index,
                args: cap(args),
                self_ty,
            },
            Origin::Any(v) => Origin::Any(cap(v)),
            Origin::All(v) => Origin::All(cap(v)),
            Origin::Set {
                path,
                value,
                strong,
            } => Origin::Set {
                path,
                value: Box::new(value.capped(depth - 1)),
                strong,
            },
            o => o,
        }
    }
}

/// Origins nested deeper than this are cut when the driver writes them (`Origin::capped`).
pub const MAX_ORIGIN_DEPTH: usize = 30;

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
    /// The source text of the callee expression at the call, when written on one line outside
    /// macros (`decrypt::aes_ctr::<Aes128Ctr>`): it tells the call apart from a neighbour that
    /// instantiates the function with other type arguments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
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
    /// The defining paths of the reached functions (as `Links` names them): a value named in
    /// one of them reaches a call at run time.
    #[serde(default)]
    pub paths: Vec<String>,
    /// The crates whose code the walk reached, inside the algorithm crates too (followed there
    /// for this only): the packages that run.
    #[serde(default)]
    pub crates: Vec<CrateRef>,
    /// `crates` is complete (no walk limit was hit).
    #[serde(default)]
    pub crates_complete: bool,
}
