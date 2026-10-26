//! Facts written by `rcbom-driver` (one JSON file per compiled crate) and read by
//! `rcbom-analysis`. The driver is knowledge-base agnostic apart from a crate filter: it reports
//! every place where code names a function, type or static of a crate the knowledge base knows,
//! with the source position of that name. Matching against the knowledge base happens on the
//! stable side, on these structured facts, never on printed MIR.

use serde::{Deserialize, Serialize};

/// The owner of a followed closure's own parameters in `Origin::Call::fed`.
pub const CLOSURE_INPUT: &str = "<input>";

/// Bumped whenever the shape below changes; the analysis refuses mismatched facts.
pub const FACTS_VERSION: u32 = 33;

/// How the links name a static's initializer as the owner of what it stores and calls
/// (`FieldStore::func`, `LocalCall::caller`): `static <path> <id>`, so that a value stored there
/// reaches a call only when the static is reachable.
pub fn static_owner(path: &str, id: &str) -> String {
    format!("static {path} {id}")
}

/// The `Origin::Through::callee` of a write into an element of a field holding a list
/// (`v.algorithms[0] = RS512`, `*v.algorithms.first_mut().unwrap() = ..`): the value written is
/// one of the list's, beside the others.
pub const ELEMENT_WRITE: &str = "<element write>";

/// The `Origin::Call::callee` of a `Result`'s error value (`Err(e)`, its argument `e`): the
/// error side, which `ok()`, `?` and `unwrap_or` do not read.
pub const RESULT_ERR: &str = "core::result::Result::Err";

/// The marker of a write into an element of a list by function `writer` (`ELEMENT_WRITE`, then
/// the function).
pub fn element_write(writer: &str) -> String {
    format!("{ELEMENT_WRITE} {writer}")
}

/// The function a list element write marker names (`Some("")` when it names none); `None` for
/// another callee.
pub fn element_writer(callee: &str) -> Option<&str> {
    callee.strip_prefix(ELEMENT_WRITE).map(|w| w.trim_start())
}

/// The prefix of an `Origin::Through::callee` that stands for a value not followed, with why
/// after it (`<not followed> a cell ..`): never a value of the read, a gap beside the values found.
pub const NOT_FOLLOWED: &str = "<not followed>";

/// The `FieldStore::adt` and `Origin::Field::adt` of a tuple's element: stored only in a
/// static's or a constant's initializer (`PAIRS[i].0`); read from any tuple, where the analysis
/// projects it (that static, `Option::zip`'s pair) or says it does not follow it.
pub const TUPLE: &str = "(tuple)";

/// How the links name a named constant's initializer as the owner of what it stores, as
/// `static_owner` does a static's.
pub fn const_owner(path: &str, id: &str) -> String {
    format!("const {path} {id}")
}

/// The path and id of the static (or named constant) an owner names (`static_owner`,
/// `const_owner`).
pub fn owner_static(owner: &str) -> Option<(&str, &str)> {
    owner
        .strip_prefix("static ")
        .or_else(|| owner.strip_prefix("const "))?
        .rsplit_once(' ')
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CrateFacts {
    pub facts_version: u32,
    pub krate: CrateInfo,
    /// Places in this crate's own source, scanned per item without following calls.
    /// For fn items without generics, the body is monomorphic; for generic ones, only calls
    /// whose generic arguments are already concrete are kept, except in a library's generic
    /// functions its users can call (and their closures), where a call into a KB crate is kept
    /// with its types as parameters (`TyTree::Param`).
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
    /// Instances (`origins::body_name`) whose summaries the instance bound left unrecorded: a
    /// call or a write through one of them is cut, not "returns or writes nothing".
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub truncated: Vec<String>,
    /// A call between functions of the program's own crates none of whose arguments can carry
    /// an algorithm (`decode_token(&args)` with the parsed command line): its arguments'
    /// origins, read only to tell whether a value depends on the program's input.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub arg_calls: Vec<LocalCall>,
    /// The functions (and instances) taking a `&mut` (or a value holding one) whose summaries
    /// record no write through it: the value left as it was (`fn up(&mut self) {}`), not a
    /// function the driver did not see.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub summarised: Vec<String>,
    /// The functions of the crate (and instances) made a function pointer or a trait object
    /// (`h as fn(D)`, `&h as &dyn Fn(D)`, `Box<dyn Fn(D)>` of `Box::new(h)`), with their type: a
    /// call through a pointer of that type that is not followed may run any of them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub named: Vec<FnShape>,
    /// Function pointers and trait objects of functions handed where the code that may call
    /// them is not followed (the standard library's `for_each(p)`, `set_hook(b)`, a stop crate's
    /// function), by the function handing them and their type: whatever functions they are may
    /// run there with values not followed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub opaque: Vec<FnShape>,
    /// Calls of a trait's method on a trait object (`t.run(&SHA1)` with `t: &dyn Alg`): the
    /// body each type coerced to it runs (`coercions`) may run.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dyn_calls: Vec<DynCall>,
}

/// A call of a trait's method on a trait object of `trait_path` (as `Coercion::trait_path`
/// names it), by the trait method's path, and the method's type past the receiver (a `sig` as
/// `FnShape`'s), which the bodies it may run share. The receiver is unknown: it is of whichever
/// type the object holds, made of values another type's are not.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DynCall {
    pub call: LocalCall,
    pub trait_path: String,
    pub sig: String,
}

/// A function (or the function handing a pointer on) and the type of a pointer to it: its
/// number of parameters and `sig` (`fn(&ring::digest::Algorithm) -> ()`, regions erased; `*`
/// for a type not known, which pairs with any).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FnShape {
    pub func: String,
    pub arity: usize,
    pub sig: String,
}

/// Type `ty` (an ADT's defining path with its type arguments, `app::W<app::A>`; `dyn <trait>`
/// for an upcast from another trait object; any other type as rustc prints it) is coerced to
/// `dyn trait_path` at `at`: the cast in a function's body, or the item of the constant or
/// static whose value holds the vtable (none for a span without a position). `methods`: for
/// each method of the trait object (the trait's, its supertraits'), by defining path, the body a
/// call through it runs for `ty`, as the links name it (the type's implementation, or the
/// trait's default body: `Origin::Call::runs`), and its type past the receiver (a `sig` as
/// `FnShape`'s).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Coercion {
    pub trait_path: String,
    pub ty: String,
    pub at: Option<Loc>,
    /// The coercion is written in a static's value (not a constant's, nor a function's).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub in_static: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<(String, String, String)>,
}

/// Function `func` writes `value` through its parameter `index`; `value` names its parameters.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ParamWrite {
    pub func: String,
    pub index: usize,
    pub value: Origin,
    /// Written through a borrow the parameter holds, not through the parameter itself: the
    /// fields from its value (behind it, for a `&mut` parameter) to that borrow (`fn wset(w: W) {
    /// *w.slot = v }`: `[0]`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub path: Vec<usize>,
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
        for c in other.arg_calls {
            if !self.arg_calls.contains(&c) {
                self.arg_calls.push(c);
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
                    for w in s.writers {
                        if !x.writers.contains(&w) {
                            x.writers.push(w);
                        }
                    }
                }
                None => self.statics.push(s),
            }
        }
        for t in other.truncated {
            if !self.truncated.contains(&t) {
                self.truncated.push(t);
            }
        }
        for f in other.summarised {
            if !self.summarised.contains(&f) {
                self.summarised.push(f);
            }
        }
        for a in other.named {
            if !self.named.contains(&a) {
                self.named.push(a);
            }
        }
        for a in other.opaque {
            if !self.opaque.contains(&a) {
                self.opaque.push(a);
            }
        }
        for c in other.dyn_calls {
            if !self.dyn_calls.contains(&c) {
                self.dyn_calls.push(c);
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
    /// Defining path of the function storing it, whose parameters `value` names; in a static's
    /// initializer the static (`static_owner`); empty in a constant's or a promoted constant's.
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
    /// Of `values`, those a function of the program puts there at run time, with the function
    /// (by defining path): a value only dead code stores is none the static holds.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub writers: Vec<(String, Origin)>,
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
    /// rustc's working directory; relative span paths are relative to it.
    pub cwd: String,
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
        /// The pointer's type, as `FnShape::sig` gives it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sig: Option<String>,
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
        /// A literal index range (`..4`, `4..`, `2..6`): where it starts and ends (none: at
        /// the end), as the elements a write through it covers.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        range: Option<(u64, Option<u64>)>,
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
        /// For a call through a function pointer the driver does not resolve in this body
        /// (`callee` is `<indirect>`: a parameter, a field, a table's element), where the
        /// pointer comes from: the functions named as values it may be run there.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pointer: Option<Box<Origin>>,
        /// For a closure followed to what it returns (`callee` is `<closure>`, whose `args` read
        /// its own parameters as `Unknown`): the same value with its parameters as
        /// `Param { owner: Some(CLOSURE_INPUT) }`, for the analysis to give them the value a
        /// combinator passes the closure (`o.map(|x| x)`: the `Option`'s value), where it knows
        /// it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fed: Option<Box<Origin>>,
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
        /// For a function item used as a value, the body it runs when that is another than
        /// `path`'s item, as for `Call::runs`: a trait method's implementation for a known
        /// `Self` (`map(Pick::alg)` on a `Fast`: `<app::Fast as app::Pick>::alg`), an instance of
        /// a generic function of the program (`map(alg_of)`: `app::alg_of::<app::Fast>`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        runs: Option<String>,
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
        /// The type of the place written, when the function takes it as a trait object (`fn
        /// up_dyn(u: &mut dyn Up)` called with `&mut b`, a `B`: `app::B`): the trait-object
        /// calls inside write with that type's implementation.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        place_ty: Option<String>,
        /// Through a borrow the argument holds at these fields (`ParamWrite::path`): `wset(W {
        /// slot: &mut x })` writing `x`.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        path: Vec<usize>,
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
                pointer,
                fed,
            } => Origin::Call {
                callee,
                krate,
                self_ty,
                args: args.into_iter().map(|a| a.params_of(owner)).collect(),
                span,
                runs,
                pointer: pointer.map(|p| Box::new(p.params_of(owner))),
                fed: fed.map(|f| Box::new(f.params_of(owner))),
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
                place_ty,
                path,
            } => Origin::Written {
                callee,
                index,
                args: args.into_iter().map(|a| a.params_of(owner)).collect(),
                self_ty,
                place_ty,
                path,
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
                pointer,
                fed,
            } => Origin::Call {
                callee,
                krate,
                self_ty,
                args: cap(args),
                span,
                runs,
                pointer: pointer.map(|p| Box::new(p.capped(depth - 1))),
                fed: fed.map(|f| Box::new(f.capped(depth - 1))),
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
                place_ty,
                path,
            } => Origin::Written {
                callee,
                index,
                args: cap(args),
                self_ty,
                place_ty,
                path,
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
    /// For a site that is a call, which call: what its boundary edges name too.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call: Option<CallId>,
}

/// One call, as its site and its boundary edges both name it: where the compiler writes its
/// whole expression (inside a macro's definition, for a macro's code) and the function as named
/// there, before the call is resolved (`core::ops::arith::Mul::mul`,
/// `core::option::Option::unwrap_or_default`). An occurrence made from a site accounts for the
/// edges of its own call, not for every call at its position.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CallId {
    pub span: Loc,
    pub named: String,
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
    /// The artifact walked: `bin <name>` for a binary (cargo's target name), `lib <package>` for
    /// a library of the workspace (its public API).
    #[serde(default)]
    pub artifact: String,
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
    /// The symbols of the compiler's shims the walk went through (drop glue, a closure's
    /// `call_once`, a tuple's `clone`): with `fns`, what the walk reached, for the check against
    /// the linker (`cargo cbom --check-walk`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub shims: Vec<String>,
    /// Of those, a library's generic functions its users may call, which no instance walks
    /// (only a caller has their type arguments): reached, but not walked.
    #[serde(default)]
    pub generic: Vec<String>,
    /// The crates whose code the walk reached, inside the algorithm crates too (followed there
    /// for this only): the packages that run.
    #[serde(default)]
    pub crates: Vec<CrateRef>,
    /// `crates` is complete (no walk limit was hit).
    #[serde(default)]
    pub crates_complete: bool,
    /// What the points-to analysis (`RCBOM_PTA`) found, when it ran.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub points_to: Option<PointsTo>,
    /// The calls of the walked code into a crate of the crypto set other than the caller's: the
    /// edges a CBOM accounts for (`rcbom:run:boundary-check`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub boundary: Vec<BoundaryEdge>,
}

/// A call of walked code into a crate of the crypto set (`RCBOM_KB_CRATES`: the knowledge
/// base's crates and the unmodelled crypto packages) other than the caller's, by the function
/// it resolves to: an implementation for a known type is its crate's (`<orion::aead::SecretKey
/// as Default>::default` is orion's), whether or not the call is a site.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BoundaryEdge {
    /// The calling body, as a site's owner.
    pub owner: Owner,
    /// Where a site of the call is: the callee's name, or the macro call it comes from.
    pub span: Loc,
    /// The function the call resolves to, by its defining path, with its crate.
    pub callee: DefRef,
    /// The trait the callee is a method of, or implements (`core::convert::AsRef`), by its
    /// defining path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trait_path: Option<String>,
    /// The callee is a coroutine's body (an `async fn`'s or block's), polled where it is awaited.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub coroutine: bool,
    /// The structs and enums among the callee's type arguments, behind references
    /// (`rand::rngs::small::SmallRng` for `v.shuffle(&mut small_rng)`), by defining path.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub types: Vec<String>,
    /// The function reaches the call as a value (`hasher.map(|h| h(&d))` with `Some(blake3::
    /// hash)`): it is cited where it is named.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub through_value: bool,
    /// The code making the call runs on behalf of the crypto layer, on every way the walk
    /// reaches it: it is an algorithm crate's or a crate implementing one (`Algorithm`), or a
    /// crypto package's (`Package`), or a generic instance every chain of instantiations of
    /// which starts in such code (nom's parser run on age's closure).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_behalf: Option<Behalf>,
    /// Which call it is (for a call the standard library makes, the program's call into it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call: Option<CallId>,
    /// The source text at `span` and its line, as a site's (`Site::text`, `Site::line_text`), and
    /// the macro it comes from: for an occurrence the check cites itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line_text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expansion: Option<Expansion>,
    /// A call the standard library makes on the program's behalf, whose body has no source
    /// positions: the standard-library function the walked code called there
    /// (`core::option::Option::unwrap_or_default`, running orion's `SecretKey::default`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub std_entry: Option<String>,
}

/// Whose code a call of `BoundaryEdge` runs for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Behalf {
    /// An algorithm crate's implementation (a stop crate, or a crate implementing one).
    Algorithm,
    /// Another crypto package's code (a protocol crate, a package without entries).
    Package,
}

/// The points-to analysis' answers at the calls into the knowledge-base crates: what each
/// argument may point to, in every copy of the calling body it solved.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PointsTo {
    pub calls: Vec<PtaCall>,
    /// The struct or enum each knowledge-base static or constant the analysis read is
    /// (`ring::digest::SHA256`: `ring::digest::Algorithm`): an argument that points to a value
    /// of one of these types can carry that descriptor.
    pub static_types: Vec<(DefRef, String)>,
}

/// A call into a knowledge-base crate, at its callee expression (as `Site::span` places it).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PtaCall {
    pub at: Loc,
    /// Defining path of the function called.
    pub callee: String,
    /// The instance whose body holds the call: its mangled name (`Owner::id` of the walk's
    /// sites) and its item's def-path hash (`Owner::id` of the per-item scan's).
    pub owner: String,
    pub owner_def: String,
    /// The copy holding the call is reached from the roots through bound calls: an empty
    /// answer there is a value not followed, elsewhere dead code.
    pub live: bool,
    /// Per argument (`None`: not one that can hold a pointer the analysis follows).
    pub args: Vec<Option<PtaArg>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PtaArg {
    /// The knowledge-base statics and constants it may point to.
    pub statics: Vec<DefRef>,
    /// It may point to what code not translated reaches.
    pub unknown: bool,
    /// Other objects it may point to (locals, heap, constant memory).
    pub others: usize,
    /// The struct or enum it points to (`ring::digest::Algorithm`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pointee: Option<String>,
    /// It is itself a pointer to that type (`&Algorithm`), not a value holding one.
    #[serde(default)]
    pub direct: bool,
}
