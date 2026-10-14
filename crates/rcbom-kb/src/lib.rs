//! The knowledge base: which crates are cryptographic (Layer 1) and how their types, statics
//! and functions map to registry-named algorithms (Layer 2). It is data (`kb/seed.toml`); this
//! crate loads and validates it.

pub mod registry;

use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};
use regex::Regex;
use serde::Deserialize;

/// The seed shipped with the tool.
pub const SEED: &str = include_str!("../../../kb/seed.toml");

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    version: String,
    #[serde(rename = "crate")]
    crates: Vec<CrateEntry>,
    #[serde(rename = "type", default)]
    types: Vec<TypeEntry>,
    #[serde(rename = "static", default)]
    statics: Vec<StaticRaw>,
    #[serde(rename = "fn", default)]
    fns: Vec<FnRaw>,
    #[serde(rename = "use", default)]
    uses: Vec<UseEntry>,
    #[serde(rename = "protocol", default)]
    protocols: Vec<ProtocolRaw>,
    #[serde(rename = "role", default)]
    roles: Vec<RoleRaw>,
    #[serde(rename = "source", default)]
    sources: Vec<SourceRaw>,
    #[serde(rename = "passthrough", default)]
    passthroughs: Vec<PassthroughRaw>,
    #[serde(rename = "seeded", default)]
    seeded: Vec<SourceRaw>,
    #[serde(rename = "produces", default)]
    produces: Vec<ProducesRaw>,
    #[serde(rename = "operation", default)]
    operations: Vec<OperationRaw>,
    #[serde(rename = "boundary", default)]
    boundaries: Vec<BoundaryRaw>,
    #[serde(rename = "enum", default)]
    enums: Vec<EnumRaw>,
    #[serde(default)]
    unmodelled: UnmodelledRaw,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BoundaryRaw {
    #[serde(rename = "crate")]
    krate: String,
    path: String,
    #[serde(rename = "use")]
    function: String,
    algorithm: FieldRef,
    #[serde(default)]
    key: Option<FieldRef>,
    #[serde(rename = "enum")]
    enumeration: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnumRaw {
    #[serde(rename = "crate")]
    krate: String,
    name: String,
    variants: BTreeMap<String, Variant>,
}

/// Layer 1 for packages without `[[crate]]` entries: which are cryptographic anyway.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnmodelledRaw {
    #[serde(default)]
    crypto: Vec<String>,
    #[serde(default)]
    support: Vec<String>,
    #[serde(default)]
    not_crypto: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OperationRaw {
    #[serde(rename = "crate")]
    krate: OneOrMany,
    path: String,
    primitive: String,
    #[serde(rename = "use")]
    function: String,
    #[serde(default)]
    algorithm: usize,
    #[serde(default)]
    self_type: bool,
    #[serde(default)]
    setup: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProducesRaw {
    path: String,
    role: String,
    method: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PassthroughRaw {
    path: String,
    args: Vec<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RoleRaw {
    path: String,
    args: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceRaw {
    kind: String,
    path: String,
}

/// Which value arguments of an API are key material: index -> role (`key`, `nonce`, ...).
#[derive(Debug)]
pub struct RoleEntry {
    pub pattern: Regex,
    pub args: BTreeMap<usize, String>,
}

/// A call whose result is external input or randomness.
#[derive(Debug)]
pub struct SourceEntry {
    pub kind: String,
    pub pattern: Regex,
}

/// A call handing the library a value of the program's type that the library asks for data
/// through a trait method (`SealingKey::new(key, seq)`: ring calls `seq.advance()` for each
/// nonce): the `role` of the call is what the program's implementation of `method` (a suffix of
/// the trait method's path) returns, for the types among the call's generic arguments.
#[derive(Debug)]
pub struct ProducesEntry {
    pub pattern: Regex,
    pub role: String,
    pub method: String,
}

/// A call whose result carries the value of some of its arguments only: the data, not the
/// message of `anyhow::Context::context(result, "msg")` or the engine of
/// `Engine::decode(&STANDARD, input)`.
#[derive(Debug)]
pub struct PassthroughEntry {
    pub pattern: Regex,
    /// Value argument indices whose origins the result has (the receiver is argument 0).
    pub args: Vec<usize>,
}

/// A call that performs an operation whose algorithm is a run-time value (`ring::digest::
/// digest(alg, data)`, `LessSafeKey::seal_in_place_append_tag` on a key built from one): it is
/// always reported, with the algorithms that reach it, or as an unknown algorithm when none
/// does.
#[derive(Debug)]
pub struct OperationEntry {
    pub krates: Vec<String>,
    /// Regex over the callee's path inside its crate, generic arguments removed.
    pub pattern: Regex,
    pub primitive: String,
    /// The `cryptoFunctions` value of the call.
    pub function: String,
    /// The value argument that carries the algorithm (the receiver is argument 0).
    pub algorithm: usize,
    /// The algorithm is the Self type of the call (RustCrypto traits: `Digest::digest` on
    /// `Sha3_256`), not a value.
    pub self_type: bool,
    /// The call sets the algorithm up (`Digest::new`, `KeyInit::new`) without using it: its
    /// occurrence has no use.
    pub setup: bool,
}

/// A call's value argument (the receiver is argument 0), or a field of the struct behind it
/// (`Header.alg` of `encode(&header, ..)`: struct `adt` by its name, field `field`).
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldRef {
    pub arg: usize,
    #[serde(rename = "struct", default)]
    pub adt: Option<String>,
    #[serde(default)]
    pub field: Option<String>,
}

/// A protocol crate's API modelled at its boundary (jsonwebtoken's `encode`, `decode`): the
/// algorithm is a variant of an enum (`[[enum]]`) held in a field of the struct an argument
/// points to; with `key`, only the variants the key's family allows.
#[derive(Debug)]
pub struct BoundaryEntry {
    pub krate: String,
    /// Regex over the callee's path inside its crate, generic arguments removed.
    pub pattern: Regex,
    /// The call's use (`sign`; a `mac` asset's is the use of `sign` for MACs, `tag`).
    pub function: String,
    pub algorithm: FieldRef,
    pub key: Option<FieldRef>,
    pub enumeration: String,
}

/// One variant of an algorithm enum: its asset, and the key family it needs (the variant name
/// of the key's family enum: jsonwebtoken's `AlgorithmFamily::Hmac`).
#[derive(Clone, Debug, Deserialize)]
pub struct Variant {
    #[serde(flatten)]
    pub algo: Algo,
    #[serde(default)]
    pub key: Option<String>,
}

/// An enum whose values name algorithms (jsonwebtoken's `Algorithm`), by variant name.
#[derive(Debug)]
pub struct EnumEntry {
    pub krate: String,
    pub name: String,
    pub variants: BTreeMap<String, Variant>,
}

/// A package the knowledge base has no `[[crate]]` entry for, recognised as cryptographic from
/// its metadata or the `[unmodelled]` lists.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Unmodelled {
    /// It implements, wraps or binds cryptography; its APIs are not in the knowledge base.
    Crypto,
    /// Crypto-adjacent: encodings of keys and certificates, buffers, constant-time helpers.
    Support,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Algorithm,
    Trait,
    Protocol,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrateEntry {
    pub package: String,
    #[serde(deserialize_with = "de_req")]
    pub versions: semver::VersionReq,
    pub role: Role,
    #[serde(default)]
    pub candidates: Vec<String>,
    #[serde(default)]
    pub backends: BTreeMap<String, String>,
}

impl CrateEntry {
    /// The crate name rustc uses for this package's library.
    pub fn crate_name(&self) -> String {
        self.package.replace('-', "_")
    }
}

/// What every algorithm entry carries.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct Algo {
    /// Registry-pattern name; `{param}` or `{1}` placeholders.
    pub asset: String,
    pub family: String,
    pub primitive: String,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub parameter_set: Option<String>,
    #[serde(default)]
    pub curve: Option<String>,
    #[serde(default)]
    pub functions: Vec<String>,
    #[serde(default)]
    pub note: Option<String>,
    /// A parameter the analysis cannot recover statically; reported, never guessed.
    #[serde(default)]
    pub unresolved: Option<String>,
    /// Key material rather than an algorithm (`private-key`, ...): a CycloneDX
    /// related-crypto-material type. The registry has no name for a key with no scheme.
    #[serde(default)]
    pub material: Option<String>,
    /// Size in bits of the material; a template over the parameters (`{bits}`).
    #[serde(default)]
    pub size: Option<String>,
    /// Parameter values that an optional `[..]` part of the name leaves out
    /// (`{ nonce_bits = "96", tag_bits = "128" }` for AES-GCM).
    #[serde(default)]
    pub defaults: BTreeMap<String, String>,
    /// Placeholders of `asset` (outside its optional `[..]` parts) the analysis left
    /// unresolved when it filled the name: `["hash"]` for `HKDF-{hash}` with no hash found.
    /// Set by the analysis, never by the knowledge base.
    #[serde(skip)]
    pub open: Vec<String>,
    /// What a call matched by a `[[fn]]` entry does when its method is not a listed use
    /// (`keygen` for `RsaPrivateKey::new`). Without it such a call sets the asset up.
    #[serde(default, rename = "use")]
    pub implied_use: Option<String>,
    /// (`[[type]]` entries) Methods whose parameters are not those of the constructor that built
    /// the receiver: `verify_password` takes them from the stored hash,
    /// `hash_password_customized` from its arguments.
    #[serde(default)]
    pub own_params: Vec<String>,
    /// (`[[type]]` entries) Parameters a method of `own_params` uses when its arguments leave
    /// them out: `hash_password_customized(pw, None, ..)` hashes with the crate's default
    /// variant (`{ variant = "id" }` for argon2), not the receiver's.
    #[serde(default)]
    pub own_defaults: BTreeMap<String, String>,
    /// Packages implementing the algorithm under the one whose API is matched (rand_chacha
    /// under rand's `ThreadRng`, getrandom under rand_core's `OsRng`): providers too, where the
    /// build has them as that package's dependencies.
    #[serde(default)]
    pub implemented_by: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct TypeEntry {
    #[serde(rename = "crate")]
    pub krate: String,
    pub name: String,
    /// Regex over the type's path inside its crate, when the name alone is ambiguous (rsa's
    /// `pkcs1v15::SigningKey` and `pss::SigningKey`).
    #[serde(default)]
    pub module: Option<String>,
    #[serde(flatten)]
    pub algo: Algo,
    #[serde(default)]
    pub params: BTreeMap<String, Param>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Param {
    #[serde(default)]
    pub arg: Option<usize>,
    #[serde(default)]
    pub parent_arg: Option<usize>,
    #[serde(default)]
    pub map: BTreeMap<String, String>,
    #[serde(default)]
    pub typenum: bool,
    #[serde(default)]
    pub asset: bool,
    #[serde(default)]
    pub scale: Option<u64>,
    /// Value argument N of the call, when it is an integer constant.
    #[serde(default)]
    pub const_arg: Option<usize>,
    /// The length of the array behind value argument N.
    #[serde(default)]
    pub arg_len: Option<usize>,
    /// Generic arguments of generic arguments: `arg = 0, path = [0]` is the first argument of
    /// the first argument (`ChaChaCore` in `ChaChaPoly1305<StreamCipherCoreWrapper<ChaChaCore<
    /// U10>>, U12>`).
    #[serde(default)]
    pub path: Vec<usize>,
    /// (`[[type]]` entries) The entry matches only when this parameter resolves: the `AES` of
    /// `cbc::Encryptor<C>` holds only when `C` is an AES type, not for `Encryptor<Blowfish>`.
    #[serde(default)]
    pub required: bool,
    /// (`[[fn]]` entries) A fixed value, the crate's own default: `scrypt::Params::recommended()`
    /// is log_n 17, r 8, p 1, 32 bytes. A call the value is passed to can override it (the
    /// output length of `scrypt(.., &params, out)`).
    #[serde(default)]
    pub value: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

impl OneOrMany {
    fn into_vec(self) -> Vec<String> {
        match self {
            OneOrMany::One(s) => vec![s],
            OneOrMany::Many(v) => v,
        }
    }
}

#[derive(Debug, Deserialize)]
struct StaticRaw {
    #[serde(rename = "crate")]
    krate: OneOrMany,
    name: String,
    /// Regex over the item's path inside its crate (`aead::quic::`), when the name alone is
    /// ambiguous (`AES_128` is a QUIC header-protection key in `aead::quic`, a CMAC key in
    /// `cmac`).
    #[serde(default)]
    module: Option<String>,
    /// The asset's name when the call that names the descriptor (in its arguments or in its
    /// receiver's construction) is one of these methods: the key-wrapping key of aws-lc-rs's
    /// `key_wrap::AES_256` is AES-256-KW for `wrap`, AES-256-KWP for `wrap_with_padding`.
    #[serde(default)]
    asset_by_method: BTreeMap<String, String>,
    #[serde(flatten)]
    algo: Algo,
}

#[derive(Debug, Deserialize)]
struct FnRaw {
    #[serde(rename = "crate")]
    krate: OneOrMany,
    path: String,
    #[serde(default)]
    self_type: Option<String>,
    #[serde(default)]
    params: BTreeMap<String, Param>,
    #[serde(flatten)]
    algo: Algo,
}

/// A static or function entry. For functions with `self_type`, the entry's crate is the crate
/// of that type, and the callee may be anywhere (`<Argon2 as Default>::default`).
#[derive(Debug)]
pub struct PatternEntry {
    pub krates: Vec<String>,
    pub pattern: Regex,
    /// For statics: regex the path inside the crate must match.
    pub module: Option<Regex>,
    pub self_type: Option<String>,
    pub params: BTreeMap<String, Param>,
    /// For statics: method -> asset name template (`asset_by_method`).
    pub asset_by_method: BTreeMap<String, String>,
    pub algo: Algo,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtocolRaw {
    #[serde(rename = "crate")]
    krate: String,
    path: String,
    name: String,
    #[serde(rename = "type")]
    kind: String,
    versions: BTreeMap<String, String>,
    suites: String,
    groups: String,
}

/// A call that configures a protocol stack (`rustls::ClientConfig::builder`).
#[derive(Debug)]
pub struct ProtocolEntry {
    pub krate: String,
    pub pattern: Regex,
    pub name: String,
    /// CycloneDX `protocolProperties.type`.
    pub kind: String,
    /// version -> feature of the protocol crate that enables it ("" = always).
    pub versions: BTreeMap<String, String>,
    /// Names of the protocol crate's statics that are cipher suites, and key-exchange groups.
    pub suites: Regex,
    pub groups: Regex,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UseEntry {
    pub function: String,
    pub methods: Vec<String>,
    #[serde(default)]
    pub primitives: Vec<String>,
}

#[derive(Debug)]
pub struct Kb {
    pub version: String,
    pub crates: Vec<CrateEntry>,
    pub types: Vec<TypeEntry>,
    pub statics: Vec<PatternEntry>,
    pub fns: Vec<PatternEntry>,
    pub uses: Vec<UseEntry>,
    pub protocols: Vec<ProtocolEntry>,
    pub roles: Vec<RoleEntry>,
    pub sources: Vec<SourceEntry>,
    pub passthroughs: Vec<PassthroughEntry>,
    /// Random generators built from a seed (`StdRng::seed_from_u64(42)`): their output is as
    /// predictable as the seed. `kind` is unused.
    pub seeded: Vec<SourceEntry>,
    pub produces: Vec<ProducesEntry>,
    pub operations: Vec<OperationEntry>,
    pub boundaries: Vec<BoundaryEntry>,
    pub enums: Vec<EnumEntry>,
    /// Packages without `[[crate]]` entries that are cryptographic although their metadata does
    /// not say so (age-core), and crypto-adjacent helpers whose metadata says cryptography.
    pub unmodelled_crypto: Vec<String>,
    pub unmodelled_support: Vec<String>,
    /// Types of modelled crates that compute no cryptography (rand's `SmallRng`), by name.
    pub not_crypto: Vec<String>,
    /// The crates of the build being analysed, by name: the package each one comes from. Set
    /// once per run (`bind_crates`); crate names alone are ambiguous (the package md-5's
    /// library is named `md5`, like the package md5's).
    crate_packages: std::sync::RwLock<std::collections::HashMap<String, String>>,
}

/// `cryptoFunctions` values CycloneDX 1.7 accepts.
const FUNCTIONS: &[&str] = &[
    "generate",
    "keygen",
    "encrypt",
    "decrypt",
    "digest",
    "tag",
    "keyderive",
    "sign",
    "verify",
    "encapsulate",
    "decapsulate",
    "other",
    "unknown",
];
/// `primitive` values CycloneDX 1.7 accepts.
const PRIMITIVES: &[&str] = &[
    "drbg",
    "mac",
    "block-cipher",
    "stream-cipher",
    "signature",
    "hash",
    "pke",
    "xof",
    "kdf",
    "key-agree",
    "kem",
    "ae",
    "combiner",
    "key-wrap",
    "other",
    "unknown",
];

/// `algorithmFamily` values CycloneDX 1.7 accepts (the enum of `cryptography-defs.schema.json`,
/// which lags the registry: it has no `TLS-PRF`).
static FAMILY_ENUM: std::sync::LazyLock<Vec<String>> = std::sync::LazyLock::new(|| {
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schema/cryptography-defs.schema.json"
    ))
    .expect("cryptography-defs.schema.json");
    schema["definitions"]["algorithmFamiliesEnum"]["enum"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|f| f.as_str().map(str::to_string))
        .collect()
});

/// Can `algorithmFamily` say this family? A registry family the 1.7 enum lacks (`TLS-PRF`)
/// cannot: the field is optional, and the family goes in a property instead.
pub fn in_family_enum(family: &str) -> bool {
    FAMILY_ENUM.iter().any(|f| f == family)
}

fn de_req<'de, D: serde::Deserializer<'de>>(d: D) -> Result<semver::VersionReq, D::Error> {
    let s = String::deserialize(d)?;
    semver::VersionReq::parse(&s).map_err(serde::de::Error::custom)
}

impl Kb {
    pub fn seed() -> Result<Kb> {
        Kb::parse(SEED).context("parsing the built-in knowledge base")
    }

    pub fn parse(text: &str) -> Result<Kb> {
        let raw: Raw = toml::from_str(text)?;
        let pat = |s: &str| Regex::new(s).with_context(|| format!("bad regex {s:?}"));
        let kb = Kb {
            version: raw.version,
            crates: raw.crates,
            types: raw.types,
            statics: raw
                .statics
                .into_iter()
                .map(|s| {
                    Ok(PatternEntry {
                        krates: s.krate.into_vec(),
                        pattern: pat(&s.name)?,
                        module: s.module.as_deref().map(pat).transpose()?,
                        self_type: None,
                        params: BTreeMap::new(),
                        asset_by_method: s.asset_by_method,
                        algo: s.algo,
                    })
                })
                .collect::<Result<_>>()?,
            fns: raw
                .fns
                .into_iter()
                .map(|s| {
                    Ok(PatternEntry {
                        krates: s.krate.into_vec(),
                        pattern: pat(&s.path)?,
                        module: None,
                        self_type: s.self_type,
                        params: s.params,
                        asset_by_method: BTreeMap::new(),
                        algo: s.algo,
                    })
                })
                .collect::<Result<_>>()?,
            uses: raw.uses,
            protocols: raw
                .protocols
                .into_iter()
                .map(|p| {
                    Ok(ProtocolEntry {
                        krate: p.krate,
                        pattern: pat(&p.path)?,
                        name: p.name,
                        kind: p.kind,
                        versions: p.versions,
                        suites: pat(&p.suites)?,
                        groups: pat(&p.groups)?,
                    })
                })
                .collect::<Result<_>>()?,
            roles: raw
                .roles
                .into_iter()
                .map(|r| {
                    let args = r
                        .args
                        .into_iter()
                        .map(|(k, v)| {
                            Ok((
                                k.parse::<usize>()
                                    .with_context(|| format!("role index {k:?}"))?,
                                v,
                            ))
                        })
                        .collect::<Result<_>>()?;
                    Ok(RoleEntry {
                        pattern: pat(&r.path)?,
                        args,
                    })
                })
                .collect::<Result<_>>()?,
            sources: raw
                .sources
                .into_iter()
                .map(|s| {
                    Ok(SourceEntry {
                        kind: s.kind,
                        pattern: pat(&s.path)?,
                    })
                })
                .collect::<Result<_>>()?,
            passthroughs: raw
                .passthroughs
                .into_iter()
                .map(|p| {
                    Ok(PassthroughEntry {
                        pattern: pat(&p.path)?,
                        args: p.args,
                    })
                })
                .collect::<Result<_>>()?,
            produces: raw
                .produces
                .into_iter()
                .map(|p| {
                    Ok(ProducesEntry {
                        pattern: pat(&p.path)?,
                        role: p.role,
                        method: p.method,
                    })
                })
                .collect::<Result<_>>()?,
            seeded: raw
                .seeded
                .into_iter()
                .map(|s| {
                    Ok(SourceEntry {
                        kind: s.kind,
                        pattern: pat(&s.path)?,
                    })
                })
                .collect::<Result<_>>()?,
            operations: raw
                .operations
                .into_iter()
                .map(|o| {
                    Ok(OperationEntry {
                        krates: o.krate.into_vec(),
                        pattern: pat(&o.path)?,
                        primitive: o.primitive,
                        function: o.function,
                        algorithm: o.algorithm,
                        self_type: o.self_type,
                        setup: o.setup,
                    })
                })
                .collect::<Result<_>>()?,
            boundaries: raw
                .boundaries
                .into_iter()
                .map(|b| {
                    Ok(BoundaryEntry {
                        pattern: Regex::new(&b.path)
                            .with_context(|| format!("[[boundary]] path {:?}", b.path))?,
                        krate: b.krate,
                        function: b.function,
                        algorithm: b.algorithm,
                        key: b.key,
                        enumeration: b.enumeration,
                    })
                })
                .collect::<Result<_>>()?,
            enums: raw
                .enums
                .into_iter()
                .map(|e| EnumEntry {
                    krate: e.krate,
                    name: e.name,
                    variants: e.variants,
                })
                .collect(),
            unmodelled_crypto: raw.unmodelled.crypto,
            unmodelled_support: raw.unmodelled.support,
            not_crypto: raw.unmodelled.not_crypto,
            crate_packages: Default::default(),
        };
        kb.validate()?;
        Ok(kb)
    }

    fn validate(&self) -> Result<()> {
        // a `[[type]]` module restriction is matched later, by path; it must compile now
        for t in &self.types {
            if let Some(m) = &t.module {
                Regex::new(m).with_context(|| format!("[[type]] {}: module {m:?}", t.name))?;
            }
        }
        for b in &self.boundaries {
            if !self.enums.iter().any(|e| e.name == b.enumeration) {
                bail!("[[boundary]] {}: no [[enum]] {}", b.pattern, b.enumeration);
            }
            if !FUNCTIONS.contains(&b.function.as_str()) {
                bail!(
                    "[[boundary]] {}: use {:?} is not a CycloneDX value",
                    b.pattern,
                    b.function
                );
            }
        }
        let algos = self
            .types
            .iter()
            .map(|t| &t.algo)
            .chain(self.statics.iter().map(|s| &s.algo))
            .chain(self.fns.iter().map(|f| &f.algo))
            .chain(
                self.enums
                    .iter()
                    .flat_map(|e| e.variants.values().map(|v| &v.algo)),
            );
        for a in algos {
            // a family of the 1.7 enum, or one the registry has added since (written as a
            // property); key material has no algorithmProperties, its family is a property
            // a random generator the registry has no family for (`OS-RNG`) names none
            let unnamed_drbg = a.primitive == "drbg" && a.family.is_empty();
            if a.material.is_none()
                && !unnamed_drbg
                && !in_family_enum(&a.family)
                && !registry::family(&a.family)
            {
                bail!(
                    "{}: algorithm family {:?} is neither a CycloneDX 1.7 algorithmFamily nor \
                     a Cryptography Registry family",
                    a.asset,
                    a.family
                );
            }
            if !PRIMITIVES.contains(&a.primitive.as_str()) {
                bail!(
                    "{}: primitive {:?} is not a CycloneDX value",
                    a.asset,
                    a.primitive
                );
            }
            for f in &a.functions {
                if !FUNCTIONS.contains(&f.as_str()) {
                    bail!("{}: cryptoFunction {f:?} is not a CycloneDX value", a.asset);
                }
            }
            // what a `[[fn]]` call does (`use = "keygen"`) is a cryptoFunction too
            if let Some(u) = &a.implied_use
                && !FUNCTIONS.contains(&u.as_str())
            {
                bail!("{}: use {u:?} is not a CycloneDX cryptoFunction", a.asset);
            }
        }
        for f in &self.fns {
            if f.params.values().any(|p| p.required) {
                bail!(
                    "{}: `required` is for [[type]] parameters; a [[fn]] entry names its asset whatever resolves",
                    f.algo.asset
                );
            }
        }
        for t in &self.types {
            if t.params.values().any(|p| p.value.is_some()) {
                bail!(
                    "{}: a fixed `value` is for [[fn]] parameters (a constructor's defaults)",
                    t.algo.asset
                );
            }
        }
        for u in &self.uses {
            if !FUNCTIONS.contains(&u.function.as_str()) {
                bail!("use {:?} is not a CycloneDX cryptoFunction", u.function);
            }
        }
        for o in &self.operations {
            // `encrypt or decrypt`: a call that does either (`apply_keystream`)
            if !o.function.split(" or ").all(|f| FUNCTIONS.contains(&f)) {
                bail!(
                    "[[operation]] {}: use {:?} is not a CycloneDX cryptoFunction",
                    o.pattern,
                    o.function
                );
            }
            if !PRIMITIVES.contains(&o.primitive.as_str()) {
                bail!(
                    "[[operation]] {}: primitive {:?} is not a CycloneDX value",
                    o.pattern,
                    o.primitive
                );
            }
        }
        let known: Vec<String> = self.crates.iter().map(|c| c.crate_name()).collect();
        let entry_crates = self
            .types
            .iter()
            .map(|t| &t.krate)
            .chain(self.statics.iter().flat_map(|s| &s.krates))
            .chain(self.fns.iter().flat_map(|f| &f.krates))
            .chain(self.protocols.iter().map(|p| &p.krate))
            .chain(self.operations.iter().flat_map(|o| &o.krates));
        for k in entry_crates {
            if !known.contains(k) {
                bail!("entry for crate {k:?}, which has no [[crate]] entry");
            }
        }
        Ok(())
    }

    pub fn crate_by_package(
        &self,
        package: &str,
        version: &semver::Version,
    ) -> Option<&CrateEntry> {
        self.crates
            .iter()
            .find(|c| c.package == package && c.versions.matches(version))
    }

    /// The `[[crate]]` entry of a crate of the build, any version. Once the build's crates are
    /// bound (`bind_crates`), by the package the crate comes from; before, by the crate name the
    /// entry's package would have.
    pub fn crate_by_name(&self, crate_name: &str) -> Option<&CrateEntry> {
        let bound = self
            .crate_packages
            .read()
            .unwrap_or_else(|e| e.into_inner());
        if bound.is_empty() {
            return self.crates.iter().find(|c| c.crate_name() == crate_name);
        }
        let package = bound.get(crate_name)?;
        self.crates.iter().find(|c| &c.package == package)
    }

    /// Records the package each crate of the build comes from (crate name -> package name).
    pub fn bind_crates(&self, crates: std::collections::HashMap<String, String>) {
        *self
            .crate_packages
            .write()
            .unwrap_or_else(|e| e.into_inner()) = crates;
    }

    /// Is a package without a `[[crate]]` entry cryptographic, from its `Cargo.toml` metadata:
    /// a `cryptography` category or a crypto keyword, or the `[unmodelled]` crypto list (for
    /// packages whose metadata says nothing)? Among those, encodings, parsers, memory wipers
    /// and the `[unmodelled]` support list are support crates; the list never makes a package
    /// cryptographic by itself.
    pub fn unmodelled(
        &self,
        package: &str,
        categories: &[String],
        keywords: &[String],
    ) -> Option<Unmodelled> {
        if self.unmodelled_crypto.iter().any(|p| p == package) {
            return Some(Unmodelled::Crypto);
        }
        let crypto = categories.iter().any(|c| c == "cryptography")
            || keywords.iter().any(|k| {
                matches!(
                    k.as_str(),
                    "crypto" | "cryptography" | "encryption" | "tls" | "certificate" | "x509"
                )
            });
        if !crypto {
            return None;
        }
        let support = self.unmodelled_support.iter().any(|p| p == package)
            || categories.iter().any(|c| {
                matches!(
                    c.as_str(),
                    "encoding" | "parser-implementations" | "memory-management"
                )
            });
        Some(if support {
            Unmodelled::Support
        } else {
            Unmodelled::Crypto
        })
    }

    /// The boundary model of a call (`[[boundary]]`), by crate name and path inside it.
    pub fn boundary(&self, krate: &str, path: &str) -> Option<&BoundaryEntry> {
        self.boundaries
            .iter()
            .find(|b| b.krate == krate && b.pattern.is_match(path))
    }

    /// The `[[operation]]` entry of a callee: its crate name and its path inside the crate,
    /// generic arguments removed (`digest::Context::update`).
    pub fn operation(&self, krate: &str, path: &str) -> Option<&OperationEntry> {
        self.operations
            .iter()
            .find(|o| o.krates.iter().any(|k| k == krate) && o.pattern.is_match(path))
    }

    /// The use a call to `method` makes of an asset with `primitive`, if it is one. A method
    /// listed under several uses makes one of them, and the call alone does not say which:
    /// `apply_keystream` encrypts or decrypts (`encrypt or decrypt`).
    pub fn use_of(&self, method: &str, primitive: &str) -> Option<String> {
        let all: Vec<&str> = self
            .uses
            .iter()
            .filter(|u| {
                u.methods.iter().any(|m| m == method)
                    && (u.primitives.is_empty() || u.primitives.iter().any(|p| p == primitive))
            })
            .map(|u| u.function.as_str())
            .collect();
        (!all.is_empty()).then(|| all.join(" or "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_parses_and_validates() {
        let kb = Kb::seed().unwrap();
        assert!(kb.crate_by_name("aes_gcm").is_some());
        assert_eq!(kb.use_of("update", "mac").as_deref(), Some("tag"));
        assert_eq!(kb.use_of("update", "hash").as_deref(), Some("digest"));
        assert_eq!(kb.use_of("new_from_slice", "ae"), None);
        // the same operation either way
        assert_eq!(
            kb.use_of("apply_keystream", "stream-cipher").as_deref(),
            Some("encrypt or decrypt")
        );
        assert_eq!(
            kb.use_of("decrypt_blinded", "pke").as_deref(),
            Some("decrypt")
        );
    }

    #[test]
    fn operations_match_by_crate_and_path() {
        let kb = Kb::seed().unwrap();
        let o = kb.operation("ring", "digest::digest").unwrap();
        assert_eq!(
            (o.primitive.as_str(), o.function.as_str()),
            ("hash", "digest")
        );
        assert!(kb.operation("ring", "digest::Context::new").is_none());
        assert!(kb.operation("sha2", "digest::digest").is_none());
        let seal = kb
            .operation(
                "aws_lc_rs",
                "aead::less_safe_key::LessSafeKey::seal_in_place_append_tag",
            )
            .unwrap();
        assert_eq!(seal.function, "encrypt");
        let bad = SEED.replacen(
            "use = \"digest\"\nalgorithm",
            "use = \"hashing\"\nalgorithm",
            1,
        );
        assert!(Kb::parse(&bad).is_err());
    }

    #[test]
    fn unmodelled_packages_from_metadata() {
        let kb = Kb::seed().unwrap();
        let v = |xs: &[&str]| xs.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        let crypto = Some(Unmodelled::Crypto);
        let support = Some(Unmodelled::Support);
        // ml-kem: a cryptography category; der: an encoding too; rustls-platform-verifier:
        // keywords only; age-core: no metadata, listed; block-buffer: listed as support
        assert_eq!(
            kb.unmodelled("ml-kem", &v(&["cryptography", "no-std"]), &v(&[])),
            crypto
        );
        assert_eq!(
            kb.unmodelled("der", &v(&["cryptography", "encoding"]), &v(&[])),
            support
        );
        assert_eq!(
            kb.unmodelled("x", &v(&[]), &v(&["tls", "certificate"])),
            crypto
        );
        assert_eq!(kb.unmodelled("age-core", &v(&[]), &v(&[])), crypto);
        assert_eq!(
            kb.unmodelled("block-buffer", &v(&["cryptography"]), &v(&[])),
            support
        );
        assert_eq!(
            kb.unmodelled("serde", &v(&["encoding"]), &v(&["serde"])),
            None
        );
    }

    #[test]
    fn bound_crates_are_looked_up_by_package() {
        let kb = Kb::seed().unwrap();
        // before binding, by name: the package md5 (0.7) has the crate md5
        assert_eq!(
            kb.crate_by_name("md5").map(|c| c.package.as_str()),
            Some("md5")
        );
        // in a build whose crate md5 comes from the package md-5, it is md-5's entry
        kb.bind_crates([("md5".to_string(), "md-5".to_string())].into());
        assert_eq!(
            kb.crate_by_name("md5").map(|c| c.package.as_str()),
            Some("md-5")
        );
        assert!(kb.crate_by_name("ring").is_none());
    }

    #[test]
    fn rejects_values_outside_the_cyclonedx_enums() {
        let bad = SEED.replace("primitive = \"ae\"", "primitive = \"aead\"");
        assert!(Kb::parse(&bad).is_err());
    }

    #[test]
    fn rejects_a_family_outside_cyclonedx_and_the_registry() {
        let bad = SEED.replacen("family = \"HKDF\"", "family = \"NOT-A-FAMILY\"", 1);
        let err = Kb::parse(&bad).unwrap_err().to_string();
        assert!(err.contains("NOT-A-FAMILY"), "{err}");
        // a registry family the 1.7 enum lacks is accepted, and not written as algorithmFamily
        let ok = SEED.replacen("family = \"HKDF\"", "family = \"TLS-PRF\"", 1);
        assert!(Kb::parse(&ok).is_ok());
        assert!(!in_family_enum("TLS-PRF") && in_family_enum("HKDF"));
    }

    #[test]
    fn rejects_a_fn_use_outside_the_cyclonedx_enum() {
        assert!(SEED.contains("use = \"keygen\""));
        let bad = SEED.replacen("use = \"keygen\"", "use = \"keygeneration\"", 1);
        let err = Kb::parse(&bad).unwrap_err().to_string();
        assert!(err.contains("keygeneration"), "{err}");
    }
}
