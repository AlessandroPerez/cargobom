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

/// A call whose result carries the value of some of its arguments only: the data, not the
/// message of `anyhow::Context::context(result, "msg")` or the engine of
/// `Engine::decode(&STANDARD, input)`.
#[derive(Debug)]
pub struct PassthroughEntry {
    pub pattern: Regex,
    /// Value argument indices whose origins the result has (the receiver is argument 0).
    pub args: Vec<usize>,
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
#[derive(Clone, Debug, Deserialize)]
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
    /// What a call matched by a `[[fn]]` entry does when its method is not a listed use
    /// (`keygen` for `RsaPrivateKey::new`). Without it such a call sets the asset up.
    #[serde(default, rename = "use")]
    pub implied_use: Option<String>,
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
        };
        kb.validate()?;
        Ok(kb)
    }

    fn validate(&self) -> Result<()> {
        let algos = self
            .types
            .iter()
            .map(|t| &t.algo)
            .chain(self.statics.iter().map(|s| &s.algo))
            .chain(self.fns.iter().map(|f| &f.algo));
        for a in algos {
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
        }
        for u in &self.uses {
            if !FUNCTIONS.contains(&u.function.as_str()) {
                bail!("use {:?} is not a CycloneDX cryptoFunction", u.function);
            }
        }
        let known: Vec<String> = self.crates.iter().map(|c| c.crate_name()).collect();
        let entry_crates = self
            .types
            .iter()
            .map(|t| &t.krate)
            .chain(self.statics.iter().flat_map(|s| &s.krates))
            .chain(self.fns.iter().flat_map(|f| &f.krates))
            .chain(self.protocols.iter().map(|p| &p.krate));
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

    pub fn crate_by_name(&self, crate_name: &str) -> Option<&CrateEntry> {
        self.crates.iter().find(|c| c.crate_name() == crate_name)
    }

    /// Crates the driver must report sites for.
    pub fn crate_names(&self) -> Vec<String> {
        self.crates.iter().map(|c| c.crate_name()).collect()
    }

    /// Crates whose bodies the reachability walk does not enter.
    pub fn stop_crate_names(&self) -> Vec<String> {
        self.crates
            .iter()
            .filter(|c| c.role != Role::Protocol)
            .map(|c| c.crate_name())
            .collect()
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
    fn rejects_values_outside_the_cyclonedx_enums() {
        let bad = SEED.replace("primitive = \"ae\"", "primitive = \"aead\"");
        assert!(Kb::parse(&bad).is_err());
    }
}
