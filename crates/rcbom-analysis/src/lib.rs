//! Layer 2 on the stable side: match the driver's facts against the knowledge base, decide
//! tiers (reachable from a workspace entry point, or only present in a compiled crate), recover
//! parameters and composition from generic arguments, classify uses by the method called, and
//! assemble a CycloneDX 1.7 CBOM together with Layer 1.
mod assets;
mod boundary;
mod cbom;
mod coverage;
mod engine;
mod links;
mod matcher;
mod pointers;
mod provenance;
mod run;
mod search;
mod sites;
mod unknowns;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use rcbom_facts::{CrateFacts, FACTS_VERSION, OwnerKind, Site, Target, Tier};
use rcbom_kb::{Algo, Kb, Role};
use rcbom_manifest::Manifest;

pub use cbom::{RunInfo, to_cyclonedx};
pub use coverage::{Checked, Coverage};
pub use matcher::static_names;
use matcher::{
    Match, match_constructor, match_fn, match_fn_with, match_protocol, match_static, match_types,
};
pub use run::analyze;

use assets::*;
use engine::*;
use sites::*;
use unknowns::*;

/// What an occurrence is evidence of.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    /// A call into a crypto API (`Aead::encrypt`, `x25519_dalek::..::diffie_hellman`).
    Call,
    /// A crypto type chosen as a generic argument of the user's own code (`seal::<Aes256Gcm>`).
    Instantiation,
    /// A static algorithm descriptor named in code (`&ring::aead::AES_256_GCM`).
    Static,
    /// A static named in code that leads to algorithm descriptors (`DIGESTS`, a rustls suite).
    ViaStatic,
    /// The asset is part of another one used here (the SHA-256 inside `Hmac<Sha256>`).
    Component,
}

#[derive(Clone, Debug)]
pub struct Occurrence {
    pub location: String,
    pub line: usize,
    /// 0-based character column (CycloneDX `offset`, CBOMkit convention).
    pub offset: usize,
    pub symbol: String,
    pub kind: Kind,
    pub tier: Tier,
    pub function: Option<String>,
    /// Enclosing item.
    pub owner: String,
    /// The macro the code comes from, when it was called at this position.
    pub macro_tag: Option<(rcbom_facts::MacroKind, String)>,
    /// The source line of the position, trimmed, when the driver had it.
    pub line_text: Option<String>,
    /// The source text the position names, when the driver had it.
    pub code: Option<String>,
    pub detail: Vec<String>,
    /// Package the source file belongs to.
    pub package: (String, String),
    /// Key material arguments of the call and where they come from: (role, kind), e.g.
    /// ("nonce", "hard-coded").
    pub provenance: Vec<(String, String)>,
    /// The knowledge-base note of the entry this occurrence matched (`QUIC header protection`).
    pub note: Option<String>,
    /// Found only by the per-item scan of a generic function's body, not in an instance of it:
    /// what its type parameters choose is not known there.
    pub generic_body: bool,
    /// The calls that created the generic instance it is in, innermost first (location, line,
    /// 0-based column), as the `instantiated by` details cite them.
    pub via: Vec<(String, usize, usize)>,
    /// The artifacts whose walk reaches it (`bin rage-keygen`, `lib rcgen`); none when it is
    /// not reachable.
    pub artifacts: BTreeSet<String>,
    /// The calls it stands for (`Site::call`): the boundary check's edges it accounts for.
    pub calls: BTreeSet<rcbom_facts::CallId>,
}

#[derive(Clone, Debug)]
pub struct Asset {
    /// Name, primitive and material together (`matcher::asset_key`).
    pub key: String,
    pub name: String,
    pub algo: Algo,
    /// Parameter values; several when occurrences disagree.
    pub params: BTreeMap<String, BTreeSet<String>>,
    pub occurrences: Vec<Occurrence>,
    /// Keys of component assets.
    pub components: BTreeSet<String>,
    /// Packages (name, version) implementing it.
    pub providers: BTreeSet<(String, String)>,
    /// The notes of the knowledge-base entries that matched it (`None`: an entry without).
    pub entry_notes: BTreeSet<Option<String>>,
}

/// How a package's crypto code is used, from Layer 2's point of view.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Usage {
    DeclaredNotUsed,
    Present,
    Reachable,
}

/// A protocol configured by the program (TLS through rustls), with what the reachable
/// configuration offers.
#[derive(Clone, Debug)]
pub struct Protocol {
    pub name: String,
    /// CycloneDX `protocolProperties.type`.
    pub kind: String,
    pub versions: Vec<String>,
    pub suites: Vec<String>,
    pub groups: Vec<String>,
    /// Backend packages, comma-separated: the providers the code names, else those of the
    /// reachable cipher suites, else what Layer 1's features select.
    pub backend: Option<String>,
    pub occurrences: Vec<Occurrence>,
    /// The protocol crate's package.
    pub package: Option<(String, String)>,
    /// Providers named by the program's reachable calls, and by any of its calls.
    named_backends: BTreeSet<String>,
    named_present: BTreeSet<String>,
    suite_backends: BTreeSet<String>,
    feature_backends: Vec<String>,
}

pub struct Analysis {
    pub assets: BTreeMap<String, Asset>,
    pub protocols: BTreeMap<String, Protocol>,
    pub usage: HashMap<(String, String), Usage>,
    pub notes: Vec<String>,
    pub instances: usize,
    /// The artifacts walked (`bin rage`, `bin rage-keygen`, `lib rcgen`), sorted.
    pub artifacts: Vec<String>,
    /// Layer 2 ran: without it (`--manifest-only`) nothing is known about use.
    pub layer2: bool,
    /// The boundary check: the walked code's calls into crypto packages, and whether each is
    /// cited (`coverage`).
    pub coverage: Coverage,
}

/// The facts files in `dir` of the cargo units `units` (file stems `<crate><unit>`), sorted by
/// crate, so that the result never depends on the order the file system lists them in: a crate
/// compiled by an earlier build, with other dependencies or features, leaves a file under
/// another unit id that must not be read.
pub fn load_facts(
    dir: &Path,
    units: &std::collections::BTreeSet<String>,
) -> Result<Vec<CrateFacts>> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)?
        .map(|e| e.map(|e| e.path()))
        .collect::<std::io::Result<_>>()?;
    paths.sort();
    let mut out = Vec::new();
    for p in paths {
        let stem = p.file_stem().map(|s| s.to_string_lossy().to_string());
        if !stem.as_ref().is_some_and(|s| units.contains(s)) {
            continue;
        }
        if p.extension().is_some_and(|x| x == "json") {
            let f: CrateFacts = serde_json::from_slice(&std::fs::read(&p)?)
                .map_err(|e| anyhow::anyhow!("{}: {e}", p.display()))?;
            if f.facts_version != FACTS_VERSION {
                bail!(
                    "{}: facts version {} (expected {FACTS_VERSION}); rebuild the driver",
                    p.display(),
                    f.facts_version
                );
            }
            out.push(f);
        }
    }
    out.sort_by(|a, b| {
        (&a.krate.name, &a.krate.stable_id, &a.krate.unit).cmp(&(
            &b.krate.name,
            &b.krate.stable_id,
            &b.krate.unit,
        ))
    });
    Ok(out)
}

struct Ctx<'a> {
    kb: &'a Kb,
    /// (crate name, stable id) -> (package, version)
    crates: HashMap<(String, String), (String, String)>,
    /// The program's own packages (members, path dependencies), by (name, version): never
    /// the crates the knowledge base describes.
    local: BTreeSet<(String, String)>,
    /// Call sites by (owner, file, line, column): the site of a call an argument comes from.
    calls: HashMap<CallKey<'a>, &'a Site>,
    /// What the calls a constructor's value is passed to matched, by the constructor's call
    /// site: `Params::new(15, 8, 1, 32)` set up for `scrypt(.., &p, out)` with a 64-byte `out`
    /// is scrypt-32768-8-1-64, as the call is.
    consumers: std::cell::RefCell<HashMap<CallKey<'a>, Vec<Match>>>,
    /// Filled while sites are matched: each constructor call linked to the call its value is
    /// passed to, with what that call matched (first pass), to become `consumers` (second).
    links: std::cell::RefCell<HashMap<CallKey<'a>, Vec<Match>>>,
    /// Values across functions (`links`): fields, results, parameters, mutable statics.
    flow: links::LinkIndex,
    /// The field names of the knowledge-base crates' structs, by path (`CrateFacts::fields`).
    fields: HashMap<String, Vec<String>>,
    /// The variants of their field-less enums (name, discriminant), by path.
    variants: HashMap<String, Vec<(String, i128)>>,
    /// The points-to analysis' answers (`RCBOM_PTA`), by the position of the call (absolute
    /// file, line, column): one per copy of the calling body it solved.
    pta: HashMap<(PathBuf, usize, usize), Vec<&'a rcbom_facts::PtaCall>>,
    /// The types of the knowledge base's descriptors it read (`ring::digest::Algorithm`).
    descriptor_types: HashSet<String>,
    /// Crates of cryptographic packages the knowledge base does not model (Layer 1's
    /// `unmodelled`): ml-kem, p256, sha3, md-5 (`md5`), by (crate name, stable id): two
    /// packages may name their library alike.
    unmodelled: HashSet<(String, String)>,
    /// The walked calls into crypto packages (`Reach::boundary`) by position (file as the
    /// site's, line, column): whether every one there runs on behalf of the crypto layer (subtle's
    /// `CtOption::map` instantiated by primeorder), as the boundary check takes it.
    behalf: HashMap<(String, usize, usize), bool>,
}

type CallKey<'a> = (&'a str, &'a str, usize, usize);

/// (match, kind, use, symbol, details, reached only from data no entry point reaches)
type SiteMatch = (Match, Kind, Option<String>, String, Vec<String>, bool);

/// The detail of a call whose parameters are not its receiver's (`verify_password`): it is
/// not merged into the receiver's constructor on the same line.
const OWN_PARAMS: &str = ": its own parameters, not its receiver's";

/// (primitive, use, reason, providing packages) of an operation whose algorithm is not named.
type Unresolved = (String, String, String, Vec<(String, String)>);

/// What the points-to analysis (`RCBOM_PTA`) answers at a call given a descriptor by reference
/// (an argument that is a pointer to a descriptor's type), over the copies of the calling body
/// it reached from the roots.
struct PtaVerdict {
    /// The descriptors the knowledge base names that the argument may point to.
    found: Vec<rcbom_facts::DefRef>,
    /// Nothing else: in no copy may the argument point to a value of code the engine does not
    /// follow, to another object (a value built at run time), or to a static the knowledge base
    /// does not name, and every copy has an answer.
    complete: bool,
}

/// The name of the asset of operations whose algorithm the analysis does not find; its family
/// is empty.
pub const UNKNOWN: &str = "unknown";

#[cfg(test)]
mod tests {
    use super::{short, table_members};
    use rcbom_facts::{CrateRef, DefRef};

    fn def(krate: &str, path: &str) -> DefRef {
        DefRef {
            krate: CrateRef {
                name: krate.into(),
                stable_id: "0".into(),
            },
            path: path.into(),
            id: path.into(),
        }
    }

    /// A value read from a static's data is one of its descriptors only when the data is a
    /// list of them (R4.3) or holds one; a field read of a table of several, or a table of
    /// other statics, is the unknown, never every descriptor of the data.
    #[test]
    fn a_table_gives_members_only_as_a_list_of_descriptors() {
        let kb = rcbom_kb::Kb::seed().unwrap();
        let supported = |_: &CrateRef| true;
        let sha256 = def("ring", "ring::digest::SHA256");
        let sha384 = def("ring", "ring::digest::SHA384");
        let base = def("app", "app::BASE");
        let fix = def("app", "app::FIX");
        let list = def("app", "app::DIGESTS");
        let refs = def("app", "app::AREF");
        let nested = def("app", "app::TT");
        let edges = |id: &str| match id {
            "app::DIGESTS" => vec![sha256.clone(), sha384.clone()],
            "app::TT" => vec![list.clone()],
            "app::AREF" => vec![base.clone(), fix.clone()],
            "app::BASE" => vec![sha256.clone()],
            "app::FIX" => vec![sha384.clone()],
            _ => Vec::new(),
        };
        let closure = |id: &str| {
            let mut out = vec![def("app", id)];
            let mut stack = edges(id);
            while let Some(d) = stack.pop() {
                stack.extend(edges(&d.id));
                out.push(d);
            }
            out
        };
        // `BASE` and `FIX` are structs (their initializers store fields); the lists store none
        let fields = |id: &str| matches!(id, "app::BASE" | "app::FIX");
        let no_fields = |_: &str| false;
        let paths = |r: Result<Vec<DefRef>, String>| -> Result<Vec<String>, String> {
            r.map(|v| {
                let mut p: Vec<String> = v.into_iter().map(|d| d.path).collect();
                p.sort();
                p
            })
        };
        // `DIGESTS[i]`: any element
        assert_eq!(
            paths(table_members(
                &kb, &list, false, &closure, &edges, &no_fields, &supported
            )),
            Ok(vec![
                "ring::digest::SHA256".to_string(),
                "ring::digest::SHA384".to_string()
            ])
        );
        // `TT[0][i]`, a list of lists: any element
        assert_eq!(
            paths(table_members(
                &kb, &nested, false, &closure, &edges, &no_fields, &supported
            )),
            Ok(vec![
                "ring::digest::SHA256".to_string(),
                "ring::digest::SHA384".to_string()
            ])
        );
        // `DIGESTS[i].h`-like field read, and `AREF[i]` of structs: not followed
        assert!(table_members(&kb, &list, true, &closure, &edges, &no_fields, &supported).is_err());
        assert!(table_members(&kb, &refs, false, &closure, &edges, &fields, &supported).is_err());
        // one algorithm in the data: that one
        assert_eq!(
            paths(table_members(
                &kb, &base, true, &closure, &edges, &fields, &supported
            )),
            Ok(vec!["ring::digest::SHA256".to_string()])
        );
    }

    #[test]
    fn short_names_keep_the_item() {
        assert_eq!(
            short("micro::seal::<aes_gcm::AesGcm<aes_gcm::aes::Aes256, typenum::U12>>"),
            "micro::seal::<..>"
        );
        assert_eq!(
            short(
                "rusty_paseto::core::paseto_impl::v4_public::<impl rusty_paseto::core::Paseto<'_, V4, Public>>::try_sign"
            ),
            "rusty_paseto::core::paseto_impl::v4_public::<impl rusty_paseto::core::Paseto<'_, V4, Public>>::try_sign"
        );
        assert_eq!(
            short(
                "<rcgen::KeyPair as core::convert::TryFrom<&rustls_pki_types::PrivateKeyDer<'_>>>::try_from"
            ),
            "<rcgen::KeyPair as core::convert::TryFrom<&rustls_pki_types::PrivateKeyDer<'_>>>::try_from"
        );
        assert_eq!(
            short(
                "<rcgen::key_pair::KeyPair as rcgen::key_pair::SigningKey>::sign_with_a_long_name"
            ),
            "<rcgen::key_pair::KeyPair as rcgen::key_pair::SigningKey>::sign_with_a_long_name"
        );
        assert_eq!(
            short(
                "hyper_rustls::connector::builder::ConnectorBuilder::<WantsTlsConfig>::with_native_roots"
            ),
            "hyper_rustls::connector::builder::ConnectorBuilder::<..>::with_native_roots"
        );
        assert_eq!(
            short("a_crate::module::apply::<fn(&[u8]) -> std::vec::Vec<u8>, u8>::run_it"),
            "a_crate::module::apply::<..>::run_it"
        );
        assert_eq!(short("a::b::<c>"), "a::b::<c>");
    }
}
