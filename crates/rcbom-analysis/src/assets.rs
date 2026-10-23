//! Assets: their kinds, the merge of less specific names, the packages providing them.

use super::*;

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Call => "call",
            Kind::Instantiation => "instantiation",
            Kind::Static => "static",
            Kind::ViaStatic => "via-static",
            Kind::Component => "component",
        }
    }
}
impl Asset {
    /// An operation's asset whose algorithm the analysis does not find (not key material of
    /// no single family: `DecodingKey::from_jwk`'s).
    pub fn unresolved(&self) -> bool {
        self.name == UNKNOWN && self.algo.family.is_empty() && self.algo.material.is_none()
    }

    pub fn reachable(&self) -> bool {
        self.occurrences.iter().any(|o| o.tier == Tier::Reachable)
    }

    /// The uses the program makes of the asset: those seen at reachable occurrences when the
    /// asset is reachable (code that only exists in a dependency is not the program's use),
    /// else those seen anywhere.
    pub fn observed_functions(&self) -> BTreeSet<String> {
        let reachable = self.reachable();
        self.occurrences
            .iter()
            .filter(|o| !reachable || o.tier == Tier::Reachable)
            .filter_map(|o| o.function.as_deref())
            // `encrypt or decrypt`: the asset is used for either
            .flat_map(|f| f.split(" or ").map(str::to_string))
            .collect()
    }
}
/// The backend package a protocol crate's path names, by its `backends` (feature -> package):
/// rustls's `crypto::ring::default_provider`, `crypto::aws_lc_rs::tls13::TLS13_AES_128_GCM_SHA256`.
pub(super) fn backend_in_path<'a>(
    path: &str,
    backends: &'a BTreeMap<String, String>,
) -> Option<&'a str> {
    backends
        .iter()
        .find(|(feature, _)| path.contains(&format!("::{feature}::")))
        .map(|(_, package)| package.as_str())
}
/// One use found twice on a line, once with run-time parameters unresolved (`Argon2` from
/// `hash_password`) and once resolved (`Argon2id-19456-2-1` from `Argon2::default()`): the
/// resolved name keeps the occurrence, and the use.
pub(super) fn merge_less_specific(assets: &mut BTreeMap<String, Asset>) {
    let keys: Vec<String> = assets.keys().cloned().collect();
    for general in &keys {
        for specific in &keys {
            let (g, s) = (&assets[general], &assets[specific]);
            // `PBKDF2-SHA-256` -> `PBKDF2-SHA-256-1000-32`, the family name `Argon2` ->
            // `Argon2id-19456-2-1`: a prefix ending at a part boundary (not `PBKDF2-SHA-256-1000`
            // -> `PBKDF2-SHA-256-10000-32`), same family and primitive (the QUIC
            // header-protection `AES-128`, a block cipher, never merges into `AES-128-GCM`),
            // algorithms only
            let boundary = s.name.starts_with(&format!("{}-", g.name))
                || (g.name == g.algo.family && s.name.starts_with(&g.name));
            if general == specific
                || !boundary
                || g.algo.family != s.algo.family
                || g.algo.primitive != s.algo.primitive
                || g.algo.material.is_some()
                || s.algo.material.is_some()
            {
                continue;
            }
            let from_general = assets[general].occurrences.clone();
            let mut merged = Vec::new();
            {
                let s = assets.get_mut(specific).unwrap();
                for g in from_general {
                    if g.detail.iter().any(|d| d.ends_with(OWN_PARAMS)) {
                        continue;
                    }
                    // two parts of one asset are two algorithms: the BLAKE2b of an Argon2 tag of
                    // unknown length is not the BLAKE2b-512 of its H0
                    let parts = |o: &Occurrence| {
                        o.kind == Kind::Component
                            && g.kind == Kind::Component
                            && o.detail == g.detail
                    };
                    if let Some(o) = s
                        .occurrences
                        .iter_mut()
                        .find(|o| o.location == g.location && o.line == g.line && !parts(o))
                    {
                        if o.function.is_none() {
                            o.function = g.function;
                        }
                        o.artifacts.extend(g.artifacts);
                        for d in g.detail {
                            if !o.detail.contains(&d) {
                                o.detail.push(d);
                            }
                        }
                        for p in g.provenance {
                            if !o.provenance.contains(&p) {
                                o.provenance.push(p);
                            }
                        }
                        merged.push((g.location, g.line, g.offset, g.symbol));
                    }
                }
            }
            // only the occurrences merged: another on the line (`Argon2::from(Params::default())
            // .verify_password(..)`, a call naming its own parameters) stays
            let g = assets.get_mut(general).unwrap();
            g.occurrences.retain(|o| {
                !merged.contains(&(o.location.clone(), o.line, o.offset, o.symbol.clone()))
            });
        }
    }
    assets.retain(|_, a| !a.occurrences.is_empty());
}
/// `micro::seal::<aes_gcm::AesGcm<aes_gcm::aes::Aes256, ..>>` -> `micro::seal::<..>`, for
/// human-readable context; the full instance stays in the facts. Only a path's generic
/// arguments are elided, the item's name is kept (`ConnectorBuilder::<WantsTlsConfig>::
/// with_native_roots` -> `ConnectorBuilder::<..>::with_native_roots`), and so are the types of
/// a qualified segment (`<impl Paseto<'_, V4, Public>>::try_sign`).
pub(super) fn short(name: &str) -> String {
    if name.len() <= 60 {
        return name.to_string();
    }
    let mut out = String::new();
    // nesting inside elided arguments
    let mut skip = 0usize;
    let mut prev = None;
    for (i, c) in name.char_indices() {
        if skip > 0 {
            match c {
                '<' => skip += 1,
                // not the arrow of a function type (`fn(&[u8]) -> Vec<u8>`)
                '>' if prev != Some('-') => skip -= 1,
                _ => {}
            }
            if skip == 0 {
                out.push_str("..>");
            }
        } else {
            out.push(c);
            // the generic arguments of a path (`seal::<..>`, `ConnectorBuilder::<..>`); a type's
            // in a qualified segment (`<KeyPair as TryFrom<&PrivateKeyDer<'_>>>`, `<impl
            // Paseto<'_, V4, Public>>`) tell impls apart, and stay
            if c == '<' && prev == Some(':') && !name[i + 1..].starts_with("impl ") {
                skip = 1;
            }
        }
        prev = Some(c);
    }
    out
}
/// The crates of the ADTs a type tree names (`OsRng` in `generate_nonce::<OsRng>`).
pub(super) fn adt_crates<'a>(t: &'a rcbom_facts::TyTree, out: &mut Vec<&'a rcbom_facts::CrateRef>) {
    use rcbom_facts::TyTree;
    match t {
        TyTree::Adt { krate, args, .. } => {
            out.push(krate);
            args.iter().for_each(|a| adt_crates(a, out));
        }
        TyTree::Ref(t) | TyTree::Slice(t) | TyTree::Array(t, _) => adt_crates(t, out),
        TyTree::Tuple(ts) => ts.iter().for_each(|a| adt_crates(a, out)),
        _ => {}
    }
}
