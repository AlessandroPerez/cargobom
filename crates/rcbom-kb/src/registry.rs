//! The CycloneDX Cryptography Registry's name patterns (`data/cryptography-defs.json`), to
//! check asset names: the JSON schema only enforces families.
//!
//! Pattern notation: `[x]` is optional, `(a|b)` a choice, `{name}` a parameter value.

use std::sync::LazyLock;

const DEFS: &str = include_str!("../data/cryptography-defs.json");

/// A pattern's parts: text, a bracketed or parenthesised group of alternatives (optional when
/// in `[..]`), a parameter.
#[derive(Debug)]
enum Tok {
    Lit(Vec<char>),
    Group { alts: Vec<Vec<Tok>>, optional: bool },
    Param(Param),
}

/// What a parameter's value is: a number (`{keyLength}`), another algorithm's name, as the
/// registry names it (`{hashAlgorithm}` in `HMAC[-{hashAlgorithm}]`), an elliptic curve of the
/// registry's list, or a word (`{mode}`, `{padding}`, `{namedGroup}`).
#[derive(Debug, Clone, Copy, PartialEq)]
enum Param {
    Number,
    Algorithm,
    /// A mask generation function: `MGF1`, with its hash (`MGF1-SHA-1`), which the registry
    /// has no family of its own for
    MaskGen,
    Curve,
    Word,
}

fn param(name: &str) -> Param {
    match name {
        "aead"
        | "auxFunction"
        | "blockCipher"
        | "cipherAlgorithm"
        | "encryptionAlgorithm"
        | "hashAlgorithm"
        | "hashfun"
        | "kdf"
        | "kem"
        | "ksf"
        | "mac"
        | "macAlgorithm"
        | "otherBlockCipher"
        | "prfFunction"
        | "symmetricCipher" => Param::Algorithm,
        "maskGenAlgorithm" => Param::MaskGen,
        "ellipticCurve" => Param::Curve,
        "mode" | "padding" | "group" | "namedGroup" | "authmode" => Param::Word,
        _ => Param::Number,
    }
}

struct Registry {
    patterns: Vec<(String, Vec<Tok>)>,
    curves: Vec<String>,
}

static REGISTRY: LazyLock<Registry> = LazyLock::new(|| {
    let defs: serde_json::Value = serde_json::from_str(DEFS).expect("registry JSON");
    let mut patterns = Vec::new();
    for a in defs["algorithms"].as_array().into_iter().flatten() {
        let family = a["family"].as_str().unwrap_or_default().to_string();
        for v in a["variant"].as_array().into_iter().flatten() {
            if let Some(p) = v["pattern"].as_str() {
                let chars: Vec<char> = p.chars().collect();
                let (toks, _) = parse(&chars, 0);
                patterns.push((family.clone(), toks));
            }
        }
    }
    let mut curves = Vec::new();
    for e in defs["ellipticCurves"].as_array().into_iter().flatten() {
        for c in e["curves"].as_array().into_iter().flatten() {
            curves.extend(c["name"].as_str().map(str::to_string));
            for a in c["aliases"].as_array().into_iter().flatten() {
                curves.extend(a["name"].as_str().or(a.as_str()).map(str::to_string));
            }
        }
    }
    Registry { patterns, curves }
});

/// The registry notation from `i` to the end of the group it is in: its alternatives' parts,
/// and where it stopped (at a `]`, `)` or the end).
fn parse(p: &[char], mut i: usize) -> (Vec<Tok>, usize) {
    let mut alts: Vec<Vec<Tok>> = vec![Vec::new()];
    while i < p.len() {
        match p[i] {
            '[' | '(' => {
                let (inner, end) = parse(p, i + 1);
                let alts_inner = match inner.into_iter().next() {
                    Some(Tok::Group { alts, .. }) => alts,
                    _ => vec![Vec::new()],
                };
                alts.last_mut().unwrap().push(Tok::Group {
                    alts: alts_inner,
                    optional: p[i] == '[',
                });
                i = end + 1;
            }
            ']' | ')' => break,
            '|' => {
                alts.push(Vec::new());
                i += 1;
            }
            '{' => {
                let end = (i..p.len()).find(|&j| p[j] == '}').unwrap_or(p.len());
                let name: String = p[i + 1..end].iter().collect();
                alts.last_mut().unwrap().push(Tok::Param(param(&name)));
                i = end + 1;
            }
            c => {
                match alts.last_mut().unwrap().last_mut() {
                    Some(Tok::Lit(l)) => l.push(c),
                    _ => alts.last_mut().unwrap().push(Tok::Lit(vec![c])),
                }
                i += 1;
            }
        }
    }
    // one group holding the alternatives (the caller unwraps it)
    (
        vec![Tok::Group {
            alts,
            optional: false,
        }],
        i,
    )
}

/// The positions after `name[i..]` matches `toks`, a parameter that names an algorithm being a
/// registry name itself, at most `depth` levels down.
fn ends(toks: &[Tok], name: &[char], i: usize, depth: usize, out: &mut Vec<usize>) {
    let Some((first, rest)) = toks.split_first() else {
        if !out.contains(&i) {
            out.push(i);
        }
        return;
    };
    match first {
        Tok::Lit(l) => {
            if name[i..].starts_with(l) {
                ends(rest, name, i + l.len(), depth, out);
            }
        }
        Tok::Group { alts, optional } => {
            let mut mids = Vec::new();
            for a in alts {
                ends(a, name, i, depth, &mut mids);
            }
            if *optional && !mids.contains(&i) {
                mids.push(i);
            }
            for m in mids {
                ends(rest, name, m, depth, out);
            }
        }
        Tok::Param(kind) => {
            for e in i + 1..=name.len() {
                let v = &name[i..e];
                let ok = match kind {
                    Param::Number => v.iter().all(char::is_ascii_digit),
                    Param::Word => v.iter().all(char::is_ascii_alphanumeric) || curve(v),
                    Param::Curve => curve(v),
                    Param::Algorithm => {
                        depth > 0 && named(&v.iter().collect::<String>(), depth - 1)
                    }
                    Param::MaskGen => {
                        let s: String = v.iter().collect();
                        s == "MGF1"
                            || s.strip_prefix("MGF1-")
                                .is_some_and(|h| depth > 0 && named(h, depth - 1))
                    }
                };
                if ok {
                    ends(rest, name, e, depth, out);
                }
            }
        }
    }
}

fn curve(v: &[char]) -> bool {
    let s: String = v.iter().collect();
    REGISTRY.curves.contains(&s)
}

/// Does some registry pattern produce this name, its algorithm parameters `depth` levels down?
fn named(name: &str, depth: usize) -> bool {
    let chars: Vec<char> = name.chars().collect();
    REGISTRY.patterns.iter().any(|(_, toks)| {
        let mut out = Vec::new();
        ends(toks, &chars, 0, depth, &mut out);
        out.contains(&chars.len())
    })
}

/// The registry's algorithm names as a package name may write them: each family and the text
/// each pattern starts with (`BLAKE2b` of `BLAKE2b[-{digestSize}]`), lowercase without `-`
/// and `/` (`sha1`, `blake2b`, `aes`), of three characters or more.
static WORDS: LazyLock<std::collections::HashSet<String>> = LazyLock::new(|| {
    let norm = |t: &str| -> String {
        t.chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .collect::<String>()
            .to_ascii_lowercase()
    };
    // (a pattern is one group of alternatives: each one's leading text)
    fn leading(toks: &[Tok], out: &mut Vec<String>) {
        match toks.first() {
            Some(Tok::Lit(chars)) => out.push(chars.iter().collect()),
            Some(Tok::Group {
                alts,
                optional: false,
            }) => alts.iter().for_each(|a| leading(a, out)),
            _ => {}
        }
    }
    let mut out = std::collections::HashSet::new();
    for (family, toks) in &REGISTRY.patterns {
        out.insert(norm(family));
        let mut texts = Vec::new();
        leading(toks, &mut texts);
        out.extend(texts.iter().map(|t| norm(t)));
    }
    out.retain(|w| w.len() >= 3);
    out
});

/// Does a package's name name an algorithm of the registry: its first part (`blake2b` of
/// `blake2b_simd`, `sha1` of `sha1_smol`) or all of it written without separators (`md-5`),
/// without the affix that says a crate is Rust's (`argon2` of `rust-argon2`, of `argon2-rs`)?
pub fn names_algorithm(package: &str) -> bool {
    let lower = package.to_ascii_lowercase();
    let lower = ["rust-", "rust_", "rs-", "rs_"]
        .iter()
        .find_map(|p| lower.strip_prefix(p))
        .or_else(|| {
            ["-rs", "_rs", "-rust", "_rust"]
                .iter()
                .find_map(|s| lower.strip_suffix(s))
        })
        .unwrap_or(&lower)
        .to_string();
    let first = lower.split(['-', '_']).next().unwrap_or("");
    let joined: String = lower
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    WORDS.contains(first) || WORDS.contains(&joined)
}

/// Is this a family of the registry? It lists some that the 1.7 schema's `algorithmFamily`
/// enum does not (`TLS-PRF`): see [`crate::in_family_enum`].
pub fn family(family: &str) -> bool {
    REGISTRY.patterns.iter().any(|(f, _)| f == family)
}

/// Does some registry pattern produce this name? A parameter is a number, an elliptic curve of
/// the registry's list, a word (a mode, a padding, a group), or, for an algorithm
/// (`{hashAlgorithm}`), a name the registry produces in turn (`RSA-OAEP-SHA-256-MGF1-SHA-1`).
pub fn valid(name: &str) -> bool {
    named(name, 3)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_names() {
        assert!(REGISTRY.patterns.len() > 100);
        for ok in [
            "AES-256-GCM",
            "AES-GCM",
            "AES-256-GCM-128-128",
            "AES-128",
            "HMAC-SHA-256",
            "HMAC-SHA-512/256",
            "SHA-512/224",
            "PBKDF2-SHA-256-1000-32",
            "Argon2id-19456-2-1",
            "ChaCha20-Poly1305",
            "XChaCha20-Poly1305",
            "ECDSA-P-256-SHA-256",
            "Ed25519",
            "x25519",
            "BLAKE3",
            "ML-KEM-768",
            "RSA-PKCS1-1.5-SHA-256",
        ] {
            assert!(valid(ok), "{ok}");
        }
        for bad in [
            "Argon2",
            "SHA-2",
            "SHA-257",
            "ChaCha8-Poly1305",
            "HKDF-SHA-257",
            "HMAC-banana",
            "AES-256-GCM-x-y",
        ] {
            assert!(!valid(bad), "{bad}");
        }
        assert!(valid("TLS12-PRF-SHA-256"));
        assert!(family("TLS-PRF") && family("HMAC") && !family("NOT-A-FAMILY"));
    }
}
