//! The CycloneDX Cryptography Registry's name patterns (`schema/cryptography-defs.json`), to
//! check asset names: the JSON schema only enforces families.
//!
//! Pattern notation: `[x]` is optional, `(a|b)` a choice, `{name}` a parameter value.

use std::sync::LazyLock;

use regex::Regex;

const DEFS: &str = include_str!("../../../schema/cryptography-defs.json");

static PATTERNS: LazyLock<Vec<(String, Regex)>> = LazyLock::new(|| {
    let defs: serde_json::Value = serde_json::from_str(DEFS).expect("registry JSON");
    let mut out = Vec::new();
    for a in defs["algorithms"].as_array().into_iter().flatten() {
        let family = a["family"].as_str().unwrap_or_default().to_string();
        for v in a["variant"].as_array().into_iter().flatten() {
            if let Some(p) = v["pattern"].as_str()
                && let Ok(r) = Regex::new(&format!("^(?:{})$", to_regex(p)))
            {
                out.push((family.clone(), r));
            }
        }
    }
    out
});

/// The registry notation as a regular expression.
fn to_regex(pattern: &str) -> String {
    let mut out = String::new();
    let mut chars = pattern.chars();
    while let Some(c) = chars.next() {
        match c {
            '[' => out.push_str("(?:"),
            ']' => out.push_str(")?"),
            '(' => out.push_str("(?:"),
            ')' | '|' => out.push(c),
            '{' => {
                for d in chars.by_ref() {
                    if d == '}' {
                        break;
                    }
                }
                out.push_str(".+?");
            }
            _ => out.push_str(&regex::escape(&c.to_string())),
        }
    }
    out
}

/// Is this a family of the registry? It lists some that the 1.7 schema's `algorithmFamily`
/// enum does not (`TLS-PRF`): see [`crate::in_family_enum`].
pub fn family(family: &str) -> bool {
    PATTERNS.iter().any(|(f, _)| f == family)
}

/// Does some registry pattern produce this name?
pub fn valid(name: &str, _family: &str) -> bool {
    PATTERNS.iter().any(|(_, r)| r.is_match(name))
}

/// Number of patterns loaded (for tests).
pub fn patterns() -> usize {
    PATTERNS.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_names() {
        assert!(patterns() > 100);
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
            assert!(valid(ok, ""), "{ok}");
        }
        for bad in ["Argon2", "SHA-2", "SHA-257", "ChaCha8-Poly1305"] {
            assert!(!valid(bad, ""), "{bad}");
        }
        assert!(valid("TLS12-PRF-SHA-256", ""));
        assert!(family("TLS-PRF") && family("HMAC") && !family("NOT-A-FAMILY"));
    }
}
