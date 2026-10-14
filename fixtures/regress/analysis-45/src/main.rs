// audit 8 probe w3: an algorithm named here or reaching from another function
use ring::digest::{digest, Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};

fn pick() -> &'static Digest { &SHA384 }

fn mix(p: &'static Digest, n: usize, d: &[u8]) -> usize {
    let a = if n > 1 { &SHA256 } else { p };
    digest(a, d).as_ref().len() // SHA-256, SHA-512
}

struct S { alg: &'static Digest }

fn field_mix(s: &S, n: usize, d: &[u8]) -> usize {
    let a = if n > 1 { &SHA256 } else { s.alg };
    digest(a, d).as_ref().len() // SHA-256, SHA-1
}

fn main() {
    let n = std::env::args().count();
    let d = b"data";
    let a = if n > 1 { &SHA256 } else { pick() };
    let _ = digest(a, d); // SHA-256, SHA-384
    let _ = mix(&SHA512, n, d);
    let _ = field_mix(&S { alg: &SHA1 }, n, d);
}
