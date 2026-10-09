// Positions the verifier rejected although they were right, or accepted although they were
// wrong (see fixtures/regress/README.md).
use sha2::{Digest, Sha256};

mod algs;
use algs::{hash_it, ALG};

// V1: two versions of sha2 (0.10 as `sha2`, 0.11 as `sha2_11`): `Sha256` and `sha2::` name
// 0.10, which provides SHA-256; 0.11 (a version the knowledge base does not cover) provides
// nothing.
fn direct(d: &[u8]) -> usize {
    Sha256::digest(d).len()
}

fn qualified(d: &[u8]) -> usize {
    sha2::Sha256::digest(d).len()
}

mod newer {
    use sha2_11::Digest;
    pub fn f(d: &[u8]) -> usize {
        sha2_11::Sha256::digest(d).len()
    }
}

// V2: one name imported from two crates in one file: in two modules, and chosen by a cfg.
mod a {
    use sha1::Sha1 as H;
    pub fn f(d: &[u8]) -> usize {
        use sha1::Digest;
        H::digest(d).len()
    }
}

mod b {
    use sha2::Sha256 as H;
    pub fn f(d: &[u8]) -> usize {
        use sha2::Digest;
        H::digest(d).len()
    }
}

#[cfg(feature = "legacy")]
use sha1::Sha1 as Hasher;
#[cfg(not(feature = "legacy"))]
use sha2::Sha256 as Hasher;

fn chosen(d: &[u8]) -> usize {
    Hasher::digest(d).len()
}

// V3: a function and a static named by aliases another file of the package defines
fn aliased(d: &[u8]) -> usize {
    hash_it(&ALG, d).as_ref().len()
}

// V4: a raw identifier
fn raw(d: &[u8]) -> usize {
    Sha256::r#digest(d).len()
}

// V5: a path right after a single `:`
struct W {
    n: usize,
}

fn colon(d: &[u8]) -> usize {
    let w = W { n:Sha256::digest(d).len() };
    w.n
}

// V6: tag-like text in a comment of the cited line
fn tags(d: &[u8]) -> usize {
    Sha256::digest(d).len() // see [derive Foo] and [macro bar!]
}

// V8: a path broken over lines with a comment between its segments, and a path from the root
fn split(d: &[u8]) -> usize {
    let h = sha2::Sha256 // first
        ::digest(d);
    h.len()
}

fn rooted(d: &[u8]) -> usize {
    ::sha2::Sha256::digest(d).len()
}

fn main() {
    let d = b"v02";
    let n = direct(d) + qualified(d) + newer::f(d) + a::f(d) + b::f(d) + chosen(d) + aliased(d);
    println!("{}", n + raw(d) + colon(d) + tags(d) + split(d) + rooted(d));
}
