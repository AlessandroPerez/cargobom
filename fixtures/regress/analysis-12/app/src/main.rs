use sha2::{Digest, Sha256};

// L4: code compiled only with debug assertions: the release build that ships has no SHA-512
#[cfg(debug_assertions)]
fn debug_only(d: &[u8]) -> usize {
    sha2::Sha512::digest(d).len()
}
#[cfg(not(debug_assertions))]
fn debug_only(_d: &[u8]) -> usize {
    0
}

fn main() {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    println!(
        "{} {} {:?} {}",
        provider.cipher_suites.len(),
        Sha256::digest(b"x").len(),
        signature::tag(b"y"),
        debug_only(b"z")
    );
}
