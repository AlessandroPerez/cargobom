// Crypto from packages the knowledge base does not model is reported as an unknown algorithm
// naming the type or the call, never dropped (round 6, item 3): MD5 from the package md-5,
// whose library is named `md5` like the package md5's; SHA3-256 from sha3; a hash chosen at run
// time behind `Box<dyn DynDigest>`; P-256 ECDH through p256. A plain `write` of a type of such
// a package is no operation.
use std::io::Write;

use md5::{Digest, Md5};
use p256::ecdh::EphemeralSecret;
use rand_core::OsRng;
use sha2::digest::DynDigest;
use sha3::Sha3_256;

fn hash_by_name(name: &str, data: &[u8]) -> Vec<u8> {
    let mut h: Box<dyn DynDigest> = match name {
        "md5" => Box::new(Md5::new()),
        _ => Box::new(sha2::Sha256::new()),
    };
    h.update(data);
    h.finalize().to_vec()
}

fn main() {
    let d = std::env::args().next().unwrap_or_default().into_bytes();
    let a = Md5::digest(&d);
    let b = Sha3_256::digest(&d);
    let c = hash_by_name(if d.is_empty() { "md5" } else { "sha256" }, &d);
    let alice = EphemeralSecret::random(&mut OsRng);
    let bob = EphemeralSecret::random(&mut OsRng);
    let shared = alice.diffie_hellman(&bob.public_key());
    let mut out = Vec::new();
    out.write_all(&a).unwrap();
    println!("{} {} {} {}", out.len(), b.len(), c.len(), shared.raw_secret_bytes().len());
}
