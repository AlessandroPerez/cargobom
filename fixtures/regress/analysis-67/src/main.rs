// round 11 regress (audit 10 probe u2): Option reads from local containers, crypto-crate results among alternatives,
// loops over containers
use ring::aead::{self, LessSafeKey, UnboundKey, AES_128_GCM, AES_256_GCM};
use ring::digest::{digest, Algorithm as Digest, SHA256, SHA384, SHA512};
use ring::hmac;
use std::collections::HashMap;

fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }

fn main() {
    let d = arg(0).into_bytes();
    let i = arg(1).len();
    let arr = [&SHA256, &SHA384];
    let _ = digest(arr.get(i).copied().unwrap_or(&SHA512), &d);
    let _ = digest(*arr.get(i % 2).unwrap(), &d);
    let _ = digest(arr.iter().copied().nth(i).unwrap_or(&SHA512), &d);
    let v = vec![&SHA256, &SHA384];
    let _ = digest(v.get(i).copied().unwrap_or(&SHA512), &d);
    let _ = digest(v.first().copied().unwrap_or(&SHA512), &d);
    let mut m = HashMap::new();
    m.insert("k", &SHA384);
    let _ = digest(m.get(arg(2).as_str()).copied().unwrap_or(&SHA256), &d);
    let k = hmac::Key::new(hmac::HMAC_SHA384, b"placeholder-not-a-key");
    let a7: &'static Digest = if arg(3).is_empty() { &SHA256 } else { k.algorithm().digest_algorithm() };
    let _ = digest(a7, &d);
    let lsk = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &[0u8; 32]).unwrap());
    let alg: &'static aead::Algorithm = if arg(4).is_empty() { &AES_128_GCM } else { lsk.algorithm() };
    let key = arg(5).into_bytes();
    let lk2 = LessSafeKey::new(UnboundKey::new(alg, &key).unwrap());
    let mut buf = d.clone();
    let _ = lk2.seal_in_place_append_tag(aead::Nonce::assume_unique_for_key([0u8; 12]), aead::Aad::empty(), &mut buf);
    for a in v.iter() { let _ = digest(a, &d); }
    for a in &arr { let _ = digest(a, &d); }
    let mut it = arr.iter();
    while let Some(a) = it.next() { let _ = digest(a, &d); }
}
