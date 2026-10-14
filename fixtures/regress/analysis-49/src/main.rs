// audit 9 probe m3: writes by trait methods (algorithm and key provenance); local + linked sets
use ring::aead::{Aad, Algorithm as Aead, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, CHACHA20_POLY1305};
use ring::digest::{digest, Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};

fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }

struct K { key: [u8; 32], alg: &'static Aead }
trait Rekey { fn rekey(&mut self); }
impl Rekey for K {
    fn rekey(&mut self) { self.key.copy_from_slice(&arg(1).as_bytes()[..32]); self.alg = &CHACHA20_POLY1305; }
}
impl K {
    fn rekey_inherent(&mut self) { self.key.copy_from_slice(&arg(1).as_bytes()[..32]); self.alg = &CHACHA20_POLY1305; }
}
fn seal(k: &K, buf: &mut Vec<u8>) {
    let lk = LessSafeKey::new(UnboundKey::new(k.alg, &k.key).unwrap());
    let _ = lk.seal_in_place_append_tag(Nonce::assume_unique_for_key([0; 12]), Aad::empty(), buf); // AES-256-GCM (k3), ChaCha20-Poly1305 (k1, k2)
}

fn pick() -> &'static Digest { &SHA384 }
struct S { alg: &'static Digest }
fn mixed(s: &S, p: &'static Digest, n: usize, d: &[u8]) {
    let a = match n { 0 => &SHA256, 1 => p, 2 => s.alg, _ => pick() };
    let _ = digest(a, d); // SHA-256, SHA-1 (p), SHA-512 (s.alg), SHA-384 (pick)
}

fn main() {
    let mut buf = arg(0).into_bytes();
    let mut k1 = K { key: [7; 32], alg: &AES_256_GCM };
    k1.rekey();
    let lk1 = LessSafeKey::new(UnboundKey::new(k1.alg, &k1.key).unwrap()); // key computed (args), ChaCha20-Poly1305
    let _ = lk1.seal_in_place_append_tag(Nonce::assume_unique_for_key([0; 12]), Aad::empty(), &mut buf); // ChaCha20-Poly1305
    let mut k2 = K { key: [7; 32], alg: &AES_256_GCM };
    k2.rekey_inherent();
    let lk2 = LessSafeKey::new(UnboundKey::new(k2.alg, &k2.key).unwrap()); // key computed (args), ChaCha20-Poly1305
    let _ = lk2.seal_in_place_append_tag(Nonce::assume_unique_for_key([0; 12]), Aad::empty(), &mut buf); // ChaCha20-Poly1305
    let k3 = K { key: [9; 32], alg: &AES_256_GCM };
    seal(&k3, &mut buf);
    seal(&k1, &mut buf);
    let s = S { alg: &SHA512 };
    mixed(&s, &SHA1, arg(2).len(), &buf);
}
