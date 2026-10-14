// audit 8 probe s1: field writes on some paths, writes by program functions through &mut, A7
use ring::aead::{UnboundKey, AES_256_GCM};
use ring::digest::{digest, Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};
use ring::{hkdf, hmac, pbkdf2};
use std::num::NonZeroU32;

fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }

struct Ctx { alg: &'static Digest, key: [u8; 32] }
impl Ctx {
    fn upgrade(&mut self) { self.alg = &SHA512; }
    fn maybe_upgrade(&mut self, b: bool) { if b { self.alg = &SHA384; } }
}
fn maybe_set(slot: &mut &'static Digest, b: bool) { if b { *slot = &SHA512; } }
fn set_second(_n: u8, slot: &mut &'static Digest) { *slot = &SHA1; }
fn fill(k: &mut [u8; 32]) { k.copy_from_slice(arg(0).as_bytes()); }
const ZERO: [u8; 32] = [0; 32];

fn main() {
    let d = arg(0).into_bytes();
    let mut c1 = Ctx { alg: &SHA256, key: [1; 32] };
    if arg(1) == "x" { c1.alg = &SHA384; }
    let _ = digest(c1.alg, &d); // SHA-256, SHA-384
    let mut a2: &'static Digest = &SHA384;
    maybe_set(&mut a2, arg(2) == "x");
    let _ = digest(a2, &d); // SHA-384, SHA-512
    let mut c3 = Ctx { alg: &SHA256, key: [1; 32] };
    maybe_set(&mut c3.alg, arg(3) == "x");
    let _ = digest(c3.alg, &d); // SHA-256, SHA-512
    let mut c4 = Ctx { alg: &SHA256, key: [1; 32] };
    c4.upgrade();
    let _ = digest(c4.alg, &d); // SHA-512
    let _ = UnboundKey::new(&AES_256_GCM, &c4.key); // key: hard-coded (the literal [1; 32])
    let mut c5 = Ctx { alg: &SHA256, key: [1; 32] };
    c5.maybe_upgrade(arg(5) == "x");
    let _ = digest(c5.alg, &d); // SHA-256, SHA-384
    let mut a6: &'static Digest = &SHA384;
    set_second(0, &mut a6);
    let _ = digest(a6, &d); // SHA-1 (`set_second` writes its second argument on every path)
    let mut c7 = Ctx { alg: &SHA256, key: [1; 32] };
    for _ in 0..arg(7).len() { c7.alg = &SHA512; }
    let _ = digest(c7.alg, &d); // SHA-256, SHA-512
    let mut k8 = [1u8; 32];
    fill(&mut k8);
    let _ = UnboundKey::new(&AES_256_GCM, &k8); // key: from the arguments, not the literal
    let _ = UnboundKey::new(&AES_256_GCM, &[0u8; 32]); // all-zero key: hard-coded
    let _ = UnboundKey::new(&AES_256_GCM, &ZERO); // all-zero const key: hard-coded
    let _ = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, b""), &d); // empty key
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &[0u8; 32]); // the program's all-zero salt: hard-coded
    let _prk = salt.extract(&[0u8; 32]); // the program's own all-zero IKM
    let ikm = vec![0u8; 32];
    let _ = hkdf::Salt::new(hkdf::HKDF_SHA384, b"nonzero-salt").extract(&ikm); // vec![0; 32] IKM
    let lz = [0u8; 48];
    let _ = hkdf::Salt::new(hkdf::HKDF_SHA512, &lz[..]).extract(&lz); // local all-zero array
    let mut out = [0u8; 32];
    pbkdf2::derive(pbkdf2::PBKDF2_HMAC_SHA256, NonZeroU32::new(1000).unwrap(), &[], b"", &mut out);
    let mut c9 = Ctx { alg: &SHA256, key: [1; 32] };
    if arg(9).is_empty() {
        let _ = digest(c9.alg, &d); // SHA-256
        return;
    }
    c9.alg = &SHA384;
    let _ = digest(c9.alg, &d); // SHA-384
    let _ = UnboundKey::new(&AES_256_GCM, &c9.key); // hard-coded
    println!("{:?}", out);
}
