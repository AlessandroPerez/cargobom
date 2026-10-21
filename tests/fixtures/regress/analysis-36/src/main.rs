// round 8 audit-prep probe: writes through `&mut` by the program's own functions, and literal
// data in a closure that is both scanned as an item and walked as an instance
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use ring::aead::{UnboundKey, AES_256_GCM};
use ring::digest::{digest, Algorithm as Digest, SHA256, SHA384, SHA512};
use std::collections::BTreeMap;

struct Ctx {
    alg: &'static Digest,
}

fn set_slot(slot: &mut &'static Digest) {
    *slot = &SHA512;
}

fn set_alg(a: &mut Algorithm) {
    *a = Algorithm::HS512;
}

fn use_ctx(c: &Ctx, d: &[u8]) -> usize {
    digest(c.alg, d).as_ref().len()
}

fn main() {
    let d = std::env::args().next().unwrap_or_default().into_bytes();
    // 1: a field written by the program's function after construction, through its first
    // argument (as a call's receiver replaces its value): SHA-512
    let mut c = Ctx { alg: &SHA256 };
    set_slot(&mut c.alg);
    let n1 = use_ctx(&c, &d);
    // 2: a whole value written by the program's function: SHA-512
    let mut a: &'static Digest = &SHA384;
    set_slot(&mut a);
    let n2 = digest(a, &d).as_ref().len();
    // 3: the header's algorithm written by the program's function: HS512, not the default
    let mut h = Header::default();
    set_alg(&mut h.alg);
    let claims = BTreeMap::from([("exp", 4_000_000_000u64)]);
    let t = encode(&h, &claims, &EncodingKey::from_secret(b"k")).unwrap();
    // 4: an all-zero key literal in a closure: one key detail, all zero
    let k = d.clone();
    let key = UnboundKey::new(&AES_256_GCM, &k).unwrap_or_else(|_| UnboundKey::new(&AES_256_GCM, &[0; 32]).unwrap());
    println!("{n1} {n2} {} {:?}", t.len(), key.algorithm());
}
