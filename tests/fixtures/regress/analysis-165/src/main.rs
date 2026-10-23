// calls into crypto packages the knowledge base does not model, made by the program: each is an
// operation, of an unknown algorithm, its use unknown where its name says none (tiny-keccak's
// `finalize`, curve25519-dalek's `mul_clamped`), but for what sets something up (a call taking
// nothing to operate on, `Sha3::v256()`; `new_from_slice`) and a stream's step (`update`); a
// keyed BLAKE2s finished through `FixedOutput::finalize_fixed` may be a hash or a MAC
use blake2::digest::{FixedOutput, KeyInit, Update};
use curve25519_dalek::montgomery::MontgomeryPoint;
use tiny_keccak::{Hasher, Sha3};

fn main() {
    let data = std::env::args().nth(1).unwrap_or_default().into_bytes();
    let mut h = Sha3::v256();
    h.update(&data);
    let mut out = [0u8; 32];
    h.finalize(&mut out);
    let secret = [7u8; 32];
    let shared = MontgomeryPoint(out).mul_clamped(secret);
    let public = MontgomeryPoint::mul_base_clamped(secret);
    let mut mac = blake2::Blake2sMac256::new_from_slice(&secret).unwrap();
    Update::update(&mut mac, &data);
    let tag = mac.finalize_fixed();
    println!("{:?} {:?} {}", shared.0[0], public.0[0], tag.len());
}
