// audit 7 probe: the new knowledge-base packages beyond the corpus's calls
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{B32, KemCore, MlKem768};
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::signature::{DigestSigner, DigestVerifier, Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use rand::distributions::{Alphanumeric, DistString};
use rand::{Rng, RngCore, SeedableRng};
use rand_core::OsRng;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Digest, Keccak256, Sha3_256, Shake128};

fn main() {
    let d = std::env::args().next().unwrap().into_bytes();
    // sha3: Keccak-256, a type of a modelled package with no entry
    let k = Keccak256::digest(&d);
    // sha3: SHA3-256 and SHAKE128
    let a = Sha3_256::digest(&d);
    let mut x = Shake128::default();
    x.update(&d);
    let mut r = x.finalize_xof();
    let mut out = [0u8; 32];
    r.read(&mut out);
    // elliptic-curve: SecretKey::random, ECDH, the shared secret's HKDF
    let sk = p256::SecretKey::random(&mut OsRng);
    let e = p256::ecdh::EphemeralSecret::random(&mut OsRng);
    let shared = e.diffie_hellman(&sk.public_key());
    let hk = shared.extract::<sha2::Sha256>(None);
    let mut okm = [0u8; 32];
    hk.expand(b"info", &mut okm).unwrap();
    let e384 = p384::ecdh::EphemeralSecret::random(&mut OsRng);
    let pk384 = p384::SecretKey::random(&mut OsRng).public_key();
    let _s384 = e384.diffie_hellman(&pk384);
    // ECDSA P-256: the curve's hash, SHA3-256 through DigestSigner, a prehash
    let s = SigningKey::random(&mut OsRng);
    let sig1: Signature = s.sign(&d);
    let sig2: Signature = s.sign_digest(Sha3_256::new_with_prefix(&d));
    let sig3: Signature = s.sign_prehash(&[7u8; 32]).unwrap();
    let v = VerifyingKey::from(&s);
    v.verify(&d, &sig1).unwrap();
    v.verify_digest(Sha3_256::new_with_prefix(&d), &sig2).unwrap();
    let s384 = p384::ecdsa::SigningKey::random(&mut OsRng);
    let sig4: p384::ecdsa::Signature = s384.sign(&d);
    // ML-KEM-768
    let (dk, ek) = MlKem768::generate_deterministic(&B32::default(), &B32::default());
    let (ct, ss) = ek.encapsulate(&mut OsRng).unwrap();
    let ss2 = dk.decapsulate(&ct).unwrap();
    let (_dk2, _ek2) = MlKem768::generate(&mut OsRng);
    // rand draws
    let mut tr = rand::thread_rng();
    let b: bool = tr.gen_bool(0.5);
    let g: u64 = tr.r#gen();
    let mut sr = rand::rngs::StdRng::from_entropy();
    sr.fill_bytes(&mut out);
    let mut seeded = rand::rngs::StdRng::from_rng(OsRng).unwrap();
    seeded.fill_bytes(&mut out);
    let mut sm = rand::rngs::SmallRng::from_entropy();
    let n: u32 = sm.r#gen();
    let mut cc = rand_chacha::ChaCha20Rng::from_entropy();
    cc.fill_bytes(&mut out);
    let pw = Alphanumeric.sample_string(&mut OsRng, 16);
    let mut os = [0u8; 8];
    OsRng.fill_bytes(&mut os);
    println!(
        "{:?} {:?} {:?} {:?} {:?} {:?} {} {} {} {} {:?} {:?}",
        k, a, out, okm, sig3, sig4, b, g, n, pw, ss == ss2, os
    );
}
