// aws-lc-rs (third audit round): the AEAD scatter/gather methods and their nonces, a cipher
// IV given to less_safe_encrypt, HMAC and PBKDF2, ML-KEM-1024, an Ed25519 key pair from a
// hard-coded seed, verification algorithms in a wrapper struct.
use aws_lc_rs::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::{cipher, digest, hmac, pbkdf2, signature, kem};
use aws_lc_rs::cipher::EncryptionContext;
use aws_lc_rs::iv::FixedLength;
use std::num::NonZeroU32;

// 1. AEAD scatter/gather API: seal_out_of_place_scatter (encrypt) and open_separate_gather
// (decrypt), both with hard-coded nonces; seal_in_place_scatter
fn scatter(key: &[u8], data: &mut [u8]) -> bool {
    let k = LessSafeKey::new(UnboundKey::new(&aead::AES_128_GCM, key).unwrap());
    let mut ct = vec![0u8; data.len()];
    let mut tag = [0u8; 32];
    let _ = k.seal_out_of_place_scatter(Nonce::assume_unique_for_key([1u8; 12]), Aad::empty(), data, &mut ct, &[], &mut tag[..16]);
    let mut pt = vec![0u8; data.len()];
    let r = k.open_separate_gather(Nonce::assume_unique_for_key([2u8; 12]), Aad::empty(), &ct, &tag[..16], &mut pt);
    let _ = k.seal_in_place_scatter(Nonce::assume_unique_for_key([3u8; 12]), Aad::empty(), data, &[], &mut tag[..16]);
    r.is_ok()
}

// 2. cipher: an AES-128-CTR encryption with a caller-chosen, hard-coded IV (less_safe_encrypt)
fn ctr_iv(key: &[u8], data: &mut [u8]) -> bool {
    let uk = cipher::UnboundCipherKey::new(&cipher::AES_128, key).unwrap();
    let ek = cipher::EncryptingKey::ctr(uk).unwrap();
    let ctx = EncryptionContext::Iv128(FixedLength::from([0u8; 16]));
    ek.less_safe_encrypt(data, ctx).is_ok()
}

// 3. HMAC-SHA-512 tag; PBKDF2-HMAC-SHA-256 with constant iterations
fn mac_kdf(key: &[u8], pw: &[u8]) -> usize {
    let k = hmac::Key::new(hmac::HMAC_SHA512, key);
    let t = hmac::sign(&k, b"data");
    let mut out = [0u8; 32];
    pbkdf2::derive(pbkdf2::PBKDF2_HMAC_SHA256, NonZeroU32::new(600_000).unwrap(), b"fixed-salt", pw, &mut out);
    t.as_ref().len() + digest::digest(&digest::SHA512_256, pw).as_ref().len()
}

// 4. ML-KEM-1024 generate + decapsulate; ML-DSA-65 is not used here
fn kem1024() -> bool {
    let dk = kem::DecapsulationKey::generate(&kem::ML_KEM_1024).unwrap();
    let ek = dk.encapsulation_key().unwrap();
    let (ct, _ss) = ek.encapsulate().unwrap();
    dk.decapsulate(ct).is_ok()
}

// 5. Ed25519 key pair from a hard-coded seed (aws-lc-rs from_seed_unchecked)
fn ed_seed(msg: &[u8]) -> usize {
    let kp = signature::Ed25519KeyPair::from_seed_unchecked(&[4u8; 32]).unwrap();
    kp.sign(msg).as_ref().len()
}

// 6. verification algorithms kept in a wrapper struct built in statics (rustls-webpki's
// `AwsLcRsAlgorithm`), verified through the field: aws-lc-rs's Ed25519 descriptor is a named
// const of a field-less struct, and must still name Ed25519 (one of the two)
struct Verifier {
    alg: &'static dyn signature::VerificationAlgorithm,
}

static ED: Verifier = Verifier {
    alg: &signature::ED25519,
};
static P256: Verifier = Verifier {
    alg: &signature::ECDSA_P256_SHA256_ASN1,
};

impl Verifier {
    fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        signature::UnparsedPublicKey::new(self.alg, pk)
            .verify(msg, sig)
            .is_ok()
    }
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let k = a[0].as_bytes();
    let mut v = k.to_vec();
    scatter(&k[..16], &mut v);
    ctr_iv(&k[..16], &mut v);
    mac_kdf(k, k);
    kem1024();
    ed_seed(k);
    println!("{} {}", ED.verify(k, k, k), P256.verify(k, k, k));
}
