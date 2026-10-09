// Knowledge-base audit cases (aws-lc-rs). Each function is one case; the comment says what the
// CBOM must show.
#![allow(deprecated)]
use aws_lc_rs::{aead, agreement, cipher, cmac, digest, hkdf, kem, key_wrap, signature, tls_prf};
use aws_lc_rs::key_wrap::{KeyWrap, KeyWrapPadded};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::KeyPair;

// keys built from an algorithm and literal bytes are hard-coded keys: RandomizedNonceKey
// (AES-128-GCM), TlsRecordSealingKey (AES-256-GCM), the QUIC header-protection key (AES-128),
// cipher::UnboundCipherKey (AES-256), cmac::Key (CMAC-AES-128)
fn literal_keys(msg: &[u8]) -> Vec<u8> {
    let k = aead::RandomizedNonceKey::new(&aead::AES_128_GCM, &[0u8; 16]).unwrap();
    let mut buf = msg.to_vec();
    let _n = k.seal_in_place_append_tag(aead::Aad::empty(), &mut buf).unwrap();
    let mut t = aead::TlsRecordSealingKey::new(&aead::AES_256_GCM, aead::TlsProtocolId::TLS13, &[1u8; 32]).unwrap();
    let nonce = aead::Nonce::assume_unique_for_key([0u8; 12]);
    let _ = t.seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut buf);
    let hp = aead::quic::HeaderProtectionKey::new(&aead::quic::AES_128, &[2u8; 16]).unwrap();
    let _mask = hp.new_mask(&[0u8; 16]);
    let uk = cipher::UnboundCipherKey::new(&cipher::AES_256, &[3u8; 32]).unwrap();
    let ek = cipher::PaddedBlockEncryptingKey::cbc_pkcs7(uk).unwrap();
    let _ = ek.encrypt(&mut buf);
    let ck = cmac::Key::new(cmac::AES_128, &[4u8; 16]).unwrap();
    let _tag = cmac::sign(&ck, msg);
    buf
}

// a pseudorandom key used as is (hkdf::Prk::new_less_safe): hard-coded key on HKDF-SHA-256;
// the TLS 1.2 PRF secret (tls_prf::Secret::new): hard-coded key on TLS12-PRF-SHA-256, derive is
// keyderive; P_SHA384 named only: TLS12-PRF-SHA-384
fn prk_and_prf() -> usize {
    let prk = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, &[5u8; 32]);
    let info: [&[u8]; 1] = [b"info"];
    let _okm = prk.expand(&info, hkdf::HKDF_SHA256).is_ok();
    let s = tls_prf::Secret::new(&tls_prf::P_SHA256, &[6u8; 48]).unwrap();
    let out = s.derive(b"master secret", b"seed", 48).unwrap();
    let _other = &tls_prf::P_SHA384;
    out.as_ref().len()
}

// ML-KEM: generate is keygen, encapsulate and decapsulate are encapsulate / decapsulate
fn ml_kem() -> bool {
    let dk = kem::DecapsulationKey::generate(&kem::ML_KEM_768).unwrap();
    let ek = dk.encapsulation_key().unwrap();
    let (ct, ss1) = ek.encapsulate().unwrap();
    let ss2 = dk.decapsulate(ct).unwrap();
    ss1.as_ref() == ss2.as_ref()
}

// key agreement: the shared secret of agree_ephemeral (defining path
// agreement::ephemeral::agree_ephemeral) used as an AEAD key is derived; agreement::agree is a
// keyderive use of ECDH-P-256
fn agreements(peer: &[u8]) -> bool {
    let rng = SystemRandom::new();
    let sk = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng).unwrap();
    let shared: [u8; 32] = agreement::agree_ephemeral(sk, agreement::UnparsedPublicKey::new(&agreement::X25519, peer), aws_lc_rs::error::Unspecified, |km| {
        let mut k = [0u8; 32];
        k.copy_from_slice(km);
        Ok(k)
    })
    .unwrap();
    let ok = aead::UnboundKey::new(&aead::AES_256_GCM, &shared).is_ok();
    let pk = agreement::PrivateKey::generate(&agreement::ECDH_P256).unwrap();
    let _ = agreement::agree(&pk, agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, peer), aws_lc_rs::error::Unspecified, |km| Ok(km.to_vec()));
    ok
}

// key wrapping: the KEK (AesKek::new with a literal key) is AES-256 for key wrapping; wrap is
// AES-256-KW, wrap_with_padding AES-256-KWP (RFC 5649)
fn key_wrapping(key: &[u8]) -> usize {
    let kek = key_wrap::AesKek::new(&key_wrap::AES_256, &[7u8; 32]).unwrap();
    let mut out = [0u8; 64];
    let a = kek.wrap(&key[..16], &mut out).map(|o| o.len()).unwrap_or(0);
    let kek2 = key_wrap::AesKek::new(&key_wrap::AES_256, &[8u8; 32]).unwrap();
    let b = kek2.wrap_with_padding(key, &mut out).map(|o| o.len()).unwrap_or(0);
    a + b
}

// algorithms the knowledge base lacked: SHA3-256 / SHA3-512 digests; DES-56, 3DES-112 and
// 3DES-168 cipher keys (feature legacy-des); CMAC-3DES-168
fn legacy_and_sha3(msg: &[u8]) -> usize {
    let a = digest::digest(&digest::SHA3_256, msg);
    let b = digest::digest(&digest::SHA3_512, msg);
    let mut buf = msg.to_vec();
    for alg in [&cipher::DES_FOR_LEGACY_USE_ONLY, &cipher::DES_EDE_FOR_LEGACY_USE_ONLY, &cipher::DES_EDE3_FOR_LEGACY_USE_ONLY] {
        let _ = &alg;
    }
    let uk = cipher::UnboundCipherKey::new(&cipher::DES_EDE3_FOR_LEGACY_USE_ONLY, msg).unwrap();
    let ek = cipher::PaddedBlockEncryptingKey::cbc_pkcs7(uk).unwrap();
    let _ = ek.encrypt(&mut buf);
    let ck = cmac::Key::new(cmac::DES_EDE3_FOR_LEGACY_USE_ONLY, msg).unwrap();
    let _ = cmac::sign(&ck, msg);
    a.as_ref().len() + b.as_ref().len()
}

// what a descriptor can do: the *_SIGNING descriptors sign (EcdsaKeyPair::generate_pkcs8, sign);
// the verification ones verify (the verify call); ECDSA_P384_SHA256_ASN1, RSA_PSS_2048_8192_SHA512
// and ED25519 named without a call verify, as this program verifies with aws-lc-rs;
// RSA_PKCS1_SHA384 (a signing encoding) named without a call signs, as the program signs
fn descriptor_functions(msg: &[u8]) -> bool {
    let rng = SystemRandom::new();
    let doc = signature::EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256K1_SHA256_ASN1_SIGNING, &rng).unwrap();
    let kp = signature::EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256K1_SHA256_ASN1_SIGNING, doc.as_ref()).unwrap();
    let sig = kp.sign(&rng, msg).unwrap();
    let pk = signature::UnparsedPublicKey::new(&signature::ECDSA_P256K1_SHA256_ASN1, kp.public_key().as_ref());
    let ok = pk.verify(msg, sig.as_ref()).is_ok();
    let _verify_only = &signature::ECDSA_P384_SHA256_ASN1;
    let _rsa_verify_only = &signature::RSA_PSS_2048_8192_SHA512;
    let _ed_verify_only = &signature::ED25519;
    let _rsa_sign_only = &signature::RSA_PKCS1_SHA384;
    ok
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let k = a[0].as_bytes();
    literal_keys(k);
    prk_and_prf();
    ml_kem();
    agreements(&[9u8; 32]);
    key_wrapping(k);
    legacy_and_sha3(k);
    descriptor_functions(k);
}
