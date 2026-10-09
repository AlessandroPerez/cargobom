// Knowledge-base audit cases (RustCrypto and friends). Each function is one case; the comment
// says what the CBOM must show.
use hmac::{Hmac, Mac};
use rand::rngs::{OsRng, StdRng};
use rand::SeedableRng;
use rsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use rsa::signature::{DigestSigner, DigestVerifier, RandomizedSigner};
use rsa::{Oaep, Pkcs1v15Sign, Pss, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};

// CBC and CTR over Blowfish are not AES: no AES-CBC / AES-CTR asset (cbc/ctr entries hold for
// AES ciphers only)
fn blowfish_modes(key: &[u8], iv: &[u8], data: &mut [u8]) -> Vec<u8> {
    use cbc::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit, StreamCipher};
    let enc = cbc::Encryptor::<blowfish::Blowfish>::new_from_slices(key, iv).unwrap();
    let mut c = ctr::Ctr64BE::<blowfish::Blowfish>::new_from_slices(key, iv).unwrap();
    c.apply_keystream(data);
    enc.encrypt_padded_vec_mut::<Pkcs7>(data)
}

// aes's encrypt-only / decrypt-only types: AES-128-CBC (encrypt), AES-256-CBC (decrypt),
// AES-192-CTR
fn aes_enc_dec_types(key: &[u8], iv: &[u8], data: &mut [u8]) -> Vec<u8> {
    use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit, StreamCipher};
    let enc = cbc::Encryptor::<aes::Aes128Enc>::new_from_slices(&key[..16], iv).unwrap();
    let ct = enc.encrypt_padded_vec_mut::<Pkcs7>(data);
    let dec = cbc::Decryptor::<aes::Aes256Dec>::new_from_slices(&key[..32], iv).unwrap();
    let _ = dec.decrypt_padded_vec_mut::<Pkcs7>(&ct);
    let mut c = ctr::Ctr128BE::<aes::Aes192Enc>::new_from_slices(&key[..24], iv).unwrap();
    c.apply_keystream(data);
    ct
}

// rsa 0.9 signing with padding values: RSA-PKCS1-1.5-SHA-256 (sign, verify), RSA-PSS-SHA-256
// (sign), with SHA-256 as a component
fn rsa_padding_values(key: &RsaPrivateKey, msg: &[u8]) -> bool {
    let hashed = Sha256::digest(msg);
    let s = key.sign(Pkcs1v15Sign::new::<Sha256>(), &hashed).unwrap();
    let _p = key.sign_with_rng(&mut OsRng, Pss::new::<Sha256>(), &hashed).unwrap();
    RsaPublicKey::from(key).verify(Pkcs1v15Sign::new::<Sha256>(), &hashed, &s).is_ok()
}

// the signature traits: sign_digest, sign_prehash, try_sign_with_rng are sign;
// verify_digest, verify_prehash verify
fn signature_traits(key: &RsaPrivateKey, msg: &[u8]) -> bool {
    let sk = rsa::pkcs1v15::SigningKey::<Sha256>::new(key.clone());
    let vk = rsa::pkcs1v15::VerifyingKey::<Sha256>::new(RsaPublicKey::from(key));
    let s1: rsa::pkcs1v15::Signature = sk.sign_digest(Sha256::new_with_prefix(msg));
    let h = Sha256::digest(msg);
    let s2: rsa::pkcs1v15::Signature = sk.sign_prehash(&h).unwrap();
    let pss = rsa::pss::SigningKey::<Sha256>::new(key.clone());
    let _s3: rsa::pss::Signature = pss.try_sign_with_rng(&mut OsRng, msg).unwrap();
    vk.verify_digest(Sha256::new_with_prefix(msg), &s1).is_ok() && vk.verify_prehash(&h, &s2).is_ok()
}

// OAEP with a separate MGF1 hash: RSA-OAEP-SHA-256, mgf_hash SHA-1, both hashes components
fn oaep_mgf(key: &RsaPublicKey, msg: &[u8]) -> Vec<u8> {
    key.encrypt(&mut OsRng, Oaep::new_with_mgf_hash::<Sha256, sha1::Sha1>(), msg).unwrap()
}

// rsa's encryption key types: oaep::EncryptingKey<Sha256> is RSA-OAEP-SHA-256 (encrypt_with_rng
// is encrypt), pkcs1v15::DecryptingKey RSA-PKCS1-1.5 (pke; decrypt); a PSS salt length given
// as a constant is the salt_len parameter of RSA-PSS-SHA-256
fn rsa_keys_and_salt(key: &RsaPrivateKey, msg: &[u8]) -> bool {
    use rsa::traits::{Decryptor, RandomizedEncryptor};
    let ek = rsa::oaep::EncryptingKey::<Sha256>::new(RsaPublicKey::from(key));
    let ct = ek.encrypt_with_rng(&mut OsRng, msg).unwrap();
    let dk = rsa::pkcs1v15::DecryptingKey::new(key.clone());
    let _ = dk.decrypt(&ct);
    let h = Sha256::digest(msg);
    key.sign_with_rng(&mut OsRng, Pss::new_with_salt::<Sha256>(20), &h).is_ok()
}

// pbkdf2's generic PRF API: PBKDF2-SHA-256-4096-32 (hard-coded salt) and
// PBKDF2-SHA-256-1000-16; the HMAC is a component, not a call of its own
fn pbkdf2_generic(pw: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    pbkdf2::pbkdf2::<Hmac<Sha256>>(pw, b"fixed-salt", 4096, &mut out).unwrap();
    let _a: [u8; 16] = pbkdf2::pbkdf2_array::<Hmac<Sha256>, 16>(pw, &out, 1000).unwrap();
    out
}

// md5's streaming context: MD5, consume and compute are digest
fn md5_ctx(d: &[u8]) -> [u8; 16] {
    let mut c = md5::Context::new();
    c.consume(d);
    c.compute().0
}

// password-hash API with the crates' defaults: scrypt-131072-8-1-32, PBKDF2-SHA-256-600000-32
fn password_hash_defaults(pw: &[u8]) -> (String, String) {
    use pbkdf2::password_hash::{PasswordHasher, SaltString};
    let salt = SaltString::generate(&mut OsRng);
    let a = scrypt::Scrypt.hash_password(pw, &salt).unwrap().to_string();
    let b = pbkdf2::Pbkdf2.hash_password(pw, &salt).unwrap().to_string();
    (a, b)
}

// scrypt parameters where the Params value is built: Params::new(log_n, 8, 1, 32) gives r = 8
// and p = 1 as parameters and N as unresolved (log_n is not a constant); Params::recommended()
// is N 131072, r 8, p 1. Each scrypt call takes the name and parameters of the Params passed to
// it, with its own output length (32 bytes; the Params length is the password-hash API's):
// `scrypt` with N unresolved, and scrypt-131072-8-1-32. Each constructor is named like its call
fn scrypt_params(pw: &[u8], log_n: u8) -> [u8; 32] {
    let params = scrypt::Params::new(log_n, 8, 1, 32).unwrap();
    let mut out = [0u8; 32];
    scrypt::scrypt(pw, b"salt", &params, &mut out).unwrap();
    let fixed = scrypt::Params::recommended();
    scrypt::scrypt(pw, b"salt", &fixed, &mut out).unwrap();
    out
}

// x25519-dalek's free function: x25519 keyderive, hard-coded key (the scalar)
fn x25519_free(peer: [u8; 32]) -> [u8; 32] {
    x25519_dalek::x25519([7u8; 32], peer)
}

// key generation: EphemeralSecret::random() and StaticSecret::random() are keygen;
// EphemeralSecret::random_from_rng and ReusableSecret::random_from_rng are keygen with an rng
// role (hard-coded: a seeded StdRng; rng: OsRng), and so is x25519-dalek 2.0's deprecated
// StaticSecret::new(rng); ed25519-dalek SigningKey::generate(rng) has an rng role (hard-coded
// seed)
#[allow(deprecated)]
fn keygens() -> [u8; 32] {
    let mut seeded = StdRng::seed_from_u64(7);
    let mut seeded_ed = StdRng::seed_from_u64(8);
    let a = x25519_dalek::EphemeralSecret::random();
    let b = x25519_dalek::EphemeralSecret::random_from_rng(&mut seeded);
    let c = x25519_dalek::ReusableSecret::random_from_rng(OsRng);
    let _s = x25519_dalek::StaticSecret::random();
    let _d = x25519_dalek::StaticSecret::new(OsRng);
    let _e = ed25519_dalek::SigningKey::generate(&mut seeded_ed);
    let pb = x25519_dalek::PublicKey::from(&b);
    let _ = a.diffie_hellman(&pb);
    *c.diffie_hellman(&pb).as_bytes()
}

// Mac::verify_truncated_right is verify; blake3 finalize_xof is digest
fn verify_and_xof(key: &[u8], d: &[u8], tag: &[u8]) -> [u8; 64] {
    let mut m = Hmac::<Sha256>::new_from_slice(key).unwrap();
    m.update(d);
    let _ = m.verify_truncated_right(tag);
    let mut h = blake3::Hasher::new();
    h.update(d);
    let mut out = [0u8; 64];
    h.finalize_xof().fill(&mut out);
    out
}

// Argon2::new_with_secret: the secret is key material (hard-coded key)
fn argon2_secret(pw: &[u8], salt: &[u8]) -> [u8; 32] {
    use argon2::{Algorithm, Argon2, Params, Version};
    let a = Argon2::new_with_secret(b"pepper-pepper", Algorithm::Argon2id, Version::V0x13, Params::default()).unwrap();
    let mut out = [0u8; 32];
    a.hash_password_into(pw, salt, &mut out).unwrap();
    out
}

// jsonwebtoken from_base64_secret: HMAC secret key with a hard-coded key
fn jwt_b64() -> bool {
    let e = jsonwebtoken::EncodingKey::from_base64_secret("c2VjcmV0LXNlY3JldA==").is_ok();
    let d = jsonwebtoken::DecodingKey::from_base64_secret("c2VjcmV0LXNlY3JldA==").is_ok();
    e && d
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let key = args[0].as_bytes();
    let mut buf = [0u8; 32];
    blowfish_modes(&key[..16], &key[..8], &mut buf);
    aes_enc_dec_types(key, &key[..16], &mut buf);
    let rk = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
    rsa_padding_values(&rk, b"m");
    signature_traits(&rk, b"m");
    oaep_mgf(&RsaPublicKey::from(&rk), b"m");
    rsa_keys_and_salt(&rk, b"m");
    pbkdf2_generic(key);
    md5_ctx(key);
    password_hash_defaults(key);
    scrypt_params(key, args.len() as u8 + 10);
    x25519_free([9u8; 32]);
    keygens();
    verify_and_xof(key, key, key);
    argon2_secret(key, key);
    jwt_b64();
}
