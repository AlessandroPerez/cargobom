// Algorithms that reach a call from other functions (third audit round): through struct
// fields, the fields of structs inside them, a function's parameters (what its callers pass) and
// its return value, `?`, `Box`, and statics built from wrapper structs.
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::rand::SystemRandom;
use ring::signature::{self, EcdsaKeyPair, KeyPair};
use ring::{digest, hmac};

#[derive(Debug)]
struct Error;

// L1: a key pair built by a helper (`?`, `map_err`) and kept in a field; signing reads the
// field in another function: ECDSA P-256 SHA-256
fn key_pair(pkcs8: &[u8], rng: &SystemRandom) -> Result<EcdsaKeyPair, Error> {
    EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8, rng)
        .map_err(|_| Error)
}

struct Signer {
    rng: SystemRandom,
    inner: EcdsaKeyPair,
}

impl Signer {
    fn new(pkcs8: &[u8]) -> Result<Self, Error> {
        let rng = SystemRandom::new();
        let inner = key_pair(pkcs8, &rng)?;
        Ok(Signer { rng, inner })
    }

    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        let sig = self.inner.sign(&self.rng, msg).map_err(|_| Error)?;
        Ok(sig.as_ref().to_vec())
    }
}

// L2: an HMAC key in a field: HMAC-SHA-256 at the sign call
struct Mac {
    key: hmac::Key,
}

impl Mac {
    fn new(secret: &[u8]) -> Mac {
        Mac {
            key: hmac::Key::new(hmac::HMAC_SHA256, secret),
        }
    }

    fn tag(&self, msg: &[u8]) -> hmac::Tag {
        hmac::sign(&self.key, msg)
    }
}

// L3: wrapper structs around an AEAD algorithm, built in statics (rustls's
// `Chacha20Poly1305Aead(AeadAlgorithm(&CHACHA20_POLY1305))`): a field of a field is looked up
// through the outer struct: ChaCha20-Poly1305 only in `ChaCha::key`; `Alg::key` is called by
// the two GCM wrappers only: AES-128-GCM or AES-256-GCM, one of 2, never ChaCha20-Poly1305
struct Alg(&'static aead::Algorithm);
struct ChaCha(Alg);
struct Gcm(Alg);

static CHACHA: ChaCha = ChaCha(Alg(&aead::CHACHA20_POLY1305));
static GCM128: Gcm = Gcm(Alg(&aead::AES_128_GCM));
static GCM256: Gcm = Gcm(Alg(&aead::AES_256_GCM));

impl Alg {
    fn key(&self, k: &[u8]) -> UnboundKey {
        UnboundKey::new(self.0, k).unwrap()
    }
}

impl ChaCha {
    fn key(&self, k: &[u8]) -> UnboundKey {
        UnboundKey::new(self.0.0, k).unwrap()
    }
}

impl Gcm {
    fn key(&self, k: &[u8]) -> UnboundKey {
        self.0.key(k)
    }
}

// L4: a sealing key behind a `Box` in a struct, used by a method taking `self: Box<Self>`:
// AES-256-GCM
struct Sealer {
    key: Box<LessSafeKey>,
}

impl Sealer {
    fn seal(self: Box<Self>, buf: &mut Vec<u8>) -> bool {
        let nonce = Nonce::assume_unique_for_key([0u8; 12]);
        self.key
            .seal_in_place_append_tag(nonce, Aad::empty(), buf)
            .is_ok()
    }
}

// L5: a digest algorithm that is a parameter: what the two callers pass, SHA-256 or SHA-384
fn hash_with(alg: &'static digest::Algorithm, data: &[u8]) -> digest::Digest {
    digest::digest(alg, data)
}

// L6: a key returned by the program's own function through `?` and `Ok(..)`: AES-128-GCM at
// the seal call
fn make_key(k: &[u8]) -> Result<LessSafeKey, Error> {
    let unbound = UnboundKey::new(&aead::AES_128_GCM, k).map_err(|_| Error)?;
    Ok(LessSafeKey::new(unbound))
}

fn seal_with(k: &[u8], buf: &mut Vec<u8>) -> Result<(), Error> {
    let key = make_key(k)?;
    let nonce = Nonce::assume_unique_for_key([1u8; 12]);
    key.seal_in_place_append_tag(nonce, Aad::empty(), buf)
        .map_err(|_| Error)
}

fn main() {
    let input = std::env::args().nth(1).unwrap_or_default().into_bytes();
    if let Ok(s) = Signer::new(&input) {
        println!("{:?} {:?}", s.sign(b"m").is_ok(), s.inner.public_key().as_ref().len());
    }
    let m = Mac::new(&input);
    println!("{:?}", m.tag(b"m").as_ref().len());
    let keys = [CHACHA.key(&input), GCM128.key(&input), GCM256.key(&input)];
    println!("{}", keys.len());
    let s = Box::new(Sealer {
        key: Box::new(LessSafeKey::new(
            UnboundKey::new(&aead::AES_256_GCM, &input).unwrap(),
        )),
    });
    let mut buf = Vec::new();
    println!("{}", s.seal(&mut buf));
    println!(
        "{:?} {:?}",
        hash_with(&digest::SHA256, &input).as_ref().len(),
        hash_with(&digest::SHA384, &input).as_ref().len()
    );
    println!("{:?}", seal_with(&input, &mut buf).is_ok());
}
