// Keys and algorithms kept in enum variants, and a generic extension trait on the way (fourth
// audit round, from rcgen 0.14: `KeyPairKind::Ec(kp)` matched in `sign`, built from
// `EcdsaKeyPair::from_pkcs8(..)._err()?`). The variant's fields are links of their own
// (`Kind::Ec`, `Kind::Hash`); a standard-library enum (`Some(a)`) stands for its value.
use ring::digest;
use ring::rand::SystemRandom;
use ring::signature::{self, EcdsaKeyPair};

pub enum Kind {
    Ec(EcdsaKeyPair),
    Hash(&'static digest::Algorithm, u8),
}

// a generic wrapper of the program's: what `ext` returns is its receiver
trait Ext<T> {
    fn ext(self) -> Result<T, String>;
}

impl<T, E: std::fmt::Debug> Ext<T> for Result<T, E> {
    fn ext(self) -> Result<T, String> {
        self.map_err(|e| format!("{e:?}"))
    }
}

pub struct Holder {
    kind: Kind,
}

impl Holder {
    fn ec(alg: &'static signature::EcdsaSigningAlgorithm) -> Result<Holder, String> {
        let rng = SystemRandom::new();
        let doc = EcdsaKeyPair::generate_pkcs8(alg, &rng).ext()?;
        let kp = EcdsaKeyPair::from_pkcs8(alg, doc.as_ref(), &rng).ext()?;
        Ok(Holder { kind: Kind::Ec(kp) })
    }

    fn hash() -> Holder {
        Holder {
            kind: Kind::Hash(&digest::SHA384, 0),
        }
    }

    fn run(&self, msg: &[u8]) -> Vec<u8> {
        match &self.kind {
            // ECDSA-P-256-SHA-256, the key built in `ec` with the algorithm `main` passes
            Kind::Ec(kp) => kp.sign(&SystemRandom::new(), msg).unwrap().as_ref().to_vec(),
            // SHA-384, from `Kind::Hash`'s first field only
            Kind::Hash(alg, _) => digest::digest(alg, msg).as_ref().to_vec(),
        }
    }
}

// SHA-256, the `Some(..)` the caller passes
fn pick(alg: Option<&'static digest::Algorithm>, m: &[u8]) -> Vec<u8> {
    match alg {
        Some(a) => digest::digest(a, m).as_ref().to_vec(),
        None => Vec::new(),
    }
}

// ring's RSA key pair decoded from PKCS#8 (`RsaKeyPair` is `ring::rsa::keypair::KeyPair`): an
// RSA private key (material), its key hard-coded; the padding at `sign` names the scheme
static RSA_PKCS8: &[u8] = &[0x30, 0x82, 0x04, 0xbe, 0x02, 0x01, 0x00];

fn sign_rsa(msg: &[u8]) -> Vec<u8> {
    let kp = signature::RsaKeyPair::from_pkcs8(RSA_PKCS8).unwrap();
    let mut sig = vec![0; kp.public().modulus_len()];
    kp.sign(&signature::RSA_PKCS1_SHA256, &SystemRandom::new(), msg, &mut sig)
        .unwrap();
    sig
}

fn main() {
    println!("{}", sign_rsa(b"m").len());
    let h = Holder::ec(&signature::ECDSA_P256_SHA256_ASN1_SIGNING).unwrap();
    println!("{}", h.run(b"m").len());
    println!("{}", Holder::hash().run(b"m").len());
    println!("{}", pick(Some(&digest::SHA256), b"m").len());
}
