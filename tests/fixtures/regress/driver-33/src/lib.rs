// A library's generic functions, which no walked instance shows: their calls into the crypto
// set are accounted for too, resolved for their own type parameters where those fix the
// function. `derive_point`'s scalar multiplication and `Boxed::<K>::shared`'s X25519 ladder
// (`scalar * point` on curve25519-dalek's types, crypto_box's shape) have no knowledge-base
// meaning: the check cites them, at the operator.
use curve25519_dalek::{MontgomeryPoint, Scalar as DScalar};
use p256::elliptic_curve::PrimeField;
use p256::{ProjectivePoint, Scalar};
use sha2::{Digest, Sha256};

pub fn derive_point<T: AsRef<[u8]>>(seed: T) -> ProjectivePoint {
    let h = Sha256::digest(seed.as_ref());
    let s = Scalar::from_repr(h).unwrap();
    ProjectivePoint::GENERATOR * s
}

pub fn derive_point_bytes(seed: &[u8]) -> ProjectivePoint {
    let h = Sha256::digest(seed);
    let s = Scalar::from_repr(h).unwrap();
    ProjectivePoint::GENERATOR * s
}

pub struct Boxed<K> {
    pub secret: DScalar,
    pub kdf: K,
}

impl<K: Fn(&[u8]) -> Vec<u8>> Boxed<K> {
    pub fn shared(&self, peer: &MontgomeryPoint) -> Vec<u8> {
        let s = self.secret * peer;
        (self.kdf)(s.as_bytes())
    }
}
