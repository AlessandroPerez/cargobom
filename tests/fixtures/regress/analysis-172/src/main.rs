// Each call is accounted for by its own occurrence, not by any at its position: the
// multiplication applied to `generator()`'s result and the one in `both!` beside a cited digest
// are cited, at the operator or the macro. Operators on curve points and
// scalars (p256's, curve25519-dalek's on references) have no knowledge-base meaning: the check
// cites them as unknown operations.
use p256::elliptic_curve::{Field, Group, PrimeField};
use p256::{ProjectivePoint, Scalar};
use rand_core::OsRng;
use sha2::{Digest, Sha256};

macro_rules! both {
    ($d:expr, $s:expr) => {{
        let h = Sha256::digest($d);
        let p = ProjectivePoint::GENERATOR * $s;
        (h, p)
    }};
}

fn main() {
    let s = Scalar::random(&mut OsRng);
    let p = ProjectivePoint::GENERATOR * s;
    let q = p + ProjectivePoint::GENERATOR;
    let r = ProjectivePoint::generator() * s;
    let inv = s.invert().unwrap();
    let d = std::env::args().next().unwrap_or_default().into_bytes();
    let (h, b) = both!(&d, Scalar::from_repr(s.to_repr()).unwrap());
    let e = curve25519_dalek::EdwardsPoint::mul_base(&curve25519_dalek::Scalar::from(5u64));
    let f = &e * &curve25519_dalek::Scalar::from(3u64);
    println!(
        "{:?} {:?} {:?} {:x} {:?} {:?}",
        q.to_affine(),
        r.to_affine(),
        inv,
        h,
        b.to_affine(),
        f.compress()
    );
}
