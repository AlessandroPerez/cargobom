use lupine_sign::hybrid::{HybridSignature, HybridVerifyingKey};
use lupine_sign::mldsa::{MlDsaSignature, MlDsaVerifyingKey};

// ML-DSA alone: the walk reaches the verification of each parameter set through here first.
fn alone<P: ml_dsa::MlDsaParams>(key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let (Ok(key), Ok(signature)) = (
        MlDsaVerifyingKey::<P>::from_bytes(key),
        MlDsaSignature::<P>::from_bytes(signature),
    ) else {
        return false;
    };
    key.verify(message, &signature).is_ok()
}

// Ed25519 and ML-DSA together: the Ed25519 is the hybrid's own, whatever `P` is.
fn both<P: ml_dsa::MlDsaParams>(key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let (Ok(key), Ok(signature)) = (
        HybridVerifyingKey::<P>::from_bytes(key),
        HybridSignature::<P>::from_bytes(signature),
    ) else {
        return false;
    };
    key.verify(message, &signature).is_ok()
}

// The hybrid for whatever its caller was given: `both::<P>` names no type.
fn through<P: ml_dsa::MlDsaParams>(key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    !message.is_empty() && both::<P>(key, message, signature)
}

type Strongest = ml_dsa::MlDsa87;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let part = |i: usize| args.get(i).map(|a| a.as_bytes()).unwrap_or_default();
    let (key, message, signature) = (part(1), part(2), part(3));
    println!("{}", alone::<ml_dsa::MlDsa44>(key, message, signature));
    println!("{}", alone::<ml_dsa::MlDsa65>(key, message, signature));
    println!("{}", alone::<ml_dsa::MlDsa87>(key, message, signature));
    println!("{}", through::<ml_dsa::MlDsa44>(key, message, signature));
    println!("{}", both::<ml_dsa::MlDsa65>(key, message, signature));
    println!("{}", both::<Strongest>(key, message, signature));
}
