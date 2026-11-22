use ring::signature;

pub enum Profile {
    Rsa,
    Ecdsa256,
    Ecdsa384,
    Ed,
}

fn verify_with<A: signature::VerificationAlgorithm>(
    key: &[u8],
    msg: &[u8],
    sig: &[u8],
    algorithm: &'static A,
) -> bool {
    signature::UnparsedPublicKey::new(algorithm, key)
        .verify(msg, sig)
        .is_ok()
}

pub fn verify(p: Profile, key: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    match p {
        Profile::Rsa => {
            verify_with(key, msg, sig, &signature::RSA_PKCS1_2048_8192_SHA256)
        }
        Profile::Ecdsa256 => {
            verify_with(key, msg, sig, &signature::ECDSA_P256_SHA256_ASN1)
        }
        Profile::Ecdsa384 => {
            verify_with(key, msg, sig, &signature::ECDSA_P384_SHA384_ASN1)
        }
        Profile::Ed => {
            verify_with(key, msg, sig, &signature::ED25519)
        }
    }
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let p = match a.len() {
        1 => Profile::Rsa,
        2 => Profile::Ecdsa256,
        3 => Profile::Ecdsa384,
        _ => Profile::Ed,
    };
    println!("{}", verify(p, b"key", b"msg", b"sig"));
}
