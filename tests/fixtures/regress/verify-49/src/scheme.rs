//! openidconnect: a function generic over the signature scheme, handed a value whose
//! constructor names the hash. The call chooses RSA-PKCS1-1.5 with SHA-256 or with SHA-512;
//! inside the function the scheme is the type's, whatever hash its callers' values name.

use rsa::traits::SignatureScheme;
use rsa::{BigUint, Pkcs1v15Sign, RsaPublicKey};

fn verify_with(padding: impl SignatureScheme, msg: &[u8], sig: &[u8]) -> bool {
    let key = RsaPublicKey::new(BigUint::from(65_537u32), BigUint::from(3u32));
    match key {
        Ok(key) => key.verify(padding, msg, sig).is_ok(),
        Err(_) => false,
    }
}

pub fn verify(msg: &[u8], sig: &[u8], long: bool) -> bool {
    if long {
        verify_with(Pkcs1v15Sign::new::<sha2::Sha512>(), msg, sig)
    } else {
        verify_with(
            Pkcs1v15Sign::new::<sha2::Sha256>(),
            msg,
            sig,
        )
    }
}
