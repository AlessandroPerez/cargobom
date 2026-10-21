use rsa::pkcs8::DecodePrivateKey;
use rsa::{Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha384};

struct Signer {
    key: RsaPrivateKey,
    scheme: Pkcs1v15Sign,
}

fn load() -> Signer {
    let key = RsaPrivateKey::from_pkcs8_pem(include_str!("rsa.pem")).unwrap();
    Signer { key, scheme: Pkcs1v15Sign::new::<Sha384>() }
}

fn sign(s: &Signer, msg: &[u8]) -> Vec<u8> {
    let hashed = Sha384::digest(msg);
    s.key.sign(s.scheme.clone(), &hashed).unwrap()
}

fn check(s: &Signer, msg: &[u8], sig: &[u8]) -> bool {
    let public = RsaPublicKey::from(&s.key);
    let expected = Sha384::digest(msg);
    public.verify(s.scheme.clone(), &expected, sig).is_ok()
}

fn main() {
    let s = load();
    let sig = sign(&s, b"field");
    println!("{}", check(&s, b"field", &sig));
}
