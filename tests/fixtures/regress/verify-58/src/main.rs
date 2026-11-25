use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

struct Key<M>(M);

trait Signer {
    fn sign(&self, data: &[u8]) -> Vec<u8>;
}

trait Checker {
    fn check(&self, data: &[u8], tag: &[u8]) -> bool;
}

fn with_data<M: Mac + Clone>(mac: &M, data: &[u8]) -> M {
    let mut mac = mac.clone();
    mac.update(data);
    mac
}

impl<M: Mac + Clone> Signer for Key<M> {
    fn sign(&self, data: &[u8]) -> Vec<u8> {
        let mac = with_data(&self.0, data);
        mac.finalize().into_bytes().to_vec()
    }
}

impl<M: Mac + Clone> Checker for Key<M> {
    fn check(&self, data: &[u8], tag: &[u8]) -> bool {
        let mac = with_data(&self.0, data);
        mac.verify_slice(tag).is_ok()
    }
}

fn main() {
    let key = b"0123456789abcdef";
    let n = std::env::args().count();
    // signed with SHA-256 or SHA-1
    let signer: Box<dyn Signer> = match n {
        1 => Box::new(Key(Hmac::<Sha256>::new_from_slice(key).unwrap())),
        _ => Box::new(Key(Hmac::<Sha1>::new_from_slice(key).unwrap())),
    };
    let tag = signer.sign(b"data");
    // checked with SHA-256 or SHA-512
    let checker: Box<dyn Checker> = match n {
        1 => Box::new(Key(Hmac::<Sha256>::new_from_slice(key).unwrap())),
        _ => Box::new(Key(Hmac::<Sha512>::new_from_slice(key).unwrap())),
    };
    println!("{}", checker.check(b"data", &tag));
}
