use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};

trait Profile {
    fn cipher(&self) -> &'static aead::Algorithm;
}

struct Mobile;
struct Server;

impl Profile for Mobile {
    fn cipher(&self) -> &'static aead::Algorithm {
        &aead::CHACHA20_POLY1305
    }
}

impl Profile for Server {
    fn cipher(&self) -> &'static aead::Algorithm {
        &aead::AES_256_GCM
    }
}

fn seal(p: &dyn Profile, msg: &[u8]) -> Vec<u8> {
    let alg = p.cipher();
    let key = LessSafeKey::new(UnboundKey::new(alg, &vec![5u8; alg.key_len()]).unwrap());
    let mut buf = msg.to_vec();
    let nonce = Nonce::assume_unique_for_key([0u8; 12]);
    key.seal_in_place_append_tag(nonce, Aad::from(b"hdr"), &mut buf).unwrap();
    buf
}

fn main() {
    let p: Box<dyn Profile> = Box::new(Mobile);
    println!("{}", seal(p.as_ref(), b"dyn").len());
}
