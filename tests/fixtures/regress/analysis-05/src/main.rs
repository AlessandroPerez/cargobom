use hmac::{Hmac, Mac};
use ring::aead::{Algorithm, Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use sha2::Sha256;

const ALG: &Algorithm = &AES_256_GCM;

fn aliased(key: &[u8]) {
    let k = LessSafeKey::new(UnboundKey::new(ALG, key).unwrap());
    let mut buf = vec![0u8; 4];
    k.seal_in_place_append_tag(Nonce::assume_unique_for_key([1u8; 12]), Aad::empty(), &mut buf).unwrap();
}

fn formatted() {
    let secret = std::env::var("S").unwrap();
    let key = format!("{secret}");
    let _m = Hmac::<Sha256>::new_from_slice(key.as_bytes());
}

fn pushed() {
    let mut key = String::new();
    key.push_str("hard-coded-secret");
    let _m = Hmac::<Sha256>::new_from_slice(key.as_bytes());
}

fn two_iters(pw: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut a = [0u8; 32]; let mut b = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(pw, b"s", 10000, &mut a); let c: [u8; 32] = pbkdf2::pbkdf2_hmac_array::<Sha256, 32>(pw, b"s", 1000); b.copy_from_slice(&c);
    (a, b)
}

fn main() {
    aliased(b"k");
    formatted();
    pushed();
    let _ = two_iters(b"p");
}
