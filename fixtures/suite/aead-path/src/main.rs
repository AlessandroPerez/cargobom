use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};

const FIPS_ONLY: bool = false;

fn main() {
    let alg: &'static aead::Algorithm = if FIPS_ONLY {
        &aead::AES_128_GCM
    } else if std::env::args().count() > 1 {
        &aead::AES_256_GCM
    } else {
        &aead::CHACHA20_POLY1305
    };
    let key = LessSafeKey::new(UnboundKey::new(alg, &vec![4u8; alg.key_len()]).unwrap());
    let mut buf = b"path".to_vec();
    key.seal_in_place_append_tag(Nonce::assume_unique_for_key([9u8; 12]), Aad::empty(), &mut buf).unwrap();
    let pt = key.open_in_place(Nonce::assume_unique_for_key([9u8; 12]), Aad::empty(), &mut buf).unwrap();
    println!("{}", pt.len());
}
