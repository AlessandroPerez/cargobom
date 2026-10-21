use aws_lc_rs::{cipher, cmac, key_wrap};
use aws_lc_rs::key_wrap::KeyWrap;

fn main() {
    let k = cmac::Key::new(cmac::AES_128, &[0u8; 16]).unwrap();
    let _t = cmac::sign(&k, b"msg");
    let kek = key_wrap::AesKek::new(&key_wrap::AES_128, &[0u8; 16]).unwrap();
    let mut out = [0u8; 40];
    let _ = kek.wrap(&[0u8; 32], &mut out);
    let uk = cipher::UnboundCipherKey::new(&cipher::AES_128, &[0u8; 16]).unwrap();
    let ek = cipher::PaddedBlockEncryptingKey::cbc_pkcs7(uk).unwrap();
    let mut buf = b"hello".to_vec();
    let _ = ek.encrypt(&mut buf);
}
