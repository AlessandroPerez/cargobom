use aes::{Aes128, Aes256};
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, StreamCipher};

type CbcEnc = cbc::Encryptor<Aes256>;
type CbcDec = cbc::Decryptor<Aes256>;
type Ctr = ctr::Ctr128BE<Aes128>;

fn main() {
    let key = [0x42u8; 32];
    let iv = [0x24u8; 16];
    let ct = CbcEnc::new(&key.into(), &iv.into()).encrypt_padded_vec_mut::<Pkcs7>(b"block mode");
    let pt = CbcDec::new(&key.into(), &iv.into()).decrypt_padded_vec_mut::<Pkcs7>(&ct).unwrap();
    let mut stream = *b"counter mode";
    Ctr::new(&[0x11u8; 16].into(), &[0u8; 16].into()).apply_keystream(&mut stream);
    println!("{} {} {}", ct.len(), pt.len(), stream.len());
}
