//! pkcs5: a block cipher chosen as the type argument of a function that runs it in CBC. The
//! choice is AES-128-CBC's and AES-256-CBC's: no AES-128 or AES-256 runs on its own.

use aes::cipher::{BlockCipher, BlockEncryptMut, KeyInit, KeyIvInit, block_padding::Pkcs7};

fn cbc_encrypt<C>(key: &[u8], iv: &[u8], buf: &mut [u8], len: usize) -> usize
where
    C: BlockEncryptMut + BlockCipher + KeyInit,
{
    cbc::Encryptor::<C>::new_from_slices(&key[..C::key_size()], iv)
        .unwrap()
        .encrypt_padded_mut::<Pkcs7>(buf, len)
        .unwrap()
        .len()
}

pub fn encrypt(bits: usize, key: &[u8], iv: &[u8], buf: &mut [u8], len: usize) -> usize {
    match bits {
        0..=128 => cbc_encrypt::<aes::Aes128Enc>(key, iv, buf, len),
        _ => cbc_encrypt::<aes::Aes256Enc>(key, iv, buf, len),
    }
}
