//! zip: a key stream generic over its block cipher.

use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};

pub use aes::{Aes128, Aes256};

pub struct KeyStream<C> {
    cipher: C,
    counter: u128,
}

impl<C> KeyStream<C>
where
    C: BlockEncrypt + KeyInit,
{
    pub fn new(key: &[u8]) -> KeyStream<C> {
        KeyStream {
            cipher: C::new_from_slice(&key[..C::key_size()]).unwrap(),
            counter: 1,
        }
    }
}

pub trait Crypt {
    fn crypt_in_place(&mut self, target: &mut [u8]);
}

impl<C> Crypt for KeyStream<C>
where
    C: BlockEncrypt,
{
    fn crypt_in_place(&mut self, target: &mut [u8]) {
        for chunk in target.chunks_mut(16) {
            let mut block = GenericArray::<u8, C::BlockSize>::default();
            let n = block.len().min(16);
            block[..n].copy_from_slice(&self.counter.to_le_bytes()[..n]);
            self.counter += 1;
            self.cipher.encrypt_block(&mut block);
            for (t, k) in chunk.iter_mut().zip(block.iter()) {
                *t ^= k;
            }
        }
    }
}
