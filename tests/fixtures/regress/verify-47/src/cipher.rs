//! zip: the instances chosen by an enum, each arm calling the same method.

use crate::stream::{self, Crypt};

pub enum Cipher {
    Aes128(Box<stream::KeyStream<stream::Aes128>>),
    Aes256(Box<stream::KeyStream<stream::Aes256>>),
}

impl Cipher {
    pub fn from_mode(bits: usize, key: &[u8]) -> Self {
        // a path written over three lines: cited where it starts, its function named on the
        // third
        match bits {
            0..=128 => Cipher::Aes128(Box::new(stream::KeyStream::<
                stream::Aes128,
            >::new(key))),
            _ => Cipher::Aes256(Box::new(stream::KeyStream::<
                stream::Aes256,
            >::new(key))),
        }
    }

    pub fn crypt_in_place(&mut self, target: &mut [u8]) {
        // the arms' calls differ by the payload of the variant matched, a type of another file:
        // the instantiation of the AES-128 stream is at the first arm, not the line below
        match self {
            Self::Aes128(cipher) => cipher.crypt_in_place(target),
            Self::Aes256(cipher) => cipher.crypt_in_place(target),
        }
    }
}
