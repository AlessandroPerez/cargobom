//! mail-auth: an enum over keys of another file, each arm calling the same method on its
//! payload. The payloads are two types: the arm below the one cited is no call of that
//! instance, and the text shows it by the variant's declared type.

use crate::backend::{self, Sign};

pub enum Key {
    Short(backend::ShortKey),
    Long(backend::LongKey),
}

impl Key {
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        match self {
            Key::Short(k) => k.sign(data),
            Key::Long(k) => k.sign(data),
        }
    }
}
