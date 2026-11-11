//! dryoc and ml-dsa: an absorbing state generic over constants.

use sha2::{Digest, Sha256, Sha512};

pub struct Sponge<const RATE: usize, const ROUNDS: usize> {
    seen: Vec<u8>,
}

fn permute<const ROUNDS: usize, const WIDE: bool>(data: &[u8]) -> Vec<u8> {
    let mut out = if WIDE {
        Sha512::digest(data).to_vec()
    } else {
        Sha256::digest(data).to_vec()
    };
    out.truncate(ROUNDS);
    out
}

impl<const RATE: usize, const ROUNDS: usize> Sponge<RATE, ROUNDS> {
    pub fn new() -> Self {
        Sponge { seen: Vec::new() }
    }

    // (no type parameter of its own: every call on one variable is one instance)
    pub fn absorb(&mut self, input: &[u8]) {
        self.seen.extend_from_slice(input);
    }

    pub fn squeeze(&self) -> Vec<u8> {
        // the call's arguments are the impl's own const parameters: `ROUNDS` is `24` or `12`
        // as the instance has it, and says nothing here
        if RATE > 100 {
            permute::<ROUNDS, true>(&self.seen)
        } else {
            permute::<ROUNDS, false>(&self.seen)
        }
    }
}

const RATE_WIDE: usize = 136;

pub fn wide(data: &[u8]) -> Vec<u8> {
    // a const argument written by name
    let mut xof = Sponge::<RATE_WIDE, 24>::new();
    // two calls of one method on one variable, on consecutive lines: the instantiation cited
    // at the first is as true at the second
    xof.absorb(data);
    xof.absorb(b"domain");
    xof.squeeze()
}

pub fn narrow(data: &[u8]) -> Vec<u8> {
    let mut xof = Sponge::<64, 12>::new();
    xof.absorb(data);
    xof.squeeze()
}

pub struct Shake(Vec<u8>);

impl Shake {
    // (returns its own type: each call in a chain is on the type of the one before)
    pub fn absorb(mut self, input: &[u8]) -> Self {
        self.0.extend(Sha256::digest(input));
        self
    }
}

pub fn chained(data: &[u8]) -> Vec<u8> {
    let h = Shake(Vec::new())
        .absorb(data)
        .absorb(b"k")
        .absorb(b"l");
    h.0
}
