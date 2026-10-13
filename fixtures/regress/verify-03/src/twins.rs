// identical statements in sibling modules and in two types' methods of one name
use sha2::{Digest, Sha256, Sha512};

pub mod a {
    use super::*;
    pub fn f(d: &[u8]) -> usize {
        Sha256::digest(d).len()
    }
}

pub mod b {
    use super::*;
    pub fn f(d: &[u8]) -> usize {
        Sha256::digest(d).len()
    }
}

struct One;
struct Two;
impl One {
    fn go(d: &[u8]) -> usize {
        Sha512::digest(d).len()
    }
}
impl Two {
    fn go(d: &[u8]) -> usize {
        Sha512::digest(d).len()
    }
}

pub fn run(d: &[u8]) -> usize {
    a::f(d) + b::f(d) + One::go(d) + Two::go(d)
}
