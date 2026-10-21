mod bom;
mod crlf;
use ring::digest::{self, Algorithm, SHA256, SHA512};
use sha2::{Digest, Sha256};

// R1: function item of a KB crate stored in a local, then called
fn r1(d: &[u8]) -> usize {
    let f = Sha256::digest;
    f(d).len()
}

// R2: KB function passed as a value to a generic std function
fn r2(d: &[&[u8]]) -> usize {
    d.iter().copied().map(Sha256::digest).count()
}

// R3: KB function reified to a fn pointer
fn r3(d: &[u8]) -> usize {
    let h: fn(&'static Algorithm, &[u8]) -> digest::Digest = digest::digest;
    h(&SHA512, d).as_ref().len()
}

// P1: a const holding a reference to a ring static, used in reachable code
const ALG: &Algorithm = &SHA256;
fn p1(d: &[u8]) -> usize {
    digest::digest(ALG, d).as_ref().len()
}

// P2: a promoted array of static refs in a fn
fn p2(d: &[u8]) -> usize {
    let algs: &[&Algorithm] = &[&SHA256, &SHA512];
    algs.iter().map(|a| digest::digest(a, d).as_ref().len()).sum()
}

// P3: associated const
struct H;
impl H {
    const A: &'static Algorithm = &digest::SHA384;
    fn h(d: &[u8]) -> usize {
        digest::digest(Self::A, d).as_ref().len()
    }
}

// P4: generic fn using the const
fn p4<T: AsRef<[u8]>>(d: T) -> usize {
    digest::digest(ALG, d.as_ref()).as_ref().len()
}

fn main() {
    let d = b"x";
    let n = r1(d) + r2(&[d]) + r3(d) + p1(d) + p2(d) + H::h(d) + p4(d) + bom::b(d) + crlf::c(d);
    println!("{n}");
}
