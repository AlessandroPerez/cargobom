// A function-like procedural macro (fifth audit round): its code is cited at the invocation,
// tagged `[macro pm::hash_it!]`, expanded from its own line; the verifier accepts it without a
// `macro_rules!` body to look into. A one-line `macro_rules!` is checked in its body.
use sha2::Digest;

macro_rules! hm { ($d:expr) => { sha2::Sha512::digest($d) }; }

fn main() {
    let d = pm::hash_it!(b"data");
    let e = hm!(b"data");
    println!("{} {}", d.len(), e.len());
}
