// A second binary of the package: a crate of the build under its target's name, not the
// package's (katwalk's `mldsa_wrapper`). Its own generic function, instantiated, is an
// occurrence whose symbol is of that crate.
use sha2::Digest;

fn pick<D: Digest>(d: &[u8]) -> Vec<u8> {
    D::digest(d).to_vec()
}

fn main() {
    let input = std::env::args().nth(1).unwrap_or_default().into_bytes();
    println!("{}", pick::<sha2::Sha256>(&input).len());
}
