// Round 9: neighbouring calls that instantiate one generic function with other type arguments
// (age's `decrypt::aes_ctr::<Aes128Ctr>` above `::<Aes192Ctr>`): each `instantiated by` detail
// carries the call's text, so the self-test's line shifts onto the neighbour are rejected.
use sha2::Digest;

fn h<D: Digest>(d: &[u8]) -> Vec<u8> {
    D::digest(d).to_vec()
}

fn pick(n: usize, d: &[u8]) -> Vec<u8> {
    match n {
        0 => h::<sha2::Sha256>(d),
        1 => h::<sha2::Sha384>(d),
        _ => h::<sha2::Sha512>(d),
    }
}

fn main() {
    let n = std::env::args().count();
    println!("{}", pick(n, b"data").len());
}
