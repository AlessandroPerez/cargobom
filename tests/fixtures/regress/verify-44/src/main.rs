// shapes the verifier must read (found by the second independent review): a tuple of descriptors
// bound to a variable, then destructured (`let (p, q) = pair;` binds two parts of one
// statement); a `#[derive(Default)]` under a `#[cfg]`, whose code for a field is expanded from
// the field's line
use ring::digest::{self, Algorithm, SHA256, SHA512};
use sha2::{Digest, Sha256};

#[cfg(all())]
#[derive(Default)]
struct Wrap {
    hasher: Sha256,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let pair = (&SHA256 as &Algorithm, &SHA512 as &Algorithm);
    let (p, q) = pair;
    let d = digest::digest(if args.len() > 4 { p } else { q }, b"x");
    let w = Wrap::default();
    let h = w.hasher.chain_update(b"y").finalize();
    println!("{} {}", d.as_ref().len(), h.len());
}
