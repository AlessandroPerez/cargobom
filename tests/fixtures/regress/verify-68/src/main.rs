use sha2::{Digest, Sha256};

fn main() {
    let a = std::env::args().next().unwrap_or_default();
    println!("{:x?}", dep::via!("a token"));
    println!(
        "{:x?}",
        dep::part!("one part", Sha256::digest(a.as_bytes()))
    );
    println!("{:x?}", dep::again!("handed twice"));
}
