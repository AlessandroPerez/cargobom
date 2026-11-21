use sha2::Digest;

// The project's compiler flags set `extra`: this one is the program's.
#[cfg(extra)]
fn tagged(d: &[u8]) -> usize {
    sha2::Sha224::digest(d).len()
}

#[cfg(not(extra))]
fn tagged(d: &[u8]) -> usize {
    plain(d)
}

// Reached only from the branch the project's flags leave out.
pub fn plain(d: &[u8]) -> usize {
    sha2::Sha512_256::digest(d).len()
}

fn main() {
    let input = std::env::args().nth(1).unwrap_or_default().into_bytes();
    println!(
        "{} {} {}",
        quiet::first(&input).len(),
        checked::second(&input).len(),
        tagged(&input)
    );
}
