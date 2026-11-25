use sha2::Digest;

#[pm::keyed("a name")]
fn tag(d: &[u8]) -> Vec<u8> {
    sha2::Sha512::digest(d).to_vec()
}

#[pm::counted]
fn plain(d: &[u8]) -> Vec<u8> {
    sha2::Sha512_256::digest(d).to_vec()
}

fn main() {
    let a = std::env::args().next().unwrap_or_default();
    println!("{:x?} {:x?}", plain(b"x"), tag(a.as_bytes()));
    println!("{:x?} {:x?}", pm::hashed!("some text"), named());
    let text = a.as_bytes();
    println!("{:x?}", pm::hashed!(text));
}
