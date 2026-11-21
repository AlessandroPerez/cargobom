use sha2::Digest;

#[link(name = "rcbom_no_such_library")]
unsafe extern "C" {
    fn absent() -> u32;
}

fn main() {
    let d = sha2::Sha256::digest(std::env::args().nth(1).unwrap_or_default());
    println!("{:x} {}", d, unsafe { absent() });
}
