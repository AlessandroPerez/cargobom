use sha2::{Digest, Sha384};

#[cfg(any())]
fn legacy_checksum(data: &[u8]) -> Vec<u8> {
    sha2::Sha256::digest(data).to_vec()
}

fn main() {
    let live = Sha384::digest(b"cfg");
    #[cfg(any())]
    let live = legacy_checksum(b"cfg");
    println!("{}", live.len());
}
