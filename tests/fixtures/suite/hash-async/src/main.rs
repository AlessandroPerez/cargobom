use futures_executor::block_on;
use sha2::{Digest, Sha512};

async fn checksum(data: Vec<u8>) -> Vec<u8> {
    Sha512::digest(&data).to_vec()
}

async fn run() -> usize {
    checksum(b"async".to_vec()).await.len()
}

fn main() {
    println!("{}", block_on(run()));
}
