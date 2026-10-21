#[allow(dead_code)]
#[path = "../common.rs"]
mod common;

use sha2::{Digest, Sha256};

fn main() {
    let d = Sha256::digest(common::LABEL.as_bytes());
    println!("alpha {}", d.len());
}
