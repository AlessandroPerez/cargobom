#[path = "../common.rs"]
mod common;

use sha2::{Digest, Sha512};

fn main() {
    let body = Sha512::digest(b"beta body");
    let manifest = common::manifest_digest(common::LABEL.as_bytes());
    println!("beta {} {}", body.len(), manifest.len());
}
