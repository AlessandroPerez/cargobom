// A build script's SHA-1 runs on the host: build-only, never in the artifact, whatever the target.
use sha1::{Digest, Sha1};

fn main() {
    let d = Sha1::digest(b"build");
    println!("cargo::rustc-env=BUILD_ID={:x}", d[0]);
}
