use ring::digest::{self, Algorithm, Digest};

type HashFn = fn(&'static Algorithm, &[u8]) -> Digest;

fn main() {
    let d = std::env::args().next().unwrap().into_bytes();
    let n = std::env::args().count();
    let p: HashFn = if n > 1 {
        digest::digest
    } else {
        digest::digest
    };
    let _ = p(&digest::SHA256, &d);
    let q: HashFn = {
        let t: HashFn = digest::digest;
        t
    };
    let _ = q(&digest::SHA384, &d);
    for f in [digest::digest as HashFn] {
        let _ = f(&digest::SHA512, &d);
    }
    let r: HashFn = digest::digest;
    let _ = [r].iter().map(|h| h(&digest::SHA1_FOR_LEGACY_USE_ONLY, &d)).count();
}
