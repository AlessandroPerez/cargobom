// audit 8 probe p11: function pointers beyond audit 7's p4
use ring::digest::{self, Algorithm, Digest};

type HashFn = fn(&'static Algorithm, &[u8]) -> Digest;

static H: HashFn = digest::digest;

struct Holder {
    f: HashFn,
}

fn run2(h: &Holder, d: &[u8]) -> usize {
    (h.f)(&digest::SHA384, d).as_ref().len() // SHA-384 through a field of a parameter
}

fn my_hash(a: &'static Algorithm, d: &[u8]) -> Digest {
    digest::digest(a, d) // SHA-512 (the pointer call's argument)
}

fn pick(n: usize) -> HashFn {
    if n > 1 { digest::digest } else { my_hash }
}

fn main() {
    let d = std::env::args().next().unwrap().into_bytes();
    let _ = H(&digest::SHA256, &d); // SHA-256 through a static
    let _ = run2(&Holder { f: digest::digest }, &d);
    let f: HashFn = my_hash;
    let _ = f(&digest::SHA512, &d); // the program's function through a pointer: SHA-512 at my_hash's digest
    let v: Vec<HashFn> = vec![digest::digest];
    let _ = v[0](&digest::SHA1_FOR_LEGACY_USE_ONLY, &d); // SHA-1 through a Vec element
    let g = pick(std::env::args().count());
    let _ = g(&digest::SHA512_256, &d); // SHA-512/256 (direct or through my_hash)
    let c = |x: &[u8]| digest::digest(&digest::SHA384, x);
    let fc: fn(&[u8]) -> Digest = c;
    let _ = [fc].iter().map(|h| h(&d)).count(); // SHA-384 in the closure
}
