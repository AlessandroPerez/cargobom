use ring::digest::{self, Algorithm, Digest};

type HashFn = fn(&'static Algorithm, &[u8]) -> Digest;

static S: HashFn = digest::digest;

struct W(HashFn);

fn get() -> HashFn {
    digest::digest
}

fn call(f: HashFn, d: &[u8]) -> usize {
    f(&digest::SHA384, d).as_ref().len()
}

fn main() {
    let d = std::env::args().next().unwrap().into_bytes();
    let n = std::env::args().count();
    let p: HashFn = digest::digest;
    let _ = p(&digest::SHA256, &d);
    let o: Option<HashFn> = Some(digest::digest);
    if let Some(f) = o {
        let _ = f(&digest::SHA384, &d);
    }
    let m = match n {
        0 => digest::digest as HashFn,
        _ => digest::digest,
    };
    let _ = m(&digest::SHA512, &d);
    match o {
        Some(g) => {
            let _ = g(&digest::SHA1_FOR_LEGACY_USE_ONLY, &d);
        }
        None => {}
    }
    let h = p;
    let _ = h(&digest::SHA512_256, &d);
    let w = W(digest::digest);
    let _ = (w.0)(&digest::SHA256, &d);
    let g2 = get();
    let _ = g2(&digest::SHA384, &d);
    let mk = || digest::digest as HashFn;
    let k = mk();
    let _ = k(&digest::SHA512, &d);
    let _ = S(&digest::SHA1_FOR_LEGACY_USE_ONLY, &d);
    let a: [HashFn; 1] = [digest::digest];
    let _ = a[0](&digest::SHA512_256, &d);
    let mut it = vec![digest::digest as HashFn].into_iter();
    while let Some(q) = it.next() {
        let _ = q(&digest::SHA256, &d);
    }
    let _ = call(digest::digest, &d);
}
