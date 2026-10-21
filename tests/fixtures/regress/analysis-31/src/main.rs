// audit 7 probe: calls through function pointers
use ring::digest;
use sha2::{Digest, Sha256};

type HashFn = fn(&'static digest::Algorithm, &[u8]) -> digest::Digest;

struct Holder {
    f: HashFn,
}

fn run(h: HashFn, d: &[u8]) -> usize {
    h(&digest::SHA256, d).as_ref().len()
}

fn get() -> HashFn {
    digest::digest
}

fn main() {
    let d = std::env::args().next().unwrap().into_bytes();
    // 1: a type-selected function named as a value, then called
    let s: fn(&'static [u8; 3]) -> sha2::digest::Output<Sha256> = Sha256::digest;
    let _ = s(b"abc");
    // 2: a field
    let h = Holder { f: digest::digest };
    let _ = (h.f)(&digest::SHA384, &d);
    // 3: a tuple
    let t: (HashFn, u8) = (digest::digest, 1);
    let _ = (t.0)(&digest::SHA512, &d);
    // 4: a parameter
    let _ = run(digest::digest, &d);
    // 5: a returned pointer
    let g = get();
    let _ = g(&digest::SHA1_FOR_LEGACY_USE_ONLY, &d);
    // 6: called on the call's result
    let _ = get()(&digest::SHA256, &d);
    // 7: an Option
    let o: Option<HashFn> = Some(digest::digest);
    if let Some(f) = o {
        let _ = f(&digest::SHA384, &d);
    }
    // 8: an array of pointers
    let fs: [HashFn; 1] = [digest::digest];
    let _ = fs[0](&digest::SHA512, &d);
    // 9: map over a function value
    let v: Vec<_> = [d.as_slice()].into_iter().map(Sha256::digest).collect();
    // 10: two calls through one pointer
    let p: HashFn = digest::digest;
    let a = p(&digest::SHA256, &d);
    let b = p(
        &digest::SHA512,
        &d,
    );
    // 11: a closure coerced to a fn pointer
    let c: fn(&[u8]) -> digest::Digest = |x| digest::digest(&digest::SHA256, x);
    let _ = c(&d);
    println!("{} {} {}", v.len(), a.as_ref().len(), b.as_ref().len());
}
