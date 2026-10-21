// Function items and pointers as values, static tables of references, `Option` writes and
// closures writing captures: the cases where following them must not claim too much. Each call
// says what can reach it.
use ring::digest::{digest, Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
fn n(i: usize) -> usize { arg(i).len() }

fn fast() -> &'static Digest { &SHA512 }
fn slow() -> &'static Digest { &SHA1 }
fn apply(f: fn() -> &'static Digest) -> &'static Digest { f() }
fn lend(r: &mut &'static Digest) { if n(5) > 0 { *r = &SHA384; } }
fn run<F: FnMut()>(mut f: F) { if n(6) > 0 { f() } }

struct Cfg { h: &'static Digest }
static C1: Cfg = Cfg { h: &SHA384 };
static C2: Cfg = Cfg { h: &SHA512 };
static TABLE: [&Cfg; 2] = [&C1, &C2];

fn main() {
    let d = arg(0).into_bytes();
    // a pointer that may be one of two functions: both
    let p: fn() -> &'static Digest = if n(1) > 0 { fast } else { slow };
    let _ = digest(apply(p), &d); // SHA-512, SHA-1
    // a table of references read at a run-time index: either element's field
    let _ = digest(TABLE[n(2) % 2].h, &d); // SHA-384, SHA-512
    // `Option::replace` on one branch only: the value before stays possible
    let mut o: Option<&'static Digest> = Some(&SHA256);
    if n(3) > 0 { o.replace(&SHA384); }
    let _ = digest(o.unwrap(), &d); // SHA-256, SHA-384
    // a closure run over an empty range: its write may not happen
    let mut a: &'static Digest = &SHA256;
    (0..n(4)).for_each(|_| a = &SHA512);
    let _ = digest(a, &d); // SHA-256, SHA-512
    // a closure lending its capture to a function: what that writes is not seen here
    let mut b: &'static Digest = &SHA256;
    [0u8].iter().for_each(|_| lend(&mut b));
    let _ = digest(b, &d); // SHA-256, SHA-384
    // two closures writing the same variable, one run by a function only sometimes
    let mut c: &'static Digest = &SHA1;
    [0u8].iter().for_each(|_| c = &SHA256);
    run(|| c = &SHA512);
    let _ = digest(c, &d); // SHA-256, SHA-512 (+ may SHA-1)
    // a closure built and dropped without running: nothing written
    let mut e: &'static Digest = &SHA384;
    let f = || e = &SHA1;
    drop(f);
    let _ = digest(e, &d); // SHA-384 (+ may SHA-1)
}
