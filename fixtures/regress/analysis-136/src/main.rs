// audit 13 probe dc2: live callers that are closures, generic instances, trait methods: their unknowns stay
use ring::digest::{digest, Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384};
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
fn unk() -> &'static Digest { let mut a: &'static Digest = &SHA1; [0u8].iter().for_each(|_| a = &SHA384); a }
fn h1(a: &'static Digest, d: &[u8]) { let _ = digest(a, d); }
fn h2(a: &'static Digest, d: &[u8]) { let _ = digest(a, d); }
fn h3(a: &'static Digest, d: &[u8]) { let _ = digest(a, d); }
fn h4(a: &'static Digest, d: &[u8]) { let _ = digest(a, d); }
fn h5(a: &'static Digest, d: &[u8]) { let _ = digest(a, d); }
fn gener<T: Default>(d: &[u8]) -> T { h2(unk(), d); T::default() }
trait Run { fn run(&self, d: &[u8]); }
struct R;
impl Run for R { fn run(&self, d: &[u8]) { h3(unk(), d); } }
fn mid(a: &'static Digest) -> &'static Digest { a }

fn main() {
    let d = arg(0).into_bytes();
    h1(&SHA256, &d);
    let d2 = d.clone();
    std::thread::spawn(move || h1(unk(), &d2)).join().unwrap();
    h2(&SHA256, &d);
    let _: u8 = gener(&d);
    h3(&SHA256, &d);
    let r: &dyn Run = &R;
    r.run(&d);
    h4(&SHA256, &d);
    let _ = Some(1u8).map(|_| h4(unk(), &d));
    h5(mid(&SHA256), &d);
    let f = || h5(mid(unk()), &d);
    f();
}
