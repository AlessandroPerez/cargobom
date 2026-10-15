// audit 13 probe dc1: unknowns and dead callers
use ring::digest::{digest, Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
fn unk() -> &'static Digest { let mut a: &'static Digest = &SHA1; [0u8].iter().for_each(|_| a = &SHA384); a }
fn h1(a: &'static Digest, d: &[u8]) { let _ = digest(a, d); }
#[allow(dead_code)]
fn dead1(d: &[u8]) { dead2(d); }
#[allow(dead_code)]
fn dead2(d: &[u8]) { dead3(d); }
#[allow(dead_code)]
fn dead3(d: &[u8]) { h1(unk(), d); }
fn mid(a: &'static Digest) -> &'static Digest { a }
fn h2(a: &'static Digest, d: &[u8]) { let _ = digest(a, d); }
#[allow(dead_code)]
fn dead4(d: &[u8]) { h2(mid(unk()), d); }
fn h3(a: &'static Digest, d: &[u8]) { let _ = digest(a, d); }
#[allow(dead_code)]
fn dead5(d: &[u8]) { h3(&SHA512, d); }
struct S { a: &'static Digest }
fn h4(s: &S, d: &[u8]) { let _ = digest(s.a, d); }
#[allow(dead_code)]
fn dead6(d: &[u8]) { h4(&S { a: unk() }, d); }
fn h5(a: &'static Digest, d: &[u8]) { let _ = digest(a, d); }
fn pass5(a: &'static Digest, d: &[u8]) { h5(a, d); }
#[allow(dead_code)]
fn dead7(d: &[u8]) { pass5(&SHA512, d); }
fn h6(a: &'static Digest, d: &[u8]) { let _ = digest(a, d); }
fn mid6(a: &'static Digest) -> &'static Digest { a }
#[allow(dead_code)]
fn dead8(d: &[u8]) { h6(mid6(&SHA512), d); }

fn main() {
    let d = arg(0).into_bytes();
    h1(&SHA256, &d);
    h2(mid(&SHA256), &d);
    h3(unk(), &d);
    h4(&S { a: &SHA256 }, &d);
    pass5(unk(), &d);
    h6(mid6(unk()), &d);
    let _never = |x: &[u8]| h1(unk(), x);
}
