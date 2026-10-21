// round 14 regress (audit 13 verifier probe vs3): returned borrows written
use ring::digest::{digest, Algorithm, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384};

fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }

struct S { a: &'static Algorithm, b: &'static Algorithm }
impl S {
    fn a_mut(&mut self) -> &mut &'static Algorithm { &mut self.a }
}

fn main() {
    let d = arg(0).into_bytes();
    let mut s4 = S { a: &SHA256, b: &SHA1 };
    *s4.a_mut() = &SHA384;
    let _ = digest(s4.a, &d);
    let mut s5 = S { a: &SHA256, b: &SHA1 };
    let r = s5.a_mut();
    *r = &SHA384;
    let _ = digest(s5.a, &d);
    let mut s6 = S { a: &SHA256, b: &SHA1 };
    *S::a_mut(&mut s6) = &SHA384;
    let _ = digest(s6.a, &d);
    let _ = digest(s4.b, &d);
}
