// regress verify-19 (round 12, audit 11 M16: members written by the file's methods and functions, and their witnesses; audit 11 probe vq5)
use ring::digest::{digest, Algorithm, SHA256, SHA384, SHA512};

fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }

struct A { alg: &'static Algorithm }
struct B { alg: &'static Algorithm }
trait Up { fn up(&mut self); }
impl Up for A { fn up(&mut self) { self.alg = &SHA512; } }
impl Up for B { fn up(&mut self) {} }
impl A { fn reset(&mut self) { self.alg = &SHA512; } }
impl B { fn reset(&mut self) { let _ = self.alg.output_len(); } }

mod other {
    pub fn fill(s: &mut &'static ring::digest::Algorithm) { *s = &ring::digest::SHA512; }
}
fn fill(s: &mut &'static Algorithm) { let _ = s.output_len(); }
fn maybe(slot: &mut &'static Algorithm, c: bool) { if c { *slot = &SHA512; } }

fn main() {
    let d = arg(0).into_bytes();
    let mut b = B { alg: &SHA384 };
    b.up();
    let _ = digest(b.alg, &d);
    let mut b2 = B { alg: &SHA256 };
    b2.reset();
    let _ = digest(b2.alg, &d);
    let mut x = &SHA256;
    fill(&mut x);
    let _ = digest(x, &d);
    let mut y = &SHA384;
    other::fill(&mut y);
    let _ = digest(y, &d);
    let mut z = &SHA256;
    maybe(&mut z, arg(1).is_empty());
    let _ = digest(z, &d);
    let mut a = A { alg: &SHA256 };
    a.up();
    let _ = digest(a.alg, &d);
}
