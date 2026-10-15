// audit 12 probe c1: unknowns from dead callers (two levels, dead trait impls), members beside unknowns
use ring::digest::{digest, Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
fn h(a: &'static Digest, d: &[u8]) { let _ = digest(a, d); }
fn unknown_alg() -> &'static Digest { let mut a: &'static Digest = &SHA1; [0u8].iter().for_each(|_| a = &SHA384); a }
#[allow(dead_code)]
fn dead1(d: &[u8]) { dead2(d); }
#[allow(dead_code)]
fn dead2(d: &[u8]) { h(unknown_alg(), d); }
trait Run { fn run(&self, d: &[u8]); }
struct Never;
impl Run for Never { fn run(&self, d: &[u8]) { h2(unknown_alg(), d); } }
fn h2(a: &'static Digest, d: &[u8]) { let _ = digest(a, d); }
fn h3(a: &'static Digest, d: &[u8]) { let _ = digest(a, d); }

fn main() {
    let d = arg(0).into_bytes();
    h(&SHA256, &d);
    h2(&SHA512, &d);
    h3(&SHA256, &d);
    h3(unknown_alg(), &d);
    let mut x: &'static Digest = &SHA256;
    (0..arg(1).len()).for_each(|_| x = &SHA512);
    let _ = digest(x, &d);
}
