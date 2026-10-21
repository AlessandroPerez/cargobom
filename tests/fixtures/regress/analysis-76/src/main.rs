// round 12 regress (audit 11 probe gi2): generic functions, default bodies and generic impls of another crate of the workspace
use picklib::{gen_up, pick, Gen, Lib384, Pick, Up, W};
use ring::digest::{digest, Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA512};

fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }

struct Fast;
struct Legacy;
impl Pick for Fast { fn alg(&self) -> &'static Digest { &SHA512 } }
impl Pick for Legacy {}

struct S { alg: &'static Digest }
impl Up for S {}
struct T { alg: &'static Digest }
impl Up for T { fn up(&mut self) { self.alg = &SHA1; } }

fn main() {
    let d = arg(0).into_bytes();
    let _ = digest(Fast.alg(), &d);
    let _ = digest(Legacy.alg(), &d);
    let _ = digest(pick(&Fast), &d);
    let _ = digest(pick(&Legacy), &d);
    let _ = digest(pick(&Lib384), &d);
    let _ = digest(W(Fast).alg(), &d);
    let _ = digest(W(Legacy).alg(), &d);
    picklib::digest_with(&Fast, &d);
    let mut s = S { alg: &SHA256 };
    gen_up(&mut s);
    let _ = digest(s.alg, &d);
    let mut t = T { alg: &SHA256 };
    gen_up(&mut t);
    let _ = digest(t.alg, &d);
}
