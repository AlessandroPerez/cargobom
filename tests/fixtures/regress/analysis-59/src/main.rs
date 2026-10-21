// round 11 regress (audit 10 probe g1): trait methods returning algorithms called on type parameters (static dispatch)
use ring::digest::{digest, Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};

fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }

trait Pick { fn alg(&self) -> &'static Digest { &SHA256 } }
struct Fast;
struct Legacy;
impl Pick for Fast { fn alg(&self) -> &'static Digest { &SHA384 } }
impl Pick for Legacy {}
trait Named { fn alg(&self) -> &'static Digest; }
struct N1;
struct N2;
impl Named for N1 { fn alg(&self) -> &'static Digest { &SHA512 } }
impl Named for N2 { fn alg(&self) -> &'static Digest { &SHA1 } }

fn gen1<T: Pick>(t: &T, d: &[u8]) { let _ = digest(t.alg(), d); }
fn gen2<T: Named>(t: &T, d: &[u8]) { let _ = digest(t.alg(), d); }
fn gen_impl(t: &impl Named, d: &[u8]) -> &'static Digest { let _ = d; t.alg() }

fn main() {
    let d = arg(0).into_bytes();
    gen1(&Fast, &d);
    gen2(&N1, &d);
    let _ = digest(gen_impl(&N1, &d), &d);
    if arg(1) == "legacy" { gen1(&Legacy, &d); gen2(&N2, &d); }
}
