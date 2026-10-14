// round 11 regress (audit 10 probe g2): a type overriding a trait's default method, called directly
use ring::digest::{digest, Algorithm as Digest, SHA256, SHA384};

fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
trait Pick { fn alg(&self) -> &'static Digest { &SHA256 } }
struct Fast;
impl Pick for Fast { fn alg(&self) -> &'static Digest { &SHA384 } }
fn pass(a: &'static Digest, d: &[u8]) { let _ = digest(a, d); }

fn main() {
    let d = arg(0).into_bytes();
    let _ = digest(Fast.alg(), &d);
    pass(Fast.alg(), &d);
}
