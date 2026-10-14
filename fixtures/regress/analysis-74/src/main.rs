// round 11 regress (audit 10 probe d4): a type coerced to a trait object only in a constant-false branch
use ring::digest::{digest, Algorithm as Digest, SHA256, SHA512};

fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
const LEGACY: bool = false;
trait Pick { fn alg(&self) -> &'static Digest; }
struct Fast;
struct Dead;
impl Pick for Fast { fn alg(&self) -> &'static Digest { &SHA256 } }
impl Pick for Dead { fn alg(&self) -> &'static Digest { &SHA512 } }

fn main() {
    let d = arg(0).into_bytes();
    let p: Box<dyn Pick> = if LEGACY { Box::new(Dead) } else { Box::new(Fast) };
    let _ = digest(p.alg(), &d);
}
