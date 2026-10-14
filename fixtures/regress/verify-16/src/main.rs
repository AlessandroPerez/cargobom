// regress verify-16 (round 12, audit 11 M8, M9: coercion positions near pointers that are no coercions; table members; audit 11 probe vq6)
use ring::digest::{digest, Algorithm, SHA256, SHA384, SHA512};

fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }

trait Pick { fn alg(&self) -> &'static Algorithm; }
struct Fast;
struct Slow;
impl Pick for Fast { fn alg(&self) -> &'static Algorithm { &SHA256 } }
impl Pick for Slow { fn alg(&self) -> &'static Algorithm { &SHA384 } }

fn len_of(n: usize) -> usize { let r = &n; *r }
fn show(p: &dyn Pick) -> usize { p.alg().output_len() }

static T1: [&Algorithm; 2] = [&SHA256, &SHA384];
static T2: [&Algorithm; 2] = [&SHA384, &SHA512];

fn main() {
    let d = arg(0).into_bytes();
    let f = Fast;
    let s = Slow;
    let p: &dyn Pick = if arg(1).is_empty() { &f } else { &s };
    let _ = digest(p.alg(), &d);
    let _ = len_of(d.len());
    let r = &f;
    let _ = r.alg().output_len();
    let _ = show(&Fast);
    let i = arg(2).len() % 2;
    let _ = digest(T1[i], &d);
    let _ = digest(T2[i], &d);
}
