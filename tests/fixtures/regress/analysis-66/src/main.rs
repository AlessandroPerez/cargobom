// round 11 regress (audit 10 probe u1): the "unfollowed alternative" unknown: complete sets and silent alternatives
use ring::digest::{self, digest, Algorithm as Digest, SHA256, SHA384, SHA512};
use ring::hmac;

fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }

fn pick(s: &str) -> Option<&'static Digest> { match s { "a" => Some(&SHA256), _ => None } }
fn run(d: &[u8]) -> Option<()> {
    let a = pick(&arg(1))?;
    let _ = digest(a, d);
    Some(())
}
struct Holder { alg: &'static Digest }
fn by_param(a: &'static Digest, d: &[u8]) { let _ = digest(a, d); }

fn main() {
    let d = arg(0).into_bytes();
    // a closure writing a capture, run by an iterator over a local array
    let mut x1: &'static Digest = &SHA256;
    [1, 2, 3].iter().for_each(|_| x1 = &SHA512);
    let _ = digest(x1, &d);
    // a crypto crate's call returning an algorithm
    let ctx = digest::Context::new(&SHA384);
    let a2 = ctx.algorithm();
    let _ = digest(a2, &d);
    let a3: &'static Digest = if arg(3).is_empty() { &SHA256 } else { ctx.algorithm() };
    let _ = digest(a3, &d);
    let k = hmac::Key::new(hmac::HMAC_SHA512, b"placeholder-not-a-key");
    let a4 = k.algorithm().digest_algorithm();
    let _ = digest(a4, &d);
    // a closure writing a capture, called directly
    let mut x5: &'static Digest = &SHA256;
    let mut f = || x5 = &SHA384;
    f();
    let _ = digest(x5, &d);
    // complete sets
    run(&d);
    let a7 = pick(&arg(7)).unwrap_or(&SHA384);
    let _ = digest(a7, &d);
    let h = Holder { alg: if arg(8).is_empty() { &SHA256 } else { &SHA512 } };
    by_param(h.alg, &d);
    for a in [&SHA256, &SHA384] { let _ = digest(a, &d); }
    let i = arg(9).len();
    let a10 = [&SHA256, &SHA384].get(i).copied().unwrap_or(&SHA512);
    let _ = digest(a10, &d);
    let a11 = [&SHA256, &SHA384].into_iter().find(|a| a.output_len() == 48).unwrap();
    let _ = digest(a11, &d);
}
