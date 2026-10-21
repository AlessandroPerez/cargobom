// audit 12 probe o2: Option/Result combinators given function items (not closures)
use ring::digest::{digest, Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
fn keep(x: &'static Digest) -> &'static Digest { x }
fn keep_opt(x: &'static Digest) -> Option<&'static Digest> { Some(x) }
fn fixed(_x: &'static Digest) -> &'static Digest { &SHA384 }

fn main() {
    let d = arg(0).into_bytes();
    let o: Option<&'static Digest> = if arg(1).len() > 1 { Some(&SHA256) } else { None };
    let _ = digest(o.map_or(&SHA512, keep), &d);
    let _ = digest(o.map_or_else(|| &SHA1, keep), &d);
    let _ = digest(o.and_then(keep_opt).unwrap_or(&SHA512), &d);
    let _ = digest(o.map(std::convert::identity).unwrap_or(&SHA512), &d);
    let _ = digest(o.map(|x| keep(x)).unwrap_or(&SHA512), &d);
    let _ = digest(o.map(fixed).unwrap_or(&SHA512), &d);
    let r: Result<&'static Digest, ()> = o.ok_or(());
    let _ = digest(r.map(keep).unwrap_or(&SHA1), &d);
    let v = vec![&SHA384];
    let _ = digest(v.first().copied().map(keep).unwrap_or(&SHA1), &d);
}
