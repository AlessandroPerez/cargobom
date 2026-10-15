// audit 12 probe o1: Option/Result combinators whose closures pass the value on, fn paths, captures
use ring::digest::{digest, Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
fn keep(x: &'static Digest) -> &'static Digest { x }
struct E { h: &'static Digest }
fn res(i: usize) -> Result<&'static Digest, String> { if i > 0 { Ok(&SHA384) } else { Err(arg(2)) } }

fn main() {
    let d = arg(0).into_bytes();
    let i = arg(1).len();
    let o: Option<&'static Digest> = if i > 1 { Some(&SHA256) } else { None };
    let _ = digest(o.map(|x| x).unwrap_or(&SHA512), &d);
    let _ = digest(o.map(keep).unwrap_or(&SHA512), &d);
    let _ = digest(o.and_then(|x| Some(x)).unwrap_or(&SHA384), &d);
    let v = vec![&SHA384, &SHA512];
    let _ = digest(v.get(i).map(|x| *x).unwrap_or(&SHA1), &d);
    let _ = digest(v.first().map(|&x| x).unwrap_or(&SHA1), &d);
    let alt: &'static Digest = &SHA1;
    let _ = digest(o.map(|_| alt).unwrap_or(&SHA256), &d);
    let _ = digest(o.map_or_else(|| &SHA384, |x| x), &d);
    let _ = digest(o.map_or(&SHA512, |x| x), &d);
    let es = [E { h: &SHA256 }, E { h: &SHA512 }];
    let _ = digest(es.get(i).map(|e| e.h).unwrap_or(&SHA1), &d);
    let _ = digest(res(i).map(|x| x).unwrap_or(&SHA256), &d);
    let _ = digest(res(i).map_err(|e| e.len()).unwrap_or(&SHA1), &d);
    let _ = digest(o.filter(|_| i > 3).unwrap_or(&SHA1), &d);
    let _ = digest(o.or(Some(&SHA384)).map(|x| x).unwrap(), &d);
}
