// audit 12 probe hm1: values holding a &mut to a local, written through in the same function
use ring::digest::{digest, Algorithm as Digest, SHA256, SHA384, SHA512};
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
type D = &'static Digest;
struct Holder<'a> { r: &'a mut D }
fn main() {
    let d = arg(0).into_bytes();
    let mut x1: D = &SHA256;
    let h = Holder { r: &mut x1 };
    *h.r = &SHA512;
    let _ = digest(x1, &d);
    let mut x2: D = &SHA256;
    let o = Some(&mut x2);
    if let Some(r) = o { *r = &SHA384; }
    let _ = digest(x2, &d);
    let mut x3: D = &SHA256;
    let t = (&mut x3, 0u8);
    *t.0 = &SHA512;
    let _ = digest(x3, &d);
    let mut x4: D = &SHA256;
    let v = vec![&mut x4];
    for r in v { *r = &SHA384; }
    let _ = digest(x4, &d);
    let mut x5: D = &SHA256;
    for r in [&mut x5] { *r = &SHA512; }
    let _ = digest(x5, &d);
}
