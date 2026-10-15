// audit 13 probe a15: holders re-pointed, arrays of &mut at constant indexes, a local fn returning a holder of another argument
use ring::digest::{digest, Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
struct Holder<'a> { r: &'a mut &'static Digest }
struct Out<'a> { buf: &'a mut Vec<u8> }
fn process<'a>(x: &mut &'static Digest, scratch: &'a mut Vec<u8>) -> Out<'a> { let _ = x.output_len(); Out { buf: scratch } }

fn main() {
    let d = arg(0).into_bytes();
    let mut a: &'static Digest = &SHA256;
    let mut b: &'static Digest = &SHA256;
    {
        let mut h = Holder { r: &mut a };
        h.r = &mut b;
        *h.r = &SHA512;
    }
    let _ = digest(a, &d);
    let _ = digest(b, &d);
    let mut c: &'static Digest = &SHA256;
    let mut e: &'static Digest = &SHA1;
    {
        let arr = [&mut c, &mut e];
        *arr[1] = &SHA384;
    }
    let _ = digest(c, &d);
    let _ = digest(e, &d);
    let mut f: &'static Digest = &SHA256;
    let mut g: &'static Digest = &SHA256;
    {
        let mut o = Some(&mut f);
        o = Some(&mut g);
        if let Some(r) = o { *r = &SHA384; }
    }
    let _ = digest(f, &d);
    let _ = digest(g, &d);
    let mut x: &'static Digest = &SHA512;
    let mut scratch = Vec::new();
    {
        let out = process(&mut x, &mut scratch);
        out.buf.push(1);
    }
    let _ = digest(x, &d);
}
