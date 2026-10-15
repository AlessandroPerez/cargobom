// audit 13 probe a2: returned parts, reborrows of parameters, the pointer bound, escapes by calls (H6-H9 variations)
use ring::digest::{digest, Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
struct S { alg: &'static Digest, other: &'static Digest }
struct T { alg: &'static Digest, other: &'static Digest }
struct U { alg: &'static Digest, other: &'static Digest }
struct V { alg: &'static Digest, other: &'static Digest }
fn first<'a>(s: &'a mut S, _t: &'a mut T) -> &'a mut &'static Digest { &mut s.alg }
fn second<'a>(_n: u8, s: &'a mut U) -> &'a mut &'static Digest { &mut s.other }
fn pick<'a>(s: &'a mut V, _o: &'a mut &'static Digest) -> &'a mut &'static Digest { &mut s.alg }
fn deep_param(p: &mut &'static Digest) {
    let r1 = &mut *p; let r2 = &mut *r1; let r3 = &mut *r2; let r4 = &mut *r3; let r5 = &mut *r4;
    let r6 = &mut *r5; let r7 = &mut *r6; let r8 = &mut *r7; let r9 = &mut *r8; let r10 = &mut *r9;
    *r10 = &SHA512;
}
fn push_param(slot: &mut &'static Digest) { let mut v = Vec::new(); v.push(slot); *v[0] = &SHA384; }
fn box_param(slot: &mut &'static Digest) { let b = Box::new(slot); **b = &SHA512; }
fn opt_from(slot: &mut &'static Digest) { let o: Option<&mut &'static Digest> = Option::from(slot); if let Some(r) = o { *r = &SHA384; } }
struct H<'a> { r: &'a mut &'static Digest }
struct C { alg: &'static Digest }
fn holder_field(c: &mut C) { let h = H { r: &mut c.alg }; *h.r = &SHA384; }

fn main() {
    let d = arg(0).into_bytes();
    let mut s3 = S { alg: &SHA256, other: &SHA1 };
    let mut t4 = T { alg: &SHA256, other: &SHA1 };
    *first(&mut s3, &mut t4) = &SHA512;
    let _ = digest(s3.alg, &d);
    let _ = digest(t4.alg, &d);
    let mut s5 = U { alg: &SHA256, other: &SHA1 };
    *second(0, &mut s5) = &SHA384;
    let _ = digest(s5.other, &d);
    let _ = digest(s5.alg, &d);
    let mut s6 = V { alg: &SHA256, other: &SHA1 };
    let mut y: &'static Digest = &SHA256;
    *pick(&mut s6, &mut y) = &SHA512;
    let _ = digest(y, &d);
    let _ = digest(s6.alg, &d);
    let mut x1: &'static Digest = &SHA256;
    deep_param(&mut x1);
    let _ = digest(x1, &d);
    let mut x2: &'static Digest = &SHA256;
    push_param(&mut x2);
    let _ = digest(x2, &d);
    let mut x3: &'static Digest = &SHA256;
    box_param(&mut x3);
    let _ = digest(x3, &d);
    let mut x4: &'static Digest = &SHA256;
    opt_from(&mut x4);
    let _ = digest(x4, &d);
    let mut c = C { alg: &SHA256 };
    holder_field(&mut c);
    let _ = digest(c.alg, &d);
    let mut x5: &'static Digest = &SHA256;
    { let mut v = Vec::new(); v.push(&mut x5); for r in v { *r = &SHA512; } }
    let _ = digest(x5, &d);
    let mut x6: &'static Digest = &SHA256;
    { let b = Box::new(&mut x6); **b = &SHA384; }
    let _ = digest(x6, &d);
    let mut x7: &'static Digest = &SHA256;
    { let mut o = None; o.insert(&mut x7); if let Some(r) = o { *r = &SHA512; } }
    let _ = digest(x7, &d);
    let mut x8: &'static Digest = &SHA256;
    { for r in std::iter::once(&mut x8) { *r = &SHA384; } }
    let _ = digest(x8, &d);
    let mut x9: &'static Digest = &SHA256;
    {
        let r0 = &mut x9; let r1 = &mut *r0; let r2 = &mut *r1; let r3 = &mut *r2; let r4 = &mut *r3;
        let r5 = &mut *r4; let r6 = &mut *r5; let r7 = &mut *r6; let r8 = &mut *r7; let r9 = &mut *r8;
        let h = H { r: r9 }; *h.r = &SHA512;
    }
    let _ = digest(x9, &d);
}
