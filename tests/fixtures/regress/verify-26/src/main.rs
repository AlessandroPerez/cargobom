// regress verify-26 (round 13, audit 12 M12: swaps and replaces on some ways only; stores through a `&mut` binding, reborrows, copies, holders, a method's returned borrow; verifier probe vr13, audit 12 probes vf1, dp2, hm1, w1)
use ring::digest::{digest, Algorithm, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};

fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }

type D = &'static Algorithm;
struct Holder<'a> { r: &'a mut D }
struct S { alg: D, other: D }
impl S { fn slot(&mut self) -> &mut D { &mut self.alg } }

fn main() {
    let d = arg(0).into_bytes();
    let n = arg(1).len();
    let mut a: D = &SHA256;
    let mut b: D = &SHA512;
    if n > 1 {
        std::mem::swap(&mut a, &mut b);
    }
    let _ = digest(a, &d);
    let mut c: D = &SHA384;
    if n > 2 {
        let _old = std::mem::replace(&mut c, &SHA1);
    }
    let _ = digest(c, &d);
    let _ = digest(b, &d);
    let mut x0: D = &SHA256;
    let r = &mut x0;
    *r = &SHA512;
    let _ = digest(x0, &d);
    let mut x1: D = &SHA256;
    let r0: &mut D = &mut x1;
    let r1: &mut D = &mut *r0;
    let r2: &mut D = &mut *r1;
    *r2 = &SHA384;
    let _ = digest(x1, &d);
    let mut x2: D = &SHA256;
    let c0 = &mut x2; let c1 = c0;
    *c1 = &SHA512;
    let _ = digest(x2, &d);
    let mut x3: D = &SHA256;
    let h = Holder { r: &mut x3 };
    *h.r = &SHA512;
    let _ = digest(x3, &d);
    let mut x4: D = &SHA256;
    let t = (&mut x4, 0u8);
    *t.0 = &SHA384;
    let _ = digest(x4, &d);
    let mut s1 = S { alg: &SHA256, other: &SHA1 };
    let p = s1.slot();
    *p = &SHA512;
    let _ = digest(s1.alg, &d);
    let _ = digest(s1.other, &d);
}
