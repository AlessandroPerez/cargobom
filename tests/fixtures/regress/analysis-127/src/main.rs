// audit 13 probe a12: constants in values built locally; unrelated lost/cut pointers beside an escaped &mut (false unknowns?)
use ring::digest::{digest, Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
#[derive(Clone, Copy)]
struct Cfg { h: &'static Digest, legacy: &'static Digest }
const BASE: Cfg = Cfg { h: &SHA384, legacy: &SHA1 };
const FIX: Cfg = Cfg { h: &SHA512, legacy: &SHA1 };
const ALIAS: Cfg = BASE;
struct Outer { inner: Cfg, n: u8 }
struct Holder<'a> { r: &'a mut &'static Digest }

fn main() {
    let d = arg(0).into_bytes();
    let i = arg(1).len() % 2;
    let o = Outer { inner: BASE, n: 0 };
    let _ = digest(o.inner.legacy, &d);
    let t = (BASE, FIX);
    let _ = digest(t.1.h, &d);
    let arr = [ALIAS, FIX];
    let _ = digest(arr[i].h, &d);
    let v = vec![BASE, FIX];
    let _ = digest(v[i].h, &d);
    let rep = [BASE; 2];
    let _ = digest(rep[i].legacy, &d);
    let _ = o.n;
    let mut a: &'static Digest = &SHA256;
    {
        let h = Holder { r: &mut a };
        let _ = h.r.output_len();
        let (mut n1, mut n2) = (1u8, 2u8);
        for r in [&mut n1, &mut n2] { *r += 1; }
        let _ = n1 + n2;
    }
    let _ = digest(a, &d);
    let mut b: &'static Digest = &SHA384;
    {
        let rb = &mut b;
        let _ = rb.output_len();
        let mut n = 0u8;
        let q0 = &mut n; let q1 = &mut *q0; let q2 = &mut *q1; let q3 = &mut *q2; let q4 = &mut *q3;
        let q5 = &mut *q4; let q6 = &mut *q5; let q7 = &mut *q6; let q8 = &mut *q7; let q9 = &mut *q8;
        let q10 = &mut *q9; let q11 = &mut *q10; let q12 = &mut *q11; let q13 = &mut *q12; let q14 = &mut *q13;
        let q15 = &mut *q14; let q16 = &mut *q15; let q17 = &mut *q16; let q18 = &mut *q17; let q19 = &mut *q18;
        *q19 = 7;
        let _ = n;
    }
    let _ = digest(b, &d);
}
