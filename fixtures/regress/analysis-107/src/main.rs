// audit 12 probe dp2: writes through chains of 1, 2, 3, 6 explicit reborrows, and through let-copies
use ring::digest::{digest, Algorithm as Digest, SHA256, SHA384, SHA512};
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
fn chain1(d: &[u8]) {
    let mut a: &'static Digest = &SHA256;
    let r0: &mut &'static Digest = &mut a;
    let r1: &mut &'static Digest = &mut *r0;
    *r1 = &SHA512;
    let _ = digest(a, d);
}
fn chain2(d: &[u8]) {
    let mut a: &'static Digest = &SHA256;
    let r0: &mut &'static Digest = &mut a;
    let r1: &mut &'static Digest = &mut *r0;
    let r2: &mut &'static Digest = &mut *r1;
    *r2 = &SHA512;
    let _ = digest(a, d);
}
fn chain3(d: &[u8]) {
    let mut a: &'static Digest = &SHA256;
    let r0: &mut &'static Digest = &mut a;
    let r1: &mut &'static Digest = &mut *r0;
    let r2: &mut &'static Digest = &mut *r1;
    let r3: &mut &'static Digest = &mut *r2;
    *r3 = &SHA512;
    let _ = digest(a, d);
}
fn chain6(d: &[u8]) {
    let mut a: &'static Digest = &SHA256;
    let r0: &mut &'static Digest = &mut a;
    let r1: &mut &'static Digest = &mut *r0;
    let r2: &mut &'static Digest = &mut *r1;
    let r3: &mut &'static Digest = &mut *r2;
    let r4: &mut &'static Digest = &mut *r3;
    let r5: &mut &'static Digest = &mut *r4;
    let r6: &mut &'static Digest = &mut *r5;
    *r6 = &SHA512;
    let _ = digest(a, d);
}
fn copies(d: &[u8]) {
    let mut a: &'static Digest = &SHA256;
    let r0 = &mut a; let r1 = r0; let r2 = r1;
    *r2 = &SHA384;
    let _ = digest(a, d);
}
fn main() { let d = arg(0).into_bytes(); chain1(&d); chain2(&d); chain3(&d); chain6(&d); copies(&d); }
