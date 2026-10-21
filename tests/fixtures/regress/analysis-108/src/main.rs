// audit 12 probe dp3: writes through chains of 7, 8, 9 explicit reborrows
use ring::digest::{digest, Algorithm as Digest, SHA256, SHA512};
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
fn chain7(d: &[u8]) {
    let mut a: &'static Digest = &SHA256;
    let r0: &mut &'static Digest = &mut a;
    let r1: &mut &'static Digest = &mut *r0;
    let r2: &mut &'static Digest = &mut *r1;
    let r3: &mut &'static Digest = &mut *r2;
    let r4: &mut &'static Digest = &mut *r3;
    let r5: &mut &'static Digest = &mut *r4;
    let r6: &mut &'static Digest = &mut *r5;
    let r7: &mut &'static Digest = &mut *r6;
    *r7 = &SHA512;
    let _ = digest(a, d);
}
fn chain8(d: &[u8]) {
    let mut a: &'static Digest = &SHA256;
    let r0: &mut &'static Digest = &mut a;
    let r1: &mut &'static Digest = &mut *r0;
    let r2: &mut &'static Digest = &mut *r1;
    let r3: &mut &'static Digest = &mut *r2;
    let r4: &mut &'static Digest = &mut *r3;
    let r5: &mut &'static Digest = &mut *r4;
    let r6: &mut &'static Digest = &mut *r5;
    let r7: &mut &'static Digest = &mut *r6;
    let r8: &mut &'static Digest = &mut *r7;
    *r8 = &SHA512;
    let _ = digest(a, d);
}
fn chain9(d: &[u8]) {
    let mut a: &'static Digest = &SHA256;
    let r0: &mut &'static Digest = &mut a;
    let r1: &mut &'static Digest = &mut *r0;
    let r2: &mut &'static Digest = &mut *r1;
    let r3: &mut &'static Digest = &mut *r2;
    let r4: &mut &'static Digest = &mut *r3;
    let r5: &mut &'static Digest = &mut *r4;
    let r6: &mut &'static Digest = &mut *r5;
    let r7: &mut &'static Digest = &mut *r6;
    let r8: &mut &'static Digest = &mut *r7;
    let r9: &mut &'static Digest = &mut *r8;
    *r9 = &SHA512;
    let _ = digest(a, d);
}
fn main() { let d = arg(0).into_bytes(); chain7(&d); chain8(&d); chain9(&d); }
