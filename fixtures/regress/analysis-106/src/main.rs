// audit 12 probe dp1: a pointer reborrowed past the 16-step bound, and inside the bound
use ring::digest::{digest, Algorithm as Digest, SHA256, SHA384, SHA512};
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
fn deep(d: &[u8]) {
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
    let r10: &mut &'static Digest = &mut *r9;
    let r11: &mut &'static Digest = &mut *r10;
    let r12: &mut &'static Digest = &mut *r11;
    let r13: &mut &'static Digest = &mut *r12;
    let r14: &mut &'static Digest = &mut *r13;
    let r15: &mut &'static Digest = &mut *r14;
    let r16: &mut &'static Digest = &mut *r15;
    let r17: &mut &'static Digest = &mut *r16;
    let r18: &mut &'static Digest = &mut *r17;
    let r19: &mut &'static Digest = &mut *r18;
    let r20: &mut &'static Digest = &mut *r19;
    *r20 = &SHA512;
    let _ = digest(a, d);
}
fn shallow(d: &[u8]) {
    let mut b: &'static Digest = &SHA256;
    let s0: &mut &'static Digest = &mut b;
    let s1: &mut &'static Digest = &mut *s0;
    let s2: &mut &'static Digest = &mut *s1;
    let s3: &mut &'static Digest = &mut *s2;
    let s4: &mut &'static Digest = &mut *s3;
    let s5: &mut &'static Digest = &mut *s4;
    let s6: &mut &'static Digest = &mut *s5;
    let s7: &mut &'static Digest = &mut *s6;
    let s8: &mut &'static Digest = &mut *s7;
    let s9: &mut &'static Digest = &mut *s8;
    let s10: &mut &'static Digest = &mut *s9;
    *s10 = &SHA384;
    let _ = digest(b, d);
}
fn main() { let d = arg(0).into_bytes(); deep(&d); shallow(&d); }
