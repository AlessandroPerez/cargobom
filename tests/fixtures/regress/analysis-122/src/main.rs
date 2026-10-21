// audit 13 probe a7: long reborrow chains (cut), escapes into values by calls, holders through helpers
use ring::digest::{digest, Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
fn long_param(p: &mut &'static Digest) {
    let r1 = &mut *p; let r2 = &mut *r1; let r3 = &mut *r2; let r4 = &mut *r3; let r5 = &mut *r4;
    let r6 = &mut *r5; let r7 = &mut *r6; let r8 = &mut *r7; let r9 = &mut *r8; let r10 = &mut *r9;
    let r11 = &mut *r10; let r12 = &mut *r11; let r13 = &mut *r12; let r14 = &mut *r13; let r15 = &mut *r14;
    let r16 = &mut *r15; let r17 = &mut *r16; let r18 = &mut *r17; let r19 = &mut *r18; let r20 = &mut *r19;
    *r20 = &SHA512;
}
struct Pair { a: &'static Digest, b: &'static Digest }
fn long_field(p: &mut Pair) {
    let r1 = &mut p.a; let r2 = &mut *r1; let r3 = &mut *r2; let r4 = &mut *r3; let r5 = &mut *r4;
    let r6 = &mut *r5; let r7 = &mut *r6; let r8 = &mut *r7; let r9 = &mut *r8; let r10 = &mut *r9;
    let r11 = &mut *r10; let r12 = &mut *r11; let r13 = &mut *r12; let r14 = &mut *r13; let r15 = &mut *r14;
    let r16 = &mut *r15; let r17 = &mut *r16; let r18 = &mut *r17; let r19 = &mut *r18; let r20 = &mut *r19;
    *r20 = &SHA384;
}
struct H<'a> { r: &'a mut &'static Digest }
fn write_h(h: H) { *h.r = &SHA512; }
fn write_hm(h: &mut H) { *h.r = &SHA384; }

fn main() {
    let d = arg(0).into_bytes();
    let mut x1: &'static Digest = &SHA256;
    long_param(&mut x1);
    let _ = digest(x1, &d);
    let mut p = Pair { a: &SHA256, b: &SHA1 };
    long_field(&mut p);
    let _ = digest(p.a, &d);
    let _ = digest(p.b, &d);
    let mut x2: &'static Digest = &SHA256;
    {
        let r1 = &mut x2; let r2 = &mut *r1; let r3 = &mut *r2; let r4 = &mut *r3; let r5 = &mut *r4;
        let r6 = &mut *r5; let r7 = &mut *r6; let r8 = &mut *r7; let r9 = &mut *r8; let r10 = &mut *r9;
        let r11 = &mut *r10; let r12 = &mut *r11; let r13 = &mut *r12; let r14 = &mut *r13; let r15 = &mut *r14;
        let r16 = &mut *r15; let r17 = &mut *r16; let r18 = &mut *r17; let r19 = &mut *r18; let r20 = &mut *r19;
        *r20 = &SHA384;
    }
    let _ = digest(x2, &d);
    let mut x3: &'static Digest = &SHA256;
    write_h(H { r: &mut x3 });
    let _ = digest(x3, &d);
    let mut x4: &'static Digest = &SHA256;
    { let mut h = H { r: &mut x4 }; write_hm(&mut h); }
    let _ = digest(x4, &d);
    let mut x5: &'static Digest = &SHA256;
    { let mut v: Vec<&mut &'static Digest> = Vec::with_capacity(1); v.push(&mut x5); *v[0] = &SHA512; }
    let _ = digest(x5, &d);
    let mut x6: &'static Digest = &SHA256;
    { let mut v: Vec<&mut &'static Digest> = Vec::new(); v.push(&mut x6); if let Some(r) = v.pop() { *r = &SHA384; } }
    let _ = digest(x6, &d);
    let mut x7: &'static Digest = &SHA256;
    { let mut slot: Option<&mut &'static Digest> = None; slot.replace(&mut x7); if let Some(r) = slot { *r = &SHA512; } }
    let _ = digest(x7, &d);
}
