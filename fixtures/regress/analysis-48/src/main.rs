// audit 9 probe m1: writes through `&mut` by the program's functions, variations
use ring::digest::{digest, Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};

fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }

struct Ctx { alg: &'static Digest, n: usize }
struct Outer { inner: Ctx, tag: u8 }
trait Up { fn up(&mut self, b: bool); }
impl Up for Ctx { fn up(&mut self, b: bool) { if b { self.alg = &SHA512; } } }
impl Ctx {
    fn try_set(&mut self, s: &str) -> Result<(), std::num::ParseIntError> {
        let v: usize = s.parse()?;
        self.n = v;
        self.alg = &SHA512;
        Ok(())
    }
    fn via_ref(&mut self) { let r = &mut self.alg; *r = &SHA1; }
    fn bump(&mut self) { self.n += 1; }
    fn chain(&mut self) { self.bump(); self.bump(); self.alg = &SHA384; }
}
fn gen_set<T: Into<usize>>(slot: &mut &'static Digest, x: T) { if x.into() > 3 { *slot = &SHA512; } }
fn rec(slot: &mut &'static Digest, n: u32) { if n > 0 { rec(slot, n - 1) } else { *slot = &SHA512 } }
fn outer(slot: &mut &'static Digest) { inner(slot) }
fn inner(slot: &mut &'static Digest) { *slot = &SHA1; }
fn set_nested(o: &mut Outer) { o.inner.alg = &SHA384; }
fn opt_set(o: Option<&mut &'static Digest>) { if let Some(s) = o { *s = &SHA512; } }
fn loop_set(slot: &mut &'static Digest, n: usize) { for _ in 0..n { *slot = &SHA384; } }
fn swap_in(slot: &mut &'static Digest) { let old = std::mem::replace(slot, &SHA1); let _ = old; }
fn generic_up<T: Up>(t: &mut T, b: bool) { t.up(b) }
fn reassigned<'a>(mut slot: &'a mut &'static Digest, other: &'a mut &'static Digest) { if arg(9).is_empty() { slot = other; } *slot = &SHA512; }

fn main() {
    let d = arg(0).into_bytes();
    // a closure writing a captured variable on some calls
    let mut a1: &'static Digest = &SHA256;
    let mut f = |b: bool| if b { a1 = &SHA384; };
    f(arg(1) == "x");
    let _ = digest(a1, &d); // SHA-256, SHA-384
    // a trait method with `&mut self`, conditional
    let mut c2 = Ctx { alg: &SHA256, n: 0 };
    c2.up(arg(2) == "x");
    let _ = digest(c2.alg, &d); // SHA-256, SHA-512
    // through a generic function calling the trait method
    let mut c3 = Ctx { alg: &SHA384, n: 0 };
    generic_up(&mut c3, arg(3) == "x");
    let _ = digest(c3.alg, &d); // SHA-384, SHA-512
    // through `dyn`
    let mut c4 = Ctx { alg: &SHA256, n: 0 };
    { let u: &mut dyn Up = &mut c4; u.up(arg(4) == "x"); }
    let _ = digest(c4.alg, &d); // SHA-256, SHA-512
    // a generic function writing conditionally
    let mut a5: &'static Digest = &SHA384;
    gen_set(&mut a5, arg(5).len() as u8);
    let _ = digest(a5, &d); // SHA-384, SHA-512
    // recursion: always writes SHA-512 in the end
    let mut a6: &'static Digest = &SHA256;
    rec(&mut a6, arg(6).len() as u32);
    let _ = digest(a6, &d); // SHA-512
    // a write through `&mut` passed on to another function
    let mut a7: &'static Digest = &SHA256;
    outer(&mut a7);
    let _ = digest(a7, &d); // SHA-1
    // a nested field written through a `&mut` parameter
    let mut o8 = Outer { inner: Ctx { alg: &SHA256, n: 0 }, tag: 1 };
    set_nested(&mut o8);
    let _ = digest(o8.inner.alg, &d); // SHA-384
    // `Option<&mut T>`
    let mut a9: &'static Digest = &SHA256;
    opt_set(if arg(9).is_empty() { None } else { Some(&mut a9) });
    let _ = digest(a9, &d); // SHA-256, SHA-512
    // a write in a loop
    let mut a10: &'static Digest = &SHA256;
    loop_set(&mut a10, arg(10).len());
    let _ = digest(a10, &d); // SHA-256, SHA-384
    // `?` before the write
    let mut c11 = Ctx { alg: &SHA256, n: 0 };
    let _ = c11.try_set(&arg(11));
    let _ = digest(c11.alg, &d); // SHA-256, SHA-512
    // a write through a reborrow of a field of `&mut self`
    let mut c12 = Ctx { alg: &SHA256, n: 0 };
    c12.via_ref();
    let _ = digest(c12.alg, &d); // SHA-1
    // `mem::replace` through the parameter
    let mut a13: &'static Digest = &SHA256;
    swap_in(&mut a13);
    let _ = digest(a13, &d); // SHA-1
    // a method calling `&mut self` methods, then writing
    let mut c14 = Ctx { alg: &SHA256, n: 0 };
    c14.chain();
    let _ = digest(c14.alg, &d); // SHA-384
    // a parameter the body reassigns: the write lands in `a15` or `b15`
    let mut a15: &'static Digest = &SHA256;
    let mut b15: &'static Digest = &SHA1;
    reassigned(&mut a15, &mut b15);
    let _ = digest(a15, &d); // SHA-256, SHA-512
    let _ = digest(b15, &d); // SHA-1, SHA-512
    println!("{} {}", c2.n + c3.n + c4.n + c11.n + c12.n + c14.n, o8.tag);
}
