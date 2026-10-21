// round 14 regress (audit 13 verifier probe vc4): more coercion shapes, one trait each
use ring::digest::{digest, Algorithm, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};

fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }

// vecliteral
trait P0 { fn alg(&self) -> &'static Algorithm; }
struct T0;
struct U0;
impl P0 for T0 { fn alg(&self) -> &'static Algorithm { &SHA256 } }
impl P0 for U0 { fn alg(&self) -> &'static Algorithm { &SHA384 } }
fn run0(p: &dyn P0, d: &[u8]) -> usize { digest(p.alg(), d).as_ref().len() }
// vecas
trait P1 { fn alg(&self) -> &'static Algorithm; }
struct T1;
struct U1;
impl P1 for T1 { fn alg(&self) -> &'static Algorithm { &SHA384 } }
impl P1 for U1 { fn alg(&self) -> &'static Algorithm { &SHA512 } }
fn run1(p: &dyn P1, d: &[u8]) -> usize { digest(p.alg(), d).as_ref().len() }
// optret
trait P2 { fn alg(&self) -> &'static Algorithm; }
struct T2;
struct U2;
impl P2 for T2 { fn alg(&self) -> &'static Algorithm { &SHA512 } }
impl P2 for U2 { fn alg(&self) -> &'static Algorithm { &SHA1 } }
fn opt2() -> Option<Box<dyn P2>> { Some(Box::new(T2)) }
fn run2(p: &dyn P2, d: &[u8]) -> usize { digest(p.alg(), d).as_ref().len() }
// closurearg
trait P3 { fn alg(&self) -> &'static Algorithm; }
struct T3;
struct U3;
impl P3 for T3 { fn alg(&self) -> &'static Algorithm { &SHA1 } }
impl P3 for U3 { fn alg(&self) -> &'static Algorithm { &SHA256 } }
fn apply3(f: impl Fn() -> Box<dyn P3>) -> Box<dyn P3> { f() }
fn run3(p: &dyn P3, d: &[u8]) -> usize { digest(p.alg(), d).as_ref().len() }
// mapcast
trait P4 { fn alg(&self) -> &'static Algorithm; }
struct T4;
struct U4;
impl P4 for T4 { fn alg(&self) -> &'static Algorithm { &SHA256 } }
impl P4 for U4 { fn alg(&self) -> &'static Algorithm { &SHA384 } }
fn run4(p: &dyn P4, d: &[u8]) -> usize { digest(p.alg(), d).as_ref().len() }
// mutref
trait P5 { fn alg(&self) -> &'static Algorithm; }
struct T5;
struct U5;
impl P5 for T5 { fn alg(&self) -> &'static Algorithm { &SHA384 } }
impl P5 for U5 { fn alg(&self) -> &'static Algorithm { &SHA512 } }
fn runm5(p: &mut dyn P5, d: &[u8]) -> usize { digest(p.alg(), d).as_ref().len() }
fn run5(p: &dyn P5, d: &[u8]) -> usize { digest(p.alg(), d).as_ref().len() }
// derefbox
trait P6 { fn alg(&self) -> &'static Algorithm; }
struct T6;
struct U6;
impl P6 for T6 { fn alg(&self) -> &'static Algorithm { &SHA512 } }
impl P6 for U6 { fn alg(&self) -> &'static Algorithm { &SHA1 } }
fn run6(p: &dyn P6, d: &[u8]) -> usize { digest(p.alg(), d).as_ref().len() }
// varref
trait P7 { fn alg(&self) -> &'static Algorithm; }
struct T7;
struct U7;
impl P7 for T7 { fn alg(&self) -> &'static Algorithm { &SHA1 } }
impl P7 for U7 { fn alg(&self) -> &'static Algorithm { &SHA256 } }
fn run7(p: &dyn P7, d: &[u8]) -> usize { digest(p.alg(), d).as_ref().len() }
// methodret
trait P8 { fn alg(&self) -> &'static Algorithm; }
struct T8;
struct U8;
impl P8 for T8 { fn alg(&self) -> &'static Algorithm { &SHA256 } }
impl P8 for U8 { fn alg(&self) -> &'static Algorithm { &SHA384 } }
struct Own8 { t: T8 }
impl Own8 { fn get(&self) -> &dyn P8 { &self.t } }
fn run8(p: &dyn P8, d: &[u8]) -> usize { digest(p.alg(), d).as_ref().len() }
// letparen
trait P9 { fn alg(&self) -> &'static Algorithm; }
struct T9;
struct U9;
impl P9 for T9 { fn alg(&self) -> &'static Algorithm { &SHA384 } }
impl P9 for U9 { fn alg(&self) -> &'static Algorithm { &SHA512 } }
fn run9(p: &dyn P9, d: &[u8]) -> usize { digest(p.alg(), d).as_ref().len() }
// blockexpr
trait P10 { fn alg(&self) -> &'static Algorithm; }
struct T10;
struct U10;
impl P10 for T10 { fn alg(&self) -> &'static Algorithm { &SHA512 } }
impl P10 for U10 { fn alg(&self) -> &'static Algorithm { &SHA1 } }
fn run10(p: &dyn P10, d: &[u8]) -> usize { digest(p.alg(), d).as_ref().len() }
// ifelse
trait P11 { fn alg(&self) -> &'static Algorithm; }
struct T11;
struct U11;
impl P11 for T11 { fn alg(&self) -> &'static Algorithm { &SHA1 } }
impl P11 for U11 { fn alg(&self) -> &'static Algorithm { &SHA256 } }
fn run11(p: &dyn P11, d: &[u8]) -> usize { digest(p.alg(), d).as_ref().len() }
// refmut_param_struct
trait P12 { fn alg(&self) -> &'static Algorithm; }
struct T12;
struct U12;
impl P12 for T12 { fn alg(&self) -> &'static Algorithm { &SHA256 } }
impl P12 for U12 { fn alg(&self) -> &'static Algorithm { &SHA384 } }
struct Ctx12<'a> { p: &'a dyn P12 }
fn run12(p: &dyn P12, d: &[u8]) -> usize { digest(p.alg(), d).as_ref().len() }
// tupleann
trait P13 { fn alg(&self) -> &'static Algorithm; }
struct T13;
struct U13;
impl P13 for T13 { fn alg(&self) -> &'static Algorithm { &SHA384 } }
impl P13 for U13 { fn alg(&self) -> &'static Algorithm { &SHA512 } }
fn run13(p: &dyn P13, d: &[u8]) -> usize { digest(p.alg(), d).as_ref().len() }

#[allow(unused_parens)]
fn main() {
    let d = arg(0).into_bytes();
    let v0: Vec<Box<dyn P0>> = vec![Box::new(T0), Box::new(U0)];
    let _ = run0(v0[0].as_ref(), &d);
    let v1 = vec![Box::new(T1) as Box<dyn P1>];
    let _ = run1(v1[0].as_ref(), &d);
    let v2 = opt2().unwrap();
    let _ = run2(v2.as_ref(), &d);
    let v3 = apply3(|| Box::new(T3) as Box<dyn P3>);
    let _ = run3(v3.as_ref(), &d);
    let v4: Vec<Box<dyn P4>> = vec![T4].into_iter().map(|x| Box::new(x) as Box<dyn P4>).collect();
    let _ = run4(v4[0].as_ref(), &d);
    let mut v5 = T5;
    let _ = runm5(&mut v5, &d);
    let _ = run5(&v5, &d);
    let b6 = Box::new(T6);
    let v6: &dyn P6 = &*b6;
    let _ = run6(v6, &d);
    let f7 = T7;
    let v7: &dyn P7 = &f7;
    let _ = run7(v7, &d);
    let o8 = Own8 { t: T8 };
    let v8 = o8.get();
    let _ = run8(v8, &d);
    let v9: Box<dyn P9> = (Box::new(T9));
    let _ = run9(v9.as_ref(), &d);
    let v10: Box<dyn P10> = { let t = T10; Box::new(t) };
    let _ = run10(v10.as_ref(), &d);
    let v11: Box<dyn P11> = if d.len() > 1 { Box::new(T11) } else { Box::new(U11) };
    let _ = run11(v11.as_ref(), &d);
    let v12 = Ctx12 { p: &T12 };
    let _ = run12(v12.p, &d);
    let v13: (u8, Box<dyn P13>) = (1, Box::new(T13));
    let _ = run13(v13.1.as_ref(), &d);
}
