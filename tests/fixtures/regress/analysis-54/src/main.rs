// audit 9 probe b1: bounds (MAX_VALUES 64 in the links lookup; a cut beside a complete set; recursion; long parameter chains)
use ring::digest::{digest, Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};

fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }

fn h(a: &'static Digest, d: &[u8]) { let _ = digest(a, d); } // SHA-1, SHA-256
fn h2(a: &'static Digest, d: &[u8]) { let _ = digest(a, d); } // SHA-1, SHA-384
fn c0(d: &[u8]) { h(&SHA256, d) }
fn c1(d: &[u8]) { h(&SHA256, d) }
fn c2(d: &[u8]) { h(&SHA256, d) }
fn c3(d: &[u8]) { h(&SHA256, d) }
fn c4(d: &[u8]) { h(&SHA256, d) }
fn c5(d: &[u8]) { h(&SHA256, d) }
fn c6(d: &[u8]) { h(&SHA256, d) }
fn c7(d: &[u8]) { h(&SHA256, d) }
fn c8(d: &[u8]) { h(&SHA256, d) }
fn c9(d: &[u8]) { h(&SHA256, d) }
fn c10(d: &[u8]) { h(&SHA256, d) }
fn c11(d: &[u8]) { h(&SHA256, d) }
fn c12(d: &[u8]) { h(&SHA256, d) }
fn c13(d: &[u8]) { h(&SHA256, d) }
fn c14(d: &[u8]) { h(&SHA256, d) }
fn c15(d: &[u8]) { h(&SHA256, d) }
fn c16(d: &[u8]) { h(&SHA256, d) }
fn c17(d: &[u8]) { h(&SHA256, d) }
fn c18(d: &[u8]) { h(&SHA256, d) }
fn c19(d: &[u8]) { h(&SHA256, d) }
fn c20(d: &[u8]) { h(&SHA256, d) }
fn c21(d: &[u8]) { h(&SHA256, d) }
fn c22(d: &[u8]) { h(&SHA256, d) }
fn c23(d: &[u8]) { h(&SHA256, d) }
fn c24(d: &[u8]) { h(&SHA256, d) }
fn c25(d: &[u8]) { h(&SHA256, d) }
fn c26(d: &[u8]) { h(&SHA256, d) }
fn c27(d: &[u8]) { h(&SHA256, d) }
fn c28(d: &[u8]) { h(&SHA256, d) }
fn c29(d: &[u8]) { h(&SHA256, d) }
fn c30(d: &[u8]) { h(&SHA256, d) }
fn c31(d: &[u8]) { h(&SHA256, d) }
fn c32(d: &[u8]) { h(&SHA256, d) }
fn c33(d: &[u8]) { h(&SHA256, d) }
fn c34(d: &[u8]) { h(&SHA256, d) }
fn c35(d: &[u8]) { h(&SHA256, d) }
fn c36(d: &[u8]) { h(&SHA256, d) }
fn c37(d: &[u8]) { h(&SHA256, d) }
fn c38(d: &[u8]) { h(&SHA256, d) }
fn c39(d: &[u8]) { h(&SHA256, d) }
fn c40(d: &[u8]) { h(&SHA256, d) }
fn c41(d: &[u8]) { h(&SHA256, d) }
fn c42(d: &[u8]) { h(&SHA256, d) }
fn c43(d: &[u8]) { h(&SHA256, d) }
fn c44(d: &[u8]) { h(&SHA256, d) }
fn c45(d: &[u8]) { h(&SHA256, d) }
fn c46(d: &[u8]) { h(&SHA256, d) }
fn c47(d: &[u8]) { h(&SHA256, d) }
fn c48(d: &[u8]) { h(&SHA256, d) }
fn c49(d: &[u8]) { h(&SHA256, d) }
fn c50(d: &[u8]) { h(&SHA256, d) }
fn c51(d: &[u8]) { h(&SHA256, d) }
fn c52(d: &[u8]) { h(&SHA256, d) }
fn c53(d: &[u8]) { h(&SHA256, d) }
fn c54(d: &[u8]) { h(&SHA256, d) }
fn c55(d: &[u8]) { h(&SHA256, d) }
fn c56(d: &[u8]) { h(&SHA256, d) }
fn c57(d: &[u8]) { h(&SHA256, d) }
fn c58(d: &[u8]) { h(&SHA256, d) }
fn c59(d: &[u8]) { h(&SHA256, d) }
fn c60(d: &[u8]) { h(&SHA256, d) }
fn c61(d: &[u8]) { h(&SHA256, d) }
fn c62(d: &[u8]) { h(&SHA256, d) }
fn c63(d: &[u8]) { h(&SHA256, d) }
fn c64(d: &[u8]) { h(&SHA256, d) }
fn c65(d: &[u8]) { h(&SHA256, d) }
fn c66(d: &[u8]) { h(&SHA256, d) }
fn c67(d: &[u8]) { h(&SHA256, d) }
fn c68(d: &[u8]) { h(&SHA256, d) }
fn c69(d: &[u8]) { h(&SHA256, d) }
fn c70(d: &[u8]) { h(&SHA1, d) }
fn e0(d: &[u8]) { h2(&SHA1, d) }
fn e1(d: &[u8]) { h2(&SHA384, d) }
fn e2(d: &[u8]) { h2(&SHA384, d) }
fn e3(d: &[u8]) { h2(&SHA384, d) }
fn e4(d: &[u8]) { h2(&SHA384, d) }
fn e5(d: &[u8]) { h2(&SHA384, d) }
fn e6(d: &[u8]) { h2(&SHA384, d) }
fn e7(d: &[u8]) { h2(&SHA384, d) }
fn e8(d: &[u8]) { h2(&SHA384, d) }
fn e9(d: &[u8]) { h2(&SHA384, d) }
fn e10(d: &[u8]) { h2(&SHA384, d) }
fn e11(d: &[u8]) { h2(&SHA384, d) }
fn e12(d: &[u8]) { h2(&SHA384, d) }
fn e13(d: &[u8]) { h2(&SHA384, d) }
fn e14(d: &[u8]) { h2(&SHA384, d) }
fn e15(d: &[u8]) { h2(&SHA384, d) }
fn e16(d: &[u8]) { h2(&SHA384, d) }
fn e17(d: &[u8]) { h2(&SHA384, d) }
fn e18(d: &[u8]) { h2(&SHA384, d) }
fn e19(d: &[u8]) { h2(&SHA384, d) }
fn e20(d: &[u8]) { h2(&SHA384, d) }
fn e21(d: &[u8]) { h2(&SHA384, d) }
fn e22(d: &[u8]) { h2(&SHA384, d) }
fn e23(d: &[u8]) { h2(&SHA384, d) }
fn e24(d: &[u8]) { h2(&SHA384, d) }
fn e25(d: &[u8]) { h2(&SHA384, d) }
fn e26(d: &[u8]) { h2(&SHA384, d) }
fn e27(d: &[u8]) { h2(&SHA384, d) }
fn e28(d: &[u8]) { h2(&SHA384, d) }
fn e29(d: &[u8]) { h2(&SHA384, d) }
fn e30(d: &[u8]) { h2(&SHA384, d) }
fn e31(d: &[u8]) { h2(&SHA384, d) }
fn e32(d: &[u8]) { h2(&SHA384, d) }
fn e33(d: &[u8]) { h2(&SHA384, d) }
fn e34(d: &[u8]) { h2(&SHA384, d) }
fn e35(d: &[u8]) { h2(&SHA384, d) }
fn e36(d: &[u8]) { h2(&SHA384, d) }
fn e37(d: &[u8]) { h2(&SHA384, d) }
fn e38(d: &[u8]) { h2(&SHA384, d) }
fn e39(d: &[u8]) { h2(&SHA384, d) }
fn e40(d: &[u8]) { h2(&SHA384, d) }
fn e41(d: &[u8]) { h2(&SHA384, d) }
fn e42(d: &[u8]) { h2(&SHA384, d) }
fn e43(d: &[u8]) { h2(&SHA384, d) }
fn e44(d: &[u8]) { h2(&SHA384, d) }
fn e45(d: &[u8]) { h2(&SHA384, d) }
fn e46(d: &[u8]) { h2(&SHA384, d) }
fn e47(d: &[u8]) { h2(&SHA384, d) }
fn e48(d: &[u8]) { h2(&SHA384, d) }
fn e49(d: &[u8]) { h2(&SHA384, d) }
fn e50(d: &[u8]) { h2(&SHA384, d) }
fn e51(d: &[u8]) { h2(&SHA384, d) }
fn e52(d: &[u8]) { h2(&SHA384, d) }
fn e53(d: &[u8]) { h2(&SHA384, d) }
fn e54(d: &[u8]) { h2(&SHA384, d) }
fn e55(d: &[u8]) { h2(&SHA384, d) }
fn e56(d: &[u8]) { h2(&SHA384, d) }
fn e57(d: &[u8]) { h2(&SHA384, d) }
fn e58(d: &[u8]) { h2(&SHA384, d) }
fn e59(d: &[u8]) { h2(&SHA384, d) }
fn e60(d: &[u8]) { h2(&SHA384, d) }
fn e61(d: &[u8]) { h2(&SHA384, d) }
fn e62(d: &[u8]) { h2(&SHA384, d) }
fn e63(d: &[u8]) { h2(&SHA384, d) }
fn e64(d: &[u8]) { h2(&SHA384, d) }
fn e65(d: &[u8]) { h2(&SHA384, d) }
fn e66(d: &[u8]) { h2(&SHA384, d) }
fn e67(d: &[u8]) { h2(&SHA384, d) }
fn e68(d: &[u8]) { h2(&SHA384, d) }
fn e69(d: &[u8]) { h2(&SHA384, d) }
fn e70(d: &[u8]) { h2(&SHA384, d) }

struct S { alg: &'static Digest, n: usize }
impl S {
    fn bump(&mut self) { self.n += 1; }
    fn set(&mut self) { self.alg = &SHA512; }
}
fn rec(a: &'static Digest, n: usize, d: &[u8]) { if n > 0 { rec(a, n - 1, d) } else { let _ = digest(a, d); } } // SHA-384
fn p0(a: &'static Digest, d: &[u8]) { p1(a, d) }
fn p1(a: &'static Digest, d: &[u8]) { p2(a, d) }
fn p2(a: &'static Digest, d: &[u8]) { p3(a, d) }
fn p3(a: &'static Digest, d: &[u8]) { p4(a, d) }
fn p4(a: &'static Digest, d: &[u8]) { p5(a, d) }
fn p5(a: &'static Digest, d: &[u8]) { p6(a, d) }
fn p6(a: &'static Digest, d: &[u8]) { p7(a, d) }
fn p7(a: &'static Digest, d: &[u8]) { p8(a, d) }
fn p8(a: &'static Digest, d: &[u8]) { p9(a, d) }
fn p9(a: &'static Digest, d: &[u8]) { p10(a, d) }
fn p10(a: &'static Digest, d: &[u8]) { p11(a, d) }
fn p11(a: &'static Digest, d: &[u8]) { p12(a, d) }
fn p12(a: &'static Digest, d: &[u8]) { let _ = digest(a, d); } // SHA-256

fn main() {
    let d = arg(0).into_bytes();
    c0(&d); c1(&d); c2(&d); c3(&d); c4(&d); c5(&d); c6(&d); c7(&d); c8(&d); c9(&d); c10(&d); c11(&d);
    c12(&d); c13(&d); c14(&d); c15(&d); c16(&d); c17(&d); c18(&d); c19(&d); c20(&d); c21(&d); c22(&d); c23(&d);
    c24(&d); c25(&d); c26(&d); c27(&d); c28(&d); c29(&d); c30(&d); c31(&d); c32(&d); c33(&d); c34(&d); c35(&d);
    c36(&d); c37(&d); c38(&d); c39(&d); c40(&d); c41(&d); c42(&d); c43(&d); c44(&d); c45(&d); c46(&d); c47(&d);
    c48(&d); c49(&d); c50(&d); c51(&d); c52(&d); c53(&d); c54(&d); c55(&d); c56(&d); c57(&d); c58(&d); c59(&d);
    c60(&d); c61(&d); c62(&d); c63(&d); c64(&d); c65(&d); c66(&d); c67(&d); c68(&d); c69(&d); c70(&d); e0(&d);
    e1(&d); e2(&d); e3(&d); e4(&d); e5(&d); e6(&d); e7(&d); e8(&d); e9(&d); e10(&d); e11(&d); e12(&d);
    e13(&d); e14(&d); e15(&d); e16(&d); e17(&d); e18(&d); e19(&d); e20(&d); e21(&d); e22(&d); e23(&d); e24(&d);
    e25(&d); e26(&d); e27(&d); e28(&d); e29(&d); e30(&d); e31(&d); e32(&d); e33(&d); e34(&d); e35(&d); e36(&d);
    e37(&d); e38(&d); e39(&d); e40(&d); e41(&d); e42(&d); e43(&d); e44(&d); e45(&d); e46(&d); e47(&d); e48(&d);
    e49(&d); e50(&d); e51(&d); e52(&d); e53(&d); e54(&d); e55(&d); e56(&d); e57(&d); e58(&d); e59(&d); e60(&d);
    e61(&d); e62(&d); e63(&d); e64(&d); e65(&d); e66(&d); e67(&d); e68(&d); e69(&d); e70(&d);
    let mut s = S { alg: &SHA256, n: 0 };
    s.bump(); s.bump(); s.bump(); s.bump(); s.bump(); s.bump();
    s.bump(); s.bump(); s.bump(); s.bump(); s.bump(); s.bump();
    s.set();
    let _ = digest(s.alg, &d); // SHA-512: a complete set after a cut chain
    rec(&SHA384, arg(1).len(), &d);
    p0(&SHA256, &d);
    println!("{}", s.n);
}
