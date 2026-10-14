// round 9: a chain of writes through `&mut self` by the program's own methods (clap's
// `HelpTemplate::write_templated_help`: `self.write_display_name(); self.write_bin_name(); ..`)
// nests each value before in the next call's arguments; the driver cuts the chain like calls
// (MAX_DEPTH), never writing facts too deep to read back (jwt-cli, rage and xh failed: "recursion
// limit exceeded"). Two calls of methods that only touch `n`, then the digest of `alg`.
use ring::digest;

struct S {
    alg: &'static digest::Algorithm,
    n: usize,
}

impl S {
    fn s0(&mut self) {
        self.n += 0;
    }
    fn s1(&mut self) {
        self.n += 1;
    }
    fn s2(&mut self) {
        self.n += 2;
    }
    fn s3(&mut self) {
        self.n += 3;
    }
    fn s4(&mut self) {
        self.n += 4;
    }
    fn s5(&mut self) {
        self.n += 5;
    }
    fn s6(&mut self) {
        self.n += 6;
    }
    fn s7(&mut self) {
        self.n += 7;
    }
    fn s8(&mut self) {
        self.n += 8;
    }
    fn s9(&mut self) {
        self.n += 9;
    }
    fn s10(&mut self) {
        self.n += 10;
    }
    fn s11(&mut self) {
        self.n += 11;
    }
    fn s12(&mut self) {
        self.n += 12;
    }
    fn s13(&mut self) {
        self.n += 13;
    }
    fn s14(&mut self) {
        self.n += 14;
    }
    fn s15(&mut self) {
        self.n += 15;
    }
    fn s16(&mut self) {
        self.n += 16;
    }
    fn s17(&mut self) {
        self.n += 17;
    }
    fn s18(&mut self) {
        self.n += 18;
    }
    fn s19(&mut self) {
        self.n += 19;
    }
    fn s20(&mut self) {
        self.n += 20;
    }
    fn s21(&mut self) {
        self.n += 21;
    }
    fn s22(&mut self) {
        self.n += 22;
    }
    fn s23(&mut self) {
        self.n += 23;
    }
    fn s24(&mut self) {
        self.n += 24;
    }
    fn s25(&mut self) {
        self.n += 25;
    }
    fn s26(&mut self) {
        self.n += 26;
    }
    fn s27(&mut self) {
        self.n += 27;
    }
    fn s28(&mut self) {
        self.n += 28;
    }
    fn s29(&mut self) {
        self.n += 29;
    }
    fn s30(&mut self) {
        self.n += 30;
    }
    fn s31(&mut self) {
        self.n += 31;
    }
    fn s32(&mut self) {
        self.n += 32;
    }
    fn s33(&mut self) {
        self.n += 33;
    }
    fn s34(&mut self) {
        self.n += 34;
    }
    fn s35(&mut self) {
        self.n += 35;
    }
    fn s36(&mut self) {
        self.n += 36;
    }
    fn s37(&mut self) {
        self.n += 37;
    }
    fn s38(&mut self) {
        self.n += 38;
    }
    fn s39(&mut self) {
        self.n += 39;
    }

    // 4 writes: SHA-256 through the chain
    fn short(&mut self) {
        self.s0();
        self.s1();
        self.s2();
        self.s3();
    }

    // 12 writes, more than the search follows: an unknown whose reason says the search hit its
    // bound, never dropped
    fn medium(&mut self) {
        self.s0();
        self.s1();
        self.s2();
        self.s3();
        self.s4();
        self.s5();
        self.s6();
        self.s7();
        self.s8();
        self.s9();
        self.s10();
        self.s11();
    }

    // 40 writes
    fn long(&mut self) {
        self.s0();
        self.s1();
        self.s2();
        self.s3();
        self.s4();
        self.s5();
        self.s6();
        self.s7();
        self.s8();
        self.s9();
        self.s10();
        self.s11();
        self.s12();
        self.s13();
        self.s14();
        self.s15();
        self.s16();
        self.s17();
        self.s18();
        self.s19();
        self.s20();
        self.s21();
        self.s22();
        self.s23();
        self.s24();
        self.s25();
        self.s26();
        self.s27();
        self.s28();
        self.s29();
        self.s30();
        self.s31();
        self.s32();
        self.s33();
        self.s34();
        self.s35();
        self.s36();
        self.s37();
        self.s38();
        self.s39();
    }
}

// a field stored from itself (`fork` copies `self.d`, as rustls's hash `Context` does): the
// search meets the same read again, a cycle, which cuts nothing
struct Ctx {
    d: digest::Context,
}

impl Ctx {
    fn start(alg: &'static digest::Algorithm) -> Ctx {
        Ctx {
            d: digest::Context::new(alg),
        }
    }

    fn fork(&self) -> Ctx {
        Ctx { d: self.d.clone() }
    }

    fn finish(self) -> usize {
        self.d.finish().as_ref().len() // SHA-1, no unknown
    }
}

fn main() {
    let mut a = S { alg: &digest::SHA256, n: 0 };
    a.short();
    let _ = digest::digest(a.alg, b"a"); // SHA-256
    let mut b = S { alg: &digest::SHA384, n: 0 };
    b.medium();
    let _ = digest::digest(b.alg, b"b"); // unknown: the search hit its bound
    let mut c = S { alg: &digest::SHA512, n: 0 };
    c.long();
    let _ = digest::digest(c.alg, b"c"); // unknown: the search hit its bound
    let mut x = Ctx::start(&digest::SHA1_FOR_LEGACY_USE_ONLY);
    for _ in 0..a.n {
        x = x.fork();
    }
    println!("{}", a.n + b.n + c.n + x.finish());
}
