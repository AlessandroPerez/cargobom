// audit 8 probe w2: 17 distinct alternatives (MAX_WIDTH 16), inline and inside a function
use ring::digest::{digest, Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512, SHA512_256};

fn f0() -> &'static Digest { &SHA256 }
fn f1() -> &'static Digest { &SHA384 }
fn f2() -> &'static Digest { &SHA512 }
fn f3() -> &'static Digest { &SHA1 }
fn f4() -> &'static Digest { &SHA256 }
fn f5() -> &'static Digest { &SHA384 }
fn f6() -> &'static Digest { &SHA512 }
fn f7() -> &'static Digest { &SHA1 }
fn f8() -> &'static Digest { &SHA256 }
fn f9() -> &'static Digest { &SHA384 }
fn f10() -> &'static Digest { &SHA512 }
fn f11() -> &'static Digest { &SHA1 }
fn f12() -> &'static Digest { &SHA256 }
fn f13() -> &'static Digest { &SHA384 }
fn f14() -> &'static Digest { &SHA512 }
fn f15() -> &'static Digest { &SHA1 }

fn pick17(n: usize) -> &'static Digest {
    match n {
        0 => f0(),
        1 => f1(),
        2 => f2(),
        3 => f3(),
        4 => f4(),
        5 => f5(),
        6 => f6(),
        7 => f7(),
        8 => f8(),
        9 => f9(),
        10 => f10(),
        11 => f11(),
        12 => f12(),
        13 => f13(),
        14 => f14(),
        15 => f15(),
        _ => &SHA512_256,
    }
}

fn main() {
    let n = std::env::args().count();
    let d = b"data";
    let a: &'static Digest = match n {
        0 => f0(),
        1 => f1(),
        2 => f2(),
        3 => f3(),
        4 => f4(),
        5 => f5(),
        6 => f6(),
        7 => f7(),
        8 => f8(),
        9 => f9(),
        10 => f10(),
        11 => f11(),
        12 => f12(),
        13 => f13(),
        14 => f14(),
        15 => f15(),
        _ => &SHA512_256,
    };
    let _ = digest(a, d); // inline: SHA-1, SHA-256, SHA-384, SHA-512, SHA-512/256, and an unknown (17 alternatives: cut at 16)
    let _ = digest(pick17(n), d); // through a function (17 returns: cut at 16): the same 5 and the unknown
}
