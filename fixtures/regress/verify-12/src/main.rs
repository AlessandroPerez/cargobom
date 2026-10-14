// audit 10 probe vp5 and argsweep (M8): "algorithm from X in the arguments" names X in the code
// the call reads: its arguments and receiver, the variables they read (their bindings, the
// stores into them that may reach the call, a variant's payload), the consts and statics they
// name, import aliases
use ring::digest::{self, SHA384};
use ring::digest::SHA256 as H256;
use ring::digest::SHA512 as BIG;
use ring::hkdf;

const C384: &digest::Algorithm = &digest::SHA384;
static S512: &digest::Algorithm = &digest::SHA512;

struct Ctx {
    alg: &'static digest::Algorithm,
}

enum Pick {
    A(&'static digest::Algorithm),
    B(&'static digest::Algorithm),
}

fn main() {
    let d = std::env::args().next().unwrap().into_bytes();
    let a = &digest::SHA256;
    let b = &digest::SHA384;
    let x1 = digest::digest(a, &d);
    let x2 = digest::digest(b, &d);
    let x3 = digest::digest(&H256, &d);
    let x4 = digest::digest(&SHA384, &d);
    let x5 = digest::digest(C384, &d);
    let x6 = digest::digest(&BIG, &d);
    let x7 = digest::digest(S512, &d);
    // a store before the call replaces what the field held; one after it does not reach it
    let mut c = Ctx { alg: &digest::SHA256 };
    let x8 = digest::digest(c.alg, &d);
    c.alg = &digest::SHA512;
    let x9 = digest::digest(c.alg, &d);
    // a variant's payload
    let p = if d.is_empty() { Pick::A(&digest::SHA384) } else { Pick::B(&digest::SHA1_FOR_LEGACY_USE_ONLY) };
    let x10 = match p {
        Pick::A(x) => digest::digest(x, &d),
        Pick::B(y) => digest::digest(y, &d),
    };
    // the receiver's
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA384, &d);
    let _prk = salt.extract(&d);
    let _prk2 = hkdf::Salt::new(hkdf::HKDF_SHA256, &d).extract(&d);
    println!(
        "{}",
        x1.as_ref().len()
            + x2.as_ref().len()
            + x3.as_ref().len()
            + x4.as_ref().len()
            + x5.as_ref().len()
            + x6.as_ref().len()
            + x7.as_ref().len()
            + x8.as_ref().len()
            + x9.as_ref().len()
            + x10.as_ref().len()
    );
}
