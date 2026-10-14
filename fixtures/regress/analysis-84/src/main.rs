// round 12 regress (audit 11 probe op2): algorithm() getters whose receiver's chain names other descriptors (key bytes, updates)
use ring::digest::{digest, Context, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};
use ring::hmac;

fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }

fn main() {
    let d = arg(0).into_bytes();
    let mut ctx = Context::new(&SHA384);
    let fed = digest(&SHA256, &d);
    ctx.update(fed.as_ref());
    let _ = digest(ctx.algorithm(), &d);
    let kb = digest(&SHA512, &d);
    let k = hmac::Key::new(hmac::HMAC_SHA256, kb.as_ref());
    let _ = hmac::sign(&hmac::Key::new(k.algorithm(), b"placeholder"), &d);
    let c2 = Context::new(if arg(1).is_empty() { &SHA1 } else { &SHA256 });
    let _ = digest(c2.algorithm(), &d);
    let inner = digest(&SHA1, &d);
    let out = digest(&SHA512, inner.as_ref());
    let _ = digest(out.algorithm(), &d);
}
