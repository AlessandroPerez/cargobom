// round 14 regress (audit 13 verifier probe vp2): destructuring patterns
use ring::digest::{digest, Algorithm, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};

fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }

struct Two { h: &'static Algorithm, l: &'static Algorithm }

fn main() {
    let d = arg(0).into_bytes();
    let t = (&SHA256, (&SHA384, &SHA512));
    let (_, (_, a)) = t;
    let _ = digest(a, &d);
    let (_, (_, b)) = (&SHA256, (&SHA384, &SHA512));
    let _ = digest(b, &d);
    let [_, .., c] = [&SHA256, &SHA384, &SHA512];
    let _ = digest(c, &d);
    let [_, _, e] = [&SHA256, &SHA384, &SHA512];
    let _ = digest(e, &d);
    let s = Two { h: &SHA1, l: &SHA384 };
    let Two { l, .. } = s;
    let _ = digest(l, &d);
    let Two { h: hh, .. } = Two { h: &SHA512, l: &SHA256 };
    let _ = digest(hh, &d);
    let arr = [&SHA1, &SHA256];
    let [f, _] = arr;
    let _ = digest(f, &d);
    let _ = digest(&SHA256, &d);
    let _ = digest(&SHA384, &d);
    let _ = digest(&SHA512, &d);
    let _ = digest(&SHA1, &d);
}
