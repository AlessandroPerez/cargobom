// round 12 regress (audit 11 probe st1): tables of structs (static, const, local), field paths after an index, writes to arr[i].f
use ring::digest::{digest, Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};
use std::sync::LazyLock;

fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }

#[derive(Clone, Copy)]
struct E { h: &'static Digest, legacy: &'static Digest }
struct N { inner: E, tag: u8 }
static TABLE: [E; 2] = [E { h: &SHA256, legacy: &SHA1 }, E { h: &SHA512, legacy: &SHA1 }];
const CTABLE: [E; 2] = [E { h: &SHA384, legacy: &SHA1 }, E { h: &SHA512, legacy: &SHA1 }];
static NESTED: [N; 2] = [N { inner: E { h: &SHA256, legacy: &SHA1 }, tag: 0 }, N { inner: E { h: &SHA384, legacy: &SHA1 }, tag: 1 }];
static PAIRS: [(&Digest, &Digest); 2] = [(&SHA256, &SHA1), (&SHA384, &SHA1)];
static SLICE: &[E] = &[E { h: &SHA384, legacy: &SHA1 }];
static LAZY: LazyLock<Vec<E>> = LazyLock::new(|| vec![E { h: &SHA512, legacy: &SHA1 }]);

fn main() {
    let d = arg(0).into_bytes();
    let i = arg(1).len() % 2;
    let e = &TABLE[i];
    let _ = digest(e.h, &d);
    let _ = digest(TABLE.iter().find(|x| x.h.output_len() > 40).unwrap().h, &d);
    for x in TABLE.iter() { let _ = digest(x.legacy, &d); }
    let _ = digest(TABLE.get(i).map(|x| x.h).unwrap_or(&SHA384), &d);
    let _ = digest(CTABLE[i].h, &d);
    let _ = digest(NESTED[i].inner.h, &d);
    let _ = digest(PAIRS[i].0, &d);
    let _ = digest(PAIRS[i].1, &d);
    let _ = digest(SLICE[0].h, &d);
    let _ = digest(LAZY[0].h, &d);
    let _ = digest(TABLE[1].legacy, &d);
    let mut arr = [E { h: &SHA256, legacy: &SHA1 }, E { h: &SHA256, legacy: &SHA1 }];
    arr[i].h = &SHA384;
    let _ = digest(arr[0].h, &d);
    let _ = digest(arr[0].legacy, &d);
    let mut brr = [E { h: &SHA256, legacy: &SHA1 }, E { h: &SHA256, legacy: &SHA1 }];
    brr[1].h = &SHA512;
    let _ = digest(brr[i].h, &d);
    let el = brr[i];
    let _ = digest(el.h, &d);
    // (writes to elements of a local array at constant indexes, `crr[0].h = ..` read as
    // `crr[1].h`, are index-insensitive: a stated limitation, left out of this copy)
    let mut v = vec![E { h: &SHA256, legacy: &SHA1 }];
    v[0].h = &SHA384;
    let _ = digest(v[0].h, &d);
    let _ = NESTED[i].tag;
}
