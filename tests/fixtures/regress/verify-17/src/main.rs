// regress verify-17 (round 12, audit 11 M10, M11, M12: nested closures on one line, pointers in labelled blocks, macro rules with repetitions; audit 11 probe vq2)
use ring::digest::{digest, Algorithm, Digest, SHA256, SHA384, SHA512};

type F = fn(&'static Algorithm, &[u8]) -> Digest;

fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
fn run2(a: impl Fn(&[u8]) -> Digest, b: impl Fn(&[u8]) -> Digest, d: &[u8]) { let _ = a(d); let _ = b(d); }
fn run1(a: impl Fn(&[u8]) -> Digest, d: &[u8]) -> Digest { a(d) }

mod m {
    macro_rules! hash_all {
        ($d:expr; $($h:ident),*) => { $( let _ = ring::digest::digest(&ring::digest::$h, $d); )* };
        ($h:ident) => { let _ = ring::digest::digest(&ring::digest::$h, b"x"); };
    }
    pub(crate) use hash_all;
}

macro_rules! outer {
    ($d:expr, $h:ident) => { inner!($d, $h) };
}
macro_rules! inner {
    ($d:expr, $h:ident) => { ring::digest::digest(&ring::digest::$h, $d) };
}

fn main() {
    let d = arg(0).into_bytes();
    let g: F = match arg(1).len() {
        0 => digest,
        _ => digest,
    };
    let _ = g(&SHA256, &d);
    let fs: Vec<F> = vec![digest];
    let mut it = fs.iter();
    while let Some(f) = it.next() {
        let _ = f(&SHA384, &d);
    }
    let lb: F = 'b: {
        if arg(2).is_empty() {
            break 'b digest;
        }
        digest
    };
    let _ = lb(&SHA512, &d);
    run2(|x| digest(&SHA256, x), |x| digest(&SHA384, x), &d);
    let _ = run1(|x| run1(|y| digest(&SHA512, y), x), &d);
    m::hash_all!(&d; SHA256, SHA384);
    m::hash_all!(SHA512);
    let _ = outer!(&d, SHA384);
    let _ = outer!(&d, SHA512);
}
