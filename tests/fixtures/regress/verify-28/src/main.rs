// regress verify-28 (round 13, audit 12 L7/L8/L9: `#[cfg]` invocations of one macro told apart by the descriptor, the index of a closure's caller, a `thread_local!` with a `const` initializer; verifier probes vr7, vr5b)
macro_rules! h {
    ($f:ident) => {
        pub fn $f(d: &[u8]) -> usize {
            ring::digest::digest(&ring::digest::SHA256, d).as_ref().len()
        }
    };
}
macro_rules! g {
    ($f:ident, $a:ident) => {
        pub fn $f(d: &[u8]) -> usize {
            ring::digest::digest(&ring::digest::$a, d).as_ref().len()
        }
    };
}
mod n {
    h!(run);
    pub mod inner {
        h!(run);
    }
}
mod f {
    #[cfg(unix)]
    g!(run, SHA384);
    #[cfg(not(unix))]
    g!(run, SHA512);
}
mod p {
    g!(run, SHA384);
}
mod q {
    g!(run, SHA384);
}
mod r {
    g!(one, SHA512);
    g!(two, SHA1_FOR_LEGACY_USE_ONLY);
}
mod s { pub mod t { h!(run); } }
mod t { h!(run); }

use std::cell::RefCell;
struct Cfg { h: &'static ring::digest::Algorithm }
thread_local! { static TC: RefCell<Cfg> = const { RefCell::new(Cfg { h: &ring::digest::SHA256 }) }; }
fn run1(a: impl Fn(&[u8]) -> ring::digest::Digest, d: &[u8]) -> ring::digest::Digest { a(d) }

fn main() {
    let dd = b"x".to_vec();
    let _ = run1(|x| run1(|y| run1(|z| ring::digest::digest(&ring::digest::SHA512, z), y), x), &dd);
    let tc = TC.with(|c| c.borrow().h);
    let _ = ring::digest::digest(tc, &dd);
    let d = std::env::args().next().unwrap_or_default().into_bytes();
    let _ = n::run(&d) + n::inner::run(&d) + f::run(&d) + p::run(&d) + q::run(&d);
    let _ = r::one(&d) + r::two(&d) + s::t::run(&d) + t::run(&d);
}
