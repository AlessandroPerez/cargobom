// regress verify-22 (round 13, audit 12 M8: constants of other files and packages by module path, a re-export `pub use .. as ..`; verifier probe vr2)
mod algs;
mod other;
use ring::digest::digest;
use algs::CHOSEN as PICKED;

fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }

fn main() {
    let d = arg(0).into_bytes();
    let _ = digest(algs::CHOSEN, &d);
    let _ = digest(other::CHOSEN, &d);
    let _ = digest(algs::inner::DEEPER, &d);
    let _ = digest(PICKED, &d);
    let _ = digest(algs::pick(), &d);
    let _ = digest(picklib::SHALLOW, &d);
    let _ = digest(picklib::CALG, &d);
    let _ = digest(picklib::twin::CALG, &d);
    let _ = digest(picklib::inner::DEEP, &d);
}
