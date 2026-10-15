// round 14 regress (audit 13 verifier probe vm6): renamed dependency, glob re-export
use ring::digest::digest;
use algs::CALG2 as TOP;

fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }

fn main() {
    let d = arg(0).into_bytes();
    let _ = digest(algs::CALG, &d);
    let _ = digest(algs::RENAMED, &d);
    let _ = digest(TOP, &d);
    let _ = digest(algs::inner::deeper::DALG, &d);
    let _ = digest(algs::CALG2, &d);
}
