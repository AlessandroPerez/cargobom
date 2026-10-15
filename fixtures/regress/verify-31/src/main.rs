// round 14 regress (audit 13 verifier probe vm2): constants in directory modules, globs, scoped uses
mod a;
mod b;
mod c;
use ring::digest::digest;

fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }

fn glob_user(d: &[u8]) -> usize {
    use c::*;
    digest(K, d).as_ref().len()
}

fn main() {
    let d = arg(0).into_bytes();
    let _ = digest(a::K, &d);
    let _ = digest(a::sub::K, &d);
    let _ = digest(b::K, &d);
    let _ = digest(b::sub::K, &d);
    let _ = digest(c::K, &d);
    let _ = digest(c::inner::K, &d);
    let _ = glob_user(&d);
}
