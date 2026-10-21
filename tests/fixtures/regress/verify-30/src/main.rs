// audit13 verifier probe vm4: constants in directory modules, globs, scoped uses
mod a;
mod b;
mod c;
use ring::digest::digest;
use b::sub::*;

fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }

fn glob_user(d: &[u8]) -> usize {
    use c::*;
    digest(KALG, d).as_ref().len()
}

fn main() {
    let d = arg(0).into_bytes();
    let _ = digest(a::KALG, &d);
    let _ = digest(a::sub::KALG, &d);
    let _ = digest(b::KALG, &d);
    let _ = digest(KALG, &d);
    let _ = digest(c::KALG, &d);
    let _ = digest(c::inner::KALG, &d);
    let _ = glob_user(&d) + extra(&d);
}

fn scoped(d: &[u8]) -> usize {
    use crate::a::sub::KALG as SUBK;
    digest(SUBK, d).as_ref().len() + digest(c::RENAMED, d).as_ref().len()
}

fn more(d: &[u8]) -> usize {
    use a::*;
    digest(KALG, d).as_ref().len()
}

pub fn extra(d: &[u8]) -> usize { scoped(d) + more(d) }
