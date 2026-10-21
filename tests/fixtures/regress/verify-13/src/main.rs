// regress verify-13 (round 12, audit 11 M13): macro invocations making items. Identical
// invocations in other modules are told apart by the modules around them, invocations with other
// arguments by the descriptor their expansion names; two identical invocations in one module, of
// which `cfg` keeps one, cannot be told apart from the source: a range, never exact (C6).
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
mod a {
    h!(run);
}
mod b {
    h!(run);
}
mod c {
    g!(run, SHA384);
}
mod e {
    g!(run, SHA512);
}
mod d {
    #[cfg(unix)]
    h!(run);
    #[cfg(not(unix))]
    h!(run);
}

fn main() {
    let d = std::env::args().next().unwrap_or_default().into_bytes();
    let _ = a::run(&d) + b::run(&d) + c::run(&d) + e::run(&d) + self::d::run(&d);
}
