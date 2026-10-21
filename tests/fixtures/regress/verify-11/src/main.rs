// audit 10 probe vp8 (M12): a macro invocation makes what the rule it matches (rustc's first)
// expands to, its arguments put in: the modules of `sel!` in their order, `semi!`'s `;`
// separator, `two!`'s second rule; the line of the body cited is in that rule
macro_rules! sel {
    ($m:ident, $n:ident, 256) => {
        mod $m {
            pub mod $n {
                pub fn run(d: &[u8]) -> usize {
                    ring::digest::digest(&ring::digest::SHA256, d).as_ref().len()
                }
            }
        }
    };
    ($m:ident, $n:ident, 384) => {
        mod $m {
            pub mod $n {
                pub fn run(d: &[u8]) -> usize {
                    ring::digest::digest(&ring::digest::SHA384, d).as_ref().len()
                }
            }
        }
    };
}

sel!(gamma, delta, 256);
sel!(delta, gamma, 384);

macro_rules! semi {
    ($f:ident; $alg:ident) => {
        pub fn $f(d: &[u8]) -> usize {
            ring::digest::digest(&ring::digest::$alg, d).as_ref().len()
        }
    };
}

semi!(s1; SHA512);

macro_rules! two {
    ($n:literal, $h:ident) => {
        pub fn lit() -> usize {
            $n + ring::digest::$h.output_len()
        }
    };
    ($f:ident, $alg:ident) => {
        pub fn $f(d: &[u8]) -> usize {
            ring::digest::digest(&ring::digest::$alg, d).as_ref().len()
        }
    };
}

two!(h3, SHA512_256);

fn main() {
    let d = std::env::args().next().unwrap().into_bytes();
    let _ = gamma::delta::run(&d) + delta::gamma::run(&d) + s1(&d) + h3(&d);
}
