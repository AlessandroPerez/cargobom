macro_rules! mk {
    ($m:ident, $f:ident, $alg:ident) => {
        mod $m {
            pub fn $f(d: &[u8]) -> usize {
                ring::digest::digest(&ring::digest::$alg, d).as_ref().len()
            }
        }
    };
}

mk!(m256, hash_a, SHA256);
mk!(m384, hash_a, SHA384);
mk!(m512, hash_b, SHA512);

macro_rules! mk2 {
    ($m:ident, $alg:ident, $n:expr) => {
        mod $m {
            pub fn run(d: &[u8]) -> usize {
                ring::digest::digest(&ring::digest::$alg, d).as_ref().len() + $n as usize
            }
        }
    };
}

mk2!(k1, SHA1_FOR_LEGACY_USE_ONLY, 1u8);
mk2!(k2, SHA512_256, 2);

fn main() {
    let d = std::env::args().next().unwrap().into_bytes();
    let _ = m256::hash_a(&d) + m384::hash_a(&d) + m512::hash_b(&d);
    let _ = k1::run(&d) + k2::run(&d);
}
