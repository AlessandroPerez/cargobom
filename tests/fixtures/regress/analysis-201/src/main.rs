use hmac::{Hmac, Mac};
use sha2::Sha256;

fn tag(key: &[u8], data: &[u8], _n: usize) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

// A function that calls one of those it names, by `n`: each of them has it as a caller.
macro_rules! step {
    ($name:ident => $($next:ident)*) => {
        fn $name(key: &[u8], data: &[u8], n: usize) -> Vec<u8> {
            let mut way = 0;
            $(
                way += 1;
                if n % 6 == way - 1 {
                    return $next(key, data, n / 6);
                }
            )*
            Vec::new()
        }
    };
}

// Eleven levels of six functions, every function of a level calling every one of the next.
step!(a0 => b0 b1 b2 b3 b4 b5);
step!(a1 => b0 b1 b2 b3 b4 b5);
step!(a2 => b0 b1 b2 b3 b4 b5);
step!(a3 => b0 b1 b2 b3 b4 b5);
step!(a4 => b0 b1 b2 b3 b4 b5);
step!(a5 => b0 b1 b2 b3 b4 b5);
step!(b0 => c0 c1 c2 c3 c4 c5);
step!(b1 => c0 c1 c2 c3 c4 c5);
step!(b2 => c0 c1 c2 c3 c4 c5);
step!(b3 => c0 c1 c2 c3 c4 c5);
step!(b4 => c0 c1 c2 c3 c4 c5);
step!(b5 => c0 c1 c2 c3 c4 c5);
step!(c0 => d0 d1 d2 d3 d4 d5);
step!(c1 => d0 d1 d2 d3 d4 d5);
step!(c2 => d0 d1 d2 d3 d4 d5);
step!(c3 => d0 d1 d2 d3 d4 d5);
step!(c4 => d0 d1 d2 d3 d4 d5);
step!(c5 => d0 d1 d2 d3 d4 d5);
step!(d0 => e0 e1 e2 e3 e4 e5);
step!(d1 => e0 e1 e2 e3 e4 e5);
step!(d2 => e0 e1 e2 e3 e4 e5);
step!(d3 => e0 e1 e2 e3 e4 e5);
step!(d4 => e0 e1 e2 e3 e4 e5);
step!(d5 => e0 e1 e2 e3 e4 e5);
step!(e0 => f0 f1 f2 f3 f4 f5);
step!(e1 => f0 f1 f2 f3 f4 f5);
step!(e2 => f0 f1 f2 f3 f4 f5);
step!(e3 => f0 f1 f2 f3 f4 f5);
step!(e4 => f0 f1 f2 f3 f4 f5);
step!(e5 => f0 f1 f2 f3 f4 f5);
step!(f0 => g0 g1 g2 g3 g4 g5);
step!(f1 => g0 g1 g2 g3 g4 g5);
step!(f2 => g0 g1 g2 g3 g4 g5);
step!(f3 => g0 g1 g2 g3 g4 g5);
step!(f4 => g0 g1 g2 g3 g4 g5);
step!(f5 => g0 g1 g2 g3 g4 g5);
step!(g0 => h0 h1 h2 h3 h4 h5);
step!(g1 => h0 h1 h2 h3 h4 h5);
step!(g2 => h0 h1 h2 h3 h4 h5);
step!(g3 => h0 h1 h2 h3 h4 h5);
step!(g4 => h0 h1 h2 h3 h4 h5);
step!(g5 => h0 h1 h2 h3 h4 h5);
step!(h0 => i0 i1 i2 i3 i4 i5);
step!(h1 => i0 i1 i2 i3 i4 i5);
step!(h2 => i0 i1 i2 i3 i4 i5);
step!(h3 => i0 i1 i2 i3 i4 i5);
step!(h4 => i0 i1 i2 i3 i4 i5);
step!(h5 => i0 i1 i2 i3 i4 i5);
step!(i0 => j0 j1 j2 j3 j4 j5);
step!(i1 => j0 j1 j2 j3 j4 j5);
step!(i2 => j0 j1 j2 j3 j4 j5);
step!(i3 => j0 j1 j2 j3 j4 j5);
step!(i4 => j0 j1 j2 j3 j4 j5);
step!(i5 => j0 j1 j2 j3 j4 j5);
step!(j0 => k0 k1 k2 k3 k4 k5);
step!(j1 => k0 k1 k2 k3 k4 k5);
step!(j2 => k0 k1 k2 k3 k4 k5);
step!(j3 => k0 k1 k2 k3 k4 k5);
step!(j4 => k0 k1 k2 k3 k4 k5);
step!(j5 => k0 k1 k2 k3 k4 k5);
step!(k0 => tag);
step!(k1 => tag);
step!(k2 => tag);
step!(k3 => tag);
step!(k4 => tag);
step!(k5 => tag);

fn main() {
    let data = std::env::args().next().unwrap_or_default();
    let n = std::env::args().count();
    let key = b"a key written in the program";
    let out = match n % 6 {
        0 => a0(key, data.as_bytes(), n),
        1 => a1(key, data.as_bytes(), n),
        2 => a2(key, data.as_bytes(), n),
        3 => a3(key, data.as_bytes(), n),
        4 => a4(key, data.as_bytes(), n),
        _ => a5(key, data.as_bytes(), n),
    };
    println!("{out:x?}");
}
