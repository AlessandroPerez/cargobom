// A name lupine-sign re-exports `hybrid::generate_keypair` as, imported under a third.
use lupine_sign::hybrid_generate_keypair as hybrid_keys;

// Invokes the macro it is handed once for each parameter set, as lupine-cli's `dispatch_mldsa!`.
macro_rules! dispatch {
    ($alg:expr, $callback:ident ! ($($args:tt)*)) => {
        match $alg {
            0 => $callback!(::ml_dsa::MlDsa44, $($args)*),
            _ => $callback!(::ml_dsa::MlDsa87, $($args)*),
        }
    };
}

fn pure(alg: u8) -> usize {
    use lupine_sign::ml_dsa_generate_keypair;
    macro_rules! keygen {
        ($P:ty, $more:expr) => {{
            let mut rng = rand::rng();
            let (sk, _vk) = ml_dsa_generate_keypair::<$P>(&mut rng).expect("a key pair");
            sk.to_bytes().len() + $more
        }};
    }
    dispatch!(alg, keygen!(0))
}

fn hybrid(alg: u8) -> usize {
    macro_rules! keygen {
        ($P:ty, $more:expr) => {{
            let mut rng = rand::rng();
            let (sk, _vk) = hybrid_keys::<$P>(&mut rng).expect("a key pair");
            sk.to_bytes().len() + $more
        }};
    }
    dispatch!(alg, keygen!(0))
}

fn plain() -> usize {
    let mut rng = rand::rng();
    let (sk, _vk) = hybrid_keys::<ml_dsa::MlDsa65>(&mut rng).expect("a key pair");
    sk.to_bytes().len()
}

fn main() {
    let alg = std::env::args().count() as u8;
    println!("{}", pure(alg) + hybrid(alg) + plain());
}
