use md5::compute;
use md5::compute as hash_it;

macro_rules! val {
    ($f:ident) => {
        $f
    };
}

macro_rules! pick {
    ($f:ident) => {{
        let held: fn(&'static [u8; 1]) -> md5::Digest = $f;
        held
    }};
}

fn main() {
    let f: fn(&'static [u8; 1]) -> md5::Digest = val!(compute);
    println!("{:x?}", f(b"v"));
    let g = pick!(hash_it);
    println!("{:x?}", g(b"w"));
}
