use pm::{hashed, Hashy};

#[derive(Hashy)]
struct S;

#[hashed]
fn plain() -> usize {
    ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, b"p").as_ref().len()
}

macro_rules! inner {
    ($e:expr) => {
        ring::digest::digest(&ring::digest::SHA256, $e)
    };
}
macro_rules! outer {
    ($e:expr) => {
        $e.as_ref().len()
    };
}

fn main() {
    let a = S::hashy() + plain() + generated_384();
    let b = ml::sha512_of!(b"x").as_ref().len();
    let c = outer!(inner!(b"y"));
    println!("{a} {b} {c}");
}
