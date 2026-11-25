use md5::compute;
use sha2::{Digest, Sha256};

macro_rules! call_last {
    ($f:tt) => {
        $f(b"y")
    };
}
macro_rules! call_first {
    ($f:tt) => {
        call_last!($f)
    };
}

fn run<D: Digest>(_: D) -> Vec<u8> {
    D::digest(b"z").to_vec()
}
macro_rules! arg_last {
    ($h:tt) => {
        run($h)
    };
}
macro_rules! arg_first {
    ($h:tt) => {
        arg_last!($h)
    };
}

macro_rules! value_last {
    ($f:tt) => {
        $f
    };
}
macro_rules! value_first {
    ($f:tt) => {
        value_last!($f)
    };
}

fn other() -> md5::Digest {
    call_first!(compute)
}

fn main() {
    println!("{:x?}", call_first!(compute));
    let h = Sha256::new();
    println!("{:x?}", arg_first!(h));
    println!("{:x?}", other());
    println!("{:x?}", call_first!(compute));
    let f: fn(&'static [u8; 1]) -> md5::Digest = value_first!(compute);
    println!("{:x?}", f(b"v"));
}
