use sha2::Digest;

macro_rules! via {
    ($e:expr) => {
        pm::hashed!($e)
    };
}

macro_rules! fixed {
    () => {
        pm::hashed!("fixed text")
    };
}

macro_rules! tok {
    ($t:tt) => {
        pm::hashed!($t)
    };
}

macro_rules! deep {
    (@last $t:tt) => {
        pm::hashed!($t)
    };
    (@next $t:tt) => {
        deep!(@last $t)
    };
    ($t:tt) => {
        deep!(@next $t)
    };
}

macro_rules! inner {
    ($t:tt) => {
        pm::hashed!($t)
    };
}

macro_rules! outer {
    ($t:tt) => {
        inner!($t)
    };
}

macro_rules! wrap {
    () => {
        tok!("wrapped text")
    };
}

macro_rules! same {
    ($($t:tt)*) => {
        pm::as_is!($($t)*)
    };
}

fn main() {
    let a = std::env::args().next().unwrap_or_default();
    println!("{:x?}", via!("some text"));
    println!("{:x?}", fixed!());
    println!("{:x?}", tok!("a token"));
    println!("{:x?}", deep!("deep text"));
    println!("{:x?}", outer!("outer text"));
    println!("{:x?}", wrap!());
    println!("{:x?}", same!(sha2::Sha512::digest(a.as_bytes())));
}
