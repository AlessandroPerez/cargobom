// (macros of another file of the crate)
macro_rules! h5a {
    ($d:expr) => {
        sha5(&ring::digest::SHA256, $d)
    };
}

macro_rules! h5b {
    ($d:expr) => {
        $crate::sha5b(&ring::digest::SHA256, $d)
    };
}

macro_rules! suite6 {
    ($t:ident, $a:ident) => {
        pub struct $t;
        impl $t {
            pub fn alg() -> &'static ring::digest::Algorithm {
                &ring::digest::$a
            }
        }
    };
}

macro_rules! bind12 {
    ($n:ident) => {
        let $n: $crate::HashFn = ring::digest::digest;
    };
}
