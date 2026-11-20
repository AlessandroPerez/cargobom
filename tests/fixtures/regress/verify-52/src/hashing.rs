//! Macros the other files invoke, and what their code calls.

use sha2::digest::{FixedOutput, Update};

pub fn _new<D: Default>() -> D {
    D::default()
}

pub fn _chain<D: Update>(digest: D, data: &[u8]) -> D {
    digest.chain(data)
}

pub fn _result<D: FixedOutput>(digest: D) -> Vec<u8> {
    digest.finalize_fixed().to_vec()
}

macro_rules! chained {
    ($h:expr, $d:expr $(, $rest:expr)*) => {
        chained!($crate::hashing::_chain($h, $d) $(, $rest)*)
    };
    ($h:expr) => {
        $h
    };
}

macro_rules! short {
    ($($d:expr),*) => {
        $crate::hashing::_result(chained!($crate::hashing::_new::<sha2::Sha256>() $(, $d)*))
    };
}

macro_rules! long {
    ($($d:expr),*) => {
        $crate::hashing::_result(chained!($crate::hashing::_new::<sha2::Sha512>() $(, $d)*))
    };
}

macro_rules! versions {
    { $($contents:item)* } => {
        pub mod v1 {
            use sha2::Sha256 as Hasher;

            $($contents)*
        }
        pub mod v2 {
            use sha2::Sha384 as Hasher;

            $($contents)*
        }
    };
}
