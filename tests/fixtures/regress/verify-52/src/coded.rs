//! multihash-codetable: a macro invoked inside modules writes each hasher's trait impls
//! (`<coded::two::Sha2_256 as Default>::default`, the modules being the type's), and a derive
//! on the code type writes the method that runs them, its calls cited at the derive's name in
//! an attribute written over several lines.

use pm::Coded;

pub trait Hasher {
    fn update(&mut self, data: &[u8]);
    fn finalize(&mut self) -> Vec<u8>;
}

pub trait Coded {
    fn digest(&self, data: &[u8]) -> Vec<u8>;
}

macro_rules! hasher {
    ($module:ty, $name:ident) => {
        pub struct $name($module);

        impl Default for $name {
            fn default() -> Self {
                $name(<$module as ::sha2::Digest>::new())
            }
        }

        impl $crate::coded::Hasher for $name {
            fn update(&mut self, data: &[u8]) {
                ::sha2::Digest::update(&mut self.0, data)
            }

            fn finalize(&mut self) -> Vec<u8> {
                ::sha2::Digest::finalize_reset(&mut self.0).to_vec()
            }
        }
    };
}

pub mod two {
    hasher!(::sha2::Sha256, Sha2_256);
    hasher!(::sha2::Sha512, Sha2_512);
}

pub mod three {
    hasher!(::sha2::Sha384, Sha2_384);
}

/// A hasher of a generic type, its instances made where the derive's code names them.
pub struct Truncated<const S: usize>(::sha2::Sha512);

impl<const S: usize> Default for Truncated<S> {
    fn default() -> Self {
        Truncated(<::sha2::Sha512 as ::sha2::Digest>::new())
    }
}

impl<const S: usize> Hasher for Truncated<S> {
    fn update(&mut self, data: &[u8]) {
        ::sha2::Digest::update(&mut self.0, data)
    }

    fn finalize(&mut self) -> Vec<u8> {
        ::sha2::Digest::finalize_reset(&mut self.0)[..S].to_vec()
    }
}

#[derive(
    Clone,
    Coded,
)]
pub struct Code(pub u8);
