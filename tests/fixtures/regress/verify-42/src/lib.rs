// the verifier on a library's impls in another module than their type, which rustc names
// `m::<impl Trait for Type>::f`: a type re-exported (`public::SkKey` for `public::sk::SkKey`,
// ed25519-dalek's `SigningKey` for `signing::SigningKey`), a dependency's generic alias
// (`Hmac<D>` for `CoreWrapper<HmacCore<D>>`); and a macro whose line before the call defines a
// function of the callee's name (a line shifted there is not the call's)
pub mod macs;
pub mod public;
mod signature;

pub trait Check {
    fn check(&self, m: &[u8]) -> usize;
}

macro_rules! keyed {
    ($name:ident, $alg:ty) => {
        pub struct $name;
        impl $name {
            pub fn digest(d: &[u8]) -> usize {
                <$alg as sha2::Digest>::digest(d).len()
            }
        }
    };
}
keyed!(K256, sha2::Sha256); // SHA-256
keyed!(K512, sha2::Sha512); // SHA-512
