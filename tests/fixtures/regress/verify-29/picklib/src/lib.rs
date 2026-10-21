pub mod inner {
    pub const CALG: &ring::digest::Algorithm = &ring::digest::SHA384;
    pub mod deeper {
        pub const DALG: &ring::digest::Algorithm = &ring::digest::SHA1_FOR_LEGACY_USE_ONLY;
    }
}
pub use inner::*;
pub use inner::deeper::DALG as RENAMED;
pub const CALG2: &ring::digest::Algorithm = &ring::digest::SHA512;
