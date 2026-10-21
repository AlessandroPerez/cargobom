use ring::digest::{Algorithm, SHA256, SHA384};
pub mod inner {
    pub static DEEP: &ring::digest::Algorithm = &ring::digest::SHA256;
}
pub use inner::DEEP as SHALLOW;
pub const CALG: &Algorithm = &SHA384;
pub mod twin {
    pub const CALG: &ring::digest::Algorithm = &ring::digest::SHA512;
}
pub static BOTH: [&Algorithm; 2] = [&SHA256, &SHA384];
