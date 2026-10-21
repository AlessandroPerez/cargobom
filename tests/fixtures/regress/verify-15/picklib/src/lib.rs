use ring::digest::{Algorithm, SHA256, SHA384, SHA512};
pub static ALG: &Algorithm = &SHA512;
pub const CALG: &Algorithm = &SHA384;
pub static TABLE: [&Algorithm; 2] = [&SHA256, &SHA384];
pub mod inner { pub static DEEP: &ring::digest::Algorithm = &ring::digest::SHA256; }
