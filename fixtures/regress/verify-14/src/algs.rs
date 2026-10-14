use ring::digest::{Algorithm, SHA384, SHA512};
pub const CHOSEN: &Algorithm = &SHA384;
pub static OTHER: &Algorithm = &SHA512;
