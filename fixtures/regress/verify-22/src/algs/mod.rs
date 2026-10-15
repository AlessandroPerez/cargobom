use ring::digest::{Algorithm, SHA384};
pub mod inner;
pub const CHOSEN: &Algorithm = &SHA384;
pub const fn pick() -> &'static Algorithm { &SHA384 }
