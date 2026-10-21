pub mod inner {
    pub const KALG: &ring::digest::Algorithm = &ring::digest::SHA384;
}
pub use self::inner::KALG as RENAMED;
pub const KALG: &ring::digest::Algorithm = &ring::digest::SHA512;
