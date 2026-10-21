use ring::digest::{digest, Algorithm, SHA256, SHA384};
pub trait Pick { fn alg(&self) -> &'static Algorithm { &SHA256 } }
pub fn pick<T: Pick>(t: &T) -> &'static Algorithm { t.alg() }
pub struct Lib384;
impl Pick for Lib384 { fn alg(&self) -> &'static Algorithm { &SHA384 } }
pub struct W<T>(pub T);
pub trait Gen { fn alg(&self) -> &'static Algorithm; }
impl<T: Pick> Gen for W<T> { fn alg(&self) -> &'static Algorithm { self.0.alg() } }
pub fn digest_with<T: Pick>(t: &T, d: &[u8]) { let _ = digest(t.alg(), d); }
pub trait Up { fn up(&mut self) {} }
pub fn gen_up<T: Up>(t: &mut T) { t.up() }
