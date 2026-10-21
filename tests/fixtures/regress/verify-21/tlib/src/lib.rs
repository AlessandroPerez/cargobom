use ring::digest::{digest, Algorithm, SHA256};
pub trait Pick {
    fn alg(&self) -> &'static Algorithm { &SHA256 }
    fn via(&self) -> &'static Algorithm { self.alg() }
}
pub trait HasConst { const ALG: &'static Algorithm = &SHA256; }
pub fn pick<T: Pick>(t: &T) -> &'static Algorithm { t.alg() }
pub fn pick2<T: Pick>(t: &T) -> &'static Algorithm { pick(t) }
pub fn clos<T: Pick>(t: &T) -> &'static Algorithm { let f = || t.alg(); f() }
pub fn hash_in<T: Pick>(t: &T, d: &[u8]) { let _ = digest(t.alg(), d); }
pub fn hash_c<T: HasConst>(d: &[u8]) { let _ = digest(T::ALG, d); }
pub fn hash_clos<T: Pick>(t: &T, d: &[u8]) { let f = |x: &[u8]| { let _ = digest(t.alg(), x); }; f(d) }
pub struct Holder<T>(pub T);
impl<T: Pick> Holder<T> { pub fn get(&self) -> &'static Algorithm { self.0.alg() } }
pub fn by_dyn(p: &dyn Pick) -> &'static Algorithm { p.alg() }
pub fn by_impl(p: &impl Pick) -> &'static Algorithm { p.alg() }
pub fn boxed<T: Pick + 'static>(t: T) -> Box<dyn Pick> { Box::new(t) }
