use ring::digest::{Algorithm, SHA256, SHA384};
pub trait Pick { fn alg(&self) -> &'static Algorithm { &SHA256 } }
pub struct W<T>(pub T);
pub trait Gen { fn alg(&self) -> &'static Algorithm; }
impl<T: Pick> Gen for W<T> { fn alg(&self) -> &'static Algorithm { self.0.alg() } }
pub fn boxed<T: Pick + 'static>(t: T) -> Box<dyn Gen> { Box::new(W(t)) }
pub struct L384;
impl Pick for L384 { fn alg(&self) -> &'static Algorithm { &SHA384 } }
