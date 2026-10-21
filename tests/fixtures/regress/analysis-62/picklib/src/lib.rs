use ring::digest::{Algorithm, SHA384, SHA512};
pub trait Source { fn alg(&self) -> &'static Algorithm; }
struct Inner;
impl Source for Inner { fn alg(&self) -> &'static Algorithm { &SHA512 } }
struct Other;
impl Source for Other { fn alg(&self) -> &'static Algorithm { &SHA384 } }
pub fn make() -> Box<dyn Source> { Box::new(Inner) }
#[allow(dead_code)]
fn unused() -> Box<dyn Source> { Box::new(Other) }
