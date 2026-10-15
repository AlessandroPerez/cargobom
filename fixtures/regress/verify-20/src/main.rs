// regress verify-20 (round 13, audit 12 M7: coercion details compared with the trait the value becomes; a parameter of the type; verifier probe vr1b)
use ring::digest::{digest, Algorithm, SHA384, SHA512};
use std::sync::Arc;

fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }

trait Pick { fn alg(&self) -> &'static Algorithm; }
trait Other { fn name(&self) -> &'static str; }
struct Fast;
struct Slow;
impl Pick for Fast { fn alg(&self) -> &'static Algorithm { &SHA512 } }
impl Pick for Slow { fn alg(&self) -> &'static Algorithm { &SHA384 } }
impl Other for Fast { fn name(&self) -> &'static str { "fast" } }

fn run(p: &dyn Pick, d: &[u8]) -> usize { digest(p.alg(), d).as_ref().len() }
fn label(o: &dyn Other) -> usize { o.name().len() }
struct Holder { inner: Box<dyn Pick> }
fn wrap(s: Slow) -> Box<dyn Pick> { Box::new(s) }

fn make(n: usize) -> Box<dyn Pick> {
    let probe = &Fast;
    let _ = probe.alg();
    if n > 3 { Box::new(Slow) } else { Box::new(Slow) }
}

fn main() {
    let d = arg(0).into_bytes();
    let n = run(&Fast, &d);
    let m = label(&Fast);
    let pair: (&Fast, Option<&dyn Other>) = (&Fast, None);
    let h = Holder { inner: make(n + m) };
    let a: Arc<dyn Pick> = Arc::new(Slow);
    let c = &Slow as &dyn Pick;
    let w = wrap(Slow);
    let _ = run(h.inner.as_ref(), &d) + run(a.as_ref(), &d) + run(c, &d) + run(w.as_ref(), &d);
    let _ = pair.0.alg();
}
