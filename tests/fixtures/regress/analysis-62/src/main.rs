// round 11 regress (audit 10 probe d1): calls through trait objects, variations
use ring::digest::{digest, Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;

fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }

trait Pick { fn alg(&self) -> &'static Digest { &SHA1 } }
struct Fast;
struct Slow;
struct Legacy;
struct Dead;
impl Pick for Fast { fn alg(&self) -> &'static Digest { &SHA256 } }
impl Pick for Slow { fn alg(&self) -> &'static Digest { &SHA384 } }
impl Pick for Legacy {}
impl Pick for Dead { fn alg(&self) -> &'static Digest { &SHA512 } }
#[allow(dead_code)]
fn dead() -> Box<dyn Pick> { Box::new(Dead) }

trait One { fn alg(&self) -> &'static Digest; }
struct Only;
impl One for Only { fn alg(&self) -> &'static Digest { &SHA512 } }

trait Super { fn sup(&self) -> &'static Digest; }
trait Sub: Super {}
struct S1;
impl Super for S1 { fn sup(&self) -> &'static Digest { &SHA384 } }
impl Sub for S1 {}
struct S2;
impl Super for S2 { fn sup(&self) -> &'static Digest { &SHA1 } }

trait Hasher { const ALG: &'static Digest; }
struct H256;
struct H512;
impl Hasher for H256 { const ALG: &'static Digest = &SHA256; }
impl Hasher for H512 { const ALG: &'static Digest = &SHA512; }
struct Wrap<T>(std::marker::PhantomData<T>);
trait Gen { fn alg(&self) -> &'static Digest; }
impl<T: Hasher> Gen for Wrap<T> { fn alg(&self) -> &'static Digest { T::ALG } }

trait Num { fn alg(&self) -> &'static Digest; }
impl Num for u8 { fn alg(&self) -> &'static Digest { if *self > 1 { &SHA384 } else { &SHA256 } } }

trait Field { fn alg(&self) -> &'static Digest; }
struct Cfg { a: &'static Digest }
impl Field for Cfg { fn alg(&self) -> &'static Digest { self.a } }

trait Konst { fn alg(&self) -> &'static Digest; }
struct K1;
struct K2;
impl Konst for K1 { fn alg(&self) -> &'static Digest { &SHA256 } }
impl Konst for K2 { fn alg(&self) -> &'static Digest { &SHA1 } }
const KP: &dyn Konst = &K1;
static KS: [&(dyn Konst + Sync); 2] = [&K1, &K2];

trait Boxer { fn alg(&self) -> &'static Digest; }
struct Bx;
impl Boxer for Bx { fn alg(&self) -> &'static Digest { &SHA384 } }
fn boxed<T: Boxer + 'static>(t: T) -> Box<dyn Boxer> { Box::new(t) }

fn main() {
    let d = arg(0).into_bytes();
    // Box<dyn>, two types coerced, one type only in dead code
    let p: Box<dyn Pick> = if arg(1).is_empty() { Box::new(Fast) } else { Box::new(Slow) };
    let _ = digest(p.alg(), &d); // SHA-256, SHA-384 (+ SHA-1 may: Legacy coerced below)
    // a type using the default body
    let l: &dyn Pick = &Legacy;
    let _ = digest(l.alg(), &d); // SHA-1 (+ may SHA-256, SHA-384)
    // one type coerced: exact
    let o: &dyn One = &Only;
    let _ = digest(o.alg(), &d); // SHA-512
    // Rc and Arc
    let r: Rc<dyn One> = Rc::new(Only);
    let _ = digest(r.alg(), &d); // SHA-512
    let a: Arc<dyn One> = Arc::new(Only);
    let _ = digest(a.alg(), &d); // SHA-512
    // upcast: S1 through dyn Sub to dyn Super; S2 coerced to dyn Super directly
    let s: &dyn Sub = &S1;
    let up: &dyn Super = s;
    let _ = digest(up.sup(), &d); // SHA-384 (+ may SHA-1)
    let s2: &dyn Super = &S2;
    let _ = digest(s2.sup(), &d); // SHA-1 (+ may SHA-384)
    // a generic type, two instances coerced
    let g: Box<dyn Gen> = if arg(2).is_empty() { Box::new(Wrap::<H256>(Default::default())) } else { Box::new(Wrap::<H512>(Default::default())) };
    let _ = digest(g.alg(), &d); // SHA-256, SHA-512
    // a non-ADT type
    let n: &dyn Num = &3u8;
    let _ = digest(n.alg(), &d); // SHA-384 (+ may SHA-256)
    // the method returns a field of the object
    let c: Box<dyn Field> = Box::new(Cfg { a: &SHA512 });
    let _ = digest(c.alg(), &d); // SHA-512
    // a vtable in a constant, a static table of trait objects
    let _ = digest(KP.alg(), &d); // SHA-256 (+ may SHA-1)
    let i = arg(3).len() % 2;
    let _ = digest(KS[i].alg(), &d); // SHA-1, SHA-256
    // a type parameter coerced in a generic function
    let b = boxed(Bx);
    let _ = digest(b.alg(), &d); // SHA-384
    // trait objects in a map
    let mut m: HashMap<&str, Box<dyn Pick>> = HashMap::new();
    m.insert("f", Box::new(Fast));
    let _ = digest(m["f"].alg(), &d); // SHA-256 (+ may SHA-384, SHA-1)
    // a trait object made in a library
    let lo = picklib::make();
    let _ = digest(lo.alg(), &d); // SHA-512
}
