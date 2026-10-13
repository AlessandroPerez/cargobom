// Correct positions in unusual but ordinary code, which the verifier must accept (fifth audit
// round): impls on type aliases (a program's and sha2's `Sha256`, aes-gcm's `Aes256Gcm`) and with
// aliases in their trait arguments, impls on arrays and tuples, a raw identifier, identical
// statements in sibling modules, `format!`, tabs, Unicode, CRLF, multi-line paths, blanket and
// generic impls, closures, nested items, strings with braces.
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};
use sha2::Sha384 as Three;

mod aliases;
mod arrays;
mod crlf;
mod twins;

type Bytes = Vec<u8>;
pub struct K(usize);
// a trait impl whose trait argument is a type alias
impl From<Bytes> for K {
    fn from(b: Bytes) -> K {
        K(Sha256::digest(&b).len())
    }
}

pub struct Inner<T>(T);
type Wrapper = Inner<u8>;
// an inherent impl written on a type alias
impl Wrapper {
    fn hash(&self) -> usize {
        Sha512::digest([self.0]).len()
    }
}

// a raw identifier as a function name
fn r#type(d: &[u8]) -> usize {
    Sha256::digest(d).len()
}

fn tabs(d: &[u8]) -> usize {
	let x =	Sha256::digest(d);
	x.len()
}

fn unicode(d: &[u8]) -> usize {
    let s = "héllo→ü"; let h = Sha256::digest(s.as_bytes()); h.len() + d.len()
}

fn multiline(d: &[u8]) -> usize {
    let h = sha2::Sha256
        ::digest(d);
    let m = Hmac::<
        Sha256,
    >::new_from_slice(d)
    .unwrap();
    h.len() + m.finalize().into_bytes().len()
}

trait Hasher {
    fn hash_it(&self, d: &[u8]) -> usize {
        Three::digest(d).len()
    }
}
struct H1;
impl Hasher for H1 {}

trait Blank {
    fn blank(&self) -> usize;
}
impl<T> Blank for T
where
    T: AsRef<[u8]>,
{
    fn blank(&self) -> usize {
        <Sha256 as Digest>::digest(self.as_ref()).len()
    }
}

fn generic<D>(d: &[u8]) -> usize
where
    D: Digest,
{
    D::digest(d).len()
}

fn closures(d: &[u8]) -> usize {
    let f = |x: &[u8]| Sha256::digest(x).len();
    f(d)
}

async fn asynchronous(d: Vec<u8>) -> usize {
    Sha256::digest(&d).len()
}

fn nested(d: &[u8]) -> usize {
    fn inner(d: &[u8]) -> usize {
        Sha256::digest(d).len()
    }
    struct Local;
    impl Local {
        fn go(d: &[u8]) -> usize {
            Sha512::digest(d).len()
        }
    }
    inner(d) + Local::go(d)
}

fn strings(d: &[u8]) -> usize {
    let a = "fn fake() {"; let b = '{'; let c = r#"}"#; let e = b'"';
    let h = Sha256::digest(d); // } fn other() {
    h.len() + a.len() + (b as usize) + c.len() + e as usize
}

struct Gen<T>(T);
impl<T: AsRef<[u8]>> Gen<T>
where
    T: Clone,
{
    fn run(&self) -> usize {
        Sha256::digest(self.0.as_ref()).len()
    }
}

fn noop_waker() -> std::task::Waker {
    std::task::Waker::noop().clone()
}

fn main() {
    let v = vec![1u8, 2];
    let k: K = v.clone().into();
    let w: Wrapper = Inner(3);
    let mut fut = std::pin::pin!(asynchronous(v.clone()));
    let waker = noop_waker();
    let mut cx = std::task::Context::from_waker(&waker);
    let _ = fut.as_mut().poll(&mut cx);
    use std::future::Future;
    println!(
        "{} {} {} {} {} {} {} {} {} {} {} {} {} {}",
        k.0,
        w.hash(),
        r#type(&v),
        tabs(&v),
        unicode(&v),
        multiline(&v),
        H1.hash_it(&v),
        v.blank(),
        generic::<Sha512>(&v),
        closures(&v),
        nested(&v),
        strings(&v),
        Gen(v.clone()).run(),
        crlf::crlf(&v),
    );
    println!("{} {} {}", aliases::run(&v), arrays::run(&v), twins::run(&v));
}
