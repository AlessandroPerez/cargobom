// Ways of writing a name the checks read, one function a way.
use crate::HashFn;
use crate::hyp_algs::digest as sha7;
use crate::hyp_algs::*;
use crate::hyp_suites::S6;
use crate::hyp_types::Hasher8;
use ring::digest::digest as sha5;
use ring::digest::{SHA256, SHA384};
use sha2::digest::DynDigest;

pub trait Sum {
    fn sum(&self) -> Vec<u8>;
}

fn v(x: ring::digest::Digest) -> Vec<u8> {
    x.as_ref().to_vec()
}

// 1: a pointer in a field a constructor sets, called by a method
pub struct H1 {
    f: HashFn,
}

impl H1 {
    pub fn new() -> Self {
        H1 { f: ring::digest::digest }
    }

    pub fn run(&self, d: &[u8]) -> Vec<u8> {
        v((self.f)(&SHA256, d))
    }
}

pub fn h1(d: &[u8]) -> Vec<u8> {
    H1::new().run(d)
}

// 1b: set by a setter
pub struct H1b {
    f: Option<HashFn>,
}

impl H1b {
    fn set(&mut self, f: HashFn) {
        self.f = Some(f);
    }

    fn run(&self, d: &[u8]) -> Vec<u8> {
        match self.f {
            Some(f) => v(f(&SHA384, d)),
            None => Vec::new(),
        }
    }
}

pub fn h1b(d: &[u8]) -> Vec<u8> {
    let mut h = H1b { f: None };
    h.set(ring::digest::digest);
    h.run(d)
}

// 2: a pointer handed on by a function between
pub fn h2(d: &[u8]) -> Vec<u8> {
    mid2(ring::digest::digest, d)
}

fn mid2(f: HashFn, d: &[u8]) -> Vec<u8> {
    inner2(f, d)
}

fn inner2(g: HashFn, d: &[u8]) -> Vec<u8> {
    v(g(&SHA256, d))
}

// 3: a pointer's variable named as a method of the file is
struct Signer3;

impl Signer3 {
    fn hash(&self) -> usize {
        3
    }
}

pub fn h3(d: &[u8]) -> Vec<u8> {
    let hash: HashFn = ring::digest::digest;
    let mut o = v(hash(&SHA256, d));
    o.truncate(Signer3.hash());
    o
}

// 4: a pointer out of a static table through iterator adapters
static T4: &[(&str, HashFn)] = &[("r", ring::digest::digest)];

pub fn h4(n: &str, d: &[u8]) -> Vec<u8> {
    let f = T4.iter().find(|(k, _)| *k == n).map(|(_, f)| *f).unwrap();
    v(f(&SHA256, d))
}

// 5: a macro of another file naming the function by an alias of this file, and of the crate
pub fn h5(d: &[u8]) -> Vec<u8> {
    let mut o = v(h5a!(d));
    o.extend(v(h5b!(d)));
    o
}

// 6: a function a macro of another file writes gives the algorithm
pub fn h6(d: &[u8]) -> Vec<u8> {
    v(ring::digest::digest(S6::alg(), d))
}

// 7: an item the crate re-exports, imported under another name; and by a glob
pub fn h7(d: &[u8]) -> Vec<u8> {
    v(sha7(&SHA256, d))
}

pub fn h7g(d: &[u8]) -> Vec<u8> {
    v(digest(&SHA384, d))
}

// 8: a trait object behind a type alias of another file; behind `impl Trait`
pub fn h8(d: &[u8]) -> Vec<u8> {
    let mut h: Hasher8 = Box::new(sha2::Sha256::default());
    crate::hyp_feed::feed8(&mut h, d);
    crate::hyp_feed::feed8i(&mut *h, d);
    h.finalize_reset().to_vec()
}

// 9: the algorithm named by a macro the function invokes
macro_rules! alg9 {
    () => {
        &ring::digest::SHA512
    };
}

pub fn h9(d: &[u8]) -> Vec<u8> {
    let a = alg9!();
    v(ring::digest::digest(a, d))
}

// 10: a pointer called as the value of a field
struct Out10 {
    tag: ring::digest::Digest,
}

pub fn h10(d: &[u8]) -> Vec<u8> {
    let h: HashFn = ring::digest::digest;
    let o = Out10 { tag: h(&SHA256, d) };
    v(o.tag)
}

// 11: a pointer called by a path
mod algs11 {
    pub const HASH: crate::HashFn = ring::digest::digest;
}

struct S11;

impl S11 {
    const F: HashFn = ring::digest::digest;
    const TABLE: [HashFn; 1] = [ring::digest::digest];

    fn go(d: &[u8]) -> Vec<u8> {
        let mut o = v((Self::F)(&SHA256, d));
        o.extend(v(Self::TABLE[0](&SHA384, d)));
        o
    }
}

pub fn h11(d: &[u8]) -> Vec<u8> {
    let mut o = v(algs11::HASH(&SHA256, d));
    o.extend(S11::go(d));
    o
}

// 12: a pointer a macro of another file binds
pub fn h12(d: &[u8]) -> Vec<u8> {
    bind12!(f);
    v(f(&SHA256, d))
}

// 13: a pointer named by an alias a glob imports
pub fn h13(d: &[u8]) -> Vec<u8> {
    let f: HashFn = r13;
    v(f(&SHA256, d))
}

// 14: an attribute and a derive by a path from the root
#[::pm::wrapped]
pub fn wrapped14(d: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    sha2::Sha384::digest(d).to_vec()
}

#[derive(::pm::Sum)]
pub struct Blob14(pub Vec<u8>);

// 15: a labelled loop over random values
pub fn h15() -> u8 {
    use rand::Rng;
    let mut n = 0u8;
    'outer: for b in rand::thread_rng()
        .sample_iter(rand::distributions::Standard)
        .take(4)
    {
        let b: u8 = b;
        n ^= b;
        if n == 0 {
            break 'outer;
        }
    }
    n
}

// 16: a macro's path over two lines, and with a space before the `!`
mac::
    free_fn!(free16a, Sha256);

mac::free_fn ! (free16b, Sha256);

// 17: an included file whose name is not written as it is
include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/inc17.rs"));

// 18: a derive far below its `#[derive(`
#[derive(
    Clone,
    // 1
    // 2
    // 3
    // 4
    // 5
    // 6
    // 7
    // 8
    // 9
    // 10
    // 11
    // 12
    // 13
    pm::Sum,
)]
pub struct Blob18(pub Vec<u8>);

// 20: two statics of one name, one for each configuration
fn narrow20(a: &'static ring::digest::Algorithm, d: &[u8]) -> ring::digest::Digest {
    ring::digest::digest(a, &d[..d.len() / 2])
}

#[cfg(not(unix))]
static H20: HashFn = narrow20;
#[cfg(unix)]
static H20: HashFn = ring::digest::digest;

pub fn h20(d: &[u8]) -> Vec<u8> {
    let mut o = v(H20(&SHA256, d));
    o.extend(v(narrow20(&SHA256, d)));
    o
}

// 21: a type parameter after one bounded by a function's signature
pub trait HasAlg21 {
    const ALG: &'static ring::digest::Algorithm;
}

pub struct A21;

impl HasAlg21 for A21 {
    const ALG: &'static ring::digest::Algorithm = &ring::digest::SHA384;
}

fn g21<F: Fn(&[u8]) -> Vec<u8>, T: HasAlg21>(f: F, d: &[u8]) -> Vec<u8> {
    let x = f(d);
    v(ring::digest::digest(T::ALG, &x))
}

pub fn h21(d: &[u8]) -> Vec<u8> {
    g21::<_, A21>(|d| d.to_vec(), d)
}

// 22: a constant of a dependency renamed in a table of the manifest
pub fn h22(d: &[u8]) -> Vec<u8> {
    v(ring::digest::digest(algs::CALG, d))
}

// 23: a trait object of a trait whose supertrait gives the method, its own parameter bounded
pub trait Feeds23<T: AsRef<Vec<u8>>>: DynDigest {}

impl<T: AsRef<Vec<u8>>> Feeds23<T> for sha2::Sha256 {}

pub fn h23(d: &[u8]) -> Vec<u8> {
    let mut b: Box<dyn Feeds23<Vec<u8>>> = Box::new(sha2::Sha256::default());
    b.update(d);
    b.finalize_reset().to_vec()
}

// 26: a pointer out of a table indexed out of another
static FNS26: [HashFn; 1] = [ring::digest::digest];
static IX26: [usize; 1] = [0];

pub fn h26(d: &[u8]) -> Vec<u8> {
    v(FNS26[IX26[0]](&SHA256, d))
}

// 27: a pointer a function returns, called where it is returned
fn pick27() -> HashFn {
    ring::digest::digest
}

fn pick27g<T>() -> HashFn {
    ring::digest::digest
}

pub fn h27(d: &[u8]) -> Vec<u8> {
    let mut o = v(pick27()(&SHA256, d));
    o.extend(v(pick27g::<u8>()(&SHA384, d)));
    o
}

// 28: a pointer and its arguments on two lines
pub fn h28(d: &[u8]) -> Vec<u8> {
    let f: HashFn = ring::digest::digest;
    v(f
        (&SHA256, d))
}

// 29: an attribute with a space after its `#`
# [pm::wrapped]
pub fn wrapped29(d: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    sha2::Sha384::digest(d).to_vec()
}

// 30: a macro by its raw name
mac::r#free_fn!(free30, Sha256);

pub fn all(d: &[u8]) -> usize {
    let parts = [
        h1(d),
        h1b(d),
        h2(d),
        h3(d),
        h4("r", d),
        h5(d),
        h6(d),
        h7(d),
        h7g(d),
        h8(d),
        h9(d),
        h10(d),
        h11(d),
        h12(d),
        h13(d),
        wrapped14(d),
        Blob14(d.to_vec()).sum(),
        vec![h15()],
        free16a(d),
        free16b(d),
        included17(d),
        Blob18(d.to_vec()).sum(),
        algs::h19(d),
        h20(d),
        h21(d),
        h22(d),
        h23(d),
        dep::hyp25::make25(d).0.to_vec(),
        h26(d),
        h27(d),
        h28(d),
        wrapped29(d),
        free30(d),
    ];
    parts.iter().map(Vec::len).sum()
}
