// The same text in the program and in `dep`: see Cargo.toml.
use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

pub trait Sum {
    fn sum(&self) -> Vec<u8>;
}

mac::free_fn!(free, Sha256);

pub struct K(pub Vec<u8>);

impl K {
    mac::method_in!(method, sha2::Sha384);
}

mac::whole_impl!(K, Sha512);

pub fn closure(d: &[u8]) -> Vec<u8> {
    let h = mac::hasher!(Sha224);
    h(d)
}

mac::pair!(plain, generic, Sha512_224);

pub fn through<T: AsRef<[u8]>>(parts: &[T]) -> Vec<u8> {
    parts.iter().flat_map(|p| generic(p)).collect()
}

mac::outer!(nested, Sha512_256);

mac::async_fn!(awaited, Sha256);

mac::table!(TABLE, pick, SHA256, SHA384, SHA512);

mac::keyed!(mac_tag, hmac::Hmac);

#[pm::wrapped]
pub fn wrapped(d: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    sha2::Sha384::digest(d).to_vec()
}

#[derive(pm::Sum)]
pub struct Blob(pub Vec<u8>);

pm::make_fn!(made);

pm::as_is! {
    pub fn kept(d: &[u8]) -> Vec<u8> {
        use sha2::Digest;
        sha2::Sha512::digest(d).to_vec()
    }
}

#[pm::twice]
pub fn doubled(d: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    sha2::Sha256::digest(d).to_vec()
}

pm::via_rules!(by_rules);

#[derive(pm::Ruled)]
pub struct Ruled(pub Vec<u8>);

pub fn dynamic(d: &[u8], wide: bool) -> Vec<u8> {
    let mut h = if wide {
        mac::boxed!(Sha512)
    } else {
        mac::boxed!(Sha256)
    };
    h.update(d);
    h.finalize_reset().to_vec()
}

// A coercion the source writes over several lines (kdbx-rs boxes its stream cipher so).
#[rustfmt::skip]
pub fn spread(d: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    let mut h: Box<dyn sha2::digest::DynDigest> = Box::new(
        sha2::Sha384::new_with_prefix(d),
    );
    h.finalize_reset().to_vec()
}

// A function generic over one hash that also runs a hash of its own (cotp's Yandex code hashes
// its key with `Sha256::new()` in a function generic over the hash of its HMAC): the fixed one
// runs in every instance, whatever the instantiation chooses.
pub fn mixed<D: sha2::Digest>(d: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    let mut fixed = sha2::Sha256::new();
    fixed.update(d);
    let key = fixed.finalize();
    let mut h = D::new();
    h.update(key);
    h.finalize().to_vec()
}

// A macro handed to another by name: `mac::dispatch!` invokes it as `$callback!(..)`.
pub fn handed(d: &[u8]) -> Vec<u8> {
    macro_rules! hash_with {
        ($h:ty) => {
            <$h as sha2::Digest>::digest(d).to_vec()
        };
    }
    mac::dispatch!(d.len() % 2, hash_with)
}

// Two calls of one invocation, of a block cipher and of the mode made of it.
pub fn sized(key: &[u8], d: &[u8]) -> Vec<u8> {
    use aes::Aes128;
    mac::cbc_with!(Aes128, key, &[0u8; 16], d)
}

// A function of two type parameters, given one by its caller and the other by that one's
// caller (xml-sec's `run_oaep_primitive::<D, Sha1>` in `run_oaep_mgf::<Sha512>`): each
// instantiation chooses one hash, for one parameter.
pub fn two<D: sha2::Digest, M: sha2::Digest>(d: &[u8]) -> Vec<u8> {
    let mut v = D::digest(d).to_vec();
    v.extend(M::digest(d));
    v
}

pub fn one<D: sha2::Digest>(d: &[u8]) -> Vec<u8> {
    two::<D, sha2::Sha224>(d)
}

// A trait imported under another name, its objects written with that name (hqckem-ref's
// `pub(crate) use sha3::digest::XofReader as Xof;` and `&mut dyn Xof`).
mod names {
    pub(crate) use sha2::digest::DynDigest as Dd;
}

#[path = "feeding.rs"]
mod feeding;
pub use feeding::fed;

// A crypto package's trait implemented for a type of the standard library, called in a
// generic function (ece-native's `record.extend_from_slice(..)` with `B: aead::Buffer`): the
// function is the trait's crate's, `<Vec<u8> as aead::Buffer>::extend_from_slice`.
pub fn put<B: aead::Buffer>(b: &mut B, d: &[u8]) -> usize {
    b.extend_from_slice(d).map_or(0, |()| b.len())
}

// A function pointer held by a variable of the function's own name, bound on the line above
// the one that names it, at the same column (superboring's `from_components`).
fn narrow(a: &'static ring::digest::Algorithm, d: &[u8]) -> ring::digest::Digest {
    ring::digest::digest(a, &d[..d.len() / 2])
}

pub fn pointed(d: &[u8]) -> Vec<u8> {
    let digest = if d.len() > 8 {
        ring::digest::digest
    } else {
        narrow
    };
    digest(&ring::digest::SHA384, d).as_ref().to_vec()
}

fn block_on<F: Future>(f: F) -> F::Output {
    let mut f = pin!(f);
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
    }
}

pub fn all(d: &[u8]) -> usize {
    let k = K(d.to_vec());
    let parts = [
        free(d),
        k.method(),
        k.whole(),
        closure(d),
        plain(d),
        through(&[d, d]),
        nested(d),
        block_on(awaited(d.to_vec())),
        pick(d.len(), d),
        mac_tag(d, d),
        wrapped(d),
        Blob(d.to_vec()).sum(),
        made(d),
        kept(d),
        doubled(d),
        by_rules(d),
        Ruled(d.to_vec()).ruled(),
        dynamic(d, d.len().is_multiple_of(2)),
        spread(d),
        mixed::<sha2::Sha512>(d),
        mixed::<sha2::Sha224>(d),
        handed(d),
        sized(d, d),
        one::<sha2::Sha512>(d),
        pointed(d),
    ];
    let mut h = sha2::Sha384::default();
    fed(&mut h, d);
    let mut buffer = Vec::new();
    parts.iter().map(Vec::len).sum::<usize>() + put(&mut buffer, d)
}
