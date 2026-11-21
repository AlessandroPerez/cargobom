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
    ];
    parts.iter().map(Vec::len).sum()
}
