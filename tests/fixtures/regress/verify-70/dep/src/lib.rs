use md5::compute;
use sha2::Digest;

pub trait Stream {
    fn seal(&self, data: &[u8]) -> Vec<u8>;
    fn open(&self, data: &[u8]) -> Vec<u8>;
}
pub struct Hashing<D>(pub core::marker::PhantomData<D>);
impl<D: Digest> Stream for Hashing<D> {
    fn seal(&self, data: &[u8]) -> Vec<u8> {
        D::digest(data).to_vec()
    }
    fn open(&self, data: &[u8]) -> Vec<u8> {
        D::new().chain_update(data).finalize().to_vec()
    }
}

macro_rules! object {
    ($name:ident, $next:tt, $last:tt, $op:tt) => {
        pub struct $name<S: Stream>(pub S);
        impl<S: Stream> $name<S> {
            pub fn $next(&self, data: &[u8]) -> Vec<u8> {
                self.0.$op(data)
            }
            pub fn $last(self, data: &[u8]) -> Vec<u8> {
                self.0.$op(data)
            }
        }
    };
}
object!(Sealer, seal_next, seal_last, seal);
object!(Opener, open_next, open_last, open);

macro_rules! twice {
    ($a:ident, $b:ident, $f:tt) => {
        pub fn $a<T: AsRef<[u8]>>(data: T) -> Vec<u8> {
            $f(data.as_ref()).0.to_vec()
        }
        pub fn $b<T: AsRef<[u8]>>(data: T) -> Vec<u8> {
            $f(data.as_ref()).0.to_vec()
        }
    };
}
twice!(first_md5, second_md5, compute);

macro_rules! assoc {
    ($a:ident, $b:ident, $m:tt) => {
        pub fn $a<D: Digest>(data: &[u8]) -> Vec<u8> {
            D::$m(data).to_vec()
        }
        pub fn $b<D: Digest>(data: &[u8]) -> Vec<u8> {
            D::$m(data).to_vec()
        }
    };
}
assoc!(one, two, digest);
