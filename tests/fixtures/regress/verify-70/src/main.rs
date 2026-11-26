use dep::{Hashing, Opener, Sealer};
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};

trait Local {
    fn sum(&self, data: &[u8]) -> Vec<u8>;
}
struct With<D>(core::marker::PhantomData<D>);
impl<D: Digest> Local for With<D> {
    fn sum(&self, data: &[u8]) -> Vec<u8> {
        D::digest(data).to_vec()
    }
}
macro_rules! local {
    ($name:ident, $next:tt, $last:tt, $op:tt) => {
        struct $name<L: Local>(L);
        impl<L: Local> $name<L> {
            #[allow(dead_code)]
            fn $next(&self, data: &[u8]) -> Vec<u8> {
                self.0.$op(data)
            }
            fn $last(self, data: &[u8]) -> Vec<u8> {
                self.0.$op(data)
            }
        }
    };
}
local!(Here, sum_next, sum_last, sum);

fn main() {
    let s = Sealer(Hashing::<Sha256>(Default::default()));
    println!("{:x?}", s.seal_last(b"b"));
    let o = Opener(Hashing::<Sha512>(Default::default()));
    println!("{:x?}", o.open_next(b"c"));
    println!("{:x?}", o.open_last(b"d"));
    println!("{:x?}", dep::second_md5("e"));
    println!("{:x?}", dep::first_md5("f"));
    println!("{:x?}", dep::one::<Sha384>(b"g"));
    println!("{:x?}", dep::two::<Sha384>(b"g"));
    let h = Here(With::<Sha224>(Default::default()));
    println!("{:x?}", h.sum_last(b"h"));
}
