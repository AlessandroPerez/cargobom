use hmac::Mac;
use paste::paste;
use sha2::{Digest, Sha256, Sha384};

macro_rules! impl_hash {
    ($name:ident, $ty:ty) => {
        paste! {
            #[allow(non_camel_case_types)]
            pub struct [<Hash_ $ty>];

            impl [<Hash_ $ty>] {
                pub fn start(&self) -> [<Ctx_ $ty>] {
                    [<Ctx_ $ty>]($ty::new())
                }

                pub fn hash(&self, data: &[u8]) -> Vec<u8> {
                    $ty::digest(data).to_vec()
                }

                pub fn mac(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
                    let mut m = hmac::Hmac::<$ty>::new_from_slice(key).unwrap();
                    m.update(data);
                    m.finalize().into_bytes().to_vec()
                }

                pub fn len(&self) -> usize {
                    <$ty as Digest>::output_size()
                }
            }

            #[allow(non_camel_case_types)]
            pub struct [<Ctx_ $ty>]($ty);

            impl [<Ctx_ $ty>] {
                pub fn finish(mut self, data: &[u8]) -> Vec<u8> {
                    self.0.update(data);
                    self.0.finalize().to_vec()
                }
            }

            pub const $name: [<Hash_ $ty>] = [<Hash_ $ty>];
        }
    };
}

impl_hash! {SHA256, Sha256}
impl_hash! {SHA384, Sha384}

fn main() {
    let input = std::env::args().nth(1).unwrap_or_default();
    let a = SHA256.start().finish(input.as_bytes());
    let b = SHA256.hash(input.as_bytes());
    let c = SHA384.start().finish(input.as_bytes());
    let d = SHA384.mac(&a, input.as_bytes());
    let n = SHA384.len();
    println!("{} {} {} {} {n}", a.len(), b.len(), c.len(), d.len());
}
