use hmac::{Hmac, Mac};

fn main() {
    let mut m = <Hmac<sha3::Sha3_256> as Mac>::new_from_slice(b"k").unwrap();
    m.update(b"x");
    let _k = jsonwebtoken::EncodingKey::from_secret(b"secret");
}
