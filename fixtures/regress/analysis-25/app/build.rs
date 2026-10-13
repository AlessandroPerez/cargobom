use hmac::Mac;
fn main() {
    let mut m = hmac::Hmac::<hashing::Sha256>::new_from_slice(b"k").unwrap();
    m.update(b"x");
    let _ = m.finalize();
}
