use ring::hmac;

fn session_key() -> hmac::Key {
    hmac::Key::new(hmac::HMAC_SHA512, b"session secret")
}

fn authenticate(key: &hmac::Key, msg: &[u8]) -> hmac::Tag {
    hmac::sign(key, msg)
}

fn main() {
    let key = session_key();
    let tag = authenticate(&key, b"interproc");
    println!("{}", hmac::verify(&key, b"interproc", tag.as_ref()).is_ok());
}
