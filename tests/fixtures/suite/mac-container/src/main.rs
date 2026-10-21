use ring::hmac;
use std::collections::HashMap;

fn main() {
    let mut keys: HashMap<&str, hmac::Key> = HashMap::new();
    keys.insert("v1", hmac::Key::new(hmac::HMAC_SHA256, b"old webhook secret"));
    keys.insert("v2", hmac::Key::new(hmac::HMAC_SHA384, b"new webhook secret"));
    let body = b"{\"event\":\"push\"}";
    let tag = hmac::sign(&keys["v2"], body);
    let ok = hmac::verify(&keys["v2"], body, tag.as_ref()).is_ok();
    println!("{ok}");
}
