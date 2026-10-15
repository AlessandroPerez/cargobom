// audit 13 probe sl2: selector with string choices, constants through fields and consts
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use std::collections::HashMap;
type C = HashMap<String, String>;
const NAME: &str = "a";
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
fn hdr_for(s: &str) -> Header { match s { "a" => Header::new(Algorithm::HS256), _ => Header::new(Algorithm::HS384) } }
struct Cfg { name: &'static str }

fn main() {
    let c = C::new();
    let k = EncodingKey::from_secret(b"placeholder");
    let _ = encode(&hdr_for(&arg(1)), &c, &k);
    let _ = encode(&hdr_for("a"), &c, &k);
    let _ = encode(&hdr_for(NAME), &c, &k);
    let cfg = Cfg { name: "b" };
    let _ = encode(&hdr_for(cfg.name), &c, &k);
    for n in ["a", "b"] { let _ = encode(&hdr_for(n), &c, &k); }
}
