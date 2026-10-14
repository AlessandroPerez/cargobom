// round 11 regress (audit 10 probe j2): type-join members stored by trait impls no entry point reaches
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use std::collections::HashMap;

type C = HashMap<String, String>;
fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }

struct Svc { h: Header }
impl From<u8> for Svc { fn from(_: u8) -> Self { Svc { h: Header::new(Algorithm::HS512) } } }
impl Default for Svc { fn default() -> Self { Svc { h: Header::new(Algorithm::HS384) } } }
trait Make { fn make() -> Svc; }
struct M;
impl Make for M { fn make() -> Svc { Svc { h: Header::new(Algorithm::HS512) } } }
fn live() -> Svc { Svc { h: Header::new(Algorithm::HS256) } }

fn main() {
    let c = C::new();
    let k = EncodingKey::from_secret(b"k");
    let s: Box<Svc> = Box::new(live());
    let m: HashMap<u8, Svc> = HashMap::from([(1, live())]);
    let _ = encode(&m[&1].h, &c, &k);
    let _ = encode(&s.h, &c, &k);
    let _ = arg(0);
}
