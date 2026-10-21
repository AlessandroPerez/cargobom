use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use std::collections::BTreeMap;

trait Audience {
    fn alg(&self) -> Algorithm;
}

struct Partner;
struct Bank;

impl Audience for Partner {
    fn alg(&self) -> Algorithm { Algorithm::RS256 }
}

impl Audience for Bank {
    fn alg(&self) -> Algorithm { Algorithm::PS256 }
}

fn round_trip(a: &dyn Audience) -> bool {
    let claims = BTreeMap::from([("exp", 4_000_000_000u64)]);
    let key = EncodingKey::from_rsa_pem(include_bytes!("rsa.pem")).unwrap();
    let token = encode(&Header::new(a.alg()), &claims, &key).unwrap();
    let public = DecodingKey::from_rsa_pem(include_bytes!("rsa_pub.pem")).unwrap();
    decode::<BTreeMap<String, u64>>(&token, &public, &Validation::new(a.alg())).is_ok()
}

fn main() {
    let partner: Box<dyn Audience> = Box::new(Partner);
    let bank: Box<dyn Audience> = Box::new(Bank);
    println!("{} {}", round_trip(partner.as_ref()), round_trip(bank.as_ref()));
}
