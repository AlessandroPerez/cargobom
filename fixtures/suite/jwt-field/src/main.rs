use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use std::collections::BTreeMap;

struct JwtConfig {
    issuer: &'static str,
    alg: Algorithm,
}

fn config() -> JwtConfig {
    JwtConfig { issuer: "auth", alg: Algorithm::ES256 }
}

fn mint(cfg: &JwtConfig) -> String {
    let claims = BTreeMap::from([("exp", 4_000_000_000u64)]);
    let key = EncodingKey::from_ec_pem(include_bytes!("ec.pem")).unwrap();
    encode(&Header::new(cfg.alg), &claims, &key).unwrap()
}

fn accept(cfg: &JwtConfig, token: &str) -> bool {
    let mut v = Validation::new(cfg.alg);
    v.set_required_spec_claims(&["exp"]);
    let key = DecodingKey::from_ec_pem(include_bytes!("ec_pub.pem")).unwrap();
    decode::<BTreeMap<String, u64>>(token, &key, &v).is_ok()
}

fn main() {
    let cfg = config();
    let token = mint(&cfg);
    println!("{} {}", cfg.issuer, accept(&cfg, &token));
}
