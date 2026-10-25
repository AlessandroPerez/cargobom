// Signature validation disabled on one branch only, through the validator's own variable: the
// decode keeps its candidate, with the note that on a way to the call it only decodes.
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};

#[derive(serde::Deserialize)]
struct Claims {
    sub: String,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let token = args.get(1).cloned().unwrap_or_default();
    let key = DecodingKey::from_secret(args.get(2).map(String::as_bytes).unwrap_or_default());
    let mut v = Validation::new(Algorithm::HS512);
    if args.len() > 3 {
        v.insecure_disable_signature_validation();
    }
    if let Ok(d) = decode::<Claims>(&token, &key, &v) {
        println!("{}", d.claims.sub);
    }
}
