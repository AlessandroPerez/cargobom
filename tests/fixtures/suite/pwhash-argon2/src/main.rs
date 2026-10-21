use argon2::password_hash::{PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;

fn main() {
    let salt = SaltString::encode_b64(b"fixed-salt-16byt").unwrap();
    let argon = Argon2::default();
    let hash = argon.hash_password(b"correct horse", &salt).unwrap();
    let ok = argon.verify_password(b"correct horse", &hash).is_ok();
    println!("{} {}", hash.to_string().len(), ok);
}
