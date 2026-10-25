// A struct written field by field (a constant tag, a random salt, a computed limit), then
// handed to a method that reads one field (`&self.kdf_salt`): the provenance its callers give
// is that field's, not the fields beside it (minisign's secret key).
const KDF_ALG: [u8; 2] = *b"Sc";

#[derive(Default)]
struct SecretKey {
    kdf_alg: [u8; 2],
    kdf_salt: [u8; 32],
    kdf_opslimit_le: [u8; 8],
}

fn store_u64_le(x: u64) -> [u8; 8] {
    x.to_le_bytes()
}

impl SecretKey {
    fn encrypt(self, password: &str) -> [u8; 32] {
        let params = scrypt::Params::new(10, 8, 1, 32).unwrap();
        let mut out = [0u8; 32];
        scrypt::scrypt(password.as_bytes(), &self.kdf_salt, &params, &mut out).unwrap();
        out
    }
}

fn generate(password: &str) -> [u8; 32] {
    let mut sk = SecretKey::default();
    let mut kdf_salt = [0u8; 32];
    getrandom::getrandom(&mut kdf_salt).unwrap();
    sk.kdf_alg = KDF_ALG;
    sk.kdf_salt = kdf_salt;
    sk.kdf_opslimit_le = store_u64_le(1 << 20);
    sk.encrypt(password)
}

fn main() {
    let pw = std::env::args().nth(1).unwrap_or_default();
    println!("{:02x?}", &generate(&pw)[..4]);
}
