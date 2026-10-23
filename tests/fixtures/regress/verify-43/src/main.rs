// shapes the verifier must place (found on rbw, biscuit-auth and rcgen): an `async fn`
// instantiated where it is awaited, `.await` on the call's line or the next; an `#[async_trait]`
// method, cited at its `async`, in the impl and as a trait's default body; a method's own type
// argument (`::<block_padding::Pkcs7>`) that is not the asset's; a generic method instantiated by
// the impl a `#[derive(Hash)]` writes; a closure of a library's generic function (`lib43`); and
// two calls of a generic function on adjacent lines whose instances their arguments choose, in
// totp-rs, a crypto package the knowledge base does not model, whose calls into itself record
// no `[instantiation]` occurrence (`Algorithm::hash(HmacSha256::new_from_slice(..))` beside
// `HmacSha512`'s)
use std::hash::{Hash, Hasher};

use cbc::cipher::{BlockEncryptMut, KeyIvInit};
use sha2::{Digest, Sha256, Sha384, Sha512};

pub struct Key(pub [u8; 32]);

impl Hash for Key {
    fn hash<H: Hasher>(&self, state: &mut H) {
        Sha256::digest(self.0).hash(state);
    }
}

#[derive(Hash)]
pub enum PublicKey {
    A(Key),
}

async fn digest_later(d: &[u8]) -> Vec<u8> {
    Sha512::digest(d).to_vec()
}

#[async_trait::async_trait]
trait Signer {
    async fn sign(&self, d: &[u8]) -> Vec<u8>;

    async fn sign_twice(&self, d: &[u8]) -> Vec<u8> {
        let first = self.sign(d).await;
        self.sign(&first).await
    }
}

struct S;

#[async_trait::async_trait]
impl Signer for S {
    async fn sign(&self, d: &[u8]) -> Vec<u8> {
        Sha384::digest(d).to_vec()
    }
}

fn encrypt(key: &[u8; 32], iv: &[u8; 16], m: &[u8]) -> Vec<u8> {
    let cipher = cbc::Encryptor::<aes::Aes256>::new(key.into(), iv.into());
    cipher.encrypt_padded_vec_mut::<block_padding::Pkcs7>(m)
}

fn main() {
    let (a, b) = futures_executor::block_on(async {
        let a = digest_later(b"x")
            .await;
        let b = S.sign_twice(b"y").await;
        (a, b)
    });
    let mut h = std::collections::hash_map::DefaultHasher::new();
    PublicKey::A(Key([1; 32])).hash(&mut h);
    let c = encrypt(&[0; 32], &[0; 16], b"m");
    let otp = totp_rs::TOTP::new(totp_rs::Algorithm::SHA256, 6, 1, 30, vec![7u8; 16])
        .map(|t| t.generate(59))
        .unwrap_or_default();
    let s = lib43::serialize_with_a_writer_whose_name_is_long_enough(&[1u8; 4]);
    println!(
        "{} {} {} {} {} {}",
        a.len(),
        b.len(),
        c.len(),
        s.len(),
        otp,
        h.finish()
    );
}
