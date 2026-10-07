//! Phase 0 spike target: three patterns a CBOM tool must resolve.
use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::Aes256Gcm;
use chacha20poly1305::ChaCha20Poly1305;
use hmac::{Hmac, Mac};
use sha2::Sha256;

// Pattern 1: generic wrapper. The algorithm is only known at the call site.
fn seal<A: Aead + AeadCore + KeyInit>(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let cipher = A::new_from_slice(key).expect("key length");
    let nonce = A::generate_nonce(&mut OsRng);
    cipher.encrypt(&nonce, msg).expect("encrypt")
}

// Pattern 2: dyn dispatch, implementation chosen at runtime.
trait Sealer {
    fn seal(&self, msg: &[u8]) -> Vec<u8>;
}
struct AesSealer([u8; 32]);
struct ChaChaSealer([u8; 32]);
impl Sealer for AesSealer {
    fn seal(&self, msg: &[u8]) -> Vec<u8> {
        seal::<Aes256Gcm>(&self.0, msg)
    }
}
impl Sealer for ChaChaSealer {
    fn seal(&self, msg: &[u8]) -> Vec<u8> {
        seal::<ChaCha20Poly1305>(&self.0, msg)
    }
}
fn pick(name: &str) -> Box<dyn Sealer> {
    if name == "aes" { Box::new(AesSealer([7; 32])) } else { Box::new(ChaChaSealer([7; 32])) }
}

// Pattern 3: ring selects the algorithm through a static constant.
fn ring_seal(key: &[u8], msg: &mut Vec<u8>) {
    use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
    let k = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).unwrap());
    let nonce = Nonce::assume_unique_for_key([0u8; 12]); // hard-coded nonce, for provenance later
    k.seal_in_place_append_tag(nonce, Aad::empty(), msg).unwrap();
}

// Pattern 4: composition in the type.
fn mac(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).unwrap();
    m.update(msg);
    m.finalize().into_bytes().to_vec()
}

fn main() {
    let which = std::env::args().nth(1).unwrap_or_default();
    let s = pick(&which);
    let ct = s.seal(b"hello");
    let mut buf = b"hello".to_vec();
    ring_seal(&[1u8; 32], &mut buf);
    let t = mac(b"k", b"m");
    println!("{} {} {}", ct.len(), buf.len(), t.len());
}
