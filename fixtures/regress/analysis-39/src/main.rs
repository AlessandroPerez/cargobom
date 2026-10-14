// audit 8 probe s2: the program's &mut self methods on structs holding crypto objects; A7 forms
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::{hkdf, hmac};

struct Sealer {
    key: LessSafeKey,
    counter: u64,
}

impl Sealer {
    fn bump(&mut self) {
        self.counter += 1;
    }
    fn nonce(&self) -> Nonce {
        let mut n = [0u8; 12];
        n[4..].copy_from_slice(&self.counter.to_be_bytes());
        Nonce::assume_unique_for_key(n)
    }
}

struct Mac {
    ctx: hmac::Context,
    n: usize,
}

impl Mac {
    fn feed(&mut self, d: &[u8]) {
        self.n += d.len();
        self.ctx.update(d);
    }
}

const ZSALT: [u8; 32] = [0; 32];
static SZSALT: [u8; 32] = [0; 32];

fn main() {
    let k = std::env::args().next().unwrap_or_default().into_bytes();
    let mut s = Sealer { key: LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &k).unwrap()), counter: 0 };
    s.bump();
    let mut buf = b"hello".to_vec();
    let _ = s.key.seal_in_place_append_tag(s.nonce(), Aad::empty(), &mut buf); // AES-256-GCM
    let mut m = Mac { ctx: hmac::Context::with_key(&hmac::Key::new(hmac::HMAC_SHA384, &k)), n: 0 };
    m.feed(b"data");
    let _ = m.ctx.sign(); // HMAC-SHA-384
    // A7 forms of an all-zero salt
    let _ = hkdf::Salt::new(hkdf::HKDF_SHA256, &ZSALT); // const all-zero salt
    let _ = hkdf::Salt::new(hkdf::HKDF_SHA256, &SZSALT); // static all-zero salt
    let vz = vec![0u8; 32];
    let _ = hkdf::Salt::new(hkdf::HKDF_SHA256, &vz); // vec![0; 32] salt
    let zeroes = [0u8; 64];
    let _ = hkdf::Salt::new(hkdf::HKDF_SHA384, &zeroes[..48]); // a slice of a local all-zero array
}
