// audit 8 probe s3: the same struct passed by &mut to the program's method and to another crate's function
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};

struct Sealer {
    key: LessSafeKey,
    counter: u64,
}

impl Sealer {
    fn bump(&mut self) {
        self.counter += 1;
    }
}

fn touch<T>(_t: &mut T) {}

fn main() {
    let k = std::env::args().next().unwrap_or_default().into_bytes();
    let mut a = Sealer { key: LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &k).unwrap()), counter: 0 };
    let mut buf = b"hello".to_vec();
    let _ = a.key.seal_in_place_append_tag(Nonce::assume_unique_for_key([1; 12]), Aad::empty(), &mut buf); // AES-256-GCM (no call before)
    let mut b = Sealer { key: LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &k).unwrap()), counter: 0 };
    std::mem::drop(&mut b);
    let _ = b.key.seal_in_place_append_tag(Nonce::assume_unique_for_key([2; 12]), Aad::empty(), &mut buf); // after another crate's fn
    let mut c = Sealer { key: LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &k).unwrap()), counter: 0 };
    c.bump();
    let _ = c.key.seal_in_place_append_tag(Nonce::assume_unique_for_key([3; 12]), Aad::empty(), &mut buf); // after the program's &mut self method
    let mut d = Sealer { key: LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &k).unwrap()), counter: 0 };
    touch(&mut d);
    let _ = d.key.seal_in_place_append_tag(Nonce::assume_unique_for_key([4; 12]), Aad::empty(), &mut buf); // after the program's generic fn writing nothing
}
