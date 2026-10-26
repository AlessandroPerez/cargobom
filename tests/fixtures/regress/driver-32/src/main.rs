// Calls the standard library makes into a crypto package on the program's behalf: orion's
// `SecretKey::default()` draws a random key, and `unwrap_or_default`, `mem::take`, an array's
// `Default` and `get_or_insert_default` run it inside std, whose MIR has no source positions.
// Each is cited at the program's call into std; `repeat_with(SecretKey::default)` names the
// function itself, cited where it is named.
use orion::aead::{self, SecretKey};

fn main() {
    let none: Option<SecretKey> = None;
    let k1: SecretKey = none.unwrap_or_default();
    let mut holder = SecretKey::default();
    let k2 = std::mem::take(&mut holder);
    let ks: [SecretKey; 2] = Default::default();
    let mut slot: Option<SecretKey> = None;
    let v: Vec<SecretKey> = std::iter::repeat_with(SecretKey::default).take(2).collect();
    let c = aead::seal(&k1, b"m").unwrap();
    let n = aead::open(&k2, &c).is_ok() as usize
        + aead::open(&holder, &c).is_ok() as usize
        + aead::open(&ks[0], &c).is_ok() as usize
        + aead::open(&ks[1], &c).is_ok() as usize
        + aead::open(slot.get_or_insert_default(), &c).is_ok() as usize
        + aead::open(&v[0], &c).is_ok() as usize;
    println!("{n}");
}
