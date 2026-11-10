// siphasher: SipHash by its rounds, a MAC. `SipHasher13` fed through `core::hash::Hasher` and
// read by `finish128` (as phf's tables are hashed) is SipHash-1-3; the one-shot `hash` of a
// `SipHasher24`, and `SipHasher` (2-4 by its definition), are SipHash-2-4. A `HashMap` built
// on `SipHasher13` hashes its keys inside the standard library: cited at the program's calls
// into it, by name. `sha-1`, the package sha1 was published as until 0.10.1, is SHA-1.
use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hash, Hasher};

use sha1::{Digest, Sha1};
use siphasher::sip::{SipHasher, SipHasher24};
use siphasher::sip128::{Hasher128, SipHasher13};

fn table_hash(key: u64, x: &str) -> (u64, u64) {
    let mut hasher = SipHasher13::new_with_keys(0, key);
    x.hash(&mut hasher);
    let h = hasher.finish128();
    (h.h1, h.h2)
}

fn main() {
    let (lo, hi) = table_hash(7, "name");
    let one_shot = SipHasher24::new_with_key(&[1u8; 16]).hash(b"message");
    let mut plain = SipHasher::new();
    plain.write(b"message");
    let default_rounds = plain.finish();
    let mut map: HashMap<&str, u32, BuildHasherDefault<siphasher::sip::SipHasher13>> =
        HashMap::default();
    map.insert("a", 1);
    let found = map.get("a").copied();
    let digest = Sha1::digest(b"message");
    println!("{lo} {hi} {one_shot} {default_rounds} {found:?} {}", digest.len());
}
