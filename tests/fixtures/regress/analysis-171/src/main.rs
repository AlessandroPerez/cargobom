// The program's own function, reached only as a callback of ring's `agree_ephemeral`, calls
// blake2b_simd (a crypto package without entries): it is the program's code, whatever calls
// it, and its call is cited as the convention says, as the closure's and main's are.
use ring::agreement::{self, EphemeralPrivateKey, UnparsedPublicKey, X25519};
use ring::rand::SystemRandom;

fn kdf_named(shared: &[u8]) -> Vec<u8> {
    blake2b_simd::blake2b(shared).as_bytes().to_vec()
}

fn main() {
    let rng = SystemRandom::new();
    let peer = UnparsedPublicKey::new(&X25519, [9u8; 32]);
    let my = EphemeralPrivateKey::generate(&X25519, &rng).unwrap();
    let k1 = agreement::agree_ephemeral(my, &peer, |shared| {
        blake2b_simd::blake2b(shared).as_bytes().to_vec()
    })
    .unwrap();
    let my2 = EphemeralPrivateKey::generate(&X25519, &rng).unwrap();
    let k2 = agreement::agree_ephemeral(my2, &peer, kdf_named).unwrap();
    let k3 = blake2b_simd::blake2b(&k1).as_bytes().to_vec();
    println!("{} {} {}", k1.len(), k2.len(), k3.len());
}
