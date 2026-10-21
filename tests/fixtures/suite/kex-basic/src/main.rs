use ring::agreement::{self, EphemeralPrivateKey, UnparsedPublicKey, X25519};
use ring::rand::SystemRandom;
use x25519_dalek::{EphemeralSecret, PublicKey};

fn main() {
    let alice = EphemeralSecret::random();
    let alice_public = PublicKey::from(&alice);

    let rng = SystemRandom::new();
    let bob = EphemeralPrivateKey::generate(&X25519, &rng).unwrap();
    let bob_public: [u8; 32] = bob.compute_public_key().unwrap().as_ref().try_into().unwrap();

    let alice_shared = alice.diffie_hellman(&PublicKey::from(bob_public));
    let peer = UnparsedPublicKey::new(&X25519, alice_public.as_bytes());
    let bob_shared = agreement::agree_ephemeral(bob, &peer, |km| km.to_vec()).unwrap();
    println!("{}", alice_shared.as_bytes()[..] == bob_shared[..]);
}
