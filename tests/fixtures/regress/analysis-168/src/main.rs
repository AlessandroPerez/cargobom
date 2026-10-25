// Calls into a crypto package the knowledge base does not model (orion): every one is cited,
// what it does not known but for a use its name has; a constructor may draw a key
// (`SecretKey::default()` is random), a generic name (`finalize`) names no use, and a step of
// a stream (`update`) is not cited. rand 0.9's free `fill` draws from the thread generator.
use orion::aead;
use orion::hazardous::hash::blake2::blake2b::Blake2b;

fn main() {
    let key = aead::SecretKey::default();
    let sealed = aead::seal(&key, b"message").unwrap();
    let opened = aead::open(&key, &sealed).unwrap();

    let mut state = Blake2b::new(32).unwrap();
    state.update(&opened).unwrap();
    let digest = state.finalize().unwrap();

    let mut buf = [0u8; 16];
    rand::fill(&mut buf);
    println!("{} {:02x?}", digest.len(), buf);
}
