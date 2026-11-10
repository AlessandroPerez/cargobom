// rand 0.10: `rand_core::Rng` (the former `RngCore`), `rand::RngExt` (the former `Rng`),
// `TryRng`, the operating system's generator as `SysRng` (getrandom's), and ChaCha generators
// from chacha20's `rng` feature instead of rand_chacha. Each draw is named by its generator
// as rand 0.8's and 0.9's are; a key drawn from one is `rng`, and one drawn from a generator
// seeded with a constant is predictable.
use aes_gcm::aead::KeyInit;
use aes_gcm::Aes256Gcm;
use rand::rngs::{ChaCha20Rng, StdRng, SysRng};
use rand::seq::SliceRandom;
use rand::{Rng, RngExt, SeedableRng, TryRng};

fn main() {
    let mut rng = rand::rng();
    let mut k1 = [0u8; 32];
    rng.fill_bytes(&mut k1);
    let n: u64 = rng.random();
    let r = rng.random_range(0..10u32);
    let x: u32 = rand::random();
    let mut b = [0u8; 16];
    rand::fill(&mut b);
    let mut k2 = [0u8; 32];
    SysRng.try_fill_bytes(&mut k2).unwrap();
    let mut std = StdRng::from_rng(&mut rng);
    let y = std.next_u64();
    let mut seeded = ChaCha20Rng::from_seed([7u8; 32]);
    let mut k3 = [0u8; 32];
    seeded.fill_bytes(&mut k3);
    let mut v = vec![1u8, 2, 3];
    v.shuffle(&mut rng);
    let mut k4 = [0u8; 32];
    getrandom::fill(&mut k4).unwrap();
    let ok = Aes256Gcm::new_from_slice(&k1).is_ok() as u8
        + Aes256Gcm::new_from_slice(&k2).is_ok() as u8
        + Aes256Gcm::new_from_slice(&k3).is_ok() as u8
        + Aes256Gcm::new_from_slice(&k4).is_ok() as u8;
    println!("{n} {r} {x} {y} {} {} {ok}", b[0], v[0]);
}
