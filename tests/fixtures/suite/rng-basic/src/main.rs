use rand::rngs::OsRng;
use rand::{Rng, RngCore};
use ring::rand::{SecureRandom, SystemRandom};

fn main() {
    let mut nonce = [0u8; 12];
    SystemRandom::new().fill(&mut nonce).unwrap();
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let mut token = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut token);
    let jitter: u32 = rand::thread_rng().gen_range(0..100);
    println!("{} {} {} {}", nonce.len(), salt.len(), token.len(), jitter < 100);
}
