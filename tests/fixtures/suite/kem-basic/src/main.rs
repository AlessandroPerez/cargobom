use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{KemCore, MlKem768};
use rand_core::OsRng;

fn main() {
    let (dk, ek) = MlKem768::generate(&mut OsRng);
    let (ct, sender_key) = ek.encapsulate(&mut OsRng).unwrap();
    let receiver_key = dk.decapsulate(&ct).unwrap();
    println!("{}", sender_key == receiver_key);
}
