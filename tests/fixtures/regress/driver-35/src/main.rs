// uuid with its `fast-rng` feature draws `Uuid::new_v4()` from rand's thread generator
// (ChaCha12), not from the operating system's: the program's call is cited by the call uuid
// makes in this build (`rand::random`), also through a closure the standard library runs
// (`map(|_| Uuid::new_v4())`).
use uuid::Uuid;

fn main() {
    let one = Uuid::new_v4();
    let many: Vec<Uuid> = (0..3).map(|_| Uuid::new_v4()).collect();
    println!("{one} {}", many.len());
}
