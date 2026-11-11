mod closures;

use rand::RngCore;
use rand::rngs::OsRng;
use sha2::digest::DynDigest;
use sha2::{Digest, Sha256, Sha512};

/// The two hashes the program can be asked for: every type the build makes a `dyn DynDigest`.
fn hasher(alg: &str) -> Box<dyn DynDigest> {
    match alg {
        "sha512" => Box::new(Sha512::new()),
        _ => Box::new(Sha256::new()),
    }
}

/// A generator of the program's own, no algorithm the knowledge base names.
struct Counter(u64);

impl RngCore for Counter {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn next_u64(&mut self) -> u64 {
        self.0 += 1;
        self.0
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for b in dest {
            *b = self.next_u64() as u8;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

/// The operating system's generator, or the program's counter for tests.
fn generator(test: bool) -> Box<dyn RngCore> {
    if test {
        Box::new(Counter(0))
    } else {
        Box::new(OsRng)
    }
}

fn main() {
    let alg = std::env::args().nth(1).unwrap_or_default();

    // SHA-256 or SHA-512: the set is complete, no unknown beside it
    let mut h = hasher(&alg);
    h.update(b"upload");
    let sum = h.finalize();

    // the OS generator, or a type the knowledge base does not name: OS-RNG beside an unknown
    let mut rng = generator(alg == "test");
    let mut salt = [0u8; 16];
    rng.fill_bytes(&mut salt);

    println!("{sum:x?} {salt:x?} {:x?}", closures::run(alg.as_bytes()));
}
