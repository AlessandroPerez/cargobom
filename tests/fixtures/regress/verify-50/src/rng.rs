//! jj-lib's `JJRng`: a `rand_chacha` generator made by a generic function of rand
//! (`rand::make_rng()`), and drawn from by a method of a trait of rand (`rng.random()`). rand
//! 0.10 does not depend on rand_chacha: the generator's type gives the asset, the function's
//! crate says nothing of it.

use std::sync::Mutex;

use rand::RngExt as _;
use rand::SeedableRng as _;
use rand_chacha::ChaCha20Rng;

pub struct Ids(Mutex<ChaCha20Rng>);

impl Ids {
    pub fn new(seed: Option<u64>) -> Self {
        Self(Mutex::new(Self::rng_from_seed(seed)))
    }

    fn rng_from_seed(seed: Option<u64>) -> ChaCha20Rng {
        match seed {
            Some(seed) => ChaCha20Rng::seed_from_u64(seed),
            None => rand::make_rng(),
        }
    }

    pub fn id(&self, length: usize) -> Vec<u8> {
        let mut rng = self.0.lock().unwrap();
        (0..length).map(|_| rng.random::<u8>()).collect()
    }
}
