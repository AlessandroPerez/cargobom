// rand's `seq` traits draw from the generator they are given: the draw is the call's, never
// dropped (a ChaCha12 generator of rand 0.8; an unknown one of rand 0.10, a version the knowledge
// base does not cover); a draw from a generator that computes no cryptography is no operation
mod old {
    use rand08::rngs::SmallRng;
    use rand08::seq::{IteratorRandom, SliceRandom};
    use rand08::SeedableRng;
    pub fn draws(v: &mut [u8]) {
        let mut t = rand08::thread_rng();
        v.shuffle(&mut t); // ChaCha12-RNG
        let _ = v.choose(&mut t); // ChaCha12-RNG
        let _ = (0..v.len()).choose(&mut t); // ChaCha12-RNG
        let mut s = SmallRng::seed_from_u64(7);
        v.shuffle(&mut s); // no operation
    }
}
mod new {
    use rand::rngs::SmallRng;
    use rand::seq::{IndexedRandom, SliceRandom};
    use rand::SeedableRng;
    pub fn draws(v: &mut [u8]) {
        let mut r = rand::rng();
        v.shuffle(&mut r); // an unknown generator
        let _ = v.choose(&mut r); // an unknown generator
        let mut s = SmallRng::seed_from_u64(7);
        v.shuffle(&mut s); // no operation
    }
}
fn main() {
    let mut v: Vec<u8> = std::env::args().flat_map(String::into_bytes).collect();
    old::draws(&mut v);
    new::draws(&mut v);
}
