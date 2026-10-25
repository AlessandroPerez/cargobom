// A crypto package whose metadata names no crypto (blake2b_simd: keywords only, no category)
// is one by its name, which names an algorithm of the Cryptography Registry: Layer 1 lists it
// and its calls are unknowns.
fn main() {
    let msg = std::env::args().collect::<String>();
    let h = blake2b_simd::blake2b(msg.as_bytes());
    let k = blake2b_simd::Params::new()
        .hash_length(32)
        .key(b"k")
        .hash(msg.as_bytes());
    println!("{} {}", h.to_hex(), k.to_hex());
}
