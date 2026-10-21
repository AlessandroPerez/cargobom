// audit 7 probe: RNG draws through other entry points
use rand::Rng;
use ring::rand::SystemRandom;

fn main() {
    let rng = SystemRandom::new();
    let k: [u8; 32] = ring::rand::generate(&rng).unwrap().expose();
    let mut t = rand::thread_rng();
    let r = t.gen_ratio(1, 3);
    let mut buf = [0u8; 8];
    getrandom::getrandom(&mut buf).unwrap();
    let v: Vec<u8> = (&mut t).sample_iter(rand::distributions::Standard).take(4).collect();
    println!("{:?} {} {:?} {:?}", k, r, buf, v);
}
