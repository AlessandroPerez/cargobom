use ring::digest;
use std::thread;

fn main() {
    let alg = &digest::SHA384;
    let payload = b"thread payload".to_vec();
    let worker = thread::spawn(move || digest::digest(alg, &payload));
    let d = worker.join().unwrap();
    println!("{}", d.as_ref().len());
}
