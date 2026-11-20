mod boxed;
mod mapped;
mod suites;

fn main() {
    let input = std::env::args().nth(1).unwrap_or_default().into_bytes();
    let mut data = input.clone();
    data.resize(32, 0);
    let which = if input.len() % 2 == 0 {
        &suites::SUITE_AES_256
    } else {
        &suites::SUITE_CHACHA
    };
    let a = suites::open(which, &[7; 32], &mut data);
    let b = boxed::Padding::new::<sha2::Sha256>().label(&input);
    let c = mapped::all(&[input.clone(), data]).unwrap_or_default();
    let names: Vec<&str> = c.iter().map(|s| s.0.as_str()).collect();
    println!("{a} {:x?} {}", &b[..4], names.join(","));
}
