fn main() {
    let k = std::env::args().collect::<String>();
    let t = v45::tag::<sha2::Sha256>(k.as_bytes(), b"alpha");
    println!("{:02x?}", &t[..4]);
}
