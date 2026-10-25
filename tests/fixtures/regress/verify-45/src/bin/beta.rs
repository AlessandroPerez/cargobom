fn main() {
    let k = std::env::args().collect::<String>();
    let t = v45::tag::<sha2::Sha512>(k.as_bytes(), b"beta");
    println!("{:02x?}", &t[..4]);
}
