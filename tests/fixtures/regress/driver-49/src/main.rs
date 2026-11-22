use sha2::Digest;

fn main() {
    let pixels = std::env::args().nth(1).unwrap_or_default().into_bytes();
    let n = (pixels.len() / 4).max(1) as u32;
    let mut data = pixels.clone();
    data.resize((n * 4) as usize, 0);
    let image = qoi::encode_to_vec(&data, n, 1).unwrap_or_default();
    println!("{:x}", sha2::Sha256::digest(&image));
}
