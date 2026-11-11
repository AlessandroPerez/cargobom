mod cipher;
mod ctx;
mod kdf;
mod kem;
mod modes;
mod own;
mod stream;
mod table;
mod wrap;

fn main() {
    let input = std::env::args().nth(1).unwrap_or_default();
    let data = input.as_bytes();
    let key = [7u8; 32];
    let iv = [9u8; 16];

    println!("{:x?}", kdf::both(data));
    println!("{:x?}", kem::suite(data));

    let mut c = cipher::Cipher::from_mode(data.len() * 8, &key);
    let mut buf = data.to_vec();
    c.crypt_in_place(&mut buf);
    println!("{buf:x?}");

    let mut room = vec![0u8; data.len() + 16];
    room[..data.len()].copy_from_slice(data);
    println!("{}", modes::encrypt(data.len() * 8, &key, &iv, &mut room, data.len()));

    for name in ["aes128-ctr", "aes256-ctr", "aes128-cbc"] {
        let mut block = [0u8; 32];
        table::CIPHERS[name].seal(&key, &iv, &mut block);
        println!("{block:x?}");
    }

    println!("{:x?}", wrap::digest(data));
    println!("{:x?}", wrap::leader(data));
    println!("{:x?}", ctx::respond(data));
}
