const ROUNDS: u32 = 16;

fn main() {
    let mut key_iv = [0u8; 48];
    bcrypt_pbkdf::bcrypt_pbkdf("ssh key passphrase", b"16-byte-kdf-salt", ROUNDS, &mut key_iv).unwrap();
    println!("{:02x?}", &key_iv[..4]);
}
