use scrypt::Params;

fn wallet_params() -> Params {
    Params::new(14, 8, 1, 32).unwrap()
}

fn main() {
    let params = wallet_params();
    let mut key = [0u8; 32];
    scrypt::scrypt(b"wallet passphrase", b"wallet-salt", &params, &mut key).unwrap();
    println!("{:02x?}", &key[..4]);
}
