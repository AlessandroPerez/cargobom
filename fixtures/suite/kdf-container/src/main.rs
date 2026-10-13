use ring::pbkdf2;
use std::num::NonZeroU32;

fn rounds(n: u32) -> NonZeroU32 {
    NonZeroU32::new(n).unwrap()
}

fn main() {
    let prfs: Vec<pbkdf2::Algorithm> = vec![pbkdf2::PBKDF2_HMAC_SHA1, pbkdf2::PBKDF2_HMAC_SHA256];
    let mut legacy = [0u8; 20];
    pbkdf2::derive(prfs[0], rounds(4096), b"salt-a", b"old password", &mut legacy);
    let mut current = [0u8; 32];
    pbkdf2::derive(prfs[1], rounds(310_000), b"salt-b", b"new password", &mut current);
    println!("{:02x?} {:02x?}", &legacy[..2], &current[..2]);
}
