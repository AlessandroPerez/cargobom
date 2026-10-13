use ring::pbkdf2;
use std::num::NonZeroU32;

trait KdfProfile {
    fn prf(&self) -> pbkdf2::Algorithm;
    fn name(&self) -> &'static str;
}

struct Interactive;
struct Archival;

impl KdfProfile for Interactive {
    fn prf(&self) -> pbkdf2::Algorithm { pbkdf2::PBKDF2_HMAC_SHA256 }
    fn name(&self) -> &'static str { "interactive" }
}

impl KdfProfile for Archival {
    fn prf(&self) -> pbkdf2::Algorithm { pbkdf2::PBKDF2_HMAC_SHA512 }
    fn name(&self) -> &'static str { "archival" }
}

fn derive_key(p: &dyn KdfProfile, pw: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    pbkdf2::derive(p.prf(), NonZeroU32::new(600_000).unwrap(), b"dyn-salt", pw, &mut out);
    out
}

fn main() {
    let used: Box<dyn KdfProfile> = Box::new(Interactive);
    let listed: Box<dyn KdfProfile> = Box::new(Archival);
    let key = derive_key(used.as_ref(), b"pw");
    println!("{} {} {:02x?}", used.name(), listed.name(), &key[..2]);
}
