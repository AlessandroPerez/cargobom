// The RustCrypto generation after 0.10 (digest 0.11, crypto-common 0.2): its hashes are named
// structs (`sha2::Sha256`, no longer an alias of a wrapper around a core type), `Hmac<D>` is a
// struct over the hash itself, and `Mac::new_from_slice` moved to `KeyInit`. Each call is named
// as its 0.10 counterpart is: the hash by its type, the HMAC and the KDFs with their hash, the
// PBKDF2 and scrypt parameters from their constant arguments.
use hmac::{Hmac, HmacReset, KeyInit, Mac, SimpleHmac};
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512, Sha512_256};

fn main() {
    let data = std::env::args().nth(1).unwrap_or_default();
    let data = data.as_bytes();
    // hashes
    let d1 = Sha256::digest(data);
    let mut h = Sha512::new();
    h.update(data);
    let d2 = h.finalize();
    let d3 = Sha384::digest(data);
    let d4 = Sha224::digest(data);
    let d5 = Sha512_256::digest(data);
    let d6 = sha1::Sha1::digest(data);
    let d7 = md5::Md5::digest(data);
    // HMAC
    let mut m = Hmac::<Sha256>::new_from_slice(b"key").unwrap();
    m.update(data);
    let tag = m.finalize().into_bytes();
    let mut v = Hmac::<Sha512>::new_from_slice(b"key").unwrap();
    v.update(data);
    let ok = v.verify_slice(&tag).is_ok();
    let mut r = HmacReset::<Sha384>::new_from_slice(b"key").unwrap();
    r.update(data);
    let t2 = r.finalize_reset().into_bytes();
    let mut s = SimpleHmac::<sha1::Sha1>::new_from_slice(b"key").unwrap();
    s.update(data);
    let t3 = s.finalize().into_bytes();
    // HKDF
    let hk = hkdf::Hkdf::<Sha256>::new(Some(b"salt"), data);
    let mut okm = [0u8; 42];
    hk.expand(b"info", &mut okm).unwrap();
    // PBKDF2
    let mut k1 = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(data, b"salt", 600_000, &mut k1);
    let k2 = pbkdf2::pbkdf2_hmac_array::<Sha512, 20>(data, b"salt", 1_000);
    let mut k3 = [0u8; 16];
    pbkdf2::pbkdf2::<Hmac<sha1::Sha1>>(data, b"salt", 4_096, &mut k3).unwrap();
    // scrypt
    let params = scrypt::Params::new(15, 8, 1).unwrap();
    let mut k4 = [0u8; 64];
    scrypt::scrypt(data, b"salt", &params, &mut k4).unwrap();
    let mut k5 = [0u8; 32];
    scrypt::scrypt(data, b"salt", &scrypt::Params::RECOMMENDED, &mut k5).unwrap();
    println!(
        "{} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {}",
        d1.len(), d2.len(), d3.len(), d4.len(), d5.len(), d6.len(), d7.len(), tag.len(), ok,
        t2.len(), t3.len(), okm.len(), k1.len(), k2.len(), k3.len(), k4.len(), k5.len()
    );
}
