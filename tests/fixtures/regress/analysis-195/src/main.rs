// The fips203, fips204 and fips205 crates name a parameter set by its module: keys are made
// on the module's `KG` or by its `try_keygen`. fips203's and fips204's key types are shared
// ones whose sizes say the set (`EncapsKey<1184>` is ML-KEM-768's, `PrivateKey<8, 7>`
// ML-DSA-87's); every fips205 module has its own. The pre-hash signatures are HashML-DSA and
// HashSLH-DSA; a ciphertext's bytes are an encoding, a key's are setup.
use fips203::traits::{Decaps, Encaps, KeyGen as _, SerDes as _};
use fips204::traits::{KeyGen as _, SerDes as _, Signer as _, Verifier as _};
use fips205::traits::{KeyGen as _, Signer as _, Verifier as _};

fn kem() -> bool {
    let (ek, dk) = fips203::ml_kem_768::KG::try_keygen().unwrap();
    let (k1, ct) = ek.try_encaps().unwrap();
    let k2 = dk.try_decaps(&ct).unwrap();
    let (ek2, _dk2) = fips203::ml_kem_1024::KG::keygen_from_seed([1u8; 32], [2u8; 32]);
    let sent = ct.into_bytes();
    let public = ek2.into_bytes();
    k1 == k2 && sent.len() < public.len()
}

fn lattice(msg: &[u8]) -> bool {
    let (pk, sk) = fips204::ml_dsa_65::try_keygen().unwrap();
    let sig = sk.try_sign(msg, b"").unwrap();
    let (pk2, sk2) = fips204::ml_dsa_87::KG::keygen_from_seed(&[3u8; 32]);
    let pre = sk2.try_hash_sign(msg, b"", &fips204::Ph::SHA512).unwrap();
    let stored = fips204::ml_dsa_87::PublicKey::try_from_bytes(pk2.clone().into_bytes()).unwrap();
    pk.verify(msg, &sig, b"") && stored.hash_verify(msg, &pre, b"", &fips204::Ph::SHA512)
}

fn hashes(msg: &[u8]) -> bool {
    let (pk, sk) = fips205::slh_dsa_shake_128f::try_keygen().unwrap();
    let sig = sk.try_sign(msg, b"", true).unwrap();
    let (pk2, sk2) = fips205::slh_dsa_sha2_192s::KG::try_keygen().unwrap();
    let pre = sk2.try_hash_sign(msg, b"", &fips205::Ph::SHA256, true).unwrap();
    pk.verify(msg, &sig, b"") && pk2.hash_verify(msg, &pre, b"", &fips205::Ph::SHA256)
}

fn main() {
    let msg = b"post-quantum";
    println!("{} {} {}", kem(), lattice(msg), hashes(msg));
}
