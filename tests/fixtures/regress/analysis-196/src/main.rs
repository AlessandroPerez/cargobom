// PQClean's ML-KEM behind pqcrypto-mlkem: free functions in a module per parameter set
// (`mlkem768::keypair()`), with the set's own key types; their bytes go through the traits of
// pqcrypto-traits (a key's are setup, a ciphertext's and a shared secret's an encoding).
use pqcrypto_mlkem::{mlkem1024, mlkem768};
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SharedSecret as _};

fn main() {
    let (pk, sk) = mlkem768::keypair();
    let (k1, ct) = mlkem768::encapsulate(&pk);
    let k2 = mlkem768::decapsulate(&ct, &sk);

    let (pk2, _) = mlkem1024::keypair();
    let stored = mlkem1024::PublicKey::from_bytes(pk2.as_bytes()).unwrap();
    let (k3, ct2) = mlkem1024::encapsulate(&stored);
    println!("{} {} {}", k1.as_bytes() == k2.as_bytes(), k3.as_bytes().len(), ct2.as_bytes().len());
}
