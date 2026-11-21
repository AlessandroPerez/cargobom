// X-Wing, a hybrid KEM: ML-KEM-768 with X25519, their shared secrets combined by SHA3-256.
// The registry has no name for it; its parts are components where it is used. Keys are made
// on the scheme (`XWingKem`, kem's `Kem`) or by `Generate` on the decapsulation key.
use x_wing::kem::{Decapsulate, Decapsulator, Encapsulate, Generate, Kem};
use x_wing::{DecapsulationKey, XWingKem};

fn main() {
    let (dk, ek) = XWingKem::generate_keypair();
    let (ct, k1) = ek.encapsulate();
    let k2 = dk.decapsulate(&ct);

    let dk2 = DecapsulationKey::generate();
    let ek2 = dk2.encapsulation_key();
    let (ct2, k3) = ek2.encapsulate_deterministic(&[9u8; 64].into());
    let k4 = dk2.decapsulate(&ct2);
    println!("{} {}", k1 == k2, k3 == k4);
}
