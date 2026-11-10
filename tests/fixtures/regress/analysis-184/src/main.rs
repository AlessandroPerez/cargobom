// ml-kem 0.3 over kem 0.3: the parameter set is a type of its own (`MlKem768`, 0.2's
// `MlKem768Params`), keys are made by `Kem::generate_keypair_from_rng` on it, and the
// encapsulation and decapsulation keys are `EncapsulationKey<MlKem768>` and
// `DecapsulationKey<MlKem768>` as before.
use ml_kem::kem::{Decapsulate, Encapsulate, Kem};
use ml_kem::{MlKem1024, MlKem768};

fn main() {
    let mut rng = rand::rng();
    let (dk, ek) = MlKem768::generate_keypair_from_rng(&mut rng);
    let (ct, k1) = ek.encapsulate_with_rng(&mut rng);
    let k2 = dk.decapsulate(&ct);
    let (dk2, ek2) = MlKem1024::generate_keypair_from_rng(&mut rng);
    let (ct2, _) = ek2.encapsulate_with_rng(&mut rng);
    let k3 = dk2.decapsulate(&ct2);
    println!("{} {}", k1 == k2, k3.len());
}
