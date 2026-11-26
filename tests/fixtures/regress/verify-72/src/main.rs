use lupine_cert::generate::{CertAlgorithm, CertBuilder};

fn main() {
    let algo = match std::env::args().count() {
        1 => CertAlgorithm::HybridEd25519MlDsa44,
        2 => CertAlgorithm::MlDsa65,
        _ => CertAlgorithm::HybridEd25519MlDsa87,
    };
    let cert = CertBuilder::new().self_signed(algo).expect("a certificate");
    println!("{}", cert.pem.len());
}
