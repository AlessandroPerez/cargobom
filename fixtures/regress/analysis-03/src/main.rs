use rustls::crypto::CryptoProvider;

fn main() {
    let p = CryptoProvider {
        kx_groups: vec![rustls::crypto::aws_lc_rs::kx_group::MLKEM1024],
        ..rustls::crypto::aws_lc_rs::default_provider()
    };
    let _ = p.install_default();
    let _ = rustls::ClientConfig::builder();
}

#[allow(dead_code)]
fn unused() -> CryptoProvider {
    rustls::crypto::ring::default_provider()
}
