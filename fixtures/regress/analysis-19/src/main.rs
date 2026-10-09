// Features enabled only by a dev-dependency (third audit round): rustls's `ring` feature is on in
// `cargo test` builds only; the program's build has aws-lc-rs alone.
use std::sync::Arc;

fn main() {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let roots = rustls::RootCertStore::empty();
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    println!("{}", cfg.alpn_protocols.len());
}
