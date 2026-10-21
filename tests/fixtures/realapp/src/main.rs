fn main() {
    // Touch each library so the crates are linked; the CBOM covers what they instantiate.
    let id = age::x25519::Identity::generate();
    println!("{}", id.to_public());
    let tok = jsonwebtoken::encode(&jsonwebtoken::Header::default(), &serde_json::json!({"sub":"x"}),
        &jsonwebtoken::EncodingKey::from_secret(b"secret")).unwrap();
    println!("{tok}");
    let provider = rustls::crypto::ring::default_provider();
    println!("{} suites", provider.cipher_suites.len());
}
