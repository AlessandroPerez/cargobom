# Label review sheet

For each row: does the line use that asset, with that use and those parameters? Mark ✔ or write the correction. `core` must be found by a tool; `extended` is credited if found. Negative lines must stay empty.

## cbom-real-crates-app

Source: https://github.com/cdxgen/cdxgen-plugins-bin/tree/6a646353e4fbd9d64fa115176241d7a233e19630/thirdparty/rusi/fixtures/cbom-real-crates-app  
Status: draft: annotator 1

| line | code | asset | tier | use | parameters | provenance | why | review |
|---|---|---|---|---|---|---|---|---|
| 1 | `use aes_gcm::{aead::KeyInit, Aes256Gcm};` | — none — | negative |  |  |  | imports only | |
| 2 | `use argon2::{password_hash::{PasswordHasher, SaltString}, Argon2};` | — none — | negative |  |  |  | imports only | |
| 3 | `use hmac::Hmac;` | — none — | negative |  |  |  | imports only | |
| 4 | `use jsonwebtoken::EncodingKey;` | — none — | negative |  |  |  | imports only | |
| 5 | `use pbkdf2::pbkdf2_hmac;` | — none — | negative |  |  |  | imports only | |
| 6 | `use rustls::ClientConfig;` | — none — | negative |  |  |  | imports only | |
| 8 | `use sha2::{Digest, Sha256};` | — none — | negative |  |  |  | imports only | |
| 16 | `let app_secret = std::env::var("APP_SECRET")` | — none — | negative |  |  |  | a secret read from the environment with a literal fallback: key material provenance, not an algorithm | |
| 17 | `.unwrap_or_else(\|_\| "01234567012345670123456701234567".to_string());` | — none — | negative |  |  |  | a secret read from the environment with a literal fallback: key material provenance, not an algorithm | |
| 18 | `let api_token = app_secret.clone();` | — none — | negative |  |  |  | a secret read from the environment with a literal fallback: key material provenance, not an algorithm | |
| 23 | `let _ = Sha256::digest(app_secret.as_bytes());` | SHA-256 | core | digest |  |  | Sha256::digest (sha2 0.10.9); also the hash inside Hmac<Sha256> (27) and the PRF hash of pbkdf2_hmac::<Sha256> (33) | |
| 24 | `let _ = md5::compute(app_secret.as_bytes());` | MD5 | core | digest |  |  | md5::compute (md5 0.7.0) | |
| 25 | `let _ = blake3::hash(app_secret.as_bytes());` | BLAKE3-256 | core | digest |  |  | blake3::hash (blake3 1.8.5), default 32-byte output | |
| 26 | `let _ = Aes256Gcm::new_from_slice(&app_secret.as_bytes()[..32]);` | AES-256-GCM | core | set up only | nonce_bytes=12, tag_bytes=16 | key: environment or hard-coded | Aes256Gcm::new_from_slice (aes-gcm 0.10.3): a cipher is keyed, never used to encrypt | |
| 27 | `let _ = Hmac::<Sha256>::new_from_slice(app_secret.as_bytes());` | HMAC-SHA-256 | core | set up only |  | key: environment or hard-coded | Hmac::<Sha256>::new_from_slice (hmac 0.12.1): keyed, never updated or finalized | |
| 27 | `let _ = Hmac::<Sha256>::new_from_slice(app_secret.as_bytes());` | SHA-256 | core (component) |  |  |  | Sha256::digest (sha2 0.10.9); also the hash inside Hmac<Sha256> (27) and the PRF hash of pbkdf2_hmac::<Sha256> (33) | |
| 29 | `let app_key = EncodingKey::from_secret(app_secret.as_bytes());` | HMAC secret key (jsonwebtoken) | extended | set up only |  | key: environment or hard-coded | EncodingKey::from_secret (jsonwebtoken 9.3.1) wraps an HMAC secret; HS256/384/512 is chosen only by a Header at encode time, and nothing is encoded. Key material with an undetermined algorithm | |
| 33 | `pbkdf2_hmac::<Sha256>(app_secret.as_bytes(), b"saltysalt", 1_000, &mut nonce_seed);` | PBKDF2-SHA-256-1000-32 | core | keyderive | iterations=1000, dk_len=32, salt=hard-coded b"saltysalt" (9 bytes) | password: environment or hard-coded; salt: hard-coded | pbkdf2_hmac::<Sha256>(pw, b"saltysalt", 1_000, &mut [0u8; 32]) (pbkdf2 0.12.2); 1,000 iterations and a literal salt | |
| 33 | `pbkdf2_hmac::<Sha256>(app_secret.as_bytes(), b"saltysalt", 1_000, &mut nonce_seed);` | SHA-256 | core (component) |  |  |  | Sha256::digest (sha2 0.10.9); also the hash inside Hmac<Sha256> (27) and the PRF hash of pbkdf2_hmac::<Sha256> (33) | |
| 36 | `let _ = Argon2::default().hash_password(app_secret.as_bytes(), &app_salt);` | Argon2id-19456-2-1 | core | keyderive | memory_kib=19456, passes=2, parallelism=1, output_bytes=32, salt=hard-coded b"fixed-salt-value" (16 bytes), line 35 | password: environment or hard-coded; salt: hard-coded | Argon2::default().hash_password (argon2 0.5.3): Algorithm::default() is Argon2id, Params::default() m=19*1024, t=2, p=1, 32-byte output (params.rs:42-76) | |
| 38 | `let _ = ClientConfig::builder();` | TLS (rustls 0.23.40, aws-lc-rs default provider) | core | set up only |  |  | ClientConfig::builder() installs CryptoProvider::get_default_or_install_from_crate_features(); rustls default features are aws_lc_rs, prefer-post-quantum, tls12. No connection is made: capability, not traffic | |

Capability via line 38 (reachable): AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305, SHA-256, SHA-384, HMAC-SHA-256, HMAC-SHA-384, HKDF-SHA-256, HKDF-SHA-384, x25519, ECDH-P-256, ECDH-P-384, ML-KEM-768, ECDSA-P-256-SHA-256, ECDSA-P-256-SHA-384, ECDSA-P-256-SHA-512, ECDSA-P-384-SHA-256, ECDSA-P-384-SHA-384, ECDSA-P-384-SHA-512, ECDSA-P-521-SHA-256, ECDSA-P-521-SHA-384, ECDSA-P-521-SHA-512, Ed25519, RSA-PKCS1-1.5-SHA-256, RSA-PKCS1-1.5-SHA-384, RSA-PKCS1-1.5-SHA-512, RSA-PSS-SHA-256, RSA-PSS-SHA-384, RSA-PSS-SHA-512

- cipher suites: TLS13_AES_256_GCM_SHA384, TLS13_AES_128_GCM_SHA256, TLS13_CHACHA20_POLY1305_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
- key exchange groups: X25519MLKEM768 (hybrid: x25519 + ML-KEM-768, preferred), x25519, ECDH-P-256, ECDH-P-384

Capability via line 29 (present only): jsonwebtoken-9.3.1/src/crypto/{mod,rsa,ecdsa,eddsa}.rs: HMAC-SHA-256, HMAC-SHA-384, HMAC-SHA-512, RSA-PKCS1-1.5-SHA-256, RSA-PKCS1-1.5-SHA-384, RSA-PKCS1-1.5-SHA-512, RSA-PSS-SHA-256, RSA-PSS-SHA-384, RSA-PSS-SHA-512, ECDSA-P-256-SHA-256, ECDSA-P-384-SHA-384, Ed25519, SHA-256, SHA-384, SHA-512

Capability via line 38 (reachable): rustls-0.23.40/src/crypto/aws_lc_rs/tls13.rs (quic KeyBuilder header_alg): AES-128, AES-256, ChaCha20

Capability via line 38 (present only): rustls-0.23.40/src/crypto/aws_lc_rs/mod.rs:258 (ALL_KX_GROUPS), pq/mod.rs: ML-KEM-768, ML-KEM-1024, ECDH-P-256

Crates: aes-gcm (used), argon2 (used), blake3 (used), hmac (used), jsonwebtoken (used), md5 (used), pbkdf2 (used), rustls (used), sha2 (used), aws-lc-sys (used)

## cbom-real-asymmetric-app

Source: https://github.com/cdxgen/cdxgen-plugins-bin/tree/6a646353e4fbd9d64fa115176241d7a233e19630/thirdparty/rusi/fixtures/cbom-real-asymmetric-app  
Status: draft: annotator 1

| line | code | asset | tier | use | parameters | provenance | why | review |
|---|---|---|---|---|---|---|---|---|
| 1 | `use ed25519_dalek::SigningKey;` | — none — | negative |  |  |  | imports only | |
| 2 | `use rand::thread_rng;` | — none — | negative |  |  |  | imports only | |
| 3 | `use ring::aead::{AES_256_GCM, UnboundKey};` | — none — | negative |  |  |  | imports only | |
| 4 | `use ring::digest::{digest, SHA256};` | — none — | negative |  |  |  | imports only | |
| 5 | `use rsa::RsaPrivateKey;` | — none — | negative |  |  |  | imports only | |
| 8 | `let signing_secret = std::env::var("SIGNING_SECRET")` | — none — | negative |  |  |  | a secret read from the environment with a literal fallback: key material provenance, not an algorithm | |
| 9 | `.unwrap_or_else(\|_\| "01234567012345670123456701234567".to_string());` | — none — | negative |  |  |  | a secret read from the environment with a literal fallback: key material provenance, not an algorithm | |
| 11 | `let _ = digest(&SHA256, signing_secret.as_bytes());` | SHA-256 | core | digest |  |  | ring::digest::digest(&SHA256, ..) (ring 0.17.14) | |
| 12 | `let _ = UnboundKey::new(&AES_256_GCM, &signing_secret.as_bytes()[..32]);` | AES-256-GCM | core | set up only |  | key: environment or hard-coded | ring UnboundKey::new(&AES_256_GCM, ..): a key is built, never used to seal or open | |
| 14 | `let mut rng = thread_rng();` | CSPRNG (rand ThreadRng: ChaCha12, reseeded from the OS) | extended | generate |  |  | rand 0.8.6 thread_rng(): ReseedingRng over ChaCha12Core (rngs/std.rs:13); the randomness for the RSA key generation at line 15 | |
| 15 | `let _ = RsaPrivateKey::new(&mut rng, 2048).unwrap();` | RSA private key (2048 bits) | core | keygen | type=private-key, size=2048, public_exponent=65537 | rng: rng | RsaPrivateKey::new(&mut rng, 2048) (rsa 0.9.10, e = 65537, key.rs:214-219). No scheme (PKCS#1, PSS, OAEP) is chosen, so the registry has no algorithm name for it: it is key material | |
| 16 | `let _ = SigningKey::from_bytes(&[42u8; 32]);` | Ed25519 private key | core | set up only | type=private-key, size=256, provenance=hard-coded [42u8; 32] | key: hard-coded | SigningKey::from_bytes(&[42u8; 32]) (ed25519-dalek 2.2.0): a signing key from a literal, never used to sign | |
| 16 | `let _ = SigningKey::from_bytes(&[42u8; 32]);` | SHA-512 | extended (component) |  |  |  | Ed25519 key expansion hashes the secret with SHA-512 (by definition of Ed25519) | |

Crates: ring (used), rsa (used), ed25519-dalek (used), rand (used)

## cbom-real-modern-app

Source: https://github.com/cdxgen/cdxgen-plugins-bin/tree/6a646353e4fbd9d64fa115176241d7a233e19630/thirdparty/rusi/fixtures/cbom-real-modern-app  
Status: draft: annotator 1

| line | code | asset | tier | use | parameters | provenance | why | review |
|---|---|---|---|---|---|---|---|---|
| 1 | `use chacha20poly1305::{aead::KeyInit, ChaCha20Poly1305};` | — none — | negative |  |  |  | imports only | |
| 2 | `use ring::digest;` | — none — | negative |  |  |  | imports only | |
| 3 | `use sha1::{Digest, Sha1};` | — none — | negative |  |  |  | imports only | |
| 6 | `let shared_secret = std::env::var("SHARED_SECRET")` | — none — | negative |  |  |  | a secret read from the environment with a literal fallback: key material provenance, not an algorithm | |
| 7 | `.unwrap_or_else(\|_\| "01234567012345670123456701234567".to_string());` | — none — | negative |  |  |  | a secret read from the environment with a literal fallback: key material provenance, not an algorithm | |
| 8 | `let _ = Sha1::digest(shared_secret.as_bytes());` | SHA-1 | core | digest |  |  | Sha1::digest (sha1 0.10.6) | |
| 9 | `let _ = ChaCha20Poly1305::new_from_slice(&shared_secret.as_bytes()[..32]);` | ChaCha20-Poly1305 | core | set up only | nonce_bytes=12 | key: environment or hard-coded | ChaCha20Poly1305::new_from_slice (chacha20poly1305 0.10.1): keyed, never used to encrypt | |
| 10 | `let _ = digest::SHA256_OUTPUT_LEN;` | — none — (not SHA-256) | negative |  |  |  | ring::digest::SHA256_OUTPUT_LEN is `pub const usize = 32` (digest.rs:545); nothing is hashed. A SHA-256 finding here is a false positive | |

Crates: chacha20poly1305 (used), sha1 (used), ring (no-crypto-use)

