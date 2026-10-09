# Regression fixtures

Small programs written by four rounds of independent audits of the pipeline (driver,
analysis, verification, a held-out review of crates.io projects) and after the corpus runs,
each with commented cases that once produced a wrong
CBOM or none: a lost call site, a wrong position, a wrong argument origin, a misnamed algorithm,
a false finding, a driver panic, a shifted position the verifier accepted. Each directory's
`expected.txt` is the reviewed CBOM (as `scripts/summary.py` prints it); `scripts/e2e.sh --regress`
regenerates every CBOM, verifies all positions with the shifted-position self-test, and fails on
any difference.

| fixture | covers |
|---|---|
| driver-01 | callee held in a local, a KB fn as a value and as a fn pointer, consts and assoc consts naming statics, promoted tables, a BOM file, a CRLF file |
| driver-02 | argument origins: closure captures, closure parameters, `async` saved locals, struct fields, out-parameters through slices, later mutation, writes through references, parameters reassigned, many alternatives, unit-struct RNGs |
| driver-03 | `From`/`TryFrom` constructors of KB types, a key size from a local, `OsRng` by value |
| driver-04 | `#[used]` constructors, trait upcasting, field drop glue, a closure called back by a stop crate (ring), `Display` through `format_args` |
| driver-05 | a library: public statics and trait impls as roots |
| driver-06 | derive and attribute macros, nested `macro_rules!`, a path-qualified macro |
| driver-07 | `thread_local!`, inline `const { .. }`, `LazyLock` |
| driver-08 | aws-lc-rs consts behind promoted references, a generic fn's const |
| driver-09 | dead assoc and inline consts, `include!`, a callee in a local inside `async` |
| driver-10 | a crypto value in a third-party container (no instantiation evidence) |
| driver-11 | a static built by a `const fn` |
| driver-12 | a dependency's trivial const (an enum discriminant: no MIR is stored for it), standard generic functions whose stored MIR inlines callees with inline consts |
| driver-13 | argument origins: element writes and clamping, an element written through a reference, element-wise copies, a field written after the whole struct, a fill through one of two references, a reborrowed out-parameter; integer arguments from named and associated consts; Argon2's variant as an enum value and a named const |
| driver-14 | associated consts of a trait impl, consts a `const fn` computes and an inline const calling it, an aws-lc-rs const in a generic instance, function items called from a capture, a struct field, a tuple, and through a local pointer |
| driver-15 | statics pointing at each other, a dependency's const naming a ring static, code a build script generates into `OUT_DIR` (closure names without paths), a closure reached through standard-library iterators (calls without a position) |
| driver-16 | argument origins (third audit round): a key read with `read_exact` (`alloc::io` on the pinned nightly), filled across an `.await` and inside a capturing closure, one field of a struct literal filled, a fill through `chunks_mut` and through a lock guard, `mem::replace` with a constant, array destructuring, a half overwrite, the output slice that reaches PBKDF2, the program's own `fill`; an `async` closure in a function; a knowledge-base function in an `Option` and in a static function pointer; a `LazyLock` key; a loop walking a linked list (the search used to overflow the stack) |
| driver-17 | a library's roots: a generic public function's private, non-generic callee, a public `async fn`'s body, a returned closure |
| driver-18 | values followed (fourth audit round): an enum's variant read only from that variant; statics written at run time (a lock's guard, a `static mut`, `OnceLock::set`, `LazyLock`) with their initial values; a trait's associated const in generic code and in a closure capturing it (never the trait's default); an enum-typed parameter; a local closure's parameter; a branch on a named `const`; an algorithm only an unreachable caller passes; a program static naming a composite descriptor (`&hmac::HMAC_SHA256`) |
| driver-19 | argument origins and roles (fourth audit round): secrets appended to (`extend_from_slice`, `push_str`); a loop counter and an atomic counter nonce; a key in a `Cell`, filled by a closure holding `&mut`, or through a struct's `&mut`; an `async` local overwritten after an `.await`; a nonce filled in a `split_at_mut` buffer; zeros of `vec![0; n]`; part of a literal; a generator lent to calls (`RsaPrivateKey::new(&mut rng, ..)` twice); rsa's `SigningKey::random`; Ed25519ph; Argon2's `From<Params>`, `Algorithm::default()` and `Params::default()`; scrypt's `hash_password_customized`; `hash_password_into_with_memory`'s salt; BLAKE3's `update_reader`; `from_keypair_bytes`; the program's own `RngCore` |
| driver-20 | a library's API (fourth audit round): the methods of a public type generic over a parameter the crypto does not depend on; a trait's default method a public type takes; a long name keeping its method |
| driver-21 | a procedural derive spanning its generated code at an input token (`quote_spanned!`): cited at the derive; an `async` closure passed to a generic function (an interface limit, not counted as an error) |
| analysis-01 | RustCrypto: HKDF output, `anyhow` context, `copy_from_slice`, XChaCha, SHA-512/t, PBKDF2 with run-time iterations, Argon2 constructors, scrypt and argon2 roles, Ed25519 sign/verify, AES-GCM with a 16-byte nonce |
| analysis-02 | ring: HKDF and PBKDF2 key derivation, descriptor linking through receivers only, RSA 3072, Ed25519 key pairs, SHA-512/256 |
| analysis-03 | rustls with both backends, the provider the program installs, groups set in code, a `#[path]`-shared file |
| analysis-04 | Layer 1: renamed, dotted, header and target-specific dependencies, a member crate, build and dev declarations |
| analysis-05 | an aliased const descriptor, `format!`, `push_str`, two PBKDF2 iteration counts |
| analysis-06 | HMAC algorithm and JWT HMAC key material side by side |
| analysis-07 | base64-decoded environment keys, a seeded RNG |
| analysis-08 | aws-lc-rs CMAC, AES key wrap and block-cipher keys |
| analysis-09 | knowledge base (RustCrypto): cbc and ctr over Blowfish (no AES asset), encrypt-only and decrypt-only AES types, rsa padding values and signature traits, OAEP with a separate MGF1 hash, rsa key types and a constant PSS salt length, pbkdf2's generic PRF API, md5's streaming context, password-hash defaults, scrypt `Params` built apart from the call, x25519-dalek's free function |
| analysis-10 | knowledge base (aws-lc-rs): keys from literal bytes, a pseudorandom key used as is, the TLS 1.2 PRF (registry family TLS-PRF, outside the 1.7 enum), ML-KEM, key agreement, key wrapping with and without padding, SHA-3, DES and 3DES, what a signing or verification descriptor can do |
| analysis-11 | provenance of computations (a key concatenated from a parameter and a constant, a nonce from a constant plus a sequence number, a seeded generator), an AEAD key derived with HKDF and sealed, a plain BLAKE3 hasher fed a derived key, a keyed hasher passed through the program's own helper, OAEP padding in a variable, AES through cbc and ctr, PBKDF2 with run-time iterations, scrypt `Params` through `.ok()?` with an output longer than its length, and built in a helper function (minisign) |
| analysis-12 | Layer 1: a workspace member named like a knowledge-base crate (`signature`), rustls with default features (ring only named by a weak feature), a dependency table for another platform, code compiled only with debug assertions |
| analysis-13 | a descriptor that permits one operation, used only where a call performs it: ring's verification `ED25519` kept as a tag of a signing scheme (rcgen), a signing descriptor with its signing call, a verification descriptor in a table nothing verifies with |
| analysis-14 | ring, algorithms that reach a call from other functions: a key pair built by a helper (`?`, `map_err`) and kept in a field, an HMAC key in a field, wrapper structs around an AEAD algorithm built in statics (a field of a field read through the outer struct; a method called by two wrappers only), a key behind a `Box` used by a `self: Box<Self>` method, a digest algorithm passed as a parameter, a key returned through `?` and `Ok(..)` |
| analysis-15 | RustCrypto (third audit round): Argon2's `verify_password` and `hash_password_customized` with their own parameters, `new_with_secret`'s variant, BLAKE3's key-derivation mode, HMAC keyed by a label, CBC buffer-to-buffer and CTR's fallible keystream, generators from `ThreadRng::default()`, RSA key generation (`new_with_exp`, a signing key's `random`), a seeded generator, the program's own `Default`, keys in `LazyLock` and `OnceLock` statics, a counter nonce, AES and ChaCha20 used directly, Ed25519's hazmat API and its internal SHA-512, `finalize_into`, CBC with PKCS#7 |
| analysis-16 | ring (third audit round): `open_in_place_separate_tag`, a random nonce, a verification descriptor never used to verify, PBKDF2 derive and verify, a SHA-1 context, HKDF output made an AES key (`UnboundKey::from`), key agreement and signing, descriptor uses decided by the calls made with them |
| analysis-17 | aws-lc-rs (third audit round): the AEAD scatter/gather methods and their nonces, a cipher IV given to `less_safe_encrypt`, HMAC and PBKDF2, ML-KEM-1024, an Ed25519 key pair from a hard-coded seed, verification algorithms in a wrapper struct built in statics (aws-lc-rs's Ed25519 descriptor is a named const of a field-less struct) |
| analysis-18 | a program that draws no random number (rand_core and getrandom unused); a digest in `debug_assert!` and one under `cfg(debug_assertions)`, absent from the release build |
| analysis-19 | Layer 1: rustls's `ring` feature enabled by a dev-dependency only (no ring package, aws-lc-rs the only backend) |
| analysis-20 | an algorithm that reaches a reachable call from other functions only through data no entry point reaches (a suite listed by `ALL` but not by `DEFAULT`, as rustls's ML-KEM-1024): present at that call, not reachable |
| analysis-21 | a key pair and a digest algorithm kept in enum variants and read by matching (rcgen's `KeyPairKind`), the key built through the program's generic extension trait (`.ext()?`, rcgen's `_err`), and an algorithm passed in `Some(..)`; ring's RSA key pair from PKCS#8, private key material with a hard-coded key |
| analysis-22 | aws-lc-rs (fourth audit round): `verify_sig`, the current verification API, on a descriptor and a parsed key; a digest context's `finish`; aws-lc-rs's own alias of a composite descriptor (`unstable::signature::MLDSA_44_SIGNING`) |
| analysis-23 | jsonwebtoken 9 (fourth audit round): a signing key decoded from PEM, private key material of its family with a hard-coded key; HMAC secrets hard-coded and from the environment |
| verify-01 | the same call text at the same column on neighbouring lines, on receivers of different types; a line holding backquotes |
| verify-02 | the verifier: two versions of one crate (one renamed), one alias imported from two crates (two modules; cfg), an alias defined in another file, a raw identifier, a path after a single `:`, tag-like text in a comment, a path broken by a comment, a path from the root, a quoted key and a dev-dependency of the same crate, a CRLF `Cargo.lock` |
