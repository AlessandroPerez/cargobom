# Regression fixtures

Small programs written by three independent audits of the pipeline (driver, analysis,
verification) and after the corpus runs, each with commented cases that once produced a wrong
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
| verify-01 | the same call text at the same column on neighbouring lines, on receivers of different types; a line holding backquotes |
| verify-02 | the verifier: two versions of one crate (one renamed), one alias imported from two crates (two modules; cfg), an alias defined in another file, a raw identifier, a path after a single `:`, tag-like text in a comment, a path broken by a comment, a path from the root, a quoted key and a dev-dependency of the same crate, a CRLF `Cargo.lock` |
