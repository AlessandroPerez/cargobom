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
| analysis-01 | RustCrypto: HKDF output, `anyhow` context, `copy_from_slice`, XChaCha, SHA-512/t, PBKDF2 with run-time iterations, Argon2 constructors, scrypt and argon2 roles, Ed25519 sign/verify, AES-GCM with a 16-byte nonce |
| analysis-02 | ring: HKDF and PBKDF2 key derivation, descriptor linking through receivers only, RSA 3072, Ed25519 key pairs, SHA-512/256 |
| analysis-03 | rustls with both backends, the provider the program installs, groups set in code, a `#[path]`-shared file |
| analysis-04 | Layer 1: renamed, dotted, header and target-specific dependencies, a member crate, build and dev declarations |
| analysis-05 | an aliased const descriptor, `format!`, `push_str`, two PBKDF2 iteration counts |
| analysis-06 | HMAC algorithm and JWT HMAC key material side by side |
| analysis-07 | base64-decoded environment keys, a seeded RNG |
| analysis-08 | aws-lc-rs CMAC, AES key wrap and block-cipher keys |
| verify-01 | the same call text at the same column on neighbouring lines, on receivers of different types; a line holding backquotes |
