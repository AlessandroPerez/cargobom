## Label rules

Label each program from its source code (`src/main.rs` plus key files in `src/`) and from the
documentation and source of the libraries it uses. Crate versions: ring 0.17.14, aes-gcm 0.10.3,
chacha20poly1305 0.10.1, sha2 0.10.9, hkdf 0.12.4, pbkdf2 0.12.2, ed25519-dalek 2.2.0,
rsa 0.9.10, jsonwebtoken 9.3.1 (crypto backend ring 0.17.14). Write one TOML file per program:

```toml
[[site]]
file = "src/main.rs"
line = 14                          # line holding the callee name
callee = "seal_in_place_append_tag"  # method/function name as written, last path segment, no turbofish
function = "encrypt"               # encrypt|decrypt|sign|verify|digest|tag|keyderive|keygen
must = ["ChaCha20-Poly1305"]       # sorted
may = ["AES-256-GCM"]              # sorted, may be empty
params = { iterations = "600000", length = "32" }   # optional, see R5
note = "one line on why"
```

### R1. Which calls are sites

A site is a call expression written in `src/main.rs` whose documented purpose is to perform one
of the operations below. Exactly one `[[site]]` per call expression.

| function | calls that are sites |
|---|---|
| encrypt / decrypt | AEAD encryption / decryption: `Aead::encrypt` / `decrypt`; ring `LessSafeKey::seal_in_place_append_tag` / `open_in_place` (and other `seal_*` / `open_*`) |
| sign | producing a signature: ed25519-dalek `Signer::sign`; ring `EcdsaKeyPair::sign`, `Ed25519KeyPair::sign`, `RsaKeyPair::sign`; rsa `RsaPrivateKey::sign`; `jsonwebtoken::encode` with a signature algorithm (RS\*, PS\*, ES\*, EdDSA) |
| tag | producing a MAC: `jsonwebtoken::encode` with HS256/HS384/HS512 (also HMAC `finalize`, ring `hmac::sign`) |
| verify | checking a signature or a MAC: ed25519-dalek `Verifier::verify`; ring `UnparsedPublicKey::verify`; rsa `RsaPublicKey::verify`; `jsonwebtoken::decode` for every algorithm, HS\* included |
| digest | hashing: one-shot `Digest::digest`, `finalize` |
| keyderive | PBKDF2 (`pbkdf2::pbkdf2_hmac`, ring `pbkdf2::derive`); HKDF-Extract (hkdf `Hkdf::new`, whose docs define it as the extract step, `Hkdf::extract`, ring `hkdf::Salt::extract`); HKDF-Expand (hkdf `Hkdf::expand`, ring `Okm::fill`, see R1.3) |
| keygen | generating a new key from randomness: ed25519-dalek `SigningKey::generate`; ring `EcdsaKeyPair::generate_pkcs8`, `Ed25519KeyPair::generate_pkcs8`; rsa `RsaPrivateKey::new` |

- **R1.1 Not sites.**
  - Constructors and parsers that build a key or context from bytes the program supplies, even
    when they precompute internally: `UnboundKey::new`, `LessSafeKey::new`, `KeyInit::new`,
    ring `hkdf::Salt::new`, `EcdsaKeyPair::from_pkcs8`, `Ed25519KeyPair::from_seed_unchecked`,
    `RsaKeyPair::from_pkcs8`, `RsaPrivateKey::from_pkcs8_pem`, `RsaPublicKey::from`,
    `UnparsedPublicKey::new`, `EncodingKey::from_*` and `DecodingKey::from_*`.
  - Parameter objects: `Header::new`, `Validation::new`, `Pkcs1v15Sign::new`, nonce
    constructors.
  - Getters: `verifying_key`, `public_key`, `public`, `key_len`.
  - Non-cryptographic parsing, such as `decode_header`.
  - Calls made inside libraries. Only calls written in `main.rs` are sites.
- **R1.2 Streaming APIs.** Only the call that produces the output (`finalize`, `sign`, `verify`)
  is a site. `new`, `init` and `update` are not.
- **R1.3 Lazy two-step calls.** ring `Prk::expand` only checks the length and returns an `Okm`.
  The HKDF-Expand computation happens in `Okm::fill`. Label one site at `fill`
  (`callee = "fill"`). `expand` is not a separate site.
- **R1.4 Composite calls are one site.** `jsonwebtoken::decode` (parse + verify) is one verify
  site. The HMAC calls inside PBKDF2 or HKDF are not separate sites.
- **R1.5 Dead sites.** A site in dead code (a branch whose condition is a compile-time constant
  that is false, `#[cfg]`-disabled code, a function never called from `main`) is still listed,
  with `must = []` and `may = []`.

### R2. Names

- **One name per algorithm.** Use the outermost scheme the call performs, not its internal
  components:
  - `PBKDF2-SHA-256`, not also `HMAC-SHA-256` or `SHA-256`;
  - `Ed25519`, not also `SHA-512`;
  - `RSA-PKCS1-1.5-SHA-384`, not also `SHA-384`. A separate hashing call written in `main.rs`
    is its own digest site.
- **Registry form.** Names instantiate the patterns in the CycloneDX Cryptography Registry
  (`schema/cryptography-defs.json`). Optional pattern parts are left out: no key length, tag
  length, IV length, iteration count, dkLen, MGF or salt length in the name.

| kind | names |
|---|---|
| AEAD | `AES-128-GCM`, `AES-256-GCM`, `ChaCha20-Poly1305`, `XChaCha20-Poly1305` |
| hash | `SHA-1`, `SHA-256`, `SHA-384`, `SHA-512` |
| MAC | `HMAC-SHA-256`, `HMAC-SHA-384`, `HMAC-SHA-512` |
| KDF | `PBKDF2-<hash>` where the hash is the one in the HMAC PRF, e.g. `PBKDF2-SHA-256` (iterations and length go in `params`); `HKDF-<hash>`, e.g. `HKDF-SHA-384` |
| signature | `Ed25519`; `ECDSA-P-256-SHA-256`, `ECDSA-P-384-SHA-384` (registry curve names `P-256` / `P-384`); `RSA-PKCS1-1.5-<hash>`; `RSA-PSS-<hash>` |

- **ring suffixes.** ring's `_ASN1` / `_FIXED` encodings and the `2048_8192` key-size range in
  its verification algorithm names are not part of the registry name.
- **keygen.** Name the algorithm object or type the key is generated for. For example,
  `EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, ..)` is `ECDSA-P-384-SHA-384`,
  and `SigningKey::generate` (ed25519-dalek) is `Ed25519`.
- **JWT** (jsonwebtoken `Algorithm` to registry name):

| JOSE alg | registry name |
|---|---|
| HS256 / HS384 / HS512 | `HMAC-SHA-256` / `HMAC-SHA-384` / `HMAC-SHA-512` |
| RS256 / RS384 / RS512 | `RSA-PKCS1-1.5-SHA-256` / `-SHA-384` / `-SHA-512` |
| PS256 / PS384 / PS512 | `RSA-PSS-SHA-256` / `-SHA-384` / `-SHA-512` |
| ES256 / ES384 | `ECDSA-P-256-SHA-256` / `ECDSA-P-384-SHA-384` |
| EdDSA | `Ed25519` |

### R3. must

`must` lists every algorithm the call actually uses on at least one real execution of the
program, for any command-line arguments and environment. `std::env::args().count()` can be any
value of 1 or more.

- **Fixed data.** Literal data (fixed keys, fixed map keys, data the program produces itself) is
  taken at its actual value. The program's deterministic behaviour decides: if a run-time
  computation always yields the same value, only that value counts.
- **jsonwebtoken::decode.** The algorithm used is the token header's `alg`. `decode` accepts it
  only if it is in `Validation.algorithms` and matches the key family.

### R4. may

`may` lists the algorithms that are not in `must` but that the reference analysis below reports
at the site. A tool that reports them is imprecise, not wrong. The reference analysis:

1. **Flow-insensitive** within a function. Every value ever assigned to a local, field or
   element counts, whatever the statement order and even if it is later overwritten.
2. **Field-based.** A struct field is one location shared by all objects of that struct type.
3. **Container-smashing.** All elements or values of one container (Vec, array, HashMap, ...)
   are one location. Reading any index or key yields all of them.
4. **Context-insensitive.** A function's parameter merges the arguments from all its reachable
   callers, and its return merges all returned values.
5. **Fallbacks count.** Both values of an `Option`/`Result` fallback (`unwrap_or`, `or`, ...)
   are included, even if the fallback is never taken.
6. **dyn dispatch.** A call on `dyn Trait` may reach the method of every type that is coerced to
   that `dyn Trait` somewhere in reachable code. Types never coerced to it (for example, never
   constructed) are excluded.
7. **Generics.** Only the generic instantiations reachable from `main` count.
8. **Run-time branches** (conditions on run-time data) are ignored: both arms count.
9. **Dead code is excluded.** This covers a branch whose condition is a compile-time constant
   (a `const` item or a literal) that is false, `#[cfg]`-disabled code, and functions never
   called from `main`.
10. **Library internals are not analysed.** Library calls are taken at their documented
    semantics. For example, `Header::new(alg)` sets `alg`, and `Validation::new(alg)` allows
    only `alg`. Values a library could produce by parsing input do not count.
11. **Aliasing** (added in round 15). A write through a pointer counts at every place the
    pointer may point to, flow-insensitively, as in 1. This covers `*r = v`, a field written
    through `&mut`, and a write by a function handed `&mut x`, a holder of one, or a closure
    capturing one. A pointer may point to any place whose `&mut` was taken where the pointer's
    value can come from: a re-pointed holder, a container, a call's result, another pointer.
12. **Interior mutability** (added in round 15). A value stored through a shared borrow of a
    cell counts at that cell, for every read of it, statics included. This covers `Cell::set`,
    `RefCell::borrow_mut`, a lock guard, `OnceLock::set` and an atomic store.
13. **jsonwebtoken refusal** (added in round 15). `decode` refuses the token when
    `Validation.algorithms` holds an algorithm of another family than the key's. By 1 and 3, a
    list is one location holding every value ever put in it, which cannot show that such a
    value is there on every way. So unless every value of the list is of another family, the
    key family's algorithms in the list are `may` (the `must` of R3 is unchanged: those on ways
    where the list holds none of another family).

Anything else in the source is **nothing**: a tool must not report it at the site. This covers,
in particular, constant-false branches and impls never coerced to `dyn`.

### R5. params

`params` is optional. Include a value only when a literal in `main.rs` fixes it at the site,
possibly through variables, fields, function arguments or returns. Values are strings.

| key | meaning |
|---|---|
| `iterations` | PBKDF2 rounds |
| `length` | bytes of derived output: the output buffer of PBKDF2 or HKDF-Expand |
| `key_bits` | literal RSA keygen size; never inferred from embedded key files |

- HKDF-Extract has no `length`.
- Not labelled: nonce and tag sizes, key sizes implied by the algorithm name, sizes of embedded
  keys.

### R6. note

One line explaining why.
## Extension rules (suite-ext)

These rules extend RULES.md (R1 to R6) to the categories of the extended suite. The
definitions of `must` (R3) and `may` (R4) do not change. Rules below only say which calls are
sites, how they are named, and where R3/R4 start from when a package has no single `main`.
Extra crate versions: sha3 0.10.9, md-5 0.10.6, hmac 0.12.1, argon2 0.5.3, scrypt 0.11.0,
bcrypt-pbkdf 0.10.0, aes 0.8.4, cbc 0.1.2, ctr 0.9.2, x25519-dalek 2.0.1, p256 0.13.2,
ml-kem 0.2.3, rand 0.8.8, rand_core 0.6.4, futures-executor 0.3.34.

### R7. Package sources

R1 says "written in `src/main.rs`". Read it as: written in any source file of the package's own
targets, that is `src/main.rs`, `src/bin/*.rs`, `src/lib.rs`, and the modules they include
(`mod`, `#[path]`). `file` is the path relative to the package root. Calls inside dependency
crates are still not sites (R1.1).

### R8. More site kinds

R1's table gets these rows. The `function` values `generate`, `encapsulate` and `decapsulate`
are the CycloneDX 1.7 `cryptoFunctions` values of the same name.

| function | calls that are sites |
|---|---|
| digest | ring `digest::digest`, `digest::Context::finish`; RustCrypto `Digest::digest` / `finalize` for every hash crate (sha2, sha3, md-5, ...) |
| tag | RustCrypto `Mac::finalize` (hmac); ring `hmac::sign` |
| verify | RustCrypto `Mac::verify_slice` / `verify`; ring `hmac::verify`; password-hash `PasswordVerifier::verify_password` |
| keyderive | password hashing: `PasswordHasher::hash_password`, `Argon2::hash_password_into`, `scrypt::scrypt`, `bcrypt_pbkdf::bcrypt_pbkdf`. Key agreement: x25519-dalek `EphemeralSecret::diffie_hellman` (also `StaticSecret`, `ReusableSecret`), ring `agreement::agree_ephemeral`, p256 `ecdh::EphemeralSecret::diffie_hellman` |
| encrypt / decrypt | unauthenticated block-cipher modes (cipher 0.4): `BlockEncryptMut::encrypt_padded*` / `encrypt_block*` (encrypt) and `BlockDecryptMut::decrypt_padded*` / `decrypt_block*` (decrypt); stream modes such as CTR: `StreamCipher::apply_keystream` / `try_apply_keystream` are `encrypt` (the same call also decrypts; label it `encrypt`) |
| keygen | x25519-dalek `EphemeralSecret::random` / `random_from_rng` (also `StaticSecret`, `ReusableSecret`); ring `agreement::EphemeralPrivateKey::generate`; p256 `ecdh::EphemeralSecret::random`; ml-kem `KemCore::generate` |
| encapsulate / decapsulate | ml-kem `Encapsulate::encapsulate` / `Decapsulate::decapsulate` |
| generate | RNG draws, see R9 |

- **R8.1 Key agreement is `keyderive`.** CycloneDX has no key-agreement function. Computing
  the shared secret is a key derivation.
- **R8.2 Not sites** (like R1.1 and R1.2):
  - Public-key derivation and getters: x25519-dalek `PublicKey::from(&secret)`, ring
    `EphemeralPrivateKey::compute_public_key`, p256 `EphemeralSecret::public_key`,
    `SharedSecret::raw_secret_bytes`, `as_bytes`.
  - Constructors: `hmac::Key::new`, `Mac::new_from_slice`, `KeyIvInit::new`,
    `agreement::UnparsedPublicKey::new`.
  - Parameter objects: `scrypt::Params::new`, `argon2::Params::new`, `Argon2::new`,
    `Argon2::default`, `SaltString::from_b64` / `encode_b64`.
  - Streaming steps: `Mac::update`, `Digest::new` / `update`, `Context::update`.

### R9. RNG draws

- **R9.1 Sites.** A call written in the package whose documented purpose is to return random
  output from a random generator is a site with `function = "generate"`. Examples: ring
  `SecureRandom::fill`; rand_core `RngCore::fill_bytes`, `try_fill_bytes`, `next_u32`,
  `next_u64`; rand `Rng::gen`, `gen_range`, `gen_bool`, `fill`, `sample`; `rand::random`;
  `getrandom::getrandom`.
- **R9.2 Not sites.**
  - Getting a generator: `SystemRandom::new`, `rand::thread_rng`, the `OsRng` value,
    `StdRng::from_entropy`.
  - Passing a generator to a library call (key generation, encapsulation, signing,
    `SaltString::generate`). The draw happens inside the library (R1.1). The library call is
    labelled only by its own function, for example `keygen`.
- **R9.3 Names.**
  - `OS-RNG` for operating-system generators: ring `SystemRandom`, rand / rand_core `OsRng`,
    `getrandom`.
  - `ChaCha12-RNG` for rand 0.8 `ThreadRng` (`rand::thread_rng()`) and `StdRng`.
  - The registry has no names for these generators.

### R10. Names (extends R2)

| kind | names |
|---|---|
| hash | also `SHA-224`, `SHA-512/256`, `SHA3-224` / `SHA3-256` / `SHA3-384` / `SHA3-512`, `MD5` |
| block cipher + mode | `AES-<keybits>-<mode>`, e.g. `AES-256-CBC`, `AES-128-CTR`. The padding (PKCS#7) and IV length are optional pattern parts and are left out. |
| password hashing | `Argon2id` / `Argon2i` / `Argon2d` without cost parameters (`Argon2::default()` is Argon2id v0x13); `scrypt`; `bcrypt-pbkdf` (not in the registry; the registry's `bcrypt` is a different construction, the password hash) |
| key agreement | `x25519` (registry spelling, lower case, for both x25519-dalek and ring `agreement::X25519`); `ECDH-P-256` (registry `ECDH[E][-{ellipticCurve}]`, optional `E` left out) |
| KEM | `ML-KEM-512`, `ML-KEM-768`, `ML-KEM-1024` |

- **keygen** names the scheme the key is generated for, as in R2: an x25519 ephemeral secret is
  `x25519`, a p256 `ecdh::EphemeralSecret` is `ECDH-P-256`, and `MlKem768::generate` is
  `ML-KEM-768`.

### R11. params (extends R5)

| key | meaning |
|---|---|
| `length` | also the output buffer of `scrypt::scrypt`, `bcrypt_pbkdf::bcrypt_pbkdf` and `Argon2::hash_password_into` |
| `iterations` | also the `rounds` argument of `bcrypt_pbkdf` |
| `log_n`, `r`, `p` | scrypt cost parameters from `scrypt::Params::new(log_n, r, p, len)` |

Argon2 costs taken from library defaults are not literals in the program and are not labelled.

### R12. How calls are reached and written

- **R12.1 Macros.** A call produced by a `macro_rules!` macro defined in the package is one site
  per invocation. The site is at the line of the invocation (the line holding the macro name),
  and `callee` is the function or method name written in the macro body. The macro definition
  is not a site.
- **R12.2 Indirect calls.** A call through a `fn` pointer whose target is a site kind (R1, R8)
  is a site at the line of the call. `callee` is the name written at the call (the pointer
  variable, field or parameter), for example `hash_fn` in `hash_fn(&SHA512, data)`.
- **R12.3 Closures, threads, async.** A closure or async body is reached when the program hands
  it to code that runs it: `std::thread::spawn`, an iterator adapter (`map`) whose iterator is
  consumed (`collect`), or `futures_executor::block_on` on the future, directly or through
  `.await`. Its calls are sites like any other, and captured variables carry their values.
- **R12.4 Statics.** A `static` is one location holding its initializer. A `LazyLock` /
  `OnceLock` static holds the value its initializer returns. A static array is a container
  (R4.3).
- **R12.5 Constant `match`.** In a `match` on a `const` item (or a literal), every arm whose
  pattern does not match the constant is a constant-false branch: dead code (R1.5, R4.9).

### R13. Packages with several binaries

- R3 and R4 are evaluated separately for each binary target, starting from that binary's
  `main`. A site's `must` and `may` are the unions over the binaries that reach it.
- Each site of a multi-binary package has `artifacts = [...]`: the sorted names of the binary
  targets whose `main` reaches the site.
- A module compiled into a binary that never calls into it does not add that binary.
- A site reached by no binary is dead (R1.5): `artifacts = []`, `must = []`, `may = []`.

### R14. Library packages

- For a package with only a library target (`src/lib.rs`, no binary), the entry points that
  replace `main` in R3 and R4 are the public functions of the crate API: `pub` functions and
  methods reachable from outside the crate.
- R3 ranges over every call of an entry point, with any arguments.
- A site reached from an entry point counts, even inside a private function.
- A site in code that no entry point reaches is dead (R1.5): `must = []`, `may = []`. Example:
  a private function that is never called.

### R15. Algorithms chosen from input

- **R15.1 must.** A site whose algorithm is chosen at run time by parsing input (command-line
  arguments, environment, files), for example `jsonwebtoken::Algorithm::from_str(arg)`, has in
  `must` every algorithm the parsing can produce. R3 still applies: an algorithm counts only if
  the call actually performs it for that input. For example, jsonwebtoken `encode` returns an
  error before any cryptography when the key family does not match the header algorithm.
- **R15.2 may.** R4.10 is unchanged. Values produced by parsing input are not part of the
  reference analysis, so they never appear in `may`.
- **R15.4 The program's own mapping.** R15.2 is about values a library produces by parsing
  (R4.10). A value the program maps to algorithms itself, a `match` over a parsed enum in the
  program's code (jwt-cli's `translate_algorithm`), is the program's run-time branch: its arms
  count by R4.8, each arm's algorithm in `may` at the sites its value reaches.
- **R15.3 Mixed functions.** If a site's `must` mixes MAC algorithms (`tag`) with signature
  algorithms (`sign`), as `jsonwebtoken::encode` does with a run-time algorithm, the site's
  `function` is `sign`.
