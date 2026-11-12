# cargo-cbom

A proof of concept that generates a CycloneDX 1.7 Cryptography Bill of Materials (CBOM) for a
Cargo workspace from the compiler's view of the code. For the artifact the workspace builds, it
reports:
- which cryptographic algorithms and key material the program uses, with their parameters
  (`AES-256-GCM`, `HMAC-SHA-256`, `ECDSA-P-256-SHA-256`), named after the CycloneDX Cryptography
  Registry;
- where: every finding is an evidence occurrence at a file, line, column and symbol, with the
  function it is in and why it was reported;
- how: what each call does (encrypt, sign, digest, keyderive, ...), whether the code is reachable
  from the program's entry points (an upper bound: see Limitations) or only compiled, and where
  key material comes from
  (hard-coded, environment, RNG, a parameter, derived), with findings such as
  `hard-coded-key`;
- what it cannot tell: an operation whose algorithm is not determined is reported as `unknown`,
  with the reason, never dropped; when several algorithms may reach one call, each says how
  (`one of N`, `possible`, `selector: configuration` for a run-time choice).

`cargo cbom verify` checks every position a CBOM cites against the source, independently of the
generator.

## How it works

```
cargo cbom
 |- Layer 1  (rcbom-manifest)  cargo metadata + manifests: crypto packages, backends,
 |                             native libraries, the manifest line where each enters the build
 |- Layer 2a (rcbom-driver)    cargo +nightly check with the driver as RUSTC_WRAPPER: per crate,
 |                             the sites naming crypto items, the origin of their arguments, how
 |                             values move between functions, and the instances reachable from
 |                             the entry points; written as JSON facts
 |- Layer 2b (rcbom-analysis)  stable: matches the facts against the knowledge base
 |                             (rcbom-kb), follows values across functions, applies boundary
 |                             models (jsonwebtoken), classifies key provenance, labels sets
 |- CycloneDX 1.7 JSON, validated against the vendored schemas on every run
```

- **Layer 1** finds the crypto packages that ship (by the knowledge base's `[[crate]]` entries,
  and unmodelled crypto packages by their metadata), the backend their features select and the
  native libraries they link, with the `Cargo.toml` or `Cargo.lock` line where each one enters.
- **The driver** (`crates/rcbom-driver`, its own cargo project on `nightly-2026-09-25`) compiles
  every crate normally through `rustc_public`. For each body it records the *sites* that name an
  item of a knowledge-base crate (calls with their generic arguments, statics, consts, calls
  through pointers), and for each argument an *origin* tree from the body's def-use chains
  (`&AES_256_GCM`, a literal, a parameter, a field, a call's result). It also records the
  *links* that continue origins across functions: what each function stores in struct fields,
  returns, passes to other functions and writes through `&mut`, what statics hold at run time,
  and which types are coerced to which trait objects. In a binary (or a library member) it walks
  the monomorphized instance graph from the entry points, so a site in walked code is
  `reachable`, else `present`.
- **The analysis** (`crates/rcbom-analysis`, stable) matches sites structurally: by crate, item
  path and generic-argument positions (`AesGcm<Aes256, U12>` is AES-256-GCM), descriptor statics
  (`ring::aead::AES_256_GCM`), and calls the knowledge base lists as operations. Where an
  algorithm comes from elsewhere (a field, a parameter, a trait object, a container, a static
  table), it follows the links and labels each member of the set with how it reaches the call
  and a witness. Key-material arguments are classified by the knowledge base's sources.
- **The knowledge base** (`crates/rcbom-kb/data/seed.toml`) is data: crates and their roles, types, statics and
  functions that are algorithms, operations, uses, argument roles, provenance sources,
  boundary models, and the calls that are no operation (`[[aside]]`).
- **The boundary check** accounts for every call the walked code makes into a crypto package,
  by the function it resolves to (and for those the standard library makes on its behalf, and
  those of a library's generic functions): each is cited by an occurrence of that call, or needs
  none for a reason the knowledge base or the contract states (a protocol crate the walk
  enters, a crypto package's internals, a stream's step, an `[[aside]]` kind: a view, a copy, a
  wipe, an accessor, a comparison, a function of an error type, which the compiler's impls of
  `core::error::Error` identify in any package). A call neither cited nor excused is cited by
  the check itself, as an operation of unknown algorithm: nothing the walk reaches is left
  out. A call the standard library (every crate of the toolchain's sysroot, `hashbrown` under
  `HashMap` included) or a wrapper package makes for the program (`Uuid::new_v4()` drawing
  from a random generator, a `HashMap` hashing its keys with siphasher) is cited at the
  program's call, by name when the knowledge base names the function called or the type it is
  a function of. The CBOM states the counts (`rcbom:run:boundary-check`; `in-too-deep.md`
  6.10).
- **The verifier** reopens every cited file and checks each position, and the details it can
  read in the code (the token named, the item around it, the descriptor read by the call,
  bindings in scope, closures, macro rules, coercions, witnesses); `--self-test` shifts every
  position by a line and a column and counts how many shifts it rejects. What comes from the
  walk or the value search (tiers, provenance classes, set labels) it does not check
  (Limitations).

## Build

```
rustup toolchain install nightly-2026-09-25 --component rustc-dev,llvm-tools,rust-src,clippy,rustfmt
rustup target add x86_64-unknown-linux-musl --toolchain nightly-2026-09-25   # for one test fixture
(cd crates/rcbom-driver && cargo build)      # the compiler driver, pinned nightly
cargo build                                    # the CLI and libraries, stable
```

## Use

```
cd <cargo project>
<repo>/target/debug/cargo-cbom cbom -o cbom.json            # Layers 1 and 2
<repo>/target/debug/cargo-cbom cbom --manifest-only -o ...  # Layer 1 only, nothing compiled
<repo>/target/debug/cargo-cbom cbom --features f1,f2 ...    # the artifact other features build
<repo>/target/debug/cargo-cbom cbom --no-default-features ...  # (or --all-features), as with cargo
<repo>/target/debug/cargo-cbom cbom -p member ...           # one workspace member and what it
                                                    # depends on, not the whole workspace
<repo>/target/debug/cargo-cbom cbom --target <triple> ...   # the artifact for another platform
<repo>/target/debug/cargo-cbom cbom verify cbom.json --self-test
<repo>/target/debug/cargo-cbom cbom --boundary-list calls.tsv ...  # every call into a crypto
                                                    # package and how the boundary check
                                                    # accounts for it
RCBOM_DEBUG=1 <repo>/target/debug/cargo-cbom cbom -o ...    # also print the driver's caught panics
```

In the repository, `cargo xtask summary <path>/cbom.json` prints a CBOM as one sorted line per fact
(the form of the golden files).

The CBOM describes one built artifact: a target (the host's unless `--target` names another), a
feature set, the workspace's members or those `-p` selects, and the `release` profile
(`--profile` to change it). Tests and build scripts are not in it. Another target, feature set
or member is another artifact: another run, another CBOM. `--target` needs that platform's
standard library for the pinned toolchain (`rustup target add <triple> --toolchain
nightly-2026-09-25`), a C compiler for it where a dependency's build script compiles C, and,
for `--check-walk`, a linker.

Layer 2 compiles the project, so build scripts and procedural macros run. Run it on code you
trust, or inside a container.

## Tests and evaluation

The project's tasks are an `xtask` crate (`cargo xtask <task>`, run in the repository):

```
cargo xtask check                                    # rustfmt, clippy -D warnings, unit tests
                                                     # (enforced), both workspaces
cargo xtask e2e --realapp --regress --suite          # every fixture: whole-CBOM golden files,
                                                     # every position verified and every shift
                                                     # rejected, labelled scores; fixtures in
                                                     # parallel; RCBOM_BLESS=1 rewrites goldens
cargo xtask suite <out> tests/fixtures/suite/*/      # the ground-truth suite: 53 programs, 107
                                                     # call sites labelled from source before
                                                     # any tool run
cargo xtask corpus-run <work> <out> tests/fixtures/corpus/*.toml     # the real projects' CBOMs:
                                                     # each package fetched from crates.io as
                                                     # published (`tests/fixtures/projects.toml`),
                                                     # generated and verified; heldout/, review/
                                                     # likewise
cargo xtask corpus-score <out> tests/fixtures/corpus/*.toml          # six real projects
cargo xtask corpus-score <out> tests/fixtures/heldout/*.toml         # seven held-out crates
cargo xtask corpus-score <out> tests/fixtures/review/*.toml          # the reviewer's two crates
cargo xtask score tests/fixtures/rusi/<fixture>/labels.toml <cbom>   # any tool's CBOM
cargo xtask rusi-to-cbom <rusi report>               # a rusi report as a CBOM, for `score`
cargo xtask review-sheet <fixture>...                # labels next to their source lines
```

Verdicts: **correct**; **wrong** (an algorithm outside the labels: the bar is zero);
**less-specific**; **honest-unknown** (`unknown` reported, nothing wrong); **miss**.

## Results

Every number comes from the outputs in `results/`, which the commands above regenerate; the
corpus, held-out and review projects are crates.io packages as published, pinned by their
sha256. Labels were written from source by agents that never saw tool output
(`docs/suite/RULES.md`). For the suite, corpus and held-out sets: two independent labellers per
set, compared, and adjudicated by the rules; the held-out crates were chosen after development
and their labels frozen before the first run (dufs and rustic_core were then used to fix code,
jwt and ssh-key the verifier, ssh-key and totp-rs the driver). The review crates were chosen and labelled blind by an
independent reviewer of the whole project, then used for the fixes its review found. On
10 November the knowledge base was extended to what the held-out and review projects use (the
RustCrypto generation after 0.10, blake2, p521, uuid's random draw): the rows below are after
it, so all four sets are development sets now. Before it (the build of 26 October) the held-out
row was 38 correct, 4 less-specific, 40 honest-unknown, 4 miss, the review row 28, 1, 3, 1, and
the suite had 3 less-specific sites; no algorithm was reported wrongly then or now. Since
then the tool was run on sixty-seven crates.io packages it had never been run on, in three
batches (Unseen packages, below): what those runs found is fixed in this build, and changed
three labelled sites' verdicts, all to correct: rustic_core's private `apply_with_rng`, an
honest unknown, and jwt's `Hmac<D>` signing and verification, less specific (`HMAC`).

| set | what | result |
|---|---|---|
| ground-truth suite | 53 programs, 107 call sites | 107 correct, 0 wrong, 0 miss |
| corpus | realapp, minisign, rcgen, jwt-cli, rage, xh | Layer 1: 106/106 crypto packages found, none reported that is not; Layer 2: 28 live sites: 18 correct, 10 honest-unknown, 0 miss, 0 wrong; 10 dead sites (features off), nothing reported there |
| held-out | boringtun, dufs, totp-rs, gcp_auth, rustic_core, ssh-key, jwt | Layer 1: 112/112 found, none reported that is not; Layer 2: 86 live sites: 72 correct, 0 less-specific, 13 honest-unknown, 1 miss, 0 wrong; 10 dead sites, nothing reported there |
| review | rbw 1.15.0, biscuit-auth 6.0.0 (the reviewer's labels) | Layer 1: 67/68 found, none reported that is not (the one not found, quinn-proto, is in rbw's lockfile but not in its build); Layer 2: 33 sites: 29 correct, 1 less-specific, 3 honest-unknown, 0 miss, 0 wrong |
| rusi fixtures | three labelled cdxgen fixtures, against rusi 4.1.1 | cargo-cbom: 14/14 core sites found, 19/19 reported correct, 14/14 fully named, key provenance 10/10; rusi: 12/14, 12/15, 7/14, 0/10 |
| evidence | every cited position, `verify --self-test` | fixtures (343 outputs, the suite's included): 20,857 positions verified, 12 more within a range of identical candidates, and 3 the verifier cannot confirm (each checked correct by hand); corpus 1,872, held-out 1,391 and review 797 verified, with 15 and 6 more within a range in the last two; every one of 101,169 positions shifted by a line or a column rejected |
| boundary check | every call the walked code makes into a crypto package, those the standard library makes for it and those of a library's generic functions (`rcbom:run:boundary-check`) | none left out: fixtures 11,552 calls (3,623 cited, 15 cited by the check by name, 18 cited by the check as unknown, 7,896 excused), corpus 1,568 (334, 0, 0, 1,234), held-out 1,138 (392, 3, 1, 742), review 801 (174, 1, 1, 625) |
| walk vs linker | code each binary links that the walk did not reach (`--check-walk`) | gap 0 on realapp, jwt-cli, rage, rage-keygen, xh, dufs, rbw, rbw-agent |
| cost | one cold run per project on 4 cores: compilation, analysis, walk check | 4 s (totp-rs) to 206 s (dufs) for the corpus and held-out projects, 347 s for rbw; peak memory of the process tree 0.3 to 3.5 GB (4.8 GB for rbw), measured on the build of 26 October; reruns reproduce each CBOM exactly |

Where it is not exact, the CBOM says so instead of guessing:
- **Misses.** One, in the held-out set: ssh-key's RSA key generation, which is reported as RSA
  private-key material, not as the scheme the label names. The corpus and the review set have
  none. (dufs's and rbw's `Uuid::new_v4`, misses until 10 November, are cited at the
  program's call since uuid is a wrapper package: Conventions.)
- **Less specific.** One, in the review set: rbw's `SigningKey::<Sha1>::new_unprefixed`, named
  `RSA-PKCS1-1.5` with its SHA-1 component: the signature is of the raw digest, without the
  DigestInfo prefix of RSASSA-PKCS1-v1_5 with SHA-1. (jwt's `Hmac<D>`, named `HMAC` until 11
  November, is now one of the three hashes the library's own trait bounds `D` to: Limitations,
  generic library code.)
- **Labels changed after the runs.** jwt-cli's two `decode` calls with signature validation
  disabled were labelled with the HMACs the file's other sites count, narrowed to HS256 after the
  second review and restored after the third (the label file's header says why); the CBOM keeps
  the HMAC candidates there with a note that validation is disabled on a way to the call.
- **Honest unknowns.** Each is reported as an operation of unknown algorithm, with the package
  and the reason. In the held-out set (13): what a library's callers choose (ssh-key's draws
  from its callers' `rng: &mut impl CryptoRngCore`, five), a key made before its scheme is chosen
  (ssh-key's `SecretKey::random` on three curves), and calls into crypto packages the
  knowledge base does not model: ssh-cipher's `encrypt` and `decrypt`, whose cipher is a
  run-time value, aes256ctr_poly1305aes, and sha-crypt's `verify_password`, whose algorithm is
  the stored hash's. In the corpus (10): rage's calls into age that set up its encryptor,
  decrypt or draw its passphrase, an age key generation, and digest_auth's `respond`. In the
  review set (3): rbw's `try_sign` on an ssh-key key and its two totp-rs `generate_current`.
  The boundary check cites two calls itself as unknown: ssh-key's `Signer::try_sign` on the
  type parameter of its generic `SshSig::sign` (a signature), and rbw's `parse` of an ssh-key
  public key, which the standard library runs; and four by name, the `Uuid::new_v4` draws.

**Unseen packages.** The tool is also run on crates.io packages it has never been run on, as
published. They have no labels: what a run shows is whether it completes, whether the verifier
confirms every position and rejects every shifted one, whether the walk check finds a gap and
the boundary check leaves a call out. A batch passes when every package does on its first run.
None of the three batches so far did; each finding is fixed in this build and has a fixture,
and the packages are development material from then on (`in-too-deep.md` 8 says what such a
run can and cannot show).
- *Fifteen, 10 November:* rsign2 0.6.7, cocoon 0.5.0, magic-crypt 6.0.0, djangohashers 1.8.4,
  nkeys 0.4.5, cookie 0.18.2 (`secure`), htpasswd-verify 0.3.0, passwords 3.1.19, sha256 1.6.0,
  branca 0.10.2, miniserve 0.35.0, jwt-compact 0.8.0, totp-rs 6.0.0, biscuit 0.8.0 and pgp 0.21.0
  (a sixteenth, jwt-simple, needs cmake to build here). The verifier rejected correct
  positions in four of them (10 in rsign2, 10 in miniserve, 12 in jwt-compact, 86 in pgp: a
  function type's `->` inside generic arguments, a type's default arguments, an associated
  type, a second chain of instantiations); the walk check reported 38 gaps on miniserve that
  were none (the two builds order a trait object's bindings differently); calls made inside
  the standard library's hash table were missing from the boundary check; and on pgp the
  analysis ran out of 15 GB of memory.
- *Thirty-two, 10 November:* vodozemac 0.11.2, snow 0.10.0, hpke 0.15.1, postgres-protocol
  0.6.12, aws-sigv4 1.6.5, oauth2 5.0.0, tungstenite 0.30.0, zip 9.5.0, keepass 0.17.0,
  magic-wormhole 0.8.1, bitwarden-crypto 4.0.0, pasetors 0.8.1, age 0.12.1, russh 0.65.1,
  cosmwasm-crypto 2.2.11, tiny-bip39 2.0.0, opaque-ke 4.0.1, dryoc 2.0.0, crypto_box 0.9.1,
  pueue 4.0.4, static-web-server 2.44.1, mdbook 0.5.4, oha 1.16.0, tealdeer 1.9.1, cargo-deny
  0.20.2, shadowsocks-rust 1.25.0, sccache 0.19.0, atuin 18.24.6, sqlx-cli 0.9.0 and rustic-rs
  0.11.4 (josekit and rathole do not build here: their locked openssl-sys rejects this
  machine's OpenSSL). Fifteen of the thirty passed. In the others the verifier rejected
  correct positions (1 to 149 a package: names the source writes through aliases, renamed
  traits and re-exports, const arguments, attribute macros, chains of same-named calls), and
  accepted shifted ones where two calls are textually alike; the generator reported a cipher
  bare beside the mode it was instantiated into, merged two instances at one generic line, and
  lost a merged occurrence's calls to the boundary check; the walk missed a library's
  `#[global_allocator]` and functions called through `extern` declarations, and stopped at
  200,000 instances on atuin and rustic-rs; the driver panicked on a const-generic projection
  (heapless); and a pre-release (rsa 0.10.0-rc.18) was outside its knowledge-base entry. The
  178 functions rustic-rs then still linked without the walk reaching them are the methods of
  a `Box<dyn Buf>` that nothing calls: no gap of the walk, and counted apart since
  (`uncalled object`).
- *Twenty, 11 November:* mail-auth 0.15.1, rusty_paseto 0.10.1, openidconnect 4.1.0,
  yup-oauth2 12.1.2, instant-acme 0.8.5, x509-parser 0.18.1 (`verify`), libp2p-identity 0.3.1
  (its four key features), quinn-proto 0.11.19, hickory-proto 0.26.3 (`dnssec-ring`),
  axum-extra 0.12.6 (`cookie-private`), tower-sessions 0.15.0, schnorrkel 0.11.5, frost-ed25519
  3.0.0, bip39 3.0.0, kbs2 0.7.3, git-cliff 2.14.2, cargo-audit 0.23.0, websocat 1.14.1,
  rustypaste 0.18.2 and jj-cli 0.47.1. Fourteen passed. The verifier rejected correct
  positions in five (7 in mail-auth, 4 in openidconnect, 4 in bip39, 3 in rustypaste, 47 in
  jj-cli: an impl written in another module than its type, an index operator, an attribute
  macro's closure, a derive macro's calls cited at its type's fields, a generator type handed
  to a generic function of another crate); jj-cli had 16 functions linked and not walked, the
  methods of trait objects of types that hold an `async` closure; websocat builds here only
  without its default features (OpenSSL), and passes so.

After the third batch every earlier package that builds here was re-run, versions pinned, on
the builds pushed on 11 November (64 of them; jj-cli on the build before, as clean): all
complete; 18,275 positions verified and 93 within a range, none mismatched; all 98,256
shifted positions rejected (22 more land on a call of the same instance, as true); no walk
gap in their 26 binaries (rustic-rs's 178 functions linked through a trait object nothing
calls are counted apart); 14,919 calls into crypto packages, 4,356 cited, 39 cited by the
check by name, 244 as unknown, 10,280 excused. That re-run caught two regressions the
fixtures had not (pgp's hashers boxed by `Box::<T>::default()`, a shifted position accepted in
biscuit-auth), fixed before it ended. What stays unknown in them is what the knowledge base
does not model (minisign under rsign2, bcrypt, the ciphers and modes pgp uses beyond AES-GCM);
pgp's and miniserve's `Box<dyn DynDigest>` hashers are named now, one member for each hash the
build boxes.

## Limitations

What the CBOM covers, what it reports differently from a reading of the labelling rules, and
what it does not do yet. A reviewer meeting one of these meets a known limit, not a new finding.

**Scope, by decision**
- One built artifact per run: one target, one feature set, the members selected, the `release`
  profile (each a flag: Use). Tests, build scripts, examples, and code that other features or
  targets would compile are not in that artifact's CBOM.
- Hand-rolled algorithms, unsafe code, certificates loaded at run time, and security
  configuration (which TLS suites a configuration allows) are out of scope. minisign's own
  Ed25519, BLAKE2b and SHA-512 are such code: its labels hold only its random draws and scrypt.
- Knowledge-base coverage: RustCrypto's two generations in use, the one of digest 0.10 and the
  one after it (digest 0.11, crypto-common 0.2: sha2 0.11, sha1 0.11, md-5 0.11, sha3 0.11 to
  0.12, blake2 0.10 to 0.11, hmac 0.13, hkdf 0.13, pbkdf2 0.13, scrypt 0.12, argon2 0.6,
  aead 0.6, aes 0.9, aes-gcm 0.11, chacha20poly1305 0.11, cbc 0.2, ctr 0.10, signature 3,
  ed25519-dalek 3, x25519-dalek 3, ecdsa 0.17 and the curve crates 0.14), each crate of a
  build matched by its own version; rsa 0.9 to 0.10, ml-kem 0.2 to 0.3; ring 0.17,
  aws-lc-rs 1, rustls 0.23, jsonwebtoken 9 to 11, rand 0.8 to 0.10, md5 0.7 to 0.8,
  siphasher 0.3 to 1. A pre-release counts as the release it leads to (rsa 0.10.0-rc.18 is
  rsa 0.10). Other versions and unmodelled crypto packages are reported, with their
  operations as unknown and the reason.
- Layers 3 to 5 (purpose, vulnerabilities, policy) are designed, not built: no occurrence says
  whether it protects anything (`rcbom:usage` is a package's usage tier, from the walk).

**Conventions: where the CBOM differs from a label written by the rules**
- A call into a crypto package the knowledge base does not model, made from the program or a
  dependency that is no crypto package, is cited as an operation of an unknown algorithm: what
  it does is not known, but for the use its name has (`decrypt`). A constructor is cited too
  (orion's `SecretKey::default()` draws a key), and so is a standard-library trait's method its
  types run, and a call the standard library makes into it for the program, at the program's
  call (`none.unwrap_or_default()`). Not cited: a step of a stream (`update`, the methods of `io::Read` and
  `io::Write`), what the knowledge base lists as no operation (`[[aside]]`: views, copies,
  wipes, accessors, an error type's constructors and conversions), and calls into relays:
  tokio-rustls, hyper-rustls and actix-tls wrap rustls, whose operations are cited in rustls;
  tokio-native-tls and hyper-tls wrap native-tls, whose calls are the unknowns (the platform's
  TLS library runs behind them);
  rustls-pki-types, rustls-pemfile and rustls-native-certs are PKI types, parsers and loaders. Calls between crypto packages are their internals. Where such
  a package's own code calls modelled crates, those calls are cited inside it (rage's call into
  age is an unknown at rage's line, and age's ChaCha20-Poly1305 is cited in age). Inside
  algorithm crates nothing is cited: their internals are folded into the call into them.
- A block cipher chosen as the type argument of a generic function is cited for the algorithm
  the instance runs it as: `cbc_encrypt::<aes::Aes128Enc>(..)` over a body that builds a
  `cbc::Encryptor<C>` is an instantiation of AES-128-CBC, and no AES-128 is reported for it.
  Where the function uses the cipher as it is, or nothing the knowledge base names, the
  instantiation stays the cipher's.
- A call on a type of a crypto package that the knowledge base does not name is an operation
  of unknown algorithm naming that type, also when the type holds one it names: `Cmac<Aes128>`
  is a MAC it cannot name, not an AES-128 block cipher, and the `SigningKey<Sha256>` of an rsa
  version it does not cover is no SHA-256 hash. Only a trait crate's wrappers (`CoreWrapper<T>`), the standard library's
  and the program's own types are looked through.
- A package that is not cryptographic is not cited at the program's calls into it; the calls
  its code makes into crypto packages are cited inside it. A wrapper the knowledge base lists
  (uuid) is the exception: the call it makes for the program is cited at the program's call
  too, by the operation the knowledge base names (`Uuid::new_v4()` is `rand::random`, a
  ChaCha12-RNG draw, with uuid's `fast-rng` feature, else `getrandom::fill`, OS-RNG), as a
  call the standard library makes for the program is.
- Streaming steps the knowledge base lists (`Digest::update`, `Mac::update`, ring's
  `Prk::expand`) are reported beside the call that finishes the stream; the rules label only
  the latter (the scorers count them as unlabelled uses, never as wrong: a labelled site's
  occurrences are those at its call, not those at another call its line holds).
- A call through a function pointer read from a table is cited at the calls the pointed-to
  functions make into the crypto library, not at the indirect call.
- RSA key generation (`RsaPrivateKey::new`) is reported as RSA private-key material with its
  `keygen` use, not as a signature or encryption scheme.
- A key's export to bytes (`SigningKey::to_bytes`) is setup, not a use: none of CycloneDX's
  crypto functions runs there. The occurrence is cited with the key's algorithm.
- A TLS protocol asset lists the versions, suites and groups the backend's provider module
  offers (all nine of rustls's ring suites), not those a provider the program builds or a
  `ClientConfig` restricts it to; a suite the program names is cited where it names it.
- jsonwebtoken's `decode` after `insecure_disable_signature_validation()` keeps its candidate
  algorithms, with a note that validation is disabled on a way to the call and that there it
  only decodes: whether the call is made on every way is not known, and dropping the claim
  where it is not would drop an operation.
- A set member that reaches a function several artifacts share from one artifact's code is
  tagged with every artifact reaching the call: the tags may say too much, never too little.

**Known limits**
- *Reachability is an upper bound.* `reachable` is what a walk that errs towards reaching
  finds: a trait-object method is released for every coerced type at any call through the
  trait or any escape of such an object, and a future's body counts as run where it is built.
  A vtable method no code calls, an `Arc<dyn Trait>` never called, an `async` body never polled
  are `reachable`; on realapp, whose `main` only builds rustls's ring provider, 419 of 560
  occurrences are. `present` means compiled and certainly not reached: also the methods of
  the objects of a trait no code calls through, which their vtables keep in the binary. A
  named algorithm in such code is counted as wrong by the scorers where its site is labelled
  dead; none is in the sets above.
- *Layer 1 from metadata.* An unmodelled package is a crypto package when its `Cargo.toml` says
  so (category or keyword, in any case: rust-crypto's `Crypto`), the knowledge base lists it,
  or it declares no category and its name names an algorithm of the Cryptography Registry
  (`blake2b_simd`, `sha1_smol`, `rust-argon2` without its Rust affix; the web framework `seed`
  declares what it is), and `support` when its categories are an encoding's or a parser's, or
  the knowledge base lists it as a helper (opaque-debug, whose name is the OPAQUE protocol's).
  Metadata cannot tell every case (ssh-key, which signs, has der's categories; totp-rs and
  native-tls name no crypto), so such packages are listed by name. A crypto package with
  neither metadata, a listing nor an algorithm name is outside both layers: the driver records
  calls only into the packages Layer 1 lists, and the boundary check accounts for those only.
- *What the boundary check rests on.* Every call the walk reaches into the crypto set, those the
  standard library makes on the walked code's behalf and those of a library's generic
  functions are cited, by an occurrence or by the check, or excused, relative to the walk (an
  upper bound), Layer 1's crypto set, and the knowledge base's word that an excused kind is no
  operation. A call through a function pointer, a function-typed parameter, a generic field or
  a returned function is no call of the check: the function is cited where it is named, and a
  pointer the driver does not resolve is cited at the calls the pointed-to functions make.
- *Values.* Values are followed through def-use origins, links across functions and
  standard-library summaries, not a points-to analysis. Where one is not followed, the CBOM
  says unknown with the reason (`in-too-deep.md` 6.9); the opt-in points-to engine only removes
  doubt and was not part of the evaluation.
- *Generic library code.* In a library, a generic function's type parameters belong to its
  callers: an operation on one is unknown, or named only as far as the library fixes it
  (`HMAC` of a caller's hash). A function only its own crate can name is the exception: where
  each call the crate makes gives a parameter a type that is no parameter of the caller's,
  an operation on it is that type's, a member per type where the calls give several
  (rustic_core's private `apply_with_rng(.., rng)`, only ever handed `rand::rng()`, is the
  thread generator's). So is a parameter that a trait of the library bounds: it is one of
  the types the build implements that trait for, each a member (jwt's `Hmac<D>` with `D:
  TypeLevelAlgorithmType`, signed for SHA-256, SHA-384 and SHA-512), and the occurrence says
  where another crate can name the trait and implement it for a type of its own. A private
  helper such a function hands its parameter on to takes what that parameter is (jwt's
  `get_hmac_with_data<D>`, whose `update` steps are those three HMACs'). Still the callers':
  a parameter no trait of the library bounds and no call of the library fixes.
- *Provenance.* Key material is classified for the arguments the knowledge base gives a role;
  a generator handed to an API without an `rng` role is not classified, and gets no
  `predictable-rng` finding. A parameter's provenance includes what the program's callers pass
  (a field of it, that field); callers outside the program or through pointers leave it
  `parameter`, which also stays beside what the callers pass. Classes are what some way of the
  program may bring there: a library reading one field for every key it is given (jsonwebtoken's
  `EncodingKey`) gets every key the program makes, for each algorithm it may run, and a
  hard-coded one among them gives each its finding. A value only some of whose bytes are a
  literal (a zeroed key half of which a call fills) is `partly hard-coded`, which gives no
  finding: the value is not a literal. Fills through literal index ranges that cover the whole
  buffer replace it (rustls's TLS 1.2 nonce, `[..4]` then `[4..]`); a buffer written by a loop
  (element by element, through `chunks_mut`) keeps its literal as `partly hard-coded`: the
  analysis does not count a loop's writes. A value a function of the program
  returns is `computed` by it, not followed into its body (a key `load_key()` reads from a file
  is `computed (load_key)`).
- *Positions.* A call is cited where its path starts (`Sha256::digest` at `S`); a path split
  over lines is cited at its first line, where R1 (the callee's line) puts the label one lower.
- *Trait objects.* A call on a trait object of a crypto trait (`hasher.update(..)` on a
  `Box<dyn DynDigest>`) is one of the types the build makes such an object of, anywhere the
  walk reaches: each the knowledge base names is a member (`member: dyn`, with its coercion),
  and an unknown stands beside them where one is not named. The set is of the build, not of
  the call: two functions each boxing other hashes share it. A closure called through a
  `dyn Fn` object gets the arguments of the calls made through such objects, beside an
  unknown: where else the object may be called from is not followed.
- *Names and parameters.* BLAKE3 is `BLAKE3-256` for `hash` and `keyed_hash`, `BLAKE3` for key
  derivation and XOF output. A library's generic API that sibling binaries instantiate gets no
  "callers choose" unknown for the library itself.
- *Parameters.* `rcbom:param:*` properties are not scored against the labels' `params`.
- *The verifier* is text-based. It checks every position, the token and item there, and the
  details it can read in the source (the descriptor a call reads, witnesses in the program and
  its dependencies, bindings, `instantiated by` calls, coercions, macro rules, manifest entries
  and a library component's name, version and purl; an operator's method at its operator).
  The standard library's witnesses are not read. It shares the knowledge base with the
  analysis, and its naming of a descriptor (`static_names`). It does not check the
  reachability tier, artifact tags, provenance classes, which of an asset's functions a call
  performs, set labels (member kind, `possible`, `one of N`), the reason of an unknown, or a
  registry name outside boundary models; and it cannot see an operation the CBOM leaves out
  (`in-too-deep.md` 8). An instantiation detail is held to the call's type arguments where the
  text gives them; of several calls of one generic function by the same text it is verified
  within that range, and so is a method called on a receiver the code gives no type of beside
  another such call of that method (`k.hash(state)` above `v.hash(state)`). An occurrence
  several instances of its item reach lists each one's chain, a step naming the item it
  instantiates where it does not follow the step before; a method call is not told from
  another call of that method on the same variable of another crate's type. Three fixture positions it cannot confirm are listed in
  `verify-known` files, each checked by hand.
- *Toolchain.* The driver needs its pinned nightly. Layer 2 compiles the project, so the
  project's build scripts and procedural macros run. A published package whose `Cargo.lock`
  locks versions the nightly no longer builds (bore-cli 0.6.0's proc-macro2 1.0.56) does not
  build: the run says so, and a refreshed lock is needed.

## Layout

| path | content |
|---|---|
| `crates/cargo-cbom` | CLI, schema validation (`schema/`: CycloneDX 1.7, Apache-2.0), `verify` |
| `crates/rcbom-manifest` | Layer 1 |
| `crates/rcbom-driver` | the nightly `rustc_public` driver: sites, origins, links, walk |
| `crates/rcbom-facts` | the facts exchanged between driver and analysis |
| `crates/rcbom-kb` | knowledge base loader and data (`data/`: the seed, and the Cryptography Registry, Apache-2.0) |
| `crates/rcbom-analysis` | matching, values across functions, boundary models, provenance, the boundary check, CycloneDX assembly |
| `xtask` | the project's tasks: checks, e2e, scorers, summaries |
| `tests/fixtures/` | designed cases (`micro`, `libonly`, `threads`), the `realapp` corpus program, labelled `rusi` fixtures, `suite/` (the ground-truth suite), `regress/` (probes from every audit round), `corpus/` (labels for six real projects), `heldout/` (labels for seven crates.io crates chosen after development, frozen before any run), `review/` (an independent reviewer's blind labels for two crates), `projects.toml` (the package behind each corpus, held-out and review label); each fixture with its golden `expected.txt` |
| `results/` | committed outputs behind the reported numbers |
| `docs/` | `poc_workflow.md` (the tool, its five layers, related tools), `in-too-deep.md` (how each stage works), `suite/RULES.md` (the labelling rules every label file follows) |

## Licence

Apache License 2.0 (`LICENSE`). The vendored CycloneDX schemas and Cryptography Registry are
Apache-2.0 too. The external reference cases are BOM Fidelity's, published at
https://github.com/jaooli-cyber/rust-cbom-reference-cases (release v1.0.0).
