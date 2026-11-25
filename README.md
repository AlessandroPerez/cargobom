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
- how each algorithm stands against a quantum computer, where NIST says it:
  `nistQuantumSecurityLevel` is the security category of NIST IR 8547 (October 2026), 1 to 5,
  or 0 where none is met (RSA, ECDSA, EdDSA, ECDH and X25519, which Shor's algorithm breaks;
  SHA-1 and the 224-bit hashes), with the table it comes from. An algorithm the report's tables
  do not name (HMAC, HKDF, ChaCha20-Poly1305, Argon2, MD5) has no level, which is not level 0.
  The run lists the level-0 algorithms on one line: where a move to post-quantum cryptography
  starts;
- what it cannot tell: an operation whose algorithm is not determined is reported as `unknown`,
  with the reason, never dropped; when several algorithms may reach one call, each says how
  (`one of N`, `possible`, `selector: configuration` for a run-time choice).

`cargo cbom verify` checks every position a CBOM cites against the source, independently of the
analysis that chose it; where code is (its item, the macros that write it, the calls of a
generic chain) it takes from what the compiler records, which the CBOM carries.

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
  boundary models, the calls that are no operation (`[[aside]]`), and the NIST security
  category of each algorithm that NIST IR 8547 gives one (`[[quantum]]`).
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
- **The verifier** reopens every cited file and checks each position. With each one the CBOM
  gives what the compiler records of where the code is: the item it is in, the macros that
  write it (each invocation and definition, innermost first), for every step of an
  instantiation chain what the code there is, and where a value is made a trait object. Each
  span of the record that no name in the text holds (a macro's code, an invocation, a chain
  step, a closure, a coercion) comes with a fingerprint of its column in its line. The
  verifier does not look for any of that in the text: it reads each recorded span and holds
  it to what the record says. What a path at a position names, and the values a call reads
  (the descriptor, bindings in scope, witnesses), it reads from the text itself. A value the
  text does not lead to (a pointer a constructor stored in a field) is counted as not shown, no
  mismatch. `--self-test` shifts every position, and every span of the
  record, by a line and by a column, and counts how many shifts it rejects. What comes from
  the walk or the value search (tiers, provenance classes, set labels) it does not check
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
then the tool was run on 495 crates.io packages it had never been run on, in fourteen batches
(Unseen packages, below): what those runs found is fixed in this build, but for one finding
(two versions of one crate in a build: Limitations), and changed
three labelled sites' verdicts, all to correct: rustic_core's private `apply_with_rng`, an
honest unknown, and jwt's `Hmac<D>` signing and verification, less specific (`HMAC`).

| set | what | result |
|---|---|---|
| ground-truth suite | 53 programs, 107 call sites | 107 correct, 0 wrong, 0 miss |
| corpus | realapp, minisign, rcgen, jwt-cli, rage, xh | Layer 1: 106/106 crypto packages found, none reported that is not; Layer 2: 28 live sites: 18 correct, 10 honest-unknown, 0 miss, 0 wrong; 10 dead sites (features off), nothing reported there |
| held-out | boringtun, dufs, totp-rs, gcp_auth, rustic_core, ssh-key, jwt | Layer 1: 112/112 found, none reported that is not; Layer 2: 86 live sites: 72 correct, 0 less-specific, 13 honest-unknown, 1 miss, 0 wrong; 10 dead sites, nothing reported there |
| review | rbw 1.15.0, biscuit-auth 6.0.0 (the reviewer's labels) | Layer 1: 67/68 found, none reported that is not (the one not found, quinn-proto, is in rbw's lockfile but not in its build); Layer 2: 33 sites: 29 correct, 1 less-specific, 3 honest-unknown, 0 miss, 0 wrong |
| rusi fixtures | three labelled cdxgen fixtures, against rusi 4.1.1 | cargo-cbom: 14/14 core sites found, 19/19 reported correct, 14/14 fully named, key provenance 10/10; rusi: 12/14, 12/15, 7/14, 0/10 |
| evidence | every cited position, `verify --self-test` | fixtures (389 outputs, the suite's included): 22,514 positions verified (35 of them with a fact the text does not show, all in the five fixtures built for that), 1 more within a range of identical candidates, and 3 the verifier cannot confirm (each checked correct by hand); corpus 1,872, held-out 1,406 and review 803 verified, none within a range, none with a fact not shown; every one of 208,721 positions and spans of the compiler's record shifted by a line or a column rejected |
| boundary check | every call the walked code makes into a crypto package, those the standard library makes for it and those of a library's generic functions (`rcbom:run:boundary-check`) | none left out: fixtures 12,517 calls (4,268 cited, 19 cited by the check by name, 29 cited by the check as unknown, 8,201 excused), corpus 1,568 (334, 0, 0, 1,234), held-out 1,138 (392, 3, 1, 742), review 801 (174, 1, 1, 625) |
| walk vs linker | code each binary links that the walk did not reach (`--check-walk`) | gap 0 on realapp, jwt-cli, rage, rage-keygen, xh, dufs, rbw, rbw-agent, and on the 378 binaries of the fixtures that link (`cargo xtask e2e --walk`; one fixture's does not, by design) |
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
None of the fourteen batches so far did (0 of 15, 15 of 30, 14 of 19, 17 of 22, 24 of 32, 27
of 34, 27 of 35, 30 of 33, 27 of 32, 32 of 36, 31 of 35, 39 of 41, 34 of 35, 35 of 37). Each
finding is fixed in this build and has a fixture, but for one (two versions of one crate in a
build: Limitations), and the packages are development material from then on (`in-too-deep.md`
8 says what such a run can and cannot show).
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
- *Twenty-three, 12 November:* just 1.59.0, ntpd 1.9.0, routinator 0.16.1, mongodb 3.10.0,
  rust-s3 0.38.0 (rustls), reqsign 0.20.7, fernet 0.2.2 (`rustcrypto`), fastwebsockets 0.8.1
  (`upgrade`), oo7 0.7.1, b3sum 1.8.7, uu_hashsum 0.5.0, rustls-acme 0.15.4,
  hpke-rs-rust-crypto 0.8.0, zipsign 0.2.2, p12 0.6.3, bip32 0.6.0, ureq 3.5.1, scram 0.6.0,
  tuf 0.2.0, libp2p-noise 0.47.0, srp 0.6.0, x509-certificate 0.25.0 and lettre 0.11.23
  (rustls), with the build pushed that day; tuf 0.2.0 does not build as published (its
  dependencies' versions are yanked). Seventeen of the twenty-two passed, and in all of them
  no shifted position was accepted, the walk check found no gap and the driver caught no
  panic. The verifier rejected correct positions in five (23 in rust-s3, 5 in rustls-acme, 3
  in ntpd, 1 in mongodb, 1 in libp2p-noise): a trait's default `async` method run for a type,
  `Future::poll` called by its name, an impl for the standard library's `Infallible` (`!`)
  with a defaulted argument the compiler leaves out, a receiver typed by a generic alias, a
  parenthesised `async` block, an attribute macro on an impl moving a method's body into
  another item, a formatting macro reaching a `Display` impl through the standard library.
- *Thirty-four, 20 November:* password-auth 2.0.0, cuid2 0.1.6, ecies 0.2.14 (`pure`),
  tink-aead 0.3.0, google-cloud-auth 1.19.0, tough 0.24.0, sevenz-rust 0.6.1 (`aes256`),
  openmls 0.8.3, tendermint 0.41.0, near-crypto 0.38.1, alloy-signer-local 2.6.1, object_store
  0.14.2 (`aws`), sigstore 0.15.0 (`full`, rustls), passkey-authenticator 0.6.0, spake2 0.4.0,
  libp2p-tls 0.7.0, keyring 4.2.0, sspi 0.23.1, picky 6.3.0, jsonwebtoken 12.0.0
  (`rust_crypto`), multihash-codetable 0.2.2 (its seven hash features), cargo-util 0.2.33,
  rustls 0.23.46, lopdf 0.47.0, libreauth 0.18.1, mysql_common 0.38.2, soketto 0.8.1,
  rs_merkle 1.5.0, himalaya 2.2.1, starship 1.27.0, gix 0.90.0 and apple-codesign 0.29.0, with
  the build pushed on 12 November (cargo-vet 0.10.3 and bore-cli 0.6.0 do not build on the
  pinned nightly as published: Limitations, Toolchain). Twenty-four of the thirty-two passed.
  The verifier rejected correct positions in five (59 in tendermint, 68 in
  multihash-codetable, 3 in near-crypto, 2 in sspi, 1 in picky: modules and calls a macro of
  another file writes, a macro rule handing its arguments on to another, a derive written
  over several lines or cited at its own name), accepted two shifted positions in tough (the
  `await` of a future held in a variable), and did not finish on libp2p-tls (a search
  repeated for every position). On apple-codesign the analysis overflowed its stack (rustls
  0.21's connection state, whose methods write it through one another: the walk of a written
  value's fields had no bound), and once bounded showed the limit of two versions of one
  crate.
- *Thirty-six, 21 November:* clatter 2.3.0, mla 2.1.0, age-plugin-xwing 0.2.1,
  cosmian_cover_crypt 16.0.1, sunset 0.6.0, quantum-box 0.2.0, saorsa-pqc 0.5.2,
  sequoia-openpgp 2.4.2 (`crypto-rust`, not its default backend), openmls_rust_crypto 0.6.0,
  emissary-core 0.4.0, rustls-post-quantum 0.2.4 (these eleven, and rosenpass, depend on a
  post-quantum package), librespot-core 0.8.0 (`rustls-tls-webpki-roots`), nostr 0.45.7
  (`all-nips`), ruma-signatures 0.23.0, matrix-sdk-store-encryption 0.19.1,
  mls-rs-crypto-rustcrypto 0.24.0, tor-llcrypto 0.48.0 (`full`), webrtc-dtls 0.12.0,
  webrtc-srtp 0.17.3, makiko 0.2.5, kdbx-rs 0.5.2, cotp 1.9.10, dexios 8.8.1, kestrel-cli
  1.0.3, fclones 0.35.0, cargo-deb 3.8.0, rpm 0.30.2, pdf 0.10.0, rusty-s3 0.12.0, svix
  2.11.0, voprf 0.4.1, poem 3.1.12 (`cookie`, `csrf`, `session`), secret-service 5.2.0
  (`rt-tokio-crypto-rust`) and blind-rsa-signatures 0.19.0, with the build pushed that day,
  the first whose verifier checks the compiler's record (rosenpass 0.2.3 needs the system's
  libsodium, which this machine has not; onetun 0.3.10's locked curve25519-dalek 4.0.0-rc.3
  does not build on the pinned nightly). Twenty-seven of the thirty-four passed. The verifier
  rejected correct positions in five (46 in sequoia-openpgp, 36 in openmls_rust_crypto, 3 in
  cotp, 2 in cosmian_cover_crypt, 2 in kdbx-rs: a macro's path with metavariables before its
  last name, a dependency's free function a macro writes, which the unit walking it recorded
  without its macro, a hash of its own in a function generic over another, a chain of
  instantiations starting at the second of two functions one macro call writes, a value
  boxed as a trait object over several lines); the driver caught a compiler panic on nostr
  (bitcoin_hashes' constants, computed by rotations, reach a method of a `const` trait of
  core that has no body); and the walk check reported a gap on cargo-deb that is none (its
  manifest optimises serde_json on its own, and in an optimised unit two functions of the
  same code are one, under both names).
- *Forty, 21 November:* superboring 0.1.18, bergshamra-keys 0.12.0, kryptering 0.7.1
  (`post-quantum`), affinidi-crypto 0.4.0 (`post-quantum`), bc-components 0.31.1, xml-sec 0.6.0
  (`experimental-pq`), tronic 0.8.1, katwalk 0.1.4, cas-lib 0.2.95, darkbio-crypto 0.20.1
  (`mldsa`, `eddsa`, `rsa`, `xdsa`, `xhpke`, `argon2`, `hkdf`), jose-rs 0.12.1
  (`post-quantum`), passkey-crypto 0.1.1, libsumatracrypt-rs 0.6.1, hpke-ng 0.2.0 (`pq`) (these
  fourteen, and four of the five below that do not build, depend on a post-quantum package),
  pkcs5 0.8.1 (`pbes2`), shadowsocks-crypto 0.8.0, noise-rust-crypto 0.6.2, web-push-native
  0.5.0, signatory 0.27.1 (`ed25519`, `nistp256`), enr 0.14.0, zipsign-api 0.2.2, askar-crypto
  0.3.7, libpna 0.41.1, jwt-authorizer 0.15.0, livekit-token 0.5.0, cloudfront_sign 0.4.1,
  oauth1-request 0.6.1, jose-jwk 0.1.2, discv5 0.12.0, ohttp 0.8.0, xeddsa 1.1.0, cms 0.2.3
  (`builder`), csrf 0.5.0, bc-crypto 0.14.0 and sphinx-packet 0.8.0, with the first build whose
  knowledge base has the post-quantum crates (wasi-crypto 0.1.16 needs cmake for boring-sys and
  tiny-encrypt 1.9.20 the system's PC/SC library, which this machine has not; cargo rejects
  citadel_pqcrypto 0.14.0's manifest; selenite 0.6.0's rustc-serialize and rusty_paserk 0.5.0's
  locked curve25519-dalek do not compile on the pinned nightly). Twenty-seven of the
  thirty-five passed. The verifier rejected correct positions in seven (230 in bergshamra-keys,
  209 in kryptering and 209 in jose-rs, both built on it, 42 in katwalk, 10 in xml-sec, 3 in
  web-push-native, 3 in cms) and accepted one shifted position in superboring: a macro handed
  to another by name and invoked through its metavariable (`$callback!(..)`); two calls one
  macro invocation writes, cited together, the second's code checked against the first's
  function; a function of two type parameters given one by each of two callers, where every
  instantiation was held to choose the occurrence's hash; a binary whose crate is named after
  its target, not its package; a trait imported under another name and its objects written with
  that name; a crate's trait implemented for `Vec<u8>`, taken for a function of the standard
  library; and a function pointer held by a variable of the function's own name, bound one line
  above where the function is named, at the same column.
- *Thirty-eight, 21 November:* commucat-crypto 1.0.103 (`pq`), affidavit 26.10.17, qudag-crypto
  0.6.0, chacha_box_ietf 0.2.0, structured-webauthn 0.1.0, zf-zebrachain 0.0.17, sh-secgen
  0.2.2, quantum-sign 0.1.7, breakmancer 0.9.0, pqsign 0.6.0, latticearc 0.19.0, QuantCrypt
  0.2.0, pqfile 4.3.4, crypt_guard_core 3.1.0 (these fourteen, and two of the five below that
  do not build, depend on a post-quantum package), totp-lite 2.0.1, s3s 0.17.0, bip0039 0.14.2,
  hkd32 0.7.0 (`bip39`), scratchstack-aws-signature 0.11.4, hawk 5.0.1, hdwallet 0.4.1,
  jsonwebtokens 1.2.0, boringauth 0.9.0, a2 0.10.0 (`ring`), min_jwt 0.10.0, office-crypto
  0.4.0, luks2 0.5.0, ms-offcrypto-writer 1.0.7, minreq 3.0.0 (`https-rustls`), suppaftp 13.0.0
  (`rustls-ring`), async-tls 0.13.0, machineid-rs 1.2.4 and sshcerts 0.15.4 (`encrypted-keys`,
  `rsa-signing`), with the build that has the seventh batch's fixes (hubro-sdk 1.0.2's polars-
  ops and osshkeys 0.7.0's locked proc-macro2 do not compile on the pinned nightly; libslug
  0.13.0 needs the system's OpenSSL and rsasl 2.3.1 its GSSAPI library, which this machine has
  not; cargo finds no `hmac ^0.4` for tiny-hderive 0.3.0). Thirty of the thirty-three passed,
  and for the first time no finding is the verifier's reading of a correct position. QuantCrypt
  did not run and hdwallet had two positions rejected for one cause: each pins a toolchain of
  its own (`rust-toolchain`: 1.81, 1.63), the manifest layer ran the cargo the directory
  selects and the build the pinned nightly, and the older cargo cannot read a dependency's
  manifest, or keeps the registry's sources in another directory, so that a file the build
  compiled was no file of a package the manifest layer knew. And the driver caught a compiler
  panic on s3s: a closure in an `async fn` handing a crypto call a slice the coroutine around
  it holds as a constant, read with the closure's generic arguments where the coroutine has its
  own.
- *Forty-two, 22 November:* bitwarden 2.1.0, ap-proxy-protocol 0.11.0
  (`experimental-post-quantum-crypto`), x0x 0.48.1, fips203-ffi 0.5.0, metamorphic-crypto 0.11.0,
  pq-msg 0.2.0, thruput-signing 0.47.0, shin 0.17.0, exochain-core 0.3.1, near-kit-primitives
  0.33.1, pqc-kem 0.3.2, huddle-core 2.2.1, tsp_sdk 0.16.0 (`pq`), ferrijs-std 0.9.2,
  pqhybridsign 0.1.0, li2utils 0.2.0, evnx-crypto 0.2.1, noetl 6.4.1 (these eighteen, and three
  of the nine below that do not build, are the most downloaded dependents of a post-quantum
  package not yet seen), stun_codec 0.4.0, winter-crypto 0.13.1, envcrypt 0.5.0, imagepipe 0.5.1,
  aliyun-oss-client 0.13.3, secret-toolkit-crypto 0.10.3, mostro-cli 0.17.1, midnight-base-crypto
  1.1.1, renetcode2 1.0.1, nym-outfox 3.0.0, hsh 0.0.10, mockforge-collab 0.3.248, yubihsm2
  0.45.3, papm 0.3.2 and hypershunt 1.5.0 (every ninety-fifth, by downloads, of the unseen
  dependents of fifteen classical packages), the list fixed by that rule before any was looked
  at, with the build that has the eighth batch's fixes, the boundary check's value edges and the
  verifier's not-shown outcome (thrussh 0.49.0 needs libsodium; card-cli 1.13.21,
  verifiable-credential-toolkit 0.7.0 and encryptedfs 0.1.26 the system's OpenSSL; the build
  scripts of agntcy-slim-auth 0.17.10's aws-lc-sys, bun_runtime 0.6.0's BoringSSL and
  trezor-crypto-lib 0.1.1 fail here; blockifier 0.8.0's size-of and agree 0.2.7's rustix do not
  compile on the pinned nightly). x0x did not complete on this machine: the walk check's
  unoptimised build of its library of 40,000 lines had the compiler killed at 9 GB of 16, twice
  (and the first time the run ended there with no CBOM, the analysis done: it is written without
  the check now, `regress/driver-47`). Twenty-seven of the other thirty-two passed. One run did
  not end: imagepipe depends on qoi 0.4.1, in whose encoder each of three variables is made of
  the others' values of the turn before on every branch, and the driver's search for where a
  value comes from, which holds the places under way only along the way to each, multiplied its
  ways at every step. The driver caught a compiler panic in nine functions of rtnetlink, under
  huddle-core: a write through the `&mut` that `get_or_insert_with` returned into an `Option`
  field, recorded at the field with the path the pointer adds, read as a path of the `Option`'s
  own type. The walk check found a gap in two: the closure of arrow-array's `as_time::<T>` in the
  arm of a `match T::DATA_TYPE` that twenty-six of its instances never take, under noetl, which
  the walk rightly leaves out and a build without optimisation compiles; and `secp256k1_sys::
  strlen` under mostro-cli, called by a function the crate defines under a C name for its C
  library to call back, where no Rust code calls it and the walk did not start. And the verifier
  rejected five positions in two: an unknown algorithm named by the same package twice, where
  mostro-cli's build holds two versions of bitcoin_hashes and of secp256k1 (four); and in shin
  the SHA-512 of Ed25519, cited in a generic function nine descriptors reach by value, held to
  what the call making one of its three instances names.

The fifth batch's findings were first fixed as the others had been, by more rules in the
verifier (and by the driver citing a closure a function builds and also awaits where it
builds it). The re-run of all 119 packages on that build showed what such fixes cost: one of
the new rules accepted eight shifted positions in jj-cli, a package of the third batch. And of
the eighteen packages that failed in the third to fifth batches, seventeen had failed on the
verifier misreading a correct position, two on the generator. So the verifier no longer finds
out from the text where code is. The driver records what the compiler knows of every position
(its item, the macros that write it, each step of a generic chain), the CBOM carries that
record, and the verifier checks it against the bytes (How it works; `in-too-deep.md` 8). The
rules that found items by their paths, expanded macros, typed receivers and matched chain
steps by name are deleted, 3,800 lines of the verifier's 16,900 (the check of the record
that replaces them is 1,100), and the seven packages of the fifth batch it had failed on pass
without them. Running the labelled projects and the earlier packages again on the record
found three things the fixtures had not, each a fact about the record and none a shape of
source to search for: the items of a module a macro's invocation declares and another file
writes (tokio's `cfg_rt! { mod task; }`, reqwest's `if_hyper! { mod async_impl; }`), an
`.await` a procedural attribute writes at its own position (rustypaste), and an occurrence
two functions written by one macro call share (hpke). The self-test, which now shifts every span of the record as well
as every position, found two spans the verifier held to nothing (a closure's, a macro's
outermost invocation's): every span no name in the text holds now carries a fingerprint of
its line. All of them are in a fixture (`regress/verify-54`).

The sixth batch was the first run on the record, and did not pass either. Its findings are
of three kinds: what the text was still asked (which type a coerced expression has, how a
macro's path ends, which hash a generic function's own code runs), what the record left out
(another crate's free function a macro writes, a chain starting at a second owner), and two
outside the verifier (a constant the driver could not read, a build setting the walk check
did not override). Two things changed with them. A coercion to a trait object is now on the
record too, its span with a fingerprint, and the rules that read from a line which type an
expression has are deleted: the verifier, 16,900 lines before the record, is 13,800.
And the cases are no longer left to the packages to find: one fixture (`regress/verify-55`)
is built by construction, the same file of cases compiled in the program, in a crate it
depends on and a second time in the program, crossing who writes the code (a `macro_rules!`
of another crate, an attribute, a derive, a function-like procedural macro, one of these
writing another's invocation), what it writes (a free function, a method, an impl, a
closure, an `async fn`, a static, a boxed trait object), where the item's name comes from
and how the call is written. On the build the sixth batch ran on, the verifier rejected 61 of
its 125 positions: five of that build's nine findings (the batch's and the re-run's), and one
that no package had shown, a static a macro's invocation names. A kind of code not yet in it
is added there as a case first.

The seventh batch was the first run with the post-quantum crates in the knowledge base, on
forty packages chosen for the most part among their dependents. On that code, none of it seen
before, the CBOMs named ML-DSA in ten packages, ML-KEM in nine, SLH-DSA in six and X-Wing in
three; one package called a crate not modelled yet (pqcrypto-mldsa, added since), and one the
round-three Kyber, Dilithium and Falcon, which the registry has no names for (unknown
operations of their packages). The batch did not pass: its seven findings are all in what the
verifier still reads from the text and not from the record (how a macro's invocation is
written, which instantiation of a chain chooses a hash, what a trait object's trait is called,
where a pointer's variable is bound, which crate a path's first name is), and in one case in
how the analysis cites two calls together. Each is a case of the fixture built by construction
now, in the program, a dependency and a second binary: the build the batch ran on rejects 20 of
its 183 positions and accepts 2 shifted ones.

Both batches were run again on the build with these fixes. The thirty-five packages of the
seventh and the thirty-four of the sixth complete: 9,616 and 9,473 positions verified (3 within
a range), none mismatched, all 123,226 and 113,149 shifted positions and spans rejected (2 more
as true). On the sixth batch's packages the post-quantum entries name 57 assets in thirteen
packages where the build before named 24 in twelve (ML-KEM, and ML-DSA in one): ML-DSA in six
now, SLH-DSA in three, X-Wing in three, and eighteen in saorsa-pqc, which had 238 operations of
unknown algorithm (one is left). The re-run found one thing more, in the walk check and on
cargo-deb again. The flag that had forced every unit unoptimised also turned debug assertions
on in the units the manifest optimises on its own (the compiler takes them from the level where
cargo says nothing), so rayon-core was linked with a function only a `debug_assert!` calls; and
the check's build set its own compiler flags in place of the project's. That build now runs the
compiler through the tool, which keeps each unit's arguments as the analysed build gives them
and adds only what leaves the code as it is (`regress/driver-42`). The check had been run on
the fixtures by hand: its probes run it in every e2e now, and `cargo xtask e2e --walk` runs it
on every binary of the fixtures (no gap).

The eighth batch ran on that build: thirty of thirty-three, its three failures of two causes,
neither in the verifier (a project's own toolchain file, a closure in an `async fn`; both
fixed, `regress/driver-45` and `driver-44`). Its CBOMs name ML-DSA in nine packages, ML-KEM in
six and SLH-DSA in three.

What the batches could not show was looked for apart from them. The verifier was read for every
check that still derives a fact from the text, and each legal way of writing Rust such a check
might misread was written as a case, thirty in all. One of them found a miss that no package,
fixture or check had: a function of a modelled crate named in a table behind a reference in a
static or a constant (`static TABLE: &[(&str, HashFn)] = &[("sha256", <Sha256 as
Digest>::digest)]`) and called through a pointer taken out of the table was in no CBOM. The
driver recorded the functions named in a function's nested constants and not in a static's or a
constant's; the walk does not enter a modelled crate; and a pointer in memory was no call for
the boundary check. Five of the seven hashes of `regress/driver-43` were left out, silently.
The record is fixed, and the boundary check now reads what a reached static and the constants
of walked code hold in memory: a function of a crypto package there that code outside its own
crate names is cited by that naming or by a call through a pointer to it, or else by the check
itself, by name (with the record's fix taken out again, the check names all five). A second
case was built from that one: a crypto package that exports its own functions as values (a
table of function pointers, a constant, a public field of a static). The program names none of
them and calls no function of the package. A constant's function was followed to the package's
own naming and reported; a table's element, and any function the knowledge base does not name,
were in no CBOM, and there was no call for the boundary check to miss: MD5 run, the CBOM empty
(`regress/driver-46`, a copy of md5 with such items added; none of the 6,300 crate versions
downloaded to this machine exports one). The check now reads the value of every other crate's static or
constant that walked code names, as its type says, and each crypto function there that the code
can read is a call it accounts for, cited where the item is named. One behind a private field
of a crypto package's type is not: only that package's code reads it (the functions inside
aws-lc-rs's algorithm descriptors).

The other cases were false rejections of correct positions by the verifier, 45 on the build of
the eighth batch. Half were what the text says, read too narrowly, and those are read now: the
callee of a call through a pointer (a constant called by a path, nested indexes, a call's
result, a field's value, two lines), a macro's, a derive's or an attribute's path as the
grammar lets it be written (from the root, over two lines, a blank before the `!`, a raw
identifier, far below its `#[derive(`), a dependency renamed in a manifest table or by the
workspace, a table found by its module and not by its name alone, an alias in a macro's body
resolved where the macro is invoked. The other half were facts the text does not say where they
are used: which function a pointer holds when a constructor set the field or a function between
handed it on, what type a receiver has behind an alias of another file, which algorithm a
macro's invocation names. The verifier derived such a fact from the text as far as its rules
followed, and called what they did not follow a mismatch: that is where every batch had found
source its rules did not read. It now tells the two apart. What a position, and each position
its context cites, must read is checked as before, and a text that reads otherwise is a
mismatch. A value the text leads to and finds to be another is a mismatch too. A value the text
does not lead to is the compiler's word: the position is verified, and the fact is printed and
counted apart (`NOT SHOWN`, "verified with a fact the text does not show"), and the self-test
counts a shift that passes only so apart as well. The cases are in the fixture built by
construction (`regress/verify-55`): 286 positions verified, 21 of them with a fact the text
does not show, every shifted position and span rejected. Four later fixtures hold the one other
kind, a call a procedural macro puts at a token that is not the call (`regress/verify-62`,
`verify-63`, `verify-64` and `verify-68`, fourteen positions; the thirteenth and fourteenth
batches below). No position of the other 384 fixture outputs or of the labelled sets has such a
fact.

The ninth batch ran on the build with all of this: twenty-seven of thirty-two. Its CBOMs hold
14,616 verified positions, 8 more within a range and the 5 rejected ones; all 124,602 shifted
positions and spans were rejected, and none of the positions has a fact the text does not show.
They name ML-DSA in fifteen packages, ML-KEM in twelve and X-Wing in one. Its five failures are
of six causes, none seen before and each a probe now: a search with no end
(`regress/driver-49`: a search reads a bounded number of places), a path through a holder
(`driver-48`), code behind a branch on a constant (`driver-50`: the walk records what only such
a branch reaches, and the walk check names it), a function called by its C name from code that
is not Rust's (`driver-51`: where a build links such code, the walk starts at every such
function of its crates; the randomness that pqcrypto's C code draws through one is reachable
now, where it was only present), two versions of a crypto package under one name
(`analysis-198`) and an algorithm that reaches a generic function by value (`verify-56`). The
five packages were run again on the build with the fixes and pass: shin 212 positions verified,
imagepipe 8 (in two minutes), huddle-core 1,246, noetl 814 (its twenty-six closures named as
behind a constant) and mostro-cli 691, every shifted position rejected, no panic and no gap.
The earlier batches were not run again whole on this build: the machine has 16 GB, and a sweep
was stopped twice for want of memory. What was run again of them: the three packages the eighth
batch failed on, which pass (QuantCrypt, hdwallet, s3s), and the verifier over the CBOMs of the
sixty-seven packages of the seventh and eighth batches (no position rejected but hdwallet's two
in the CBOM made before its fix, no shift accepted).

A tenth batch ran on 24 November, on the build with the ninth batch's fixes: forty-three
packages by the same rule (the dependents of the post-quantum crates ranked next, every
ninety-fifth of the unseen dependents of the classical ones). Seven do not build here, with or
without the tool: four do not compile on the pinned nightly (superposition_core 0.120.1's
rustix 0.37, geph4-protocol 0.18.0's proc-macro2 1.0.56, courses 1.0.0's tera,
wasmtime-vfs-keyfs 0.1.1's io-lifetimes 0.7), two need what the machine does not have
(shavee_core 1.1.0 an OpenSSL its openssl-sys knows, gateryx 0.1.6 cmake for aws-lc-fips-sys),
and bcrypt-generator 0.1.0 asks, through bcrypt 0.5, for a `block-cipher-trait` whose versions
are all yanked. Thirty-two of the thirty-six that build passed: turbo-surf-deno-crypto 0.273.5,
tf-types 0.1.8, qserde 0.14.89, lupine-kem 0.1.0, lupine-sign 0.1.2, libcgc 0.1.1, aethel-core
0.7.6, qssh 0.6.0, spine-crypto 2.0.1, quantum-shield 0.3.1, dilithia-core 0.5.0, jacs-core
0.16.1, ejson 2.0.0, minipgp6-sign 0.0.6, rustolio-utils 0.1.0, vvva_crypto 2.13.0,
turbo-surf-render 0.8.6, encypher-c2pa 1.10.0, truthlinked-core 0.1.3, coins-bip39 0.17.2,
cosmrs 0.22.0, activitypub_federation 0.5.12, aube-util 2.11.0, aichat 0.30.0,
gemachain-program 1.8.2, unc-crypto 0.12.2, hapi-iron-oxide 0.1.0, p2panda-encryption 0.8.1,
geiserx_ts_tunnel 0.58.9, twine_lib 0.2.2, nklave-core 0.1.0 and better-auth-api 0.10.0 (built
with its `rustls` feature: its default one is the system's TLS). The thirty-six CBOMs as first
made hold 11,499 verified positions, 4 more within a range and 12 rejected ones; all 150,498
shifted positions and spans were rejected, and their fourteen binaries have no walk gap. They
name ML-DSA in twelve packages, ML-KEM in thirteen and SLH-DSA in four; qssh's FN-DSA (the
fn-dsa crates, which the knowledge base does not model) and libcgc's X-Wing (x-wing
0.0.1-pre.1, a version before those it covers) are operations of unknown algorithm of their
packages. The four failures are of four causes, none seen before and each a probe now. The
first stopped the batch at its thirtieth package, for lack of memory, and the cause was the
tool's: under waffles-solana-sdk 1.16.0 the driver held 13 GB after a minute and a half on
libsecp256k1 0.6.0, whose build writes its precomputed points into a file of one line, 4.7 MB
holding 49,152 calls. Every site carried the text of its line, and every position was looked up
through the compiler's display column, which reads the line up to the position. What a site
carries is bounded now (`regress/driver-53`): of a line longer than 4,096 bytes, the 160 bytes
to each side of its position, which the verifier cuts from the source the same way; positions
are read from the file's line table; and the verifier takes a position in a file an item
includes (`include!("table.rs")` inside a function) as inside that item. The crate is scanned
in twenty seconds; the package and the thirteen after it were run on the build with this. In
rustls-pure 0.15.5 the verifier rejected six positions that should not have been in the CBOM:
rustls's record layer starts with `<dyn MessageEncrypter>::invalid()`, a function of the trait
object's type that takes no `self`, and it was read as a call on an object and cited for the
three AEADs the package boxes as one (`regress/analysis-199`: the compiler's record says
whether a function takes `self`, and only one that does has a receiver). The verifier had
rejected them for a reason of its own, not reading the path of a trait object's type; it reads
one now, and holds such a member to what the text shows: a path called with no argument has
neither a receiver nor a value an object could be, and a member through a trait object cited
there is a mismatch. In nordisk-pairing 0.5.32 six uses were right and their positions wrong:
for `$ty::new()` inside `paste!`, which writes the path anew from the macro's fragment, the
compiler's span runs from the first place the macro writes `$ty`, lines above the call, to the
path's end (`regress/driver-52`: such a path is placed at the writing of the fragment it starts
at). In arcis-compiler 0.16.0 every position was verified and six items were not analysed: the
search for where a closure's arguments come from met a constant of a type parameter's type
(`F::ZERO` in a function generic over its field), which the instance's arguments evaluate while
its type is still `F`, and the compiler's conversion of a value read by a type with no layout
panicked (`regress/driver-54`: the type is the instance's before the value is read). The four
pass on the build with the fixes: 284, 274, 207 and 1,539 positions verified, every shifted one
rejected, no item left out and no gap. Three more things the run showed, which none of the four
questions asks. lupine-sign 0.1.2 passed with seventeen of its ML-DSA and SLH-DSA uses as
operations of unknown algorithm: the library is generic over the parameter set
(`ml_dsa::SigningKey<P>`), and the knowledge base's entries for the key types held only for a
parameter set the code fixes. A type that is its family whatever its argument is named by the
family now, the parameter set open and no security level stated (`regress/analysis-200`; nine
ML-DSA and nine SLH-DSA occurrences in the package), where a mode of a caller's cipher
(`cbc::Encryptor<C>`) stays unknown. The facts of one crate were not bounded per function: in a
compression function written round by round (bitcoin_hashes 0.14's SHA-512, 448 calls in one
body) every call's origin trees grew to their own bound, 760 MB of facts for the crate, which
the analysis of a program of seven lines (`regress/analysis-198`) took 3.5 GB to read back. The
trees of one body share 32,768 nodes now and are read to 17 each past them, the types that
close a bound are listed up to 64 (hybrid-array's `ArraySize` had put 165 MB in every build
with it), and `cargo xtask e2e` fails a fixture whose facts for one crate pass 128 MB; no
fixture output and no labelled score changed with the bounds. And the verifier was slow where
many positions lie in macros, a quarter of an hour for the self-test of turbo-surf-deno-crypto
(839 positions, 31,375 shifts): it compiled the same patterns for every position and formatted
every package's name for every location. It takes 45 seconds now, its output the same byte for
byte.

An eleventh batch ran on 24 and 25 November, on the build with the tenth batch's fixes:
forty-three packages by the same rule. Eight do not build here, with or without the tool: four
do not compile on the pinned nightly (blazehash 0.2.5's sqlx-core and cnctd_server 0.6.6's
redis, on what the never type falls back to; wasmer-runtime-core 0.17.1, on a feature the
compiler has removed; drogue-tls 0.6.0, on one it has not made stable), hashiverse-lib 1.1.2
asks moka for a trait the version it resolves to does not have, and three need what the machine
does not have (lobstercove-lichen-core 0.5.229 what librocksdb-sys builds with, golem-cli 1.3.1
an OpenSSL its openssl-sys finds, blueprint-auth 0.2.5 cmake for protobuf-src). Thirty-one of
the thirty-five that build passed on the first run: ling-crypto 2030.1.13, craton-hsm 0.11.2,
libtut 0.0.1, minipgp6-encrypt 0.0.6, tenzro-crypto 0.2.0, cardanowall 0.12.0,
derec-cryptography 0.1.0, huddle-protocol 2.2.1, supso-project 1.0.0, arkhe-kernel 0.15.0,
mldsa-core 0.4.1, truthlinked-staking 0.1.2, apfsds-crypto 0.4.0, noxtls-crypto 0.2.20,
portal-solutions-sky 0.1.0, paraxiom-pqc 0.2.1, kotva-core 0.2.0, subxt-signer 0.51.1, dotslash
0.5.7, wacore-noise 0.7.0, pkgar 0.2.4, bsv-wasm 1.3.4, erc20_payment_lib 0.5.1,
gemachain-crate-features 1.8.2, radicle-keystore 0.2.0, matrix-sdk-search 0.19.1,
spatial-hasher 0.1.7, mockforge-ui 0.3.249, zpdf-document 0.23.0, discret 0.6.2 and
cyaxon-authifier 0.1.0. Their CBOMs, with rhwp's and blue-lang-runtime's as first made, hold
10,688 verified positions and 10 more within a range, none rejected; 91,046 of 91,050 shifted
positions and spans were rejected, and their eight binaries have no walk gap. They name ML-DSA
in twelve packages, ML-KEM in thirteen, SLH-DSA in four and X-Wing in one. The four failures
are of four causes, none seen before. Two stopped the batch for lack of memory, and both causes
were the tool's. rhwp 0.9.1 is one crate of 957,000 lines, on which the compiler alone takes
5.5 GB: the driver held 11.4 GB when the run's limit stopped it. Its scan took twelve minutes,
because a closure's enclosing body was converted from the compiler's anew for every captured
variable and every local asked the crate's recursive types again whether they hold a cell: the
last four bodies are kept and the answer is per type, and the scan takes 139 seconds. The
argument records of the calls between the program's own functions, 49,133 of them in 937 MB,
took the driver 4 GB to hold: they are written to a file beside the facts, and the analysis
reads those of the functions it asks about. And the walk check built the program while the
facts were loaded, 6.8 GB beside the compiler's 5.5: it builds first. The package passes: 949
positions verified, all 8,874 shifted ones rejected, no gap in its three binaries, in eighteen
minutes and 8.9 GB. nab 0.13.3 depends on cranelift-codegen 0.135.10, whose build generates one
function of 30,712 basic blocks, generic over a context whose types the driver cannot look
into: every write a call may make through a `&mut` it is handed defined every place the body
lends, 6.3 million definitions with a bit for each in each block, and the driver held 13.5 GB a
minute into the crate. Nothing of it is cut and all of it is held differently
(`regress/driver-56`, such a function written small: a place has one such definition with the
list of the writes that make it, which the places written alike share; the sets are computed in
sweeps in reverse postorder; whether a value at entry is overwritten is read off the
dominators): the crate takes 21 seconds and 1.5 GB. nab's default features need cmake; built
without the one that does (`impersonate`), it passes with 1,528 positions verified, all 12,803
shifted ones rejected and no gap in its three binaries, in twenty minutes and 7 GB. In
blue-lang-runtime 0.0.282 every position was verified and four shifted ones were accepted. The
package names `Hmac::<Sha256>::new_from_slice` and `Hmac::<Sha512>::new_from_slice` as function
pointers in two arms of a `match`, one below the other in the same column, and the detail of a
call through such a pointer gave where it was named as a position alone: moved one line, it
names the same function. A naming carries the start of its text and its line's fingerprint now,
as every other position a detail gives (`regress/verify-57`), and all 6,018 shifted positions
of the package are rejected. In cryptomator-rs-crypto 0.1.2 the verifier rejected one correct
position. jwt 0.16 has one generic function, `get_hmac_with_data`, that its `sign` and its
`verify_bytes` both call, and the package signs with HMAC-SHA-256 and verifies with one of
three boxed keys. The instance for SHA-256 is one, and its uses cite the caller the walk
reached it through first, `sign`; at the call in `verify_bytes` SHA-256 is chosen too, and the
uses that cite that position are those of SHA-384 and SHA-512, each of another instance of
`verify_bytes`. The verifier holds an instantiation that uses of its kind cite to be cited by a
use of its own asset; it holds that among the uses reached through the same instance now, those
whose chain goes on as the instantiation's own (`regress/verify-58`), and the package passes:
165 positions verified, every shifted one rejected. A fifth was found by the probe written for
the second. A function that assigns an algorithm to a field of its own parameter and then reads
it (`cfg.alg = &SHA512; digest(cfg.alg, d)`) had its position rejected, the parameter read as a
value from elsewhere: the verifier follows such an assignment as it follows a variable's, and
takes it as the value where it is made on every way to the read and the parameter is not used
between the two. One more thing the run showed, which none of the four questions asks.
mockforge-ui 0.3.249 is 816 crates and 2 GB of facts, and the analysis held 10.7 GB on them:
what functions return and write, the calls between them and the stores into fields are two
thirds of those facts, and they were held twice, as read and in the index made of them. They
are moved into the index, which holds 7.2 GB on the same build and makes the same CBOM, byte
for byte.

A twelfth batch ran on 25 November, on the build with the eleventh batch's fixes: forty-four
packages by the same rule. Three do not build here, with or without the tool: axiom-cli 0.1.17
resolves to a rustix that uses attributes of the compiler's own which the pinned nightly no
longer has, buttercup-crypto 0.4.2 requires an aes-soft whose one version is yanked, and
walletconnect-sdk 0.2.3 needs an OpenSSL its openssl-sys finds. Thirty-nine of the forty-one
that build passed on the first run: zks_pqcrypto 0.1.0, qs-crypto 0.1.0, hide-sign 0.10.0,
simien_crypto 0.1.2, fireplace-crypto 0.3.0, trustformers-mobile 0.2.1, algochat 0.6.0,
alibi-plugins 0.13.0 (with its `rustls` feature in place of the default one, which needs
OpenSSL), nexusq-core 4.1.2, pqrascv-core 0.2.0, qorechain-pqc 0.2.3,
philharmonic-connector-client 0.1.2, ope-transport 0.1.0, hyde-core 0.2.0, oc-crypto 0.0.7,
ope-e2e 0.1.0, kavach-pq 0.1.5, philharmonic-connector-service 0.2.2, lukuid-sdk 1.0.21,
blockle-core 0.8.0, alloy-signer-aws 2.6.1, siwe 0.6.1, davey 0.2.0, affinidi-did-common 0.5.0,
zebra-chain 16.0.0, fselect 0.10.4, vyre-driver 0.7.2, vsmtp-auth 2.2.1, redox_pkgutils 0.1.9,
stdtx 0.7.0, axum-webtools 0.1.63, smol_db_common 1.4.0, dotenv-vault 0.1.2, dechdev_rs 0.1.50,
dusk-node-data 1.7.0, rego 0.1.1, otoroshictl 0.0.20, argus-scanner 0.3.1 and fatima-core
0.0.1. The forty-one CBOMs as first made hold 13,696 verified positions and 5 more within a
range, with 13 rejected, every one of them a correct position; all 164,736 shifted positions
and spans were rejected, and the eight binaries have no walk gap. They name ML-DSA in thirteen
packages, ML-KEM in sixteen, SLH-DSA in four and X-Wing in one. The two failures are of two
causes, both the verifier's reading of what macros write, neither seen before. In
ic_object_store 1.4.4 it rejected one position. ic-transport-types 0.49.3 computes a request's
id with a serde serializer that hashes every field, and the type it is given derives
`Serialize`. serde's derive gives the call that serializes a field the span of the field whole,
and a field starts at its documentation comment: the compiler has the call that instantiates
the hashing `serialize_field` on a `///` line, where the verifier, reading comments as no code,
found none. A documentation comment is a token of the item it is on, the attribute it stands
for; a step of a chain may be at one where a procedural macro writes the caller, and nowhere
else (`regress/verify-59`, where a derive also puts a hash call itself at such a span: that
occurrence the driver cites at the derive, as before). In anyhide 0.16.0 it rejected twelve,
all in code that derive-deftly's templates write (the key types of tor-key-forge 0.37.0, the
tunnels of tor-circmgr 0.37.0). `define_derive_deftly! { Name for struct: .. }` writes a
`macro_rules!` for the template, which the compiler has defined at that invocation, and the
verifier held a macro's definition to read `macro_rules!` or `macro`, or to be a procedural
macro's function. And where a `macro_rules!` writes the struct with its `#[derive(Deftly)]` and
`#[derive_deftly(Name)]`, the compiler has the template invoked at the name inside the
attribute, with no expansion of `Deftly` between the two, and the verifier held an invocation
to read `name!` unless a procedural macro's expansion is around it. A macro may be defined at
the invocation that writes it, and an invocation cited inside an attribute is the doing of
whatever reads the attribute (`regress/verify-60`). Both pass: ic_object_store with 1,113
positions verified and all 10,186 shifted ones rejected, anyhide with 1,421 and 17,086. And one
more thing the run showed that the four questions do not ask. smol_db_common 1.4.0 and
kavach-pq 0.1.5 took twelve and thirteen minutes, for lock files of 88 and 251 packages. Both
depend on chrono-tz. The time zones of the 0.8.6 that smol_db_common resolves to are 596
constants that store 131,506 fields, and each record was added to its crate's, and then to its
field's in the analysis, by searching the list for one like it: 727 seconds in the driver and
192 in the analysis for that one crate. A list longer than sixteen records has an index of
where they are, exact, and the two packages take 21 and 57 seconds with the same CBOMs.

A thirteenth batch ran on 25 November, on the build with the twelfth batch's fixes: forty-three
packages by the same rule (a forty-fourth it draws, aloo, has no released version). Eight do
not build here, with or without the tool: truthlinked-state 0.1.3 and geph4-binder-transport
0.2.3 resolve to a rustix that uses attributes of the compiler's own which the pinned nightly
no longer has, new-home-proxy 0.1.2 to a socket2 that nightly does not compile, and five need
what the machine does not have (basil 0.7.1 and basil-core 0.7.1 the `protoc` that basil-proto
builds with, yubikey 0.8.0 and rite-piv 0.9.0 the PC/SC library of pcsc-sys, inngest 0.1.1 an
OpenSSL its openssl-sys finds). Thirty-four of the thirty-five that build passed on the first
run: tholos-pq 0.3.0, fileluya-crypto 0.1.0, minipgp6-ac2 0.0.4, rustls-pq-addon 0.0.2,
qorechain-sdk 0.15.0, q-periapt-backends 0.2.0, mcp-filesystem 2.3.0, bssh-russh 0.63.1,
oxicrypto-pq 0.3.0, southstar-http 1.0.11, aegis-crypto 0.1.5, majik-key 1.1.1, mldsa65 0.4.1,
qorechain-rdk 0.9.1, rustls-provider-rustcrypto-pq 0.1.1, kiss_chat_core 0.7.2,
quantacipher-core 2.1.0, tidex6-core 2.18.0, alloy-signer-gcp 2.6.1, polymarket-client-sdk
0.4.4, twenty-first 3.1.1, wedpr_l_crypto_zkp_utils 1.2.0, provekit-whir 0.2.0, lockboxer
0.3.0, br-pay 0.1.9, microkv 0.3.0, royalguard 0.4.9, keyphrase 0.1.4, sos-signer 0.18.0,
golang-ipc-rs 0.1.1, pocket-relay-utils 0.1.1, rclonedecrypt 0.4.11, sekejap-lang 0.20.0 and
spectre-rs 0.1.0. The thirty-five CBOMs as first made hold 12,627 verified positions and 3 more
within a range, with 1 rejected, a correct one; all 130,442 shifted positions and spans were
rejected, and the eight binaries have no walk gap. They name ML-DSA in thirteen packages,
ML-KEM in sixteen and SLH-DSA in two. The failure, in l402_middleware 2.3.6, is of the family
the twelfth batch's were: what a procedural macro writes, and where the compiler has it.
rocket's `#[launch]` over `fn rocket() -> Rocket<Build>` writes the program's `main`, which
awaits what the function returns, and gives that `.await` the span of the function's return
type. A step of a chain through the poll there is at `Rocket<Build>`, and the verifier held
what the compiler records as an `await` to read `.await` wherever no procedural macro's
expansion is around it; around this one there is none, the token is the source's. Two batches
running having found one case of the family each, it had been looked for by construction while
this batch ran, and two more were found that no package had shown: a macro that a derive or an
attribute defines (`regress/verify-61`), and a call a procedural macro writes at a token it was
handed that is not the call, the literal of `hashed!("text")` or of `#[route("/x")]`, the name
of the function an attribute is on (`regress/verify-62`). The compiler has such a call at that
token, in the source's own context: the position is right, and its text shows a literal or a
definition, which the verifier called a mismatch. Two records say where a procedural macro
writes: the one of the item, which names the macro that writes it, and one the driver now makes
of every invocation of a procedural function-like macro in the source, carried by each position
in it (`in the input of macro hashed! at ..`; facts 50). In either place a position that does
not read its callee is verified with that fact not shown, counted apart, and a rewrite or an
invocation is read as whatever token the macro put it at (`regress/verify-63` is rocket's case
written small); anywhere else both are mismatches as before. l402_middleware passes: 2,079
positions verified, all 21,695 shifted ones rejected, none not shown. The batch showed a cost
as well, as the two before it. provekit-whir 0.2.0 took twenty-two minutes, twenty of them in
the analysis: its build has 18,660 instances whose summaries the driver's bound leaves
unrecorded (arkworks' field arithmetic, generic over the field), and two questions asked at
every step of a value's search, whether a function is an instance of such an item and whether a
trait method has such an implementation, read all of their names each time. Both are sets made
once, and the package takes three and a half minutes with the same CBOM.

A fourteenth batch ran on 25 November, on the build with the thirteenth batch's fix: forty-two
packages by the same rule (a forty-third it draws, pqrascv-hardware, has no released version).
Five do not build here, with or without the tool: ckman-core 0.2.3 needs the PC/SC library of
pcsc-sys, thrussh-keys 0.45.0 the libsodium its libsodium-sys finds, php-ext-pqcrypto 0.3.3 a
PHP for ext-php-rs and blockle-node 0.8.0 a clang for the C code of rs-x11-hash, and safe_core
0.43.1 requires a crossbeam-channel whose versions are yanked. Thirty-five of the thirty-seven
that build passed on the first run: dcp-ai 2.14.0, mldsa44 0.4.1, tekflash-core 0.0.12,
libsoliton 0.1.4, mldsa87 0.4.1, rtao-upstream-core 0.490.1, majik-signature 1.3.2,
tidecoin-consensus-core 0.2.0, majik-file 1.1.0, empoorio-sdk 0.2.0, kinetic-kid 0.2.0,
ml-signify 0.4.0, kinetic-verify 0.2.0, qv-core 4.3.10, pq-jwt 0.2.2, kinetic-types 0.2.0,
thruput-test-vectors 0.64.0, entropa-core 0.1.3, kv-index 2.1.0, txtx-addon-kit 0.4.16,
longport-httpcli 5.0.0, ethsign-crypto 0.3.0, wnfs-common 0.3.0, greentic-runner-host 1.2.2,
wg_netmanager 0.5.1, ferveo-gear-tdec 0.8.0, stack_test_epic_keychain 3.0.3, nakatoshi 0.3.1,
tor-client-lib 0.3.2, no-way 0.4.1, equs-one-core 0.2.3, atlas-seed-phrase 3.0.1, underskrift
0.1.4, oxicrypto-kdf 0.3.0 and logshare 0.1.1. The thirty-six CBOMs as first made hold 12,556
verified positions and 1 more within a range, with 9 rejected; all 112,693 shifted positions
and spans were rejected, and the five binaries have no walk gap. They name ML-DSA in eighteen
packages, ML-KEM in nine and SLH-DSA in two. Of the two that did not pass, raddy-http 0.8.0 is
the limit of two versions of one crate (Limitations): its build holds rcgen 0.13.2, on ring,
and rcgen 0.14.10, on aws-lc-rs, and the P-521 signing of the second is attributed to the
first's functions as well. The verifier rejects those nine positions (the path names ring,
which provides no P-521); and for four positions of the second it looks for a function only
that version declares in the text of the first, finds none and counts the fact as not shown,
the batch's only positions so, none of them a procedural macro's. The other, iroh-services
2.0.0, did not build with the driver, and built, failed the verifier: two causes, neither seen
before. The compiler stopped in the driver (`Instance::mono: .. Option::Some::{constructor#0}
has type parameters`). What only code behind a branch on a constant reaches is followed apart
from the walk, and there an instance the compiler gives no body for was asked which function
the build defines under its symbol, as a declaration of an `extern` block is. `Some` passed as
a function (`.map(Some)`) is a constructor: it has no body to give either, and, of a generic
type, no symbol without its type arguments. Only a declaration of an `extern` block stands for
a function defined elsewhere, and the question is asked of nothing else (`regress/driver-57`).
Built, the package had two positions rejected, both of Ed25519 keys of rcan 0.4.0 that a field
serializes `#[serde(with = "verifying_key_serde")]`. serde's derive writes a wrapper whose
`serialize` calls the module's, and gives that call the span of the literal it parsed the path
from; the module's function is generic over the serializer, so that call instantiates it: a
step of the chain at a string literal, where the verifier, reading a literal as no code, found
none. It is the twelfth batch's documentation comment with another token: a literal is one, and
a step may be at one where a procedural macro writes the caller, and nowhere else
(`regress/verify-67`). iroh-services passes: 706 positions verified, all 5,855 shifted ones
rejected, none not shown. While the batch ran, the family the last three batches' failures are
of was looked at by construction again, and three more cases were found that no package had
shown. A procedural function-like macro that a declared macro invokes, `macro_rules! via {
($e:expr) => { pm::hashed!($e) } }`: the call the procedural macro writes at the token it was
handed is at `$e` in the declared macro's code, or at the token in the source that macro handed
on, and the procedural macro's invocation is nowhere around it. The driver's record says, of a
site in the invocation of a declared macro whose code leads to a procedural one, that
invocation and each it leads to (`in the input of macro via! at .., which invokes macro
pm::hashed! at ..`; facts 51), and the verifier reads each (`regress/verify-64`). The declared
macro may be another crate's, as `tokio::select!` is, and the procedural macro's invocation is
then in that crate's file (`regress/verify-68`). An invocation is named only where the source
reads as one: the template macro that derive-deftly's `define_derive_deftly!` writes invokes
`derive_deftly_engine!`, the compiler has that invocation where `define_derive_deftly!` is
invoked, and naming it there had the full run reject two positions of `regress/verify-60`
before any of this was committed. A token a declared macro hands on a second time, with no
procedural macro at all: `first!(compute)`, whose code is `last!($f)`, whose own is `$f(data)`,
`$f:tt` in both. The compiler gives such a token the place of the second macro's `$f` and no
expansion, the same span for every invocation, and the call was cited at a position inside the
macro's definition, in the function that invokes the macro. The compiler's table of
metavariable spans says the span is such a place, and the code around it, the call it is the
callee of, is in the expansion that wrote it there (`regress/verify-65`; what is left where
nothing is around it is under Limitations). And a function handed to a declared macro as an
identifier and held as a pointer, `val!(compute)` with `$f:ident`, whose naming the verifier
looked for in the macro's code and not in the invocation (`regress/verify-66`).

After the third batch every earlier package that builds here was re-run, versions pinned, on
the builds pushed on 11 November (64 of them; jj-cli on the build before, as clean): all
complete; 18,275 positions verified and 93 within a range, none mismatched; all 98,256
shifted positions rejected (22 more land on a call of the same instance, as true); no walk
gap in their 26 binaries (rustic-rs's 178 functions linked through a trait object nothing
calls are counted apart); 14,919 calls into crypto packages, 4,356 cited, 39 cited by the
check by name, 244 as unknown, 10,280 excused. That re-run caught two regressions the
fixtures had not (pgp's hashers boxed by `Box::<T>::default()`, a shifted position accepted in
biscuit-auth), fixed before it ended. After the fourth batch's fixes, which are the verifier's,
the CBOMs of all 86 packages were verified again: 24,402 positions verified and 105 within a
range, none mismatched; all 124,318 shifted positions rejected (25 more as true). What stays unknown in them is what the knowledge base
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
  build matched by its own version; rsa 0.9 to 0.10; ring 0.17, aws-lc-rs 1, rustls 0.23,
  jsonwebtoken 9 to 11, rand 0.8 to 0.10, md5 0.7 to 0.8, siphasher 0.3 to 1. Post-quantum:
  ml-kem 0.2 to 0.3, ml-dsa 0.0.4 to 0.1, slh-dsa 0.0.3 to 0.2, x-wing 0.1 (a hybrid: its
  ML-KEM-768, X25519 and SHA3-256 are listed as its components), fips203, fips204 and fips205
  0.4 to 0.5 (HashML-DSA and HashSLH-DSA named apart), pqcrypto-mlkem 0.1 and pqcrypto-mldsa
  0.1, and the ML-KEM and ML-DSA descriptors of aws-lc-rs. A pre-release counts as the
  release it leads to (rsa 0.10.0-rc.18 is rsa 0.10). Other versions and unmodelled crypto
  packages are reported, with their operations as unknown and the reason.
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
  (`HMAC` of a caller's hash; `ML-DSA` on an `ml_dsa::SigningKey<P>` of a caller's parameter
  set, with no security level, where a mode of a caller's cipher, `cbc::Encryptor<C>`, is
  unknown: `regress/analysis-200`). A function only its own crate can name is the exception:
  where each call the crate makes gives a parameter a type that is no parameter of the caller's,
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
  A path a procedural macro rebuilds from a macro's fragment (`$ty::new()` inside `paste!`) is
  cited at the writing of the fragment it starts at, not at the fragment's first. An
  occurrence carries its source line whole up to 4,096 bytes; of a longer one (generated code
  on one line) the 160 bytes to each side of its position.
- *Trait objects.* A call on a trait object of a crypto trait (`hasher.update(..)` on a
  `Box<dyn DynDigest>`) is one of the types the build makes such an object of, anywhere the
  walk reaches (a function of the object's type that takes no `self`, rustls's
  `<dyn MessageEncrypter>::invalid()`, is no such call): each the knowledge base names is a
  member (`member: dyn`, with its coercion), and an unknown stands beside them where one is not
  named. The set is of the build, not of the call: two functions each boxing other hashes share
  it. A closure called through a `dyn Fn` object gets the arguments of the calls made through
  such objects, beside an unknown: where else the object may be called from is not followed.
- *Names and parameters.* BLAKE3 is `BLAKE3-256` for `hash` and `keyed_hash`, `BLAKE3` for key
  derivation and XOF output. A library's generic API that sibling binaries instantiate gets no
  "callers choose" unknown for the library itself.
- *Parameters.* `rcbom:param:*` properties are not scored against the labels' `params`.
- *Quantum security level.* `nistQuantumSecurityLevel` is what the tables of NIST IR 8547 state
  for the algorithm's name, and nothing is derived beyond them. It is not weighed against what
  the name does not say: the random generator behind ML-DSA-44 (category 1, not 2, with one of
  less than 192 bits), the output length asked of a SHAKE, how a hash is used (the level is its
  collision category; the preimage category is in `rcbom:quantum-level:source`). An algorithm
  built on one that has a level (HMAC-SHA-256, HKDF, AES-CMAC) has none of its own, nor has one
  outside NIST's standards (ChaCha20-Poly1305, BLAKE3, Argon2), and X25519 is level 0 as the
  elliptic-curve Diffie-Hellman it is, though the report's table names the NIST scheme.
- *The verifier* is independent of the analysis, not of the compiler. Where code is (the item
  around a position, the macros that write it, what a step of an instantiation chain is,
  where a value becomes a trait object) it takes from the compiler's record in the CBOM and
  checks against the bytes; it does not ask the text again which function the code at a
  chain step calls, with which type arguments, nor which type a coerced expression has.
  Until 20 November it derived all of that from the text by rules, and each batch of unseen
  packages found source shapes the rules misread (Unseen packages). From the text it still
  reads what a path at a position names (through imports and aliases), the descriptor a call
  reads, witnesses in the program and its dependencies, bindings, manifest entries and a
  library component's name, version and purl. What a position must read (a name, an alias, a
  key) it holds the text to. What a value is where it is used (the function a pointer holds, a
  receiver's type, the descriptor an argument carries) it checks where the text leads to the
  value; where the text does not, it counts the fact as not shown (`NOT SHOWN`) and its word is
  only that the positions cited read as claimed: a wrong function claimed for a pointer whose
  way from its naming the text does not show would pass, counted so. So would a wrong callee
  claimed at a token a procedural macro was handed (a literal, a name being defined), where
  the text shows only that such a macro reads the token. The standard library's
  witnesses are not read, and a position in the standard library, which
  is compiled with functions put into their callers, is not held to the item that runs it.
  It shares the knowledge base with the analysis, and its naming of a descriptor
  (`static_names`). It does not check the reachability tier, artifact tags, provenance
  classes, which of an asset's functions a call performs, set labels (member kind,
  `possible`, `one of N`), the reason of an unknown, or a registry name outside boundary
  models; and it cannot see an operation the CBOM leaves out (`in-too-deep.md` 8). A method
  called down a chain on results of calls of the same name is verified within that range.
  Three fixture positions it cannot confirm are listed in `verify-known` files, each checked
  by hand.
- *Two versions of one crate.* Values are followed across functions by their paths, and a path
  names a crate by its name: where a build holds two versions of a crate (apple-codesign 0.29.0
  holds rustls-webpki 0.101.7 and 0.102.8, both `webpki`; raddy-http 0.8.0 holds rcgen 0.13.2
  and 0.14.10), what one version's functions pass and return is attributed to the other's too.
  The members found are then too many, never too few, and a witness function can be named in
  the wrong version: the verifier rejects those positions (22 in apple-codesign, 9 in
  raddy-http), and where it looks for a function only one version declares in the text of the
  other, it finds none and counts the fact as not shown (4 in raddy-http). The driver records
  which crates each unit is compiled against; the analysis does not use it yet.
- *A token handed on twice.* A declared macro that hands a token on as it is (`$f:tt`) to
  another that does so again leaves the compiler with the place of the second macro's `$f` for
  it and no expansion, the same span for every invocation. The driver takes the expansion from
  the code around the token (the call it is the callee of, the statement it is in), or, with
  nothing around it, from the compiler's table of metavariable spans where the macro's
  expansions all come from one invocation (`regress/verify-65`). A token that is all of its
  statement, or a call a procedural macro puts whole at such a token, in a macro invoked from
  several places, stays at a position in the macro's definition: the compiler records nothing
  that tells the invocations apart, and the verifier rejects the position. No package of the
  batches has one.
- *Toolchain.* The driver needs its pinned nightly. Layer 2 compiles the project, so the
  project's build scripts and procedural macros run. A published package whose `Cargo.lock`
  locks versions the nightly no longer builds (bore-cli 0.6.0's proc-macro2 1.0.56, cargo-vet
  0.10.3's rustix 0.37.20) does not
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
