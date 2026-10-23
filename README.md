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
  functions that are algorithms, operations, uses, argument roles, provenance sources, and
  boundary models.
- **The verifier** reopens every cited file and checks each position, and the details it can
  read in the code (the token named, the item around it, the descriptor read by the call,
  bindings in scope, closures, macro rules, coercions, witnesses); `--self-test` shifts every
  position by a line and a column and counts how many shifts it rejects. What comes from the
  walk or the value search (tiers, provenance classes, set labels) it does not check
  (Limitations).

## Build

```
rustup toolchain install nightly-2026-09-25 --component rustc-dev,llvm-tools,rust-src,clippy,rustfmt
(cd crates/rcbom-driver && cargo build)      # the compiler driver, pinned nightly
cargo build                                    # the CLI and libraries, stable
```

## Use

```
cd <cargo project>
<repo>/target/debug/cargo-cbom cbom -o cbom.json            # Layers 1 and 2
<repo>/target/debug/cargo-cbom cbom --manifest-only -o ...  # Layer 1 only, nothing compiled
<repo>/target/debug/cargo-cbom cbom --features f1,f2 ...    # the artifact other features build
<repo>/target/debug/cargo-cbom cbom verify cbom.json --self-test
RCBOM_DEBUG=1 <repo>/target/debug/cargo-cbom cbom -o ...    # also print the driver's caught panics
```

In the repository, `cargo xtask summary <path>/cbom.json` prints a CBOM as one sorted line per fact
(the form of the golden files).

The CBOM describes the built artifact: the host target, the selected features and the
`release` profile (`--profile` to change it). Tests and build scripts are not in it.

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
cargo xtask suite <out> tests/fixtures/suite/*       # the ground-truth suite: 53 programs, 107
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
jwt and ssh-key the verifier). The review crates were chosen and labelled blind by an
independent reviewer of the whole project, then used for the fixes its review found.

| set | what | result |
|---|---|---|
| ground-truth suite | 53 programs, 107 call sites | 104 correct, 3 less-specific, 0 wrong, 0 miss |
| corpus | realapp, minisign, rcgen, jwt-cli, rage, xh | Layer 1: 106/106 crypto packages found, none reported that is not; Layer 2: 28 live sites: 16 correct, 6 honest-unknown, 4 miss, 2 wrong (jwt-cli's insecure decodes, against labels amended after the runs: Limitations); 10 dead sites (features off), nothing reported there |
| held-out | boringtun, dufs, totp-rs, gcp_auth, rustic_core, ssh-key, jwt | Layer 1: 112/112 found, none reported that is not; Layer 2: 86 live sites: 38 correct, 4 less-specific, 40 honest-unknown, 4 miss, 0 wrong; 10 dead sites, nothing reported there |
| review | rbw 1.15.0, biscuit-auth 6.0.0 (the reviewer's labels) | Layer 1: 67/68 found, none reported that is not (the one not found, quinn-proto, is in rbw's lockfile but not in its build); Layer 2: 33 sites: 28 correct, 1 less-specific, 3 honest-unknown, 1 miss, 0 wrong |
| rusi fixtures | three labelled cdxgen fixtures, against rusi 4.1.1 | cargo-cbom: 14/14 core sites found, 19/19 reported correct, 14/14 fully named, key provenance 10/10; rusi: 12/14, 12/15, 7/14, 0/10 |
| evidence | every cited position, `verify --self-test` | fixtures (300 outputs, the suite's included): 19,398 positions verified, and 4 the verifier cannot confirm (each checked correct by hand); corpus 1,840, held-out 1,295 and review 799, all verified; every one of 94,350 positions shifted by a line or a column rejected |
| walk vs linker | code each binary links that the walk did not reach (`--check-walk`) | gap 0 on realapp, jwt-cli, rage, rage-keygen, xh, dufs, rbw, rbw-agent |
| cost | one cold run per project on 6 cores: compilation, analysis, walk check | 4 s (totp-rs) to 177 s (xh) for the corpus and held-out projects, 347 s for rbw; peak memory of the process tree 0.3 to 3.5 GB (4.8 GB for rbw); reruns reproduce each CBOM exactly |

Where it is not exact, the CBOM says so instead of guessing:
- **Misses.** The corpus misses are rage's calls into age that set up its encryptor
  (`with_user_passphrase`, `with_recipients`) or take no arguments
  (`read_or_generate_passphrase`); age's own operations, the passphrase's draw among them, are
  cited inside age. In the held-out set, three are dufs's `Uuid::new_v4` (the draw is reported at
  uuid's own call), and one is ssh-key's RSA key generation, which is reported as RSA
  private-key material, not as the scheme the label names. In the review set, it is rbw's
  `Uuid::new_v4`.
- **Wrong.** jwt-cli's two `decode` calls with signature validation disabled verify nothing; the
  CBOM keeps their HMAC candidates with a note that validation is disabled on a way to the call
  (Limitations), and the labels, amended after the runs to the strict reading of R15.2, allow
  only HS256 there.
- **Honest unknowns.** In the held-out set these are mostly crates at versions the knowledge base
  does not cover: the newer RustCrypto generation (sha2 0.11, hmac 0.13, rand 0.10, scrypt 0.12,
  md5 0.8, ed25519-dalek 3), and blake2, which it does not model (boringtun's BLAKE2s). They are
  reported as operations of unknown algorithm, with the package and the reason. The others are
  types a library's callers choose, and calls into crypto packages the knowledge base does not
  model (age's `decrypt`, digest_auth's `respond`, totp-rs's `generate_current`, ssh-key's
  `try_sign`).

## Limitations

What the CBOM covers, what it reports differently from a reading of the labelling rules, and
what it does not do yet. A reviewer meeting one of these meets a known limit, not a new finding.

**Scope, by decision**
- The built artifact only: one target, one feature set, the `release` profile. Tests, build
  scripts, examples, and code that other features or targets would compile are not covered.
- Hand-rolled algorithms, unsafe code, certificates loaded at run time, and security
  configuration (which TLS suites a configuration allows) are out of scope. minisign's own
  Ed25519, BLAKE2b and SHA-512 are such code: its labels hold only its random draws and scrypt.
- Knowledge-base coverage: the RustCrypto 0.10 generation, ring 0.17, aws-lc-rs 1, rustls 0.23,
  jsonwebtoken 9, rand 0.8 to 0.9. Other versions and unmodelled crypto packages are reported,
  with their operations as unknown and the reason.
- Layers 3 to 5 (purpose, vulnerabilities, policy) are designed, not built: no occurrence says
  whether it protects anything (`rcbom:usage` is Layer 1's usage tier).

**Conventions: where the CBOM differs from a label written by the rules**
- A call into a crypto package the knowledge base does not model, made from the program or a
  dependency that is no crypto package, is an operation of an unknown algorithm, but for what
  sets something up (a constructor, conversion or accessor; a call taking nothing to operate on)
  and a step of a stream. Calls between crypto packages are their internals. Where such a
  package's own code calls modelled crates, those calls are cited inside it too (rage's call
  into age is an unknown at rage's line, and age's ChaCha20-Poly1305 is cited in age). Inside
  algorithm crates nothing is cited: their internals are folded into the call into them.
- Streaming steps the knowledge base lists (`Digest::update`, `Mac::update`, ring's
  `Prk::expand`) are reported beside the call that finishes the stream; the rules label only
  the latter (the scorers count them as unlabelled uses, never as wrong).
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
  occurrences are. `present` means compiled and certainly not reached. A named algorithm in such
  code is counted as wrong by the scorers where its site is labelled dead; none is in the sets
  above.
- *Layer 1 from metadata.* An unmodelled package is a crypto package when its `Cargo.toml` says
  so (category or keyword) or the knowledge base lists it, and `support` when its categories
  are an encoding's or a parser's. Metadata cannot tell every case (ssh-key, which signs, has
  der's categories; totp-rs names no crypto), so such packages are listed by name; one not yet
  listed is reported as `support` or not at all, while its operations are still in Layer 2.
- *Values.* Values are followed through def-use origins, links across functions and
  standard-library summaries, not a points-to analysis. Where one is not followed, the CBOM
  says unknown with the reason (`in-too-deep.md` 6.9); the opt-in points-to engine only removes
  doubt and was not part of the evaluation.
- *Generic library code.* In a library, a generic function's type parameters belong to its
  callers: an operation on one is unknown, or named only as far as the library fixes it
  (`HMAC` of a caller's hash).
- *Provenance.* Key material is classified for the arguments the knowledge base gives a role;
  a generator handed to an API without an `rng` role is not classified, and gets no
  `predictable-rng` finding. A parameter's provenance includes what the program's callers pass;
  callers outside the program or through pointers leave it `parameter`.
- *Needless unknowns.* A set the code closes but the analysis does not follow is an unknown:
  a `Box<dyn DynDigest>` built from three constructors just above, a local closure called
  directly (closures handed to `map`, `and_then` are followed).
- *Names and parameters.* ring's and aws-lc-rs's PBKDF2 is named without its iteration count and
  output length; BLAKE3 is `BLAKE3-256` for `hash` and `keyed_hash`, `BLAKE3` for key derivation
  and XOF output. A library's generic API that sibling binaries instantiate gets no "callers
  choose" unknown for the library itself.
- *Parameters.* `rcbom:param:*` properties are not scored against the labels' `params`.
- *The verifier* is text-based. It checks every position, the token and item there, and the
  details it can read in the source (the descriptor a call reads, witnesses, bindings,
  `instantiated by` calls, coercions, macro rules, manifest entries). It does not check the
  reachability tier, artifact tags, provenance classes, which of an asset's functions a call
  performs, set labels (member kind, `possible`, `one of N`), the reason of an unknown, or a
  registry name outside boundary models; and it cannot see an operation the CBOM leaves out
  (`in-too-deep.md` 8). Four fixture positions it cannot confirm are listed in `verify-known`
  files, each checked by hand.
- *Toolchain.* The driver needs its pinned nightly. Layer 2 compiles the project, so the
  project's build scripts and procedural macros run.

## Layout

| path | content |
|---|---|
| `crates/cargo-cbom` | CLI, schema validation (`schema/`: CycloneDX 1.7, Apache-2.0), `verify` |
| `crates/rcbom-manifest` | Layer 1 |
| `crates/rcbom-driver` | the nightly `rustc_public` driver: sites, origins, links, walk |
| `crates/rcbom-facts` | the facts exchanged between driver and analysis |
| `crates/rcbom-kb` | knowledge base loader and data (`data/`: the seed, and the Cryptography Registry, Apache-2.0) |
| `crates/rcbom-analysis` | matching, values across functions, boundary models, provenance, CycloneDX assembly |
| `xtask` | the project's tasks: checks, e2e, scorers, summaries |
| `tests/fixtures/` | designed cases (`micro`, `libonly`, `threads`), the `realapp` corpus program, labelled `rusi` fixtures, `suite/` (the ground-truth suite), `regress/` (probes from every audit round), `corpus/` (labels for six real projects), `heldout/` (labels for seven crates.io crates no development used, frozen before any run), `review/` (an independent reviewer's blind labels for two crates), `projects.toml` (the package behind each corpus, held-out and review label); each fixture with its golden `expected.txt` |
| `tests/external/` | inputs from an external reference case (BOM Fidelity) |
| `results/` | committed outputs behind the reported numbers |
| `docs/` | `poc_workflow.md` (the tool, its five layers, related tools), `in-too-deep.md` (how each stage works), `suite/RULES.md` (the labelling rules every label file follows) |
