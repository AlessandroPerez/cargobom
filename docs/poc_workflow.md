# cargo-cbom: the tool and its five layers

## The tool

`cargo cbom` is a Cargo subcommand. It writes a CycloneDX 1.7 Cryptography Bill of Materials (CBOM) for a Rust workspace. The CBOM lists the crypto libraries the built program ships and the algorithms it uses with them, call site by call site. It also lists the key material handed to them and where that material comes from. Every finding cites a position in the source. `cargo cbom verify` re-reads every cited position and checks it against the source.

The rules every layer keeps:
- **The built artifact only.** The CBOM covers one target, one feature set and the `release` profile. Code a feature or `cfg` leaves out is a different artifact.
- **Never drop an operation.** An operation whose algorithm is not found is reported as `unknown`, with the reason. The boundary check makes this hold on every run: each call the reachable code makes into a crypto package is cited, excused by a reason the knowledge base states, or cited by the check itself as an unknown operation.
- **Honest sets.** Each algorithm reaching a call says how it is chosen, with a witness in the code: `fixed`, `table`, `caller`, `object`, `static`, `dyn`, `container` or `type-join`. The last four are marked *possible* where the member only may reach the call (`dyn` when more than one type is coerced to the object).
- **The knowledge base is data.** `crates/rcbom-kb/data/seed.toml` maps library APIs to Cryptography Registry names. The analysis has no library-specific code.

```
            Cargo workspace
                  │
  Layer 1  packages          cargo metadata, manifests, lockfile        built
  Layer 2  code              rustc driver (MIR) → facts → analysis      built
                  │
           CBOM (CycloneDX 1.7, schema-validated) → cargo cbom verify   built
                  │
  Layer 3  usage purpose     rules on the Layer 2 values, then a model  designed
  Layer 4  vulnerabilities   RustSec + reachability on the Layer 2 walk designed
  Layer 5  policy            rules over the finished CBOM               designed
```

Layers 1 and 2 decide *what is there*. Layers 3 to 5 add *what it means*: what each use is for, whether a known vulnerability is reachable, and whether a policy allows it. Each later layer reads what the earlier ones wrote. None needs the compiler again.

### Where the tool stands among existing ones

For Rust, existing tools either infer algorithms from which library is present, or match text:

| tool | what it does for Rust |
|---|---|
| cdxgen + rusi | the only source-level path: crates classified by a fixed table, source matched without types |
| lens3329, smp-pqc-inventory | manifests and lockfiles only; algorithms inferred from the library's identity ("does not prove use") |
| acdi, cipherscope | regex (acdi), regex plus tree-sitter (cipherscope); no types, no data flow |
| CodeQL | Rust GA since October 2025; three crypto queries over a 35-line RustCrypto model; no CBOM |
| Semgrep | one Rust crypto rule (weak hash constructors) |
| sonar-cryptography (CBOMkit) | the reference generator for Java, Python and Go; its Rust rules were never merged |

What cargo-cbom adds is the algorithm *at the call site*, resolved through generics, trait objects, function pointers, constants and values passed across functions. Each answer comes with its label and witness, and every position is verified.

## Layer 1: packages (built)

- **What:** the crypto packages that ship in this build. For each: its role in the knowledge base (`algorithm`, `trait` or `protocol`), and the backend its features select (rustls with aws-lc-rs or ring). Also the native libraries the build links, and crypto packages the knowledge base does not model, recognised by their metadata, an explicit list or a name that is a registry algorithm's; a package the knowledge base has at a version it does not cover is marked so. With Layer 2, each package also gets a usage tier: declared but not used, present, or reachable (`--manifest-only` leaves it unknown).
- **How:** `cargo metadata` gives the resolved graph and features without compiling. The manifests and lockfile are read as text, for the position where each package enters the build. Packages are matched to knowledge-base records by package name and version range. `--manifest-only` stops here and compiles nothing.
- **Existing tools used:** `cargo metadata` through the `cargo_metadata` crate, and `toml_edit` for positions.
- **Comparable tools:** lens3329, smp-pqc-inventory and rusi's crate table cover about this layer alone. cargo-auditable's embedded dependency list would extend it to built binaries; it is not used yet.
- Details: `in-too-deep.md` 3.

## Layer 2: code (built)

- **What:** each crypto operation the program can reach. For each: the algorithms reaching it, with their label, and its parameters (lengths, iterations, modes). Also the algorithms computed inside it (the hash of an HMAC), the key material handed to it with its provenance (hard-coded, random, derived, parameter), its reachability, and, when the workspace builds several binaries, which of them use it.
- **How:**
  - A driver on a pinned nightly (`nightly-2026-09-25`) runs as `RUSTC_WRAPPER` under `cargo check`.
  - It reads MIR through `rustc_public`: the monomorphised instances it walks from each binary's entry points, and a library's generic functions, which no instance shows. `--check-walk` checks that walk against the linker: code a binary contains that the walk did not reach, outside the standard library and the modelled crates, is a missing edge.
  - It records sites and value links as facts (JSON).
  - A stable analysis matches the facts against the knowledge base. It follows values backwards across functions, and applies the boundary models (jsonwebtoken, TLS configuration).
  - The boundary check accounts for every call the walked code makes into a crypto package (also those the standard library makes for it): cited by an occurrence, excused by a reason the knowledge base states (`[[aside]]`: a view, a copy, an accessor), or cited by the check itself as an unknown operation.
  - The analysis assembles the CBOM and validates it against the vendored CycloneDX 1.7 schemas.
  - An opt-in points-to engine only removes doubt: it narrows or closes gaps and never adds algorithms. Where it finds a value a search claiming completeness missed, the call gets the unknown. Its disagreements with the default analysis are printed, which makes it a check on that analysis.
- **Existing tools used:**
  - the compiler's `rustc_public` and `rustc_middle`;
  - the CycloneDX 1.7 schema and its Cryptography Registry, which supplies the names;
  - the `jsonschema` crate.
- **Adapted, not linked:** the driver pattern of Kani and Charon.
- **Used only as an oracle:** Rupta (a MIR points-to analysis, GPL), run locally on probes and never vendored.
- **Rejected after spikes:** SVF and PhASAR on LLVM IR, which lose pointers in Rust IR and run out of memory on xh, and a SCIP-based verifier, which has no types.
- Details: `in-too-deep.md` 4–8.

## Layer 3: usage purpose (designed)

- **What:** each use labelled `security`, `non-security` or `undetermined`, with a rationale. This is what tells SHA-1 for git object IDs, BLAKE3 for content addressing or SipHash in a `HashMap` apart from the same algorithms protecting data.
- **How, stage A (rules):**
  - *Trait family:* `std::hash::Hasher` and the non-cryptographic hasher crates (ahash, rustc-hash, crc32fast, xxhash) are never security uses.
  - *Security sinks:* the output reaches MAC or signature verification, a constant-time comparison, a KDF, key or nonce construction, an authentication header, TLS or JWT configuration, or password storage.
  - *Secret sources:* key material, passwords, tokens.
  - *Non-security sinks:* map keys, file names, cache keys, ETags and log fields, with ordinary inputs.

The rules run on the same backward value search as Layer 2. Layer 2 already provides part of their input: the use or setup label of an occurrence, `cryptoFunctions`, "configuration, not a connection", and provenance per role.
- **How, stage B (a local model, optional):** only for what the rules leave open.
  - The model sees the slice rendered as source, never whole files.
  - Its output is JSON constrained by a schema with closed enums.
  - Three local models vote.
  - The result is recorded as `method=llm`, with the model and the prompt's hash.
- **Undetermined:** cases that depend on the threat model, such as a checksum on a download, stay `undetermined`, with both readings.
- **Output:** a purpose property per occurrence (planned as `rcbom:purpose`, with confidence and rationale; `rcbom:usage` already holds a package's usage tier), and the `cryptoFunctions` that policy tools read purpose from.
- **Existing tools:** none classifies purpose at the call site.
  - The closest is package-level relevance by Hirsch et al.: a three-model local ensemble, F1 0.82–0.86, matching cloud models.
  - Crypistry's rule repository (Näther and Hirsch, 2026) and CodeQL's `rust/weak-sensitive-data-hashing` cover parts of the sink rules.
  - llama.cpp, Ollama and vLLM provide schema-constrained output.
- **Left to this and the later layers:** what Layers 1 and 2 leave out by decision (tests, build scripts, SipHash). Tests and build scripts would get their own scope.

## Layer 4: vulnerabilities (designed)

- **What:** the known advisories against the shipped packages, each linked to the library and to the crypto assets it affects. Each gets a VEX state saying whether the vulnerable code can
  run.
- **How:**
  1. Match the RustSec database against `Cargo.lock`, kept to the Layer 1 build graph.
  2. Link advisories in the `crypto-failure` category, or on knowledge-base packages, to their assets.
  3. For advisories that name functions (`affected.functions`, about 22% of them), intersect those functions with the functions Layer 2's walk reached.
  4. Set the VEX state:
     - `affected` when reached;
     - `not_affected` (`code_not_reachable`) when built but never called;
     - `not_affected` (`component_not_present`) when in the lockfile but not built;
     - `under_investigation` when the advisory names no functions.
  5. Native libraries (aws-lc, OpenSSL) map to OSV and NVD.

The walk over-approximates (trait objects reach every coerced type), so it errs towards `affected`.
- **Existing tools:**
  - The `rustsec` crate (behind cargo-audit) does the matching; it is to be used as is.
  - OSV-Scanner's Rust call analysis answers the reachability question from the binary independently. It is the cross-check: disagreements are reported, not hidden.
  - Semgrep Supply Chain added Rust reachability in April 2026.
  - lens3329 correlates lockfiles with RustSec and OSV, without reachability.
  - What is new here: reachability comes from the same walk the CBOM's tiers come from, so the VEX and the CBOM agree.
- **Output:** CycloneDX `vulnerabilities` with their analysis (VDR/VEX).

## Layer 5: policy (designed)

- **What:** a verdict per asset against the national post-quantum and deprecation policies and the organisation's own rules. Verdicts that rules decide are kept apart from those that need an analyst.
- **How:**
  - Rules are evaluated over the finished CBOM, so any CBOM can be checked.
  - Custom rules use FBK's TOML policy model (assessment and compliance levels, most-specific-rule matching). It is extended to match on Layer 3 purpose, scope, provenance (a hard-coded key), the VEX state and an evaluation date.
  - For a candidate set, the worst verdict among its members counts. A `type-join` member counts as possible, not as used.
- **Existing tools (the national packs are delegated to them, not rewritten):**
  - cbomctl: seven YAML packs (BSI, ANSSI, ASD, the EU roadmap, EO 14412, NIST IR 8547, CNSA 2.0). It reads purpose from `cryptoFunctions`, so Layer 3's labels let it answer instead of `INDET`.
  - sbom-tools: CNSA 2.0 and NIST IR 8547 checks, with SARIF and OSCAL output.
  - The FBK CBOMkit fork (Foroncelli et al., SSR 2025), the origin of the custom-rule format.
  - acdi applies the NIST IR 8547 timeline to its own findings.
- **Output:**
  - a compliance report (JSON, Markdown);
  - SARIF with the occurrences' positions, for code scanning and IDEs;
  - `cbom diff` between two commits, for pull-request gating.

## What we have atm

Layers 1 and 2 and the verifier are built, and evaluated on:
- the frozen ground-truth suite (53 programs, 107 call sites);
- six real projects with labels;
- seven held-out crates.io crates, labelled blind before any run;
- the labelled rusi fixtures, against rusi;
- external reference cases by BOM Fidelity: the rusi fixture `cbom-real-crates-app` with five controlled variants, and jwt-cli 6.1.1 and hkdf 0.12.4 labelled blind; published as a citable reference package;
- four independent reviews of the whole project, each reproducing every number. The first labelled two more crates blind (the review set); each later one attacked the analysis with new programs and blind crates, and the fourth broke the boundary check in ways since fixed in the check.

The numbers are in the README's Results. Its Limitations lists what the CBOM covers, where it deliberately differs from a label written by the rules, and what it does not do yet. Layers 3 to 5 are designed, not built.
