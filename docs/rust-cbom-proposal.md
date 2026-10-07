# Rust CBOM Generator: Architecture and Build Proposal

## 1. Summary and goals

We propose a Rust-native tool that takes a Cargo workspace and emits a CycloneDX Cryptography Bill of Materials (CBOM). Each cryptographic asset carries its algorithm, its parameters, its usage purpose, its vulnerability status and its policy verdict, with source evidence for every claim.

The tool is a five-layer pipeline that runs entirely on the user's machine. Deterministic analysis does the work: Cargo metadata, a type-resolved rustc pass and RustSec matching. A local language model handles only a small, bounded residue of ambiguous cases, and every finding it touches is labelled as inferred.

Goals:

- **Coverage:** RustCrypto, ring, aws-lc-rs, openssl, rustls and the main post-quantum (PQC) crates, including their transitive use through dependencies.
- **Completeness:** semantically complete assets (algorithm, mode, key size, padding, nonce source and composition), not bare algorithm names.
- **Context:** each asset classified as security-relevant, non-security or undetermined, with the evidence for that call.
- **Actionability:** a vulnerability view filtered by reachability (CycloneDX VDR/VEX) and policy verdicts (CNSA 2.0, NIST deprecations, custom rules) on top of the inventory.
- **Confidentiality:** no source code leaves the machine, and the CBOM is treated as sensitive output.
- **Measurability:** a labelled Rust benchmark, published with the tool, that reports precision and recall for each layer.

The first version does not cover binary-only analysis of third-party executables, runtime tracing, or languages other than Rust. C code reached through FFI is flagged but not analysed.

The contribution is threefold. This would be the first Rust CBOM generator that recovers parameters from resolved types, classifies the purpose of each use, and filters vulnerabilities by reachability. It would also produce the first public Rust CBOM benchmark.

## 2. State of the art

Rust is the main gap in CBOM tooling. The standard and the reference tools are mature for Java, Python and Go. For Rust there is one open-source generator that works at source level (cdxgen's rusi), and it recovers little beyond crate names.

### 2.1 The standard

CBOM began as IBM Research work ([IBM/CBOM](https://github.com/IBM/CBOM)) and was merged into [CycloneDX 1.6](https://cyclonedx.org/news/cyclonedx-v1.6-released/); cdxgen already emits 1.7. A CBOM 2.0 schema is in development ([PR #769](https://github.com/CycloneDX/specification/pull/769)). It adds `keyUsage`, security properties for algorithms, extended evidence metadata and arrays for implementation platforms. The maintainers have acknowledged that the spec still cannot express intended use, migration status or a framework-neutral risk object ([discussion #966](https://github.com/CycloneDX/specification/discussions/966)). The usage-purpose classification proposed here targets that gap directly.

### 2.2 Existing tools

- **[sonar-cryptography (CBOMkit-hyperion)](https://github.com/cbomkit/sonar-cryptography)** is the reference static generator. It covers Java (JCA, BouncyCastle), Python (pyca/cryptography) and Go, and has no Rust support. A community PR adding Rust detection rules was [closed](https://github.com/cbomkit/sonar-cryptography/pull/474) because language support needs a full parser and engine, not just rules. Worth borrowing: its detection-rule structure, its split between enricher and translator, and the shape of its CBOM output.
- **[cdxgen with rusi](https://github.com/cdxgen/cdxgen-plugins-bin)** is the only existing Rust path. It has two backends: one that parses source with `syn`, and one that runs a nightly rustc wrapper over MIR and HIR. Its crypto knowledge is a list of about a dozen crate families. Worth borrowing: the two-backend design, turning crates that declare `links` into separate native library components, and keeping raw detections as properties when the CycloneDX enum cannot hold them.
- **golem**, cdxgen's Go analyser in the same repository, builds SSA call graphs with static, CHA, RTA and VTA modes and has a crypto taint mode. It is the most mature architecture to mirror in Rust.
- **[Keylens](https://github.com/keylens/cbom)** is written in Rust but scans only Python and JavaScript. Its `cbom diff` command for gating pull requests is a useful idea.
- **The [.NET CBOM generator](https://github.com/systemslibrarian/PostQuantum.CryptographicBillOfMaterials)** uses Roslyn semantic analysis. Worth borrowing: a confidence value on every finding, SARIF output alongside CycloneDX, and schema validation in CI.
- **The [FBK fork of CBOMkit](https://github.com/claudioforoncelli/cbomkit#custom-policies)** consumes CBOMs in any language through a TOML policy engine. Its format is the starting point for Layer 5.

### 2.3 Research

- **Compliance on top of CBOMs.** Foroncelli, Tomasi, Piras, Dias Knob, De Matteis and Ranise ([SSR 2025](https://cris.fbk.eu/handle/11582/367387)) extend CBOMkit with a policy engine that maps assets to compliance levels through machine-readable rules. On synthetic and real software it correctly flags deprecated and disallowed primitives. The authors also note that some compliance checks remain hard to automate.
- **The tool landscape.** Nocera and Scanniello ([SEAA 2026](https://link.springer.com/chapter/10.1007/978-3-032-36587-3_33)) mined GitHub and found 46 repositories hosting generation tools against only 7 for consumption. Almost none had dependent repositories. A Rust generator that also consumes its own CBOM (for policy and VEX) addresses both halves.
- **Measured accuracy.** Olewinski, Sandler and Ebinger ([ARES 2026 workshops](https://link.springer.com/chapter/10.1007/978-3-032-35586-7_19)) benchmarked open-source discovery tools against a ground truth. They found gaps in completeness and accuracy, and that the permissive CBOM spec hampers interoperability; they recommend stricter conformance. Their references add further tools: CipherIQ cbom-generator, CZERTAINLY CBOM-Lens, csnp cryptoscan and the CodeQL-based cbom-action.
- **Ground-truth labelling.** Maaike van Leuken (TNO) has written on [LinkedIn about manually labelling 366 cryptographic assets](https://www.linkedin.com/pulse/what-manually-labelling-366-cryptographic-assets-me-maaike-van-leuken-bbdre/). She co-authored TNO's [Cryptographic Asset Discovery and Inventory](https://publications.tno.nl/publication/34645425/j6EewK7a/TNO-2025-P11921-GB.pdf) report for the Dutch NCSC. [IREKAI](https://irekai.nl/) is a Dutch company offering assessments, tooling, training and support for quantum-safe migration.
- **Discovery taxonomy.** [Hidden Ciphers and Where to Find Them](https://arxiv.org/abs/2608.04857) (2026) separates three categories: cryptographic material, artifacts and invocations. It derives detection rules from them that do not depend on any one scanner. It also points out that CycloneDX defines how to represent assets but not how to find them.
- **Semantic completeness.** IBM's [Cryptoscope](https://arxiv.org/abs/2503.19531) argues that a CBOM describing a full operation is far more useful than one naming only a primitive. Building its 97-asset Java ground truth with LLM help still required heavy manual correction.
- **LLMs as a first-pass filter.** Hirsch, Raab, Bauer and Loebenberger ([ICISSP 2026](https://arxiv.org/abs/2603.07204)) use LLM ensembles to filter software packages for cryptographic relevance. They compare on-premises with online models, which bears directly on confidentiality.
- **Rust crypto misuse.** Elsayed, Fulton and Yang ([EASE 2026](https://arxiv.org/abs/2604.27001)) found no widely adopted crypto-specific analyser for Rust. CodeQL's Rust suite found no true positives on their AEAD code. Their own regex-based detector misses key and IV flows through indirection, which needs data-flow analysis.

### 2.4 The gap

No tool today does all four of the following for Rust:

1. Recover algorithm parameters from types and constants.
2. Separate security uses from non-security uses.
3. Filter vulnerabilities by reachability.
4. Ship a labelled benchmark for evaluation.

## 3. Design principles

1. **Deterministic core, bounded inference.** The same commit and configuration always produce the same CBOM. Model output never silently becomes a fact; it is recorded as an inferred finding with its method and confidence.
2. **Analyse what ships.** The build graph for the declared target and features defines the scope, not the whole lockfile.
3. **Every claim has evidence.** Each asset records file, line, symbol, detection method and confidence. When the CycloneDX enum cannot express a detection, the raw value is kept as a property rather than dropped.
4. **Classify, never delete.** Non-security uses stay in the inventory, annotated, so a misclassification cannot hide an asset from an audit.
5. **Local by default.** The tool makes no network access except to fetch the advisory database, which can be mirrored. No source code leaves the machine.
6. **Knowledge as data.** Crate-to-algorithm mappings, detection rules and policies are versioned files that can be reviewed, not code.
7. **Standard output.** CycloneDX 1.7 now, with a migration path to CBOM 2.0, plus SARIF for CI and IDEs. Output is validated against the official schema on every run.
8. **Measured.** Each layer has its own metric on a shared benchmark, so improvements and regressions can be attributed.

## 4. Architecture overview

The tool is a single `cargo cbom` subcommand. It runs five layers in sequence, fed by four versioned inputs, all on the user's machine.

- **Input:** the Cargo workspace, meaning sources, manifests, `Cargo.lock`, and the target triple and features.
- **Layer 1, manifest and build graph:** determines which crypto crates ship and through which backend.
- **Layer 2, type-resolved code analysis:** the research core. It recovers algorithms, parameters, composition and data flow. It is fed by the crypto knowledge base.
- **Layer 3, usage purpose:** structural rules first, then an optional local model on the residue.
- **Layer 4, vulnerabilities and reachability:** matches advisories from the RustSec advisory database and checks reachability on the Layer 2 call graph.
- **CBOM assembler:** produces CycloneDX 1.7 with custom `rcbom:` properties and validates it against the schema.
- **Layer 5, policy and compliance:** applies TOML policy packs.
- **Outputs:** the CBOM in JSON, VDR/VEX, SARIF, a compliance report and a `cbom diff`.

Each layer enriches the same in-memory asset graph, and Layer 4 reuses Layer 2's call graph. A run manifest records the toolchain, target, features, knowledge-base version, advisory-database snapshot and model backend, so any CBOM can be reproduced and audited.

## 5. Layer 1 — Manifest and build graph

This layer decides which crypto crates actually ship and through which backend. It is cheap and reliable, and on its own it already yields a useful coarse CBOM.

Inputs:

- `cargo metadata --format-version 1 --filter-platform <triple>` run with the user's feature flags. This gives the resolved dependency graph, the features enabled for each package, and the `links` key.
- `Cargo.lock`, for exact versions and checksums. It is used for RustSec matching but lists more than is actually built.
- For binaries that are already built, the dependency list that [cargo-auditable](https://github.com/rust-secure-code/cargo-auditable) embeds in the executable.

Processing:

1. Mark crates found in the knowledge base as crypto providers: RustCrypto families, ring, aws-lc-rs, openssl, rustls, pqcrypto, ml-kem, ml-dsa and others.
2. Resolve which backend each feature set selects: rustls with `ring` or `aws_lc_rs`, reqwest with `native-tls` or `rustls-tls`, the jsonwebtoken backends. Emit one asset for the backend that is actually enabled.
3. Turn crates declaring `links = "ssl"`, `"crypto"` and similar into separate native-library components (OpenSSL, AWS-LC, BoringSSL). Flag the FFI boundary so that OpenSSL advisories attach to OpenSSL rather than to its Rust binding, as cdxgen does.
4. Record `build.rs` scripts and vendored C sources as evidence only; never execute them.

The output is a set of library components plus candidate algorithm assets that each crate can provide. Candidates are marked `method=manifest` and `confidence=low` until Layer 2 confirms them. A crate that is present but never called is reported as `declared-not-used`. This matters for post-quantum audits, because an unused dependency still adds attack surface and maintenance burden.

## 6. Layer 2 — Type-resolved code analysis

This layer turns call sites into complete assets by reading what Rust's type system already encodes. RustCrypto puts the algorithm and its parameters into types: `Aes256Gcm`, `Hmac<Sha256>`, `Argon2` with `Params`, or `Pbkdf2` with a rounds argument. ring and aws-lc-rs pass them as constants, such as `&aead::AES_256_GCM` or `&signature::ECDSA_P256_SHA256_ASN1_SIGNING`.

### 6.1 Front end

There are three options.

- **Primary:** a `rustc_driver` lint pass hosted in [Dylint](https://github.com/trailofbits/dylint). It sees HIR and MIR with full type information: monomorphised types, trait resolution and constants. The cost is a pinned nightly toolchain, the same constraint rusi's compiler backend has. Dylint runs Clippy-style lints as dynamic libraries using `clippy_utils`. The same pass can therefore emit CBOM facts and policy diagnostics.
- **Fallback:** the rust-analyzer crates (`ra_ap_hir`). They run on stable and give names, types and trait implementations, but no MIR. They also suit a later IDE integration.
- **Last resort:** plain `syn` parsing, which runs on stable but carries no type information. It serves as a quick pre-filter, much like rusi's stable backend.

### 6.2 Analyses

1. **Call-site detection.** Match resolved callee definitions, trait methods (`Aead::encrypt`, `Digest::update`, `Signer::sign`, `KeyInit::new`) and constant paths against the API signatures in the knowledge base. Because generic code is resolved at monomorphisation, a `fn seal<A: Aead>` used with `ChaCha20Poly1305` is attributed correctly.
2. **Parameter recovery.** Read algorithm, key size and mode from the concrete type, and read constants through MIR const evaluation. Recover the rustls `CryptoProvider` and cipher-suite lists by constant propagation over the builder chain.
3. **Composition.** Build `dependsOn` edges, such as HMAC to SHA-256, HKDF to SHA-384, or a TLS 1.3 suite to its AEAD and hash. This is what Cryptoscope calls semantic completeness.
4. **Data-flow slices over MIR,** intraprocedural first, then interprocedural over the call graph. The slices feed:
    - nonce and IV provenance (CSPRNG, counter or literal);
    - key provenance (generated, derived through a KDF, read from environment or file, or hard-coded);
    - purpose classification in Layer 3;
    - parameter values that cross function boundaries.
5. **Wrapper summaries.** In-house crates that wrap cryptography, which are common in proprietary code, get per-function summaries such as "this function performs AES-256-GCM encryption". Callers then inherit the asset.
6. **Crypto material and artifacts** (the Hidden Ciphers categories). Find embedded PEM or DER keys and certificates, `include_bytes!` of key files, and test vectors, which are tagged as test scope.

### 6.3 Scope controls

- Workspace crates are analysed by default. Dependency crates are summarised from the knowledge base rather than re-analysed, with an opt-in deep mode.
- Code under `#[cfg(test)]`, `benches/` and `examples/` is classified as non-production scope, not discarded.
- MIR sees code after macro expansion. Spans are mapped back to the macro call site for evidence.

The output is a set of `cryptographic-asset` components with `evidence.occurrences` (file, line and symbol) and `cryptoProperties`, marked `method=type-resolved` and `confidence=high`. These assets confirm or refute Layer 1's candidates.

## 7. Layer 3 — Usage purpose and the bounded LLM assist

Each asset receives a purpose label (`security`, `non-security` or `undetermined`) with a rationale. Rules decide first, and a local model sees only what the rules leave open.

### 7.1 Stage A: structural rules (no model)

- **Trait family.** `std::hash::Hash` and `Hasher` (SipHash in `HashMap`), `ahash`, `fxhash`, `xxhash-rust`, `crc32fast` and `seahash` are never cryptographic. Detection keys on traits such as `digest::Digest`, `Mac`, `Aead` and `Signer`, never on names containing "hash".
- **Security sinks.** An asset is security-relevant when its output or input reaches one of: MAC or signature verification, `subtle::ConstantTimeEq`, KDF inputs, key or nonce construction, authentication headers, TLS or JWT configuration, or password storage.
- **Secret sources.** Inputs that come from key material, passwords, tokens or secret stores also mark an asset as security-relevant.
- **Non-security sinks.** Outputs used as a map key, file name, cache key, log field, ETag or deduplication identifier, with ordinary inputs, mark an asset as non-security.
- **Known patterns.** Examples include SHA-1 for git object IDs, content addressing, and `rand::thread_rng` used for shuffling or jitter.

### 7.2 Stage B: a local model on the residue

- **Input:** the MIR slice rendered as source, the resolved types and constants, function and module names, and doc comments. It never receives whole files.
- **Output:** constrained to a JSON schema with closed enums for purpose and for the CycloneDX primitive and mode, plus a free-text rationale.
- **Recording:** each finding carries `method=llm`, the model and version, the hash of the prompt template, and a confidence. Ensembles or self-consistency voting are optional, following Hirsch et al.
- **Backends:** pluggable. The default is local (llama.cpp or Ollama), with an optional enterprise endpoint where policy allows. The run manifest records which backend ran.

### 7.3 What stays undetermined

Some checks are only security-relevant under a particular threat model, such as a checksum on a downloaded artifact. These are flagged `undetermined` with both readings explained; the tool never forces a binary label.

### 7.4 Confidentiality

Source code stays on the machine. The knowledge base can be built with any model, because it is derived from public crates. The CBOM and the SARIF output are sensitive, since together they map the cryptographic attack surface, and should be stored and shared accordingly.

The headline number to report is the share of assets that reach Stage B. If it is small, the tool's quality does not depend on the model.

## 8. Layer 4 — Vulnerabilities and reachability

This layer answers whether a vulnerable crypto function is actually called, not just whether a vulnerable crate is present. The answer is emitted as CycloneDX VDR/VEX alongside the CBOM.

1. **Match.** Load the [RustSec advisory database](https://github.com/rustsec/advisory-db) with the `rustsec` crate, which is the library behind cargo-audit, and match it against `Cargo.lock`. Advisories cross-reference CVE and GHSA identifiers. A local mirror keeps the run offline.
2. **Prioritise crypto.** Advisories in the `crypto-failure` category, or on crypto crates in the knowledge base, are linked to the affected `cryptographic-asset` components as well as the library component.
3. **Check reachability.** Many advisories list affected functions and version ranges in an `[affected] functions` field. These paths are intersected with the Layer 2 call graph, starting from the workspace's entry points.
4. **Emit VEX.**
    - `affected` when the function is reachable.
    - `not_affected` with justification `code_not_reachable` when the crate is built but the function is never called.
    - `not_affected` with `component_not_present` when the crate is in the lockfile but not in the build graph.
    - `under_investigation` when the advisory names no functions.
5. **Native libraries.** For `links` components such as OpenSSL or AWS-LC, record the vendored or system version where it can be determined. These map to OSV and NVD rather than RustSec.

`cargo-audit` and `cargo-deny` stop after step 2. Steps 3 and 4 come almost for free once the Layer 2 call graph exists, and they are a clear practical differentiator.

## 9. Layer 5 — Policy and compliance

Policies are evaluated over the finished CBOM, not the code. Any CBOM, from this tool or another, can therefore be checked, which addresses the consumption gap that Nocera and Scanniello measured.

The policy format follows the TOML model of the [FBK CBOMkit fork](https://github.com/claudioforoncelli/cbomkit#custom-policies) (Foroncelli et al., SSR 2025). A policy has:

- a header;
- global assessment levels: compliant, potentially compliant, not compliant;
- per-asset compliance levels: acceptable, deprecated, disallowed;
- rules matched on asset properties. When several rules match, the most specific one wins.

Reusing the format keeps policies portable between that tool and this one. This tool needs four extensions:

- matching on the Layer 3 purpose, so that SHA-1 is disallowed for signatures but only noted for git object IDs;
- matching on scope (production, test or example) and on provenance (a hard-coded key, a nonce from a counter);
- rules bounded in time ("deprecated, disallowed after 2030"), evaluated against a configurable date;
- matching on VEX state, for example failing on any reachable `crypto-failure` advisory.

The tool ships policy packs for the NIST SP 800-131A transitions, the NIST IR 8547 quantum-vulnerable timeline, CNSA 2.0, and a quantum-safe baseline matching CBOMkit's built-in check. Each pack cites its source document in the policy header.

The outputs are:

- a compliance report in JSON and Markdown;
- SARIF findings with source spans for GitHub code scanning and IDEs;
- optionally, the same verdicts as Dylint diagnostics, so developers see them at `cargo check` time;
- a `cbom diff` between two commits for gating pull requests, as Keylens does.

Foroncelli et al. note that some checks resist automation. The report therefore separates verdicts decided by rules from those that need an analyst's review.

## 10. CBOM output model

The output is CycloneDX 1.7 JSON, validated against the official schema on every run. A namespaced property set covers everything the spec cannot yet express.

- **Library components** (purls of the form `pkg:cargo/...`) come from Layer 1. Native `links` libraries are separate components.
- **Algorithm assets** come from Layer 2, with primitive, parameter set, mode, padding, crypto functions, classical and NIST quantum security levels, and OID.
- **Protocol assets** come from Layer 2's analysis of rustls configuration. They record TLS versions and cipher suites, linked to their algorithms.
- **Related crypto material and certificates** come from Layer 2's search for embedded material. Only type and size are recorded, never the secret value.
- **Evidence occurrences** come from Layers 1 and 2: file, line, symbol and macro call site.
- **Dependencies** (`dependsOn` and `provides`) come from Layer 2's composition analysis, for example application to library to algorithm, or HMAC to SHA-256.
- **Vulnerabilities with VEX analysis** come from Layer 4, linked to both the library and the asset.
- **Tool metadata and the run manifest** record tool and knowledge-base versions, the toolchain, target, features and model backend.

The custom properties use a namespace still to be chosen, for example `rcbom:`:

- `rcbom:usage:purpose`, `rcbom:usage:confidence` and `rcbom:usage:rationale`;
- `rcbom:detection:method`, one of `manifest`, `type-resolved`, `syntactic` or `llm`;
- `rcbom:scope`, one of `production`, `test`, `example` or `build-script`;
- `rcbom:provenance:key` and `rcbom:provenance:nonce`;
- `rcbom:raw:*` for detections the CycloneDX enum cannot hold, following cdxgen's approach.

The purpose and provenance properties fill the intended-use gap the CycloneDX maintainers acknowledged. If they prove useful, they are a candidate contribution to the CBOM 2.0 work, which already adds `keyUsage` and extended evidence. The finding of Olewinski et al. about spec permissiveness also argues for a strict profile: the tool should publish exactly which fields it always fills, so consumers can rely on them.

## 11. Crypto knowledge base for Rust

The long tail of crates is the real bottleneck; rusi knows about a dozen crate families. The knowledge base is versioned data that maps crate APIs to CycloneDX semantics. It is built offline from public sources and reviewed by a person before release.

Each entry describes one API item, keyed by crate, version range and path. It records:

- the type, trait method or constant, for example `aes_gcm::Aes256Gcm` or `ring::aead::AES_256_GCM`;
- the CycloneDX mapping: primitive, parameter set, mode, padding, crypto functions and OID;
- how parameters are recovered: from the type, from a constant argument, or from a numbered argument;
- data-flow roles: which arguments are key, nonce or input, and which return value is a tag or signature;
- the feature flags that enable the item, and any known non-security aliases.

The knowledge base is built in five steps:

1. **Seed by hand** with the top crates, each with golden tests. The seed covers RustCrypto (aes-gcm, chacha20poly1305, sha2, sha3, blake2, hmac, hkdf, pbkdf2, argon2, rsa, p256, p384, ed25519-dalek, x25519-dalek, ml-kem, ml-dsa), plus ring, aws-lc-rs, openssl, rustls, jsonwebtoken and rand.
2. **Rank the long tail** by reverse dependencies on crates.io, filtered by the cryptography category and keywords.
3. **Draft entries with an LLM** from rustdoc JSON (`cargo +nightly rustdoc -- -Z unstable-options --output-format json`) and README text. Because this is public code, cloud models are acceptable here. The output is constrained to the knowledge-base schema, mirroring the first-pass filter of Hirsch et al.
4. **Validate the drafts automatically.** Check that every path exists in the rustdoc JSON and that OIDs and enum values are valid. Then run a minimal program for each entry through Layer 2. This catches the API hallucinations that the EASE 2026 study found to be the dominant LLM failure on Rust crypto code.
5. **Review and publish** as a versioned release. Every CBOM records the knowledge-base version it used.

The knowledge base is reusable on its own: other tools, rusi included, could consume it. That makes it a natural thing to share with the community.

## 12. Evaluation and benchmark

No labelled Rust CBOM benchmark exists. Building one is a contribution in its own right and the basis for every claim the tool makes.

### 12.1 Corpus

1. **Synthetic micro-cases.** One small crate per knowledge-base entry and per misuse pattern. Together they cover generics, trait objects, wrappers, macros, backends selected by features, and non-security uses such as hash tables, cache keys and git IDs. Rust translations of CryptoAPI-Bench cases, as done by Elsayed et al., cover misuse and provenance.
2. **Real-world crates.** Roughly 20 to 30 open-source projects across domains:
    - TLS servers built on rustls;
    - password and authentication services;
    - wallets and signing tools;
    - storage that uses content addressing;
    - embedded `no_std` firmware;
    - a project already adopting PQC.
3. **Labelling protocol.** Two annotators label each asset, with adjudication. Labels cover asset type, algorithm and parameters, purpose and scope. Pre-labelling with an LLM is acceptable, but Cryptoscope's experience says to budget for heavy correction. The labelling lessons from the TNO and van Leuken work are worth collecting directly from the authors.

### 12.2 Metrics for each layer

- **Layer 1:** precision and recall of shipped crypto libraries and backends against the build graph.
- **Layer 2:** asset-level precision and recall, and parameter completeness (the share of fields correct).
- **Layer 3:** precision and recall for security versus non-security, the share left undetermined, the share reaching the model, and accuracy with and without the model.
- **Layer 4:** correctness of VEX states on known advisories, with the rate of false `not_affected` verdicts held near zero.
- **Layer 5:** agreement with expert verdicts on the policy packs.
- **Runtime:** wall-clock time and memory on the real-world set.

### 12.3 Baselines

The comparison uses:

- cdxgen with rusi, using both backends;
- a `syn`-only variant of this tool, to isolate the gain from type resolution;
- CodeQL's Rust queries for the misuse and provenance slice;
- a grep or Semgrep baseline.

Following Olewinski et al., the evaluation also reports which CBOM fields each tool fills, not only whether each asset was found.

## 13. Build plan

Build the cheap, reliable layers first so that a usable coarse CBOM exists early. Then invest in the type-resolved core, and add context last. Each phase ends at a measurable gate on the benchmark; phases are ordered but not dated.

1. **Phase 1, foundations.** The CycloneDX 1.7 model, schema validation and the run manifest; the knowledge-base schema with hand-seeded entries for the top crates; and the synthetic corpus with golden CBOMs.
    - *Gate:* valid CBOMs for every micro-case, and all knowledge-base golden tests pass.
2. **Phase 2, coarse CBOM.** Layer 1 (cargo metadata, backends selected by features, native `links` libraries), Layer 4 matching through the `rustsec` crate without reachability, and the Layer 5 policy engine compatible with the FBK format.
    - *Gate:* library detection at least on par with cdxgen and rusi.
3. **Phase 3, type-resolved core.** The Dylint pass covering call sites, monomorphised types and MIR constants; parameter recovery and composition edges; and intraprocedural key and nonce provenance. This phase is the research core and the riskiest, because it depends on nightly rustc internals.
    - *Gate:* asset recall and parameter completeness beat rusi.
4. **Phase 4, context.** Interprocedural slices and wrapper summaries, purpose rules followed by the local-model residue stage, and VEX filtered by reachability.
    - *Gate:* the share of assets reaching the model is measured, and there are no false `not_affected` verdicts.
5. **Phase 5, scale and publish.** A long-tail knowledge base drafted by an LLM and validated automatically; the labelled real-world benchmark; SARIF output and a CI action; the release, a paper, and an offer of the knowledge base to CBOMkit and cdxgen.

Phases 1 and 2 alone already give a tool comparable to existing ones.

### 13.1 What to reuse

- **CycloneDX types and serialisation:** the `cyclonedx-bom` crate from [cyclonedx-rust-cargo](https://github.com/CycloneDX/cyclonedx-rust-cargo), or a thin serde model.
- **Build graph:** the `cargo_metadata` crate.
- **Advisories:** the `rustsec` crate and the [advisory database](https://github.com/rustsec/advisory-db).
- **Lint host with typed HIR and MIR:** [Dylint](https://github.com/trailofbits/dylint) with `clippy_utils`.
- **Stable fallback front end:** `ra_ap_hir` from rust-analyzer, and `syn`.
- **Design patterns:**
    - from rusi and cdxgen: two backends, `links` handling and raw-value properties;
    - from golem: call-graph modes and crypto taint ([cdxgen-plugins-bin](https://github.com/cdxgen/cdxgen-plugins-bin));
    - from [sonar-cryptography](https://github.com/cbomkit/sonar-cryptography): the detection-rule structure and the enricher.
- **Policy format:** the TOML policies from the [FBK CBOMkit fork](https://github.com/claudioforoncelli/cbomkit#custom-policies).
- **CBOM viewer:** CBOMkit-coeus from [CBOMkit](https://github.com/cbomkit/cbomkit), or cdxgen's `cdxui` terminal interface.
- **Local inference:** llama.cpp or Ollama with decoding constrained to a JSON schema.

### 13.2 Crate layout

- `rcbom-model`: CycloneDX types, the `rcbom:` property schema and validation.
- `rcbom-kb`: the knowledge-base schema, loader and golden tests.
- `rcbom-manifest`: Layer 1.
- `rcbom-lints`: the Dylint library for Layer 2, the only crate that needs nightly.
- `rcbom-purpose`: the Layer 3 rules and the model client.
- `rcbom-vuln`: Layer 4.
- `rcbom-policy`: Layer 5.
- `cargo-cbom`: the CLI that drives the layers and writes the outputs.
- `rcbom-bench`: the corpus, labels and scoring.

## 14. Risks and open questions

Risks and mitigations:

- **Changes to nightly rustc internals** can break Layer 2 when the toolchain is updated. Mitigation: pin the toolchain for each release, keep the `ra_ap_hir` fallback, and isolate all code that talks to rustc in one crate.
- **Projects that fail to build** produce no MIR, so Layer 2 cannot run. Mitigation: fall back to `syn` plus Layer 1, and mark the run as partial in the run manifest, as the .NET tool does.
- **Knowledge-base coverage will lag behind new crates,** causing missed assets. Mitigation: report crates in the cryptography category that have no knowledge-base entry as `unknown-crypto-crate`, never skip them silently.
- **Interprocedural data flow may not scale** to large workspaces. Mitigation: summary-based analysis, with depth limits reported as diagnostics rather than hidden (the principle cdxgen's Kotlin analyser kosi applies).
- **The model may misclassify purpose.** Mitigation: classify but never delete, attach a confidence to every label, and report metrics with and without the model.
- **`unsafe` code and FFI can hide C-side algorithms.** Mitigation: flag FFI boundaries; consider a binary pass over linked native libraries later.
- **The CBOM leaks details of the attack surface.** Mitigation: local-only by default, documented handling guidance, and an optional redaction profile.

Open questions:

- Which property namespace to use, and whether to propose `usage:purpose` upstream for CBOM 2.0.
- How deep to analyse dependency crates by default: knowledge-base summaries only, or full analysis of dependencies that behave like first-party code.
- Which local model family to standardise for Stage B. This needs a small comparison on the Layer 3 slice of the benchmark.
- Whether to contribute the knowledge base and a Rust front end to CBOMkit or cdxgen, or stay standalone and interoperate through CycloneDX only.
- Whether FBK would collaborate, since their policy engine and this generator are complementary.

## 15. References

- C. Foroncelli, A. Tomasi, L. Piras, L. A. Dias Knob, P. De Matteis, S. Ranise. *Towards Cryptography Bill of Materials Compliance.* SSR 2025, LNCS 16466. https://cris.fbk.eu/handle/11582/367387 (doi:10.1007/978-3-032-19567-8_10)
- C. Foroncelli. CBOMkit fork with custom TOML policies. https://github.com/claudioforoncelli/cbomkit#custom-policies
- S. Nocera, G. Scanniello. *Cryptography Bill of Materials Generation and Consumption: A Mining Study from GitHub.* SEAA 2026, LNCS 16864. https://link.springer.com/chapter/10.1007/978-3-032-36587-3_33
- A. Olewinski, T. Sandler, P. Ebinger. *An Empirical Analysis of Open-Source Tools for Cryptographic Asset Discovery for PQC Readiness Assessment.* ARES 2026 Workshops, LNCS 16902. https://link.springer.com/chapter/10.1007/978-3-032-35586-7_19
- M. van Leuken. LinkedIn article on manually labelling 366 cryptographic assets. https://www.linkedin.com/pulse/what-manually-labelling-366-cryptographic-assets-me-maaike-van-leuken-bbdre/
- IREKAI. https://irekai.nl/
- CycloneDX v1.6 release (CBOM). https://cyclonedx.org/news/cyclonedx-v1.6-released/
- IBM CBOM specification. https://github.com/IBM/CBOM
- CycloneDX CBOM 2.0 schema changes, PR #769. https://github.com/CycloneDX/specification/pull/769
- CycloneDX discussion #966 on intended use and compliance. https://github.com/CycloneDX/specification/discussions/966
- sonar-cryptography. https://github.com/cbomkit/sonar-cryptography (Rust rules PR #474: https://github.com/cbomkit/sonar-cryptography/pull/474)
- CBOMkit. https://github.com/cbomkit/cbomkit
- cdxgen. https://github.com/cdxgen/cdxgen
- cdxgen-plugins-bin (rusi, golem, kosi). https://github.com/cdxgen/cdxgen-plugins-bin
- Keylens. https://github.com/keylens/cbom
- PostQuantum.CryptographicBillOfMaterials (.NET). https://github.com/systemslibrarian/PostQuantum.CryptographicBillOfMaterials
- RustSec advisory database. https://github.com/rustsec/advisory-db
- cargo-auditable. https://github.com/rust-secure-code/cargo-auditable
- Dylint. https://github.com/trailofbits/dylint
- cyclonedx-rust-cargo. https://github.com/CycloneDX/cyclonedx-rust-cargo
- *Hidden Ciphers and Where to Find Them: Static Discovery and Assessment of Cryptographic Assets in Software* (2026). https://arxiv.org/abs/2608.04857
- M. Moffie et al. *Cryptoscope: Analyzing Cryptographic Usages in Modern Software* (2025). https://arxiv.org/abs/2503.19531
- E. Hirsch, K. Raab, T. J. Bauer, D. Loebenberger. *Detecting Cryptographically Relevant Software Packages with Collaborative LLMs.* ICISSP 2026. https://arxiv.org/abs/2603.07204
- M. Elsayed, K. Fulton, J. Yang. *An Empirical Security Evaluation of LLM-Generated Cryptographic Rust Code.* EASE 2026. https://arxiv.org/abs/2604.27001
- T. Sijpesteijn, M. van Leuken, F. Kerling. *Cryptographic Asset Discovery and Inventory.* TNO 2025 P11921. https://publications.tno.nl/publication/34645425/j6EewK7a/TNO-2025-P11921-GB.pdf
- Z. Li, J. Wang, M. Sun, J. C. S. Lui. *MirChecker: Detecting Bugs in Rust Programs via Static Analysis.* CCS 2021. https://dl.acm.org/doi/10.1145/3460120.3484541
