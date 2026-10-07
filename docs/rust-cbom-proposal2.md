# Rust CBOM Generator — Architecture and Build Proposal (v2)

## 0. What changed since v1

- **Dylint is not a viable primary front end.** `cargo dylint` wraps workspace members only, and lint passes run on generic, pre-monomorphisation code. A `fn seal<A: Aead>` is seen once with `A` unresolved, which defeats the central claim of Layer 2. The front end is now a `rustc_driver` wrapper written against `rustc_public` (the renamed `stable_mir`), the pattern used by Kani, Charon and MIRAI. See section 6 and claim F1 in section 14.
- **The `cyclonedx-bom` crate cannot represent a CBOM.** It supports CycloneDX 1.3 to 1.5 only; cryptographic assets arrived in 1.6. The output model now builds on `serde-cyclonedx`, which generates its types from the official JSON schemas and already covers 1.6, with 1.7 to be added. Validation uses cdxgen's `cdxrs`, which bundles the 1.6 and 1.7 schemas plus crypto-specific semantic rules.
- **"Never execute build scripts" was only true for Layer 1.** Layer 2 compiles the project, and compiling runs build scripts and procedural macros. Even `cargo metadata` honours a `build.rustc` or `build.rustc-wrapper` set in the project's own `.cargo/config.toml`. A sandboxing design is now part of the architecture (section 12).
- **The vocabulary problem is already solved upstream.** CycloneDX 1.7 ships a machine-readable Cryptography Registry with 98 algorithm families, 167 parameterised variant patterns and 246 named curves. The knowledge base now targets that vocabulary instead of inventing one, and cdxgen already maps to it.
- **The knowledge base can be built without compiling crates.** docs.rs has served rustdoc JSON for every crate built since May 2025, so API inventories for the whole long tail can be drafted from public data.
- **Policy packs exist and should be consumed, not rewritten.** cbomctl evaluates a CBOM against seven national post-quantum policies and already asks for an asset's purpose, which is exactly what Layer 3 produces. sbom-tools validates CNSA 2.0 and NIST IR 8547 and emits SARIF and OSCAL. Layer 5 keeps only the FBK-style custom rules.
- **Regulatory clock.** US Executive Order 14412 (22 June 2026) directs CISA to publish minimum elements for a cryptographic bill of materials within 180 days, and sets PQC deadlines for high-value systems of 31 December 2030 (key establishment) and 31 December 2031 (signatures). The output profile should track the CISA minimum elements once published.
- **Reachability has a measurable ceiling.** 278 of the 1,270 RustSec advisories (about 22 percent) name affected functions, so function-level VEX can only be decided for that share; the rest must be reported as under investigation.
- **The only Rust crypto dataset is unusable as is.** The EASE 2026 repository ships its 20 translated CryptoAPI-Bench cases inside a notebook and carries no licence, so the benchmark must be derived afresh from the MIT-licensed CryptoAPI-Bench.

## 1. Summary and goals

We propose a Rust-native tool that takes a Cargo workspace and emits a CycloneDX 1.7 Cryptography Bill of Materials. Each cryptographic asset carries its algorithm and parameters in the registry's vocabulary, its usage purpose, its vulnerability status and its policy verdict, with source evidence for every claim.

The tool is a five-layer pipeline that runs on the user's machine, inside a sandbox when the code is untrusted. Deterministic analysis does the work: Cargo metadata, a type-resolved compiler pass over monomorphised MIR, and RustSec matching. A local language model handles only a small, bounded residue of ambiguous cases, and every finding it touches is labelled as inferred.

Goals:

- **Coverage:** RustCrypto, ring, aws-lc-rs, openssl, rustls and the PQC crates (ml-kem, ml-dsa, slh-dsa, pqcrypto, oqs, libcrux), including their transitive use through dependencies.
- **Completeness:** semantically complete assets (algorithm, mode, key size, padding, nonce source, composition), named by registry pattern, not bare crate names.
- **Context:** each asset classified as security-relevant, non-security or undetermined, with the evidence for that call.
- **Actionability:** a reachability-aware vulnerability view (VDR/VEX) and policy verdicts (custom rules in the tool; national packs through cbomctl and sbom-tools).
- **Confidentiality:** no source code leaves the machine; the CBOM is treated as sensitive output.
- **Measurability:** a labelled Rust benchmark in CycloneDX 1.7 form, published with the tool, reporting precision and recall per layer.

Out of scope for the first version: binary-only analysis of third-party executables, runtime tracing, and languages other than Rust. C reached through FFI is flagged and linked to a native component, not analysed.

The contribution is the first Rust CBOM generator that recovers parameters from monomorphised types and evaluated constants, classifies the purpose of each use, filters vulnerabilities by reachability, and ships a public Rust benchmark. No existing tool does any one of these for Rust at the type level.

## 2. State of the art

### 2.1 The standard, the registry and the regulatory clock

CBOM began as IBM Research work and was merged into CycloneDX 1.6 (April 2024). CycloneDX 1.7 (October 2025) added `algorithmFamily` and `ellipticCurve` enumerations and the [Cryptography Registry](https://cyclonedx.org/registry/cryptography), a machine-readable file ([cryptography-defs.json](https://cyclonedx.org/schema/cryptography-defs.json) with a [JSON Schema](https://cyclonedx.org/schema/cryptography-defs.schema.json)) created because tools and organisations named the same algorithms inconsistently. Parsed on 6 October 2026, it holds 98 algorithm families with 167 variant patterns such as `AES[-(128|192|256)][-(GCM|CCM)][-{tagLength}][-{ivLength}]`, `HMAC[-{hashAlgorithm}][-{tagLength}]` and `ML-KEM-(512|768|1024)`, and 246 named curves in 15 families, each with OID, form and aliases. The site says the registry may be used independently of CycloneDX, including by static analysis tools, and is updated without a specification release. One discrepancy to handle: the 1.7 schema enum lists 93 families while the registry JSON lists 98 (ANSI-KDF, RSA-X931, SP800-56C, SSH-KDF and TLS-PRF are in the JSON only).

A CBOM 2.0 schema is in development ([PR #769](https://github.com/CycloneDX/specification/pull/769)): `keyUsage`, security properties on algorithms, extended evidence metadata, arrays of implementation platforms. The maintainers acknowledge the spec still cannot express intended use, migration status or a framework-neutral risk object ([discussion #966](https://github.com/CycloneDX/specification/discussions/966)). Basil Hess (IBM Research Zurich), who leads the CycloneDX cryptography work, lists the open problems in *[The Anatomy of Cryptography Bills of Materials](https://research.ibm.com/publications/the-anatomy-of-cryptography-bills-of-materials-standardization-and-practice-in-cyclonedx)* (Eurocrypt 2026 MAgiCS workshop): false positives and negatives in detection, opacity of API abstractions, transitive dependencies, governance at scale.

Regulation now sets dates. [Executive Order 14412](https://www.whitehouse.gov/wp-content/uploads/2026/06/eo-14412.pdf), "Securing the Nation Against Advanced Cryptographic Attacks", was signed on 22 June 2026. Section 5(d) directs CISA to publish minimum elements for a cryptographic bill of materials within 180 days, so by about December 2026; section 4(b) requires high-value assets to move to PQC key establishment by 31 December 2030 and PQC digital signatures by 31 December 2031. [NIST IR 8547](https://csrc.nist.gov/pubs/ir/8547/ipd) remains an initial public draft (November 2024); its tables deprecate 112-bit RSA, ECDSA, ECDH and FFDH after 2030 and disallow them, with EdDSA, after 2035.

### 2.2 CBOM generators

- **[sonar-cryptography (CBOMkit-hyperion)](https://github.com/PQCA/sonar-cryptography)**, now under the PQCA organisation, remains the reference static generator: Java (JCA, BouncyCastle), Python (pyca/cryptography), Go (standard library, partial x/crypto), C# in development. A community PR adding 22 Rust detection rules for ring, rustls and RustCrypto ML-KEM and ML-DSA was [closed unmerged](https://github.com/PQCA/sonar-cryptography/pull/474) in August 2026; the maintainer said a language engine module must come first, and another contributor noted that SonarSource's Rust analyser exposes no AST API, suggesting an embedded tree-sitter parser instead. As of 1 October 2026 the main branch has no file mentioning Rust.
- **[cdxgen](https://github.com/CycloneDX/cdxgen) with rusi** is the only source-level Rust path today. `cbom -t rust` on its own only inventories certificate files; source-level assets come from `evinse -l rust`, which runs the rusi binary from [cdxgen-plugins-bin](https://github.com/CycloneDX/cdxgen-plugins-bin). rusi classifies crates by a fixed table (sha1, sha2, md5, blake3, aes-gcm, aes-gcm-siv, chacha20poly1305, hmac, argon2, pbkdf2, scrypt, hkdf, jsonwebtoken, rustls, tokio-rustls, native-tls, openssl, x509-parser, webpki, rustls-pemfile, rcgen, rsa, p256, p384, k256, ed25519-dalek, x25519-dalek, and ring by submodule). It knows no PQC crate and not aws-lc-rs. cdxgen turns a rusi component into a `cryptographic-asset` only if the algorithm name resolves to an OID in its `crypto-oid.json`, and otherwise drops it; it sets `primitive`, moves non-enum kinds to `cdx:rusi:crypto:kind`, records provider, operation, symbol and confidence as properties, and links the owning crate through `dependencies[].provides`. rusi has a `syn`-based stable backend and a nightly-rustc MIR/HIR backend; the latter executes build scripts. cdxgen already resolves names to the 1.7 `algorithmFamily` enum through `lib/inventory/cryptoAlgorithmFamily.js`.
- **golem**, cdxgen's Go analyser, builds SSA call graphs in static, CHA, RTA and VTA modes with a crypto taint mode. It is the most mature architecture to mirror.
- **[BF-CBOM](https://github.com/SEG-UNIBE/BF-CBOM)** (Bögli, Spieler, Kehrer; ICPC 2026 tool demo; GPL-3.0) orchestrates CBOMkit, cdxgen, Santander's CryptobomForge (over CodeQL SARIF) and a zero-shot DeepSeek generator in containers, then matches assets across tools with embedding clustering. On sampled Python and Java repositories they found "almost no lexically exact matches" between generators. Adding a worker is a five-step skeleton, which makes BF-CBOM a ready-made comparison harness for a Rust generator.
- **[Keylens](https://github.com/keylens/cbom)** is written in Rust on tree-sitter but scans only Python and JavaScript plus lockfiles. It occupies the crates.io name `cbom` (v0.1.2, July 2026); the name `cargo-cbom` is free as of 6 October 2026.
- **The [.NET CBOM generator](https://github.com/systemslibrarian/PostQuantum.CryptographicBillOfMaterials)** uses Roslyn semantic analysis and attaches a detection confidence to every finding; it outputs CycloneDX 1.6 and SARIF and validates its own output in CI.
- **Binary and system scanners** (CipherIQ cbom-generator, OmniTrust CBOM-Lens, CBOMkit-theia) inventory certificates, keys and libraries on file systems and container images and emit CycloneDX 1.6 or 1.7. They cover the native libraries a Rust analysis can only flag.

### 2.3 Rust-specific crypto inventory projects

A crates.io and GitHub sweep found four small projects, all pattern- or manifest-based and none type-resolved:

- **[lens3329](https://github.com/3329lens/3329lens)** (Apache-2.0) discovers crypto libraries from Cargo, npm and Python manifests and lockfiles, correlates offline with RustSec and OSV, and emits CycloneDX 1.6 and SARIF. Algorithms are inferred from library identity.
- **[acdi](https://github.com/vral-parmar/acdi)** (MIT) is a regex scanner over eleven languages including Rust, plus manifests, certificates and TLS endpoints; it emits CycloneDX 1.7 with `cryptoProperties` and applies the NIST IR 8547 timeline.
- **[cipherscope](https://github.com/script3r/cipherscope)** (MIT) runs a regex pre-scan then tree-sitter matching with rules in `patterns.toml`; JSONL output, no CycloneDX.
- **[smp-pqc-inventory](https://github.com/rwilliamspbg-ops/smp-pqc-testkit)** classifies Cargo.lock crates by a name table and can write CycloneDX; its README says it "does not prove use".

These are useful baselines. None recovers parameters from types, resolves feature-selected backends, or distinguishes security from non-security use.

### 2.4 General-purpose analysers with crypto rules

- **CodeQL.** Rust support became generally available on 14 October 2025 (CodeQL CLI 2.23.3), scanning without a build. Three crypto queries exist for Rust: `rust/weak-cryptographic-algorithm`, `rust/weak-sensitive-data-hashing` and `rust/hard-coded-cryptographic-value`. The Rust crypto model is a 35-line `rustcrypto.model.yml` plus a `RustCrypto.qll` that recognises `KeyInit`/`KeyIvInit` constructors and reads the algorithm from the inferred struct type. Only the RustCrypto trait family is modelled; ring, aws-lc-rs, openssl, rustls, dalek and PQC crates are not. The language-independent CBOM graph library (`shared/quantum`, with `PrintCBOMGraph` for C++ and inventory slices for Java) is not wired to Rust. The [advanced-security/cbom-action](https://github.com/advanced-security/cbom-action) last released in November 2023, effectively supports Python only and emits SARIF, not CycloneDX. CodeQL is therefore a baseline and a possible contribution target, not a foundation; the CodeQL CLI licence also restricts use on proprietary code outside GitHub Advanced Security, which cuts against the confidentiality goal.
- **Semgrep.** Rust is generally available in Semgrep Code (Pro: cross-function data flow) and community-supported in the open-source engine (single function). The public registry holds one crypto rule for Rust, `rust.lang.security.insecure-hashes` (MD2, MD4, MD5, SHA-1 constructors), plus TLS configuration checks. Semgrep Supply Chain extended reachability to Rust in April 2026; its rules are proprietary.

### 2.5 Compiler-level analysis infrastructure for Rust

This is where v1 was wrong, and the findings decide the architecture.

- **[rustc_public](https://github.com/rust-lang/rustc_public)** (renamed from `stable_mir` in 2025) is the compiler team's tool-facing API. It exposes local and external crates, MIR bodies, types, `Instance::resolve` for monomorphised callees, `Instance::body()` whose result is "eagerly monomorphized and all constants will already be evaluated", `InstanceKind::Virtual` to flag `dyn` dispatch, `try_const_eval`, and static allocations such as `&ring::aead::AES_256_GCM`. It still requires nightly with `rustc_private`, is not on crates.io, and is "subject to breaking changes"; an accepted [2026 Rust project goal](https://goals.rust-lang.org/2026/rustc-public.html) aims to publish it on crates.io with breaking-change detection. Kani builds its compiler and its cross-crate reachability collector on it and pins `nightly-2026-09-25`.
- **[Charon](https://github.com/AeneasVerif/charon)** (CAV 2025) is a `rustc_driver` extractor that wraps every crate through `RUSTC_WRAPPER`, forces `-Zalways-encode-mir` and `-Zmir-opt-level=0`, uses a Miri sysroot so standard-library bodies are available, and serialises MIR as ULLBC or LLBC for Rust or OCaml consumers. It translates the primary package plus reachable dependency items. Its IR is polymorphic by default, its `--monomorphize` mode does not support `dyn Trait`, it is self-described alpha software, and `charon-lib` is a git-only dependency.
- **[Paralegal](https://github.com/brownsys/paralegal)** (OSDI 2025) builds a flow-, context- and field-sensitive program dependence graph across crates: `cargo paralegal-flow` wraps all crates, dumps the MIR of listed dependencies for later inlining, marks sources and sinks with attributes or an external annotation file for dependency items, and uses "adaptive approximation", inlining callees only when markers are reachable and otherwise approximating by type. It monomorphises on demand along marker-reachable paths. Reported analysis times are under five seconds for most applications with all dependencies, and 88 seconds for Lemmy. It is research code, not on crates.io, pinned to `nightly-2026-04-20`. [Flowistry](https://github.com/willcrichton/flowistry) (PLDI 2022) provides the underlying intraprocedural information-flow engine and [rustc_plugin](https://github.com/cognitive-engineering-lab/rustc_plugin) the two-binary cargo scaffold; both pin `nightly-2026-05-01`.
- **[Dylint](https://github.com/trailofbits/dylint)** (6.1.0, September 2026) builds lint libraries pinned to a toolchain and runs them through `RUSTC_WORKSPACE_WRAPPER`, so dependencies are never analysed, and lints see generic code. Useful as a packaging pattern only.
- **[RAPx](https://github.com/Artisan-Lab/RAPx)** (0.7.54, released 6 October 2026) offers alias, data-flow, call-graph, range and heap analyses on MIR, but analyses only local crates and tracks an unpinned nightly. Rudra is archived; MIRAI pins `nightly-2025-01-10`; Lockbud analyses dependencies but has no releases; [Rupta](https://github.com/rustanlys/rupta) (pointer analysis, CC 2024) pins a 2024 nightly and warns of 128 GB memory use.
- **Dependency MIR.** The compiler encodes optimised MIR for ordinary functions of a dependency only when `-Zalways-encode-mir` is set, or when codegen runs and the function is generic or cross-crate inlinable. Under plain `cargo check` dependency metadata holds no MIR for ordinary functions; with the flag, it does, and the flag works under `cargo check`. The standard library needs `-Zbuild-std` or a Miri sysroot.
- **rust-analyzer as a library.** `ra_ap_hir` 0.0.357 (5 October 2026) releases weekly with no semver guarantee. `Semantics::resolve_method_call_fallback` returns the callee and a generic substitution relative to the enclosing generic context, not a whole-program monomorphisation; inference and const-evaluation are not guaranteed to match rustc. It runs build scripts and proc macros by default, which can be disabled. CodeQL's build-free Rust extractor is understood to be built on these crates (not verified in this pass), which suggests they hold up at scale as a no-build front end.

### 2.6 Vulnerability reachability for Rust

The [RustSec advisory format](https://github.com/rustsec/advisory-db) has an optional `[affected.functions]` table mapping canonical function paths to version requirements; the OSV export carries it as `ecosystem_specific.affects.functions`. Counting the repository on 3 October 2026, 278 of 1,270 advisories (about 22 percent) specify functions. OSV-Scanner's `--call-analysis=rust` compiles the project and reads DWARF debug information from the binaries to see which vulnerable functions are linked, and excludes proc-macro dependencies, dynamically linked dependencies and dependencies that link non-Rust code. cdxgen's dep-scan marks advisories reachable or not using rusi's static call graph. Semgrep Supply Chain added function-level reachability for Rust in April 2026 with proprietary rules. No tool was found that intersects `affected.functions` with a type-resolved, source-level call graph.

### 2.7 Policy and compliance tooling

- **[cbomctl](https://github.com/lvlrSajjad/cbomctl)** (Python, Apache-2.0, pre-release) evaluates one CBOM against seven YAML policy packs: BSI, ANSSI, ASD, the EU roadmap, EO 14412, NIST IR 8547 and CNSA 2.0. Every rule carries a source URL, a verification date, a binding class and a hybrid stance. It resolves an asset's purpose from `cryptoFunctions`, then `algorithmProperties.primitive`, then `assetType`, and returns `INDET` rather than guess, asking users to declare purpose or regenerate the CBOM with a generator that records it. It reports a verdict matrix, cross-jurisdiction conflicts, a satisfies-all target and a migration plan.
- **[sbom-tools](https://github.com/sbom-tool/sbom-tools)** (Rust, MIT, 238 stars) has a canonical model for CycloneDX and SPDX, a `cbom` quality profile, validation against 16 standards including CNSA 2.0 and NIST IR 8547 with per-algorithm pass or fail, and JSON, SARIF, OSCAL and HTML output.
- **The [FBK CBOMkit fork](https://github.com/claudioforoncelli/cbomkit#custom-policies)** (Foroncelli et al., SSR 2025) defines TOML policies with assessment levels, compliance levels and most-specific-rule matching.
- **[cdxrs](https://github.com/CycloneDX/cdxgen-plugins-bin)** (4.1.1, MIT, in cdxgen-plugins-bin) validates against vendored CycloneDX 1.6 and 1.7 schemas plus semantic rules, including `crypto.asset-missing-crypto-properties`, `crypto.algorithm-missing-oid`, `crypto.certificate-missing-algorithm-properties` and `purl.crypto-asset-has-purl`. It builds standalone but is not on crates.io.

### 2.8 Research

- **Discovery taxonomy and rules.** Näther (XITASO) and Hirsch (OTH Amberg-Weiden), *[Hidden Ciphers and Where to Find Them](https://arxiv.org/abs/2608.04857)* (2026), separate crypto-material, crypto-artifacts and crypto-invocations, and derive a scanner-independent rule repository, Crypistry, of 214 rules (148 discovery, 66 assessment) with detector, mapping and assessor blocks. Their scanner Crypsy emits CycloneDX 1.7. Languages are Ruby, Go and nginx, TLS and SSH configuration; no Rust. On their synthetic benchmark Cryben (197 ground-truth occurrences, ground truth itself expressed as a CycloneDX 1.7 CBOM), CBOMkit-hyperion scored precision 0.84 and recall 0.54 on the Go subset, Crypsy 0.95 and 0.89. Artefacts are on OSF (osf.io/4bc5p; not reachable from this session).
- **Compliance.** Foroncelli, Tomasi, Piras, Dias Knob, De Matteis and Ranise ([SSR 2025](https://cris.fbk.eu/handle/11582/367387)) extend CBOMkit with a policy engine; correct on deprecated and disallowed primitives; some checks resist automation.
- **The landscape.** Nocera and Scanniello ([SEAA 2026](https://link.springer.com/chapter/10.1007/978-3-032-36587-3_33)): 46 generation tools against 7 consumption tools on GitHub, almost none with dependents.
- **Measured accuracy.** Olewinski, Sandler and Ebinger ([ARES 2026 workshops](https://link.springer.com/chapter/10.1007/978-3-032-35586-7_19)): gaps in completeness and accuracy; the permissive spec hampers interoperability; stricter conformance recommended. Their ground-truth share could not be reached from this session.
- **SoK.** Yamamuro, Uemura and Fukushima (KDDI Research, [ICISSP 2026](https://www.scitepress.org/Papers/2026/142271/142271.pdf)) survey discovery sources and methods, rank keyword and parameter search as the most false-positive-prone, and recommend combining sources and tracking outputs to detect hybrid constructions.
- **Semantic completeness.** IBM's [Cryptoscope](https://arxiv.org/abs/2503.19531): a CBOM describing a full operation beats one naming a primitive; its 97-asset Java ground truth was built by LLM drafting plus manual review and is not published; reported recall 92 percent exact, precision 97 percent.
- **LLMs for crypto relevance.** Hirsch, Raab, Bauer and Loebenberger ([ICISSP 2026](https://arxiv.org/abs/2603.07204); code MIT at [OTH-AMiQuaSy/detecting-crypto-packages](https://github.com/OTH-AMiQuaSy/detecting-crypto-packages)) classify 65,295 Fedora packages for crypto relevance against a 390-package ground truth. Quantised local models (Llama-3-8B, Mistral-7B, Phi-3-mini, DeepSeek-R1) reach F1 0.72 by majority vote, 0.86 after prompt optimisation, matching the cloud ensemble's 0.86; five-fold cross-validation of the final three-model local ensemble gives precision 0.79, recall 0.86, F1 0.82. This is the only published local-versus-cloud comparison on a crypto task.
- **LLMs for misuse.** Xia et al. (ISSTA 2025): raw LLM reports exceed 50 percent false positives; with scoping and self-validation GPT-4 reaches precision 87 percent, recall 90 percent on Java benchmarks. CRYPTBARA (ASE 2025) combines dependency analysis with GPT-4o-mini for F1 95.4 percent on PyCryptoBench. No paper was found that classifies crypto use as security versus non-security purpose; that question is open.
- **LLM-drafted specifications validated by analysis.** [IRIS](https://arxiv.org/abs/2405.17238) lifts CodeQL from 27 to 55 detected vulnerabilities on CWE-Bench-Java by having an LLM label sources and sinks; DAInfer (FSE 2024) infers API specifications from library documentation at precision 79.8 and recall 82.3 percent; AdaTaint and SemTaint follow the same propose-then-validate pattern. This is the template for drafting the knowledge base.
- **Rust crypto misuse.** Elsayed, Fulton and Yang ([EASE 2026](https://arxiv.org/abs/2604.27001)): no widely adopted crypto-specific analyser for Rust; CodeQL's Rust suite gave no true positives on their AEAD samples; their regex detector misses flows through indirection.

### 2.9 Benchmarks and ground truth

Java has CryptoAPI-Bench (MIT, 171 to 181 cases), CamBench (Apache-2.0, work in progress) and MASC; Python has PyCryptoBench (1,836 cases; repository not located). For Rust there is nothing: no misuse benchmark, no CBOM ground truth. Cryptoscope's and BF-CBOM's ground truths are unpublished; the CycloneDX `bom-examples` CBOM folder holds ten single-asset schema fixtures. The TNO report *[Cryptographic Asset Discovery and Inventory](https://publications.tno.nl/publication/34645425/j6EewK7a/TNO-2025-P11921-GB.pdf)* (Sijpesteijn, van Leuken, Kerling, March 2025) is a market survey and fit-gap analysis for the Dutch government, not an empirical test; it states that "there is no ground truth" and "no reliable indicator for CADI tool accuracy at this time", that two of three dedicated vendors could not estimate their own accuracy, and recommends establishing a ground truth and a controlled test environment. Maaike van Leuken's lessons from labelling 366 assets could not be found outside LinkedIn.

### 2.10 The gap

No tool today does any of the following for Rust at the type level, and none does all four:

1. Recover algorithm parameters from monomorphised types and evaluated constants, including feature-selected backends.
2. Separate security uses from non-security uses.
3. Decide vulnerability reachability on a source-level call graph.
4. Ship a labelled Rust benchmark in CBOM form.

## 3. Design principles

1. **Deterministic core, bounded inference.** The same commit, configuration and knowledge-base version produce the same CBOM. Model output is recorded as inferred, with method and confidence, never silently promoted to fact.
2. **Analyse what ships.** The build graph for the declared target and features defines scope, not the whole lockfile.
3. **Every claim has evidence.** File, line, symbol, method and confidence on each asset. When the CycloneDX enum cannot hold a detection, keep the raw value as a property; never drop an asset for want of an OID, which is what cdxgen currently does.
4. **Classify, never delete.** Non-security uses stay in the inventory, annotated.
5. **Untrusted by default.** Anything that compiles or resolves the project runs inside a sandbox with vendored sources and no network.
6. **Registry vocabulary.** Asset names and families follow the CycloneDX Cryptography Registry patterns so that cbomctl, sbom-tools and BF-CBOM can read the output without a mapping step.
7. **Knowledge as data.** Crate-to-algorithm mappings, rules and policies are versioned files, reviewable and shareable.
8. **Standard output, validated.** CycloneDX 1.7 now, CBOM 2.0 later, SARIF for CI; every run validated with cdxrs.
9. **Measured.** Each layer has its own metric on a shared benchmark.

## 4. Architecture overview

The tool is a single `cargo cbom` subcommand running five layers in sequence, fed by four versioned inputs: the crypto knowledge base, the RustSec advisory snapshot, the policy packs and the optional local model.

- **Input:** the Cargo workspace, with target triple and features; optionally a built binary with cargo-auditable data.
- **Sandbox:** sources vendored, network disabled, project `.cargo/config.toml` neutralised (section 12).
- **Layer 1, manifest and build graph:** which crypto crates ship, through which backend, and which native libraries they link.
- **Layer 2, type-resolved code analysis:** a `rustc_driver` wrapper on `rustc_public` over monomorphised MIR; recovers algorithms, parameters, composition and provenance slices; builds the call graph.
- **Layer 3, usage purpose:** structural rules, then an optional local model on the residue.
- **Layer 4, vulnerabilities:** RustSec matching on the lockfile, reachability on the Layer 2 call graph, VEX.
- **Assembler:** CycloneDX 1.7 with registry names and `rcbom:` properties, validated with cdxrs.
- **Layer 5, policy:** custom TOML rules; national packs delegated to cbomctl and sbom-tools.
- **Outputs:** CBOM JSON, VDR/VEX, SARIF, compliance report, `cbom diff`.

A run manifest records toolchain, target, features, knowledge-base version, advisory snapshot, sandbox mode and model backend, so any CBOM can be reproduced.

## 5. Layer 1 — Manifest and build graph

This layer decides which crypto crates actually ship and through which backend. On its own it yields a coarse CBOM comparable with lens3329, smp-pqc-inventory and rusi's stable backend.

Inputs:

- `cargo metadata --format-version 1 --filter-platform <triple> --frozen` with the user's features. It resolves the dependency graph and enabled features without compiling. It does execute whatever `build.rustc` or `build.rustc-wrapper` the project's `.cargo/config.toml` names, so that file is neutralised first (section 12). `--no-deps` gives a manifest-only mode that needs no lockfile resolution at all.
- `Cargo.lock` for exact versions and checksums, used for RustSec matching; it is a superset of what is built.
- For built binaries, the dependency list that [cargo-auditable](https://github.com/rust-secure-code/cargo-auditable) embeds in a `.dep-v0` section, read with the `auditable-info` crate. cargo-auditable is now default in Alpine, NixOS, openSUSE, Void, Chimera and Wolfi, and for selected Ubuntu 26.04 packages, so post-build CBOMs of distribution binaries are realistic.
- Later, the unstable cargo `-Zsbom` precursor files, which record per-artifact resolved dependencies, features and compiler.

Processing:

1. Mark crates with knowledge-base entries as crypto providers.
2. Resolve backend selection from features. rustls 0.23.45 ships with `aws_lc_rs` and `prefer-post-quantum` in its default feature set, so a default rustls build uses aws-lc-rs and offers X25519MLKEM768 hybrid key exchange, and 0.23.44 enabled ML-DSA certificates by default; the `ring` provider is opt-in; `fips` selects aws-lc-fips-sys. reqwest chooses native-tls or rustls-tls by feature. These choices change the CBOM materially, so Layer 1 emits one asset for the backend actually enabled.
3. Turn crates declaring `links = "ssl"`, `"crypto"`, `"aws_lc_0_…"` and similar into separate native-library components (OpenSSL, AWS-LC, AWS-LC-FIPS, BoringSSL), with the FFI boundary flagged, so native advisories attach to the native component.
4. Record `build.rs` and vendored C sources as evidence only.

Output: library components plus candidate algorithm assets marked `method=manifest`, `confidence=low`, until Layer 2 confirms them. A crate present but never called is reported as `declared-not-used`.

## 6. Layer 2 — Type-resolved code analysis

This is the research core. RustCrypto puts algorithm and parameters into types: `Aes256Gcm` is `AesGcm<Aes256, U12>` with key, nonce and tag sizes as typenum generics; `Hmac<Sha256>`; `Argon2` with `Params`. ring and aws-lc-rs select algorithms through static constants: `UnboundKey::new(&aead::AES_256_GCM, key)`, `UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, bytes)`, `DecapsulationKey::generate(&kem::ML_KEM_768)`. openssl uses runtime values: `Cipher::aes_256_gcm()`, `MessageDigest::sha256()`, but also `from_nid` and `from_name(&str)`, which are data-dependent.

### 6.1 Front end

The primary front end is a `rustc_driver` wrapper in the Kani, Charon and MIRAI pattern, with the analysis written against `rustc_public`:

- `cargo check` is driven with `RUSTC_WRAPPER` set to the tool's driver for every crate, `-Zalways-encode-mir` and `-Zmir-opt-level=0` applied to all of them (so dependency bodies are present and call sites are not inlined away), a Miri or `build-std` sysroot for the standard library, and a dispatch on `CARGO_PRIMARY_PACKAGE` and `--target` so build scripts and proc-macro host crates are compiled normally and skipped by the analysis. A separate target directory avoids fingerprint interference.
- Inside the driver, `rustc_public` gives `Instance::resolve` for the monomorphised callee at each call site, `Instance::body()` with constants already evaluated, `InstanceKind::Virtual` for `dyn` dispatch, static allocations for ring-style constants, and `external_crates()` for dependency items.
- The mono-item call graph starts from the workspace's entry points and public API, following Kani's `reachability.rs`, which re-implements the compiler's collector on `rustc_public`, including vtable method collection for `dyn`.

Two secondary front ends:

- **No-build quick scan** on `ra_ap_hir` (stable Rust, build scripts disabled): maps source call sites to callees with the substitution visible in the enclosing generic context, without whole-program monomorphisation. Useful when the project does not build, for IDE integration, and as the baseline that isolates the gain from monomorphisation.
- **`syn` pre-filter** to find candidate files and crates quickly, as rusi's stable backend does.

Charon remains the fallback if its serialised IR and cargo plumbing prove easier to maintain than a hand-written driver; its lack of `dyn` support in monomorphised mode and its git-only library are the costs.

### 6.2 Analyses

1. **Call-site detection.** Match resolved instances (callee definition plus generic arguments) and constant allocations against knowledge-base entries keyed by crate, version range and definition path. Generic wrappers resolve because instances are monomorphised.
2. **Parameter recovery.** Read algorithm, key size, nonce size, tag size and mode from the concrete type's generic arguments; read ring and aws-lc-rs constants from their definition paths; read openssl constructors from method names, and fall back to constant propagation for `from_nid` and `from_name`, reporting `unresolved` when the argument is not a literal. rustls provider and cipher-suite lists come from constant propagation over the builder chain, with the feature-resolved default provider from Layer 1 as the fallback.
3. **Composition.** `dependsOn` edges from type structure: `Hmac<Sha256>` to SHA-256, `Hkdf<Sha384>` to SHA-384, a TLS 1.3 suite to its AEAD and hash, a hybrid group to its classical and PQC halves.
4. **Provenance slices over MIR.** Intraprocedural first, using the Flowistry dependency computation; interprocedural along marker-reachable paths in Paralegal's adaptive style, with knowledge-base entries acting as the external annotations that mark key, nonce and secret arguments. The slices feed nonce and IV provenance (CSPRNG, counter, literal), key provenance (generated, derived, read from environment or file, hard-coded), the purpose classifier, and parameter values that cross function boundaries.
5. **Wrapper summaries.** In-house wrapper crates get per-function summaries ("performs AES-256-GCM encrypt with a key from argument 0"), so callers inherit the asset. These are the same marker-propagation mechanism as item 4.
6. **Material and artifacts.** Embedded PEM and DER keys and certificates, `include_bytes!` of key files, and test vectors (tagged as test scope). Values are never emitted; types, sizes and locations are.

### 6.3 Scope controls

- Workspace crates are analysed in full. Dependency crates are analysed only along paths reachable from the workspace, which is what the mono-item collector gives naturally; an opt-in deep mode analyses them whole.
- Code under `#[cfg(test)]`, `benches/` and `examples/` is classified as non-production scope, not discarded.
- MIR is post-expansion; spans map back to the macro call site for evidence.

Output: `cryptographic-asset` components with `evidence.occurrences`, `cryptoProperties` and registry names, marked `method=type-resolved`, `confidence=high`, confirming or refuting Layer 1's candidates.

## 7. Layer 3 — Usage purpose and the bounded LLM assist

Each asset receives a purpose label, `security`, `non-security` or `undetermined`, with a rationale. Rules decide first; the model sees only what the rules leave open.

### 7.1 Stage A: structural rules

- **Trait family.** `std::hash::Hash` and `Hasher` (SipHash in `HashMap`), `rustc-hash` (3,206 dependents), `ahash` (2,059), `crc32fast` (1,326), `xxhash-rust` (915), `fxhash` (561), `siphasher` (261) and `seahash` (198) are never cryptographic. Detection keys on `digest::Digest`, `Mac`, `Aead`, `Signer`, `Encapsulate` and their ring and openssl counterparts. SipHash has a registry family of its own (`SipHash[-{compressionRounds}-{finalizationRounds}]`, primitive `mac`), so `HashMap` can be named canonically and labelled non-security rather than hidden.
- **Security sinks.** Output or input reaches MAC or signature verification, `subtle::ConstantTimeEq`, a KDF, key or nonce construction, an authentication header, TLS or JWT configuration, or password storage.
- **Secret sources.** Key material, passwords, tokens, secret stores.
- **Non-security sinks.** Map keys, file names, cache keys, log fields, ETags, deduplication identifiers, with ordinary inputs. `blake3` (3,890 dependents) is cryptographic but mostly used this way, which makes it the main test of this rule.
- **Known patterns.** SHA-1 for git object IDs, content addressing, `rand::thread_rng` for shuffling or jitter.

### 7.2 Stage B: a local model on the residue

- **Input:** the MIR slice rendered as source, resolved types and constants, function and module names, doc comments. Never whole files.
- **Output:** JSON constrained to a schema with closed enums for purpose and for registry primitive and family, plus a free-text rationale. llama.cpp converts a JSON Schema to a grammar but does not support `patternProperties`, `if/then/else`, `uniqueItems` or non-integer bounds and does not inject the schema into the prompt; Ollama's `format` and vLLM's `structured_outputs` offer the same. The schema is designed inside that subset.
- **Protocol:** following Hirsch et al., a small ensemble of three quantised open-weight models with majority vote and a tuned prompt; their results show three models capture most of the ensemble gain. Candidates verifiable from model cards: Qwen3-Coder, Devstral Small, gpt-oss-20b, Granite 4.0.
- **Recording:** `method=llm`, model and version, prompt-template hash, vote margin as confidence.
- **Backends:** pluggable; local by default; an enterprise endpoint where policy allows; the run manifest records which ran.

### 7.3 What stays undetermined

Checks whose security relevance depends on the threat model, such as a checksum on a downloaded artifact, are flagged `undetermined` with both readings explained.

### 7.4 Confidentiality

Source stays on the machine. The knowledge base is built from public crates, so any model may draft it. The CBOM and the SARIF output map the attack surface and are handled as sensitive. The headline number is the share of assets that reach Stage B.

## 8. Layer 4 — Vulnerabilities and reachability

1. **Match.** Load the RustSec database with the `rustsec` crate (the library behind cargo-audit) and match it against `Cargo.lock`; keep a local mirror for offline runs.
2. **Prioritise crypto.** Advisories in the `crypto-failure` category, or on knowledge-base crates, link to the affected `cryptographic-asset` components as well as the library.
3. **Reachability.** For the roughly 22 percent of advisories that list `affected.functions`, intersect those paths with the Layer 2 mono-item call graph from the workspace's entry points.
4. **Emit VEX.** `affected` when reachable; `not_affected` with `code_not_reachable` when built but never called; `not_affected` with `component_not_present` when in the lockfile but outside the build graph; `under_investigation` when the advisory names no functions, which is the majority.
5. **Cross-check.** OSV-Scanner's DWARF-based call analysis is an independent, binary-level answer to the same question; disagreements between the two are reported, not hidden.
6. **Native libraries.** For `links` components, record vendored or system versions where determinable; these map to OSV and NVD.

## 9. Layer 5 — Policy and compliance

Policies are evaluated over the finished CBOM, so any CBOM can be checked.

- **Custom rules** use the FBK TOML model (assessment levels, compliance levels, most-specific-rule matching), extended with matches on Layer 3 purpose, scope, provenance, VEX state and a configurable evaluation date.
- **National packs** are not re-implemented. The CBOM records purpose in `cryptoFunctions` and the `rcbom:` properties so that cbomctl's resolution order finds it and returns a verdict instead of `INDET`; sbom-tools provides CNSA 2.0 and NIST IR 8547 validation with SARIF and OSCAL output. The tool ships wrapper commands that invoke both when installed.
- **CISA minimum elements.** Once published under EO 14412, a conformance check for those elements joins the shipped profile.
- **Outputs:** a compliance report in JSON and Markdown, SARIF with source spans for GitHub code scanning and IDEs, and `cbom diff` between two commits for pull-request gating.

Verdicts decided by rules are separated from those needing analyst review, as Foroncelli et al. recommend.

## 10. CBOM output model

CycloneDX 1.7 JSON, validated with cdxrs on every run.

- **Library components** with `pkg:cargo` purls from Layer 1; native `links` libraries as separate components.
- **Algorithm assets** named by registry pattern (for example `AES-256-GCM`, `HMAC-SHA-256`, `ML-KEM-768`, `ECDSA-P-256-SHA-256`), with `algorithmFamily`, `ellipticCurve`, `primitive`, `parameterSetIdentifier`, `mode`, `padding`, `cryptoFunctions`, security levels and OID.
- **Protocol assets** from rustls configuration, with versions and cipher suites linked to their algorithms and hybrid groups to both halves.
- **Related crypto material and certificates** with type and size only.
- **Evidence occurrences** with file, line, symbol and macro call site.
- **Dependencies**: application to library to algorithm; composition edges.
- **Vulnerabilities** with VEX analysis, linked to library and asset.
- **Run manifest** in `metadata` and properties.

Custom properties under a namespace such as `rcbom:` cover what the spec cannot yet express: `usage:purpose`, `usage:confidence`, `usage:rationale`; `detection:method` (`manifest`, `type-resolved`, `syntactic`, `llm`); `scope`; `provenance:key`, `provenance:nonce`; `backend` (the feature-selected provider); and `raw:*` for anything outside the enums. The usage and provenance properties are candidates for CBOM 2.0, which already adds `keyUsage`; the tool also publishes a strict profile listing the fields it always fills, in answer to the interoperability finding of Olewinski et al.

Library: `serde-cyclonedx` from [psastras/sbom-rs](https://github.com/psastras/sbom-rs) (MIT; 0.10.0, June 2025), whose types are generated from the official schemas at build time and whose sibling `cargo-sbom` already writes 1.6. Adding the 1.7 schema is a small upstream contribution; a fallback is `typify` over the 1.7 schema. The docs.rs build failure of 0.10.0 is a warning that generated types from a schema this size can be brittle, so the first week of work includes compiling the 1.6 crypto types and round-tripping the `bom-examples` CBOM fixtures.

## 11. Crypto knowledge base for Rust

The knowledge base maps crate APIs to registry-named algorithms and parameters. It is versioned data, built offline from public sources and reviewed before release. Two facts make it tractable.

First, coverage follows a steep curve. The crates.io `cryptography` category holds 7,812 crates, but reverse-dependency counts concentrate use: rand 32,536, sha2 20,654, rustls 4,724, hmac 4,043, blake3 3,890, ed25519-dalek 3,140, aes-gcm 1,868, openssl 1,855, ring 1,694, aws-lc-rs 397, ml-kem 160, ml-dsa 140. About thirty crates (the RustCrypto trait and algorithm crates, ring, aws-lc-rs, rustls, openssl, the dalek crates, argon2, pbkdf2, scrypt, the PQC crates) cover the large majority of use. The long tail is reached by trait inference: any type implementing `digest::Digest`, `aead::Aead`, `signature::Signer` or `kem::Encapsulate` is cryptographic by construction, and its family can often be read from the crate's registry-style name.

Second, docs.rs serves rustdoc JSON for every crate version built since 23 May 2025 at `https://docs.rs/crate/{name}/{version}/json`, so API inventories can be drafted without compiling anything. rustdoc JSON itself remains nightly-only (format version 61), and docs.rs files carry whichever format version their build produced, so the builder must read several `rustdoc-types` versions.

Each entry is keyed by crate, semver range and definition path and records the registry mapping, how parameters are recovered (type argument, constant, argument index, method name), data-flow roles (which arguments are key, nonce, input; which results are tag or signature), the features that enable the item, and known non-security aliases. Version ranges are unavoidable: RustCrypto shipped a coordinated major bump in 2026 (crypto-common 0.2, digest 0.11, cipher 0.5, password-hash 0.6, kem 0.3, signature 3.0, aead 0.6; sha2 0.11, hmac 0.13, aes-gcm 0.11, ed25519-dalek 3.0) that renamed `AeadInPlace` to `AeadInOut`, replaced `generic-array` with `hybrid-array`, removed `CoreWrapper`, and renamed the block-cipher traits, while most deployed code still uses the previous generation. ring's last release was 0.17.14 in March 2025, so its constants are stable.

Build pipeline:

1. **Seed by hand** the thirty core crates across both RustCrypto generations, with golden tests.
2. **Rank the long tail** by reverse dependencies within the cryptography category.
3. **Draft entries with an LLM** from docs.rs rustdoc JSON and README text, constrained to the knowledge-base schema and the registry enums. DAInfer's documentation-to-specification results (precision about 80 percent, recall about 82 percent) set the expectation: drafts are useful, not final.
4. **Validate automatically.** Every definition path must exist in the rustdoc JSON; every family, primitive and curve must exist in the registry; every entry gets a minimal crate compiled through Layer 2. This catches the API hallucinations the EASE 2026 study found dominant.
5. **Review and publish** as a versioned release recorded in every CBOM.

The knowledge base is independently useful to rusi, CodeQL's Rust models and Crypistry, and is a natural community contribution.

## 12. Sandboxing and untrusted code

Nothing in cargo sandboxes build scripts or proc macros: the Rust project's "sandboxed build scripts" goal (2024) is accepted but unshipped, cargo issue #5720 remains open, and the wasm proc-macro pre-RFC never advanced. The tool therefore supplies its own isolation.

- **Manifest-only mode** (Layer 1 with `--no-deps`, or Layer 1 with `--frozen` on an already-vendored tree) executes nothing, after the project's `.cargo/config.toml` has been removed or overridden, because `cargo metadata` would otherwise run the `rustc` or wrapper that file names. This is Provenant's stance: static parsing, no execution of scanned code or package-manager code.
- **Compile modes** (Layer 2 and OSV-Scanner cross-checks) run inside a container or a bubblewrap/nsjail sandbox with `--network none`, a read-only source mount, a scratch target directory, and sources vendored beforehand with `cargo vendor --locked` or [Hermeto](https://github.com/hermetoproject/hermeto), which supports Cargo, writes the source replacement configuration, builds offline and emits its own CycloneDX SBOM. `cackle` (cargo-acl) is an alternative that sandboxes build scripts, proc macros and rustc individually on Linux.
- **Disclosure.** The run manifest records the sandbox mode; a run outside a sandbox on untrusted code is refused unless explicitly forced, and the CBOM says so.

## 13. Reuse versus build from scratch

### 13.1 Reuse as is

- CycloneDX Cryptography Registry: vocabulary for names, families, curves and OIDs.
- `cargo_metadata`, `rustsec`, `auditable-info`: build graph, advisories, embedded dependency lists.
- `serde-cyclonedx`: CycloneDX 1.6 types generated from the schema (1.7 to add).
- `cdxrs`: schema and semantic validation of 1.6 and 1.7 CBOMs (vendored; not on crates.io).
- `serde-sarif` from the same author as `serde-cyclonedx`: SARIF output.
- cbomctl and sbom-tools: national policy packs, conformance, OSCAL.
- Hermeto or `cargo vendor`: offline, vendored builds.
- BF-CBOM: the comparison harness for the evaluation.
- Hirsch et al.'s ensemble code (MIT): the local-model protocol for Stage B.
- CryptoAPI-Bench (MIT): source of misuse and provenance cases to translate.

### 13.2 Adapt

- Kani's `reachability.rs`: template for a mono-item call graph on `rustc_public`.
- Charon's driver: the cargo plumbing (`RUSTC_WRAPPER` dispatch, `always-encode-mir`, Miri sysroot, cache defeat), or Charon itself as the fallback front end.
- Flowistry's intraprocedural engine and Paralegal's adaptive inlining and external-annotation design: the provenance slices.
- `rustc_plugin`: the two-binary cargo scaffold.
- cdxgen's `cryptoAlgorithmFamily.js` resolver and `links` handling; rusi's crate table as a seed; its OID table.
- The FBK TOML policy format, with the four extensions in section 9.
- CodeQL's `rustcrypto.model.yml` and Crypistry's rule structure: cross-checks for the knowledge base.
- cargo-geiger's dependency walk and `ra_ap_hir` resolution: the no-build quick scan.

### 13.3 Build from scratch

- The `rustc_public` analysis driver: call-site matching, parameter recovery, composition, constant propagation for builders and `from_name`.
- The knowledge-base schema, seed entries, drafting pipeline and validators.
- The purpose classifier: rules, slice rendering, model prompts, ensemble voting.
- Reachability-filtered VEX over `affected.functions`.
- The assembler, the `rcbom:` property profile and the strict profile.
- The benchmark: synthetic micro-cases, real-world labels, scoring.
- The sandbox wrapper and run manifest.

## 14. Feasibility of the from-scratch claims

Each claim gets a verdict (high, medium, low, or unknown where no prior evidence exists), the evidence, the main risk, and the test that settles it.

### F1. Monomorphised call-site attribution

*Claim:* a call through `fn seal<A: Aead>` is attributed to the concrete `Aes256Gcm` or `ChaCha20Poly1305`. *Verdict: high.* `rustc_public::mir::mono::Instance::resolve` with the call site's generic arguments returns the monomorphised callee, and `Instance::body()` is documented as eagerly monomorphised with constants evaluated; Kani relies on exactly this. *Risk:* nightly API churn until the crates.io publication goal lands, and `rustc_public` objects being thread-local and non-`Send`, which shapes the driver's design. *Test:* a two-week spike resolving three patterns (generic wrapper, trait object, ring constant) in three real crates on one pinned nightly.

### F2. Parameter recovery from types and constants

*Verdict: high for RustCrypto and ring/aws-lc-rs, medium for openssl and rustls.* RustCrypto encodes key, nonce and tag sizes as typenum generics on the concrete type, readable from the instance's generic arguments; ring and aws-lc-rs constants are static allocations with definition paths. openssl's `Cipher::from_nid` and `MessageDigest::from_name` take runtime values, and rustls suites are built by chains of builder calls, so both need constant propagation and will sometimes be unresolved. *Risk:* unresolved values reported as guesses. *Test:* parameter completeness on the synthetic corpus, with `unresolved` counted as a miss, not a hit.

### F3. Composition edges

*Verdict: high.* `Hmac<Sha256>`, `Hkdf<Sha384>` and hybrid key-exchange groups are composite types, so the edge is in the type; TLS suites are enum constants with known decomposition. *Risk:* none specific beyond F2.

### F4. Cross-crate analysis of dependencies

*Verdict: medium.* Dependency MIR is available under `-Zalways-encode-mir` and `cargo check`; Charon, Kani and Paralegal all do this in production research code. The cost is a full dependency compile with MIR encoding, minutes for a mid-size workspace, plus a Miri or `build-std` sysroot for the standard library. *Risk:* build time and disk; projects whose build scripts need network or system libraries inside the sandbox. *Test:* wall-clock and memory on ten real crates of increasing size; a hard limit on dependency depth in the default mode.

### F5. Call graph with dynamic dispatch

*Verdict: medium.* The compiler's collector and Kani's port handle `dyn` by instantiating all vtable methods of unsized impls, which is sound and over-approximate; function pointers and closures resolve through the `Fn` traits when their origin is visible. *Risk:* over-approximation inflating reachability in Layer 4, which errs on the safe side (`affected` rather than `not_affected`), and MIR inlining removing call sites unless `mir-opt-level=0` is forced. *Test:* precision of `not_affected` verdicts on a set of advisories with known-unreachable functions.

### F6. Key and nonce provenance through MIR data flow

*Verdict: medium intraprocedural, low-to-medium interprocedural.* Flowistry's modular information flow is proven for within-function dependencies; Paralegal shows cross-crate, marker-driven slicing in seconds for most applications and 88 seconds for Lemmy, but it is research code tied to its policy language and pins its own nightly. The EASE 2026 false negatives were all flows through indirection, so the gain is real. *Risk:* engineering effort and analysis time; precision loss where approximation by type replaces inlining. *Test:* the CryptoAPI-Bench-derived provenance cases (hard-coded keys, static IVs, predictable entropy), reporting intraprocedural and interprocedural recall separately; ship the intraprocedural version first.

### F7. Wrapper summaries for in-house crates

*Verdict: medium.* This is marker propagation along the call graph, the same mechanism as F6, with knowledge-base entries as the initial markers. *Risk:* summaries over trait objects and closures degrade to "may perform crypto" without parameters. *Test:* a synthetic workspace with a two-level wrapper crate around aes-gcm and ring.

### F8. Purpose classification by rules

*Verdict: high for trait-family separation, medium for sink and source rules.* The `std::hash::Hasher` versus `digest::Digest` split is decided by the trait and needs no data flow; the non-cryptographic hasher crates are a closed list. Sink and source rules depend on F6, so their recall follows it. *Risk:* blake3 and SHA-256 used for content addressing in storage code, where sinks are ordinary data structures and the rules must say non-security confidently. *Test:* a labelled slice of 200 call sites across the corpus with rules only, reporting precision, recall and the undetermined share.

### F9. Local-model classification of the residue

*Verdict: unknown; the task has no prior evidence, the mechanism does.* No paper classifies crypto use as security versus non-security at call-site level. The closest evidence, Hirsch et al., is package-level relevance, where three quantised local models with majority vote and a tuned prompt reached F1 0.82 to 0.86, matching cloud models, and Xia et al. show raw LLM misuse judgements exceed 50 percent false positives until scoped and self-validated. Constrained JSON output is mature in llama.cpp, Ollama and vLLM. *Risk:* the residue may be dominated by cases that are inherently threat-model-dependent, where any label is wrong. *Test:* the Layer 3 benchmark slice with and without the model, three local models versus one cloud model, reporting accuracy on the residue only and the size of the residue.

### F10. Reachability-filtered VEX

*Verdict: high in mechanism, bounded in coverage.* Given F5, intersecting `affected.functions` with the call graph is straightforward, and the format is verified. Only about 22 percent of RustSec advisories carry functions, so most verdicts will be `under_investigation`; OSV-Scanner's DWARF approach is an independent cross-check. *Risk:* a false `not_affected` is the worst outcome; over-approximation in F5 protects against it. *Test:* zero false `not_affected` on advisories with known-reachable functions in the corpus.

### F11. Knowledge base at scale

*Verdict: medium-high.* docs.rs rustdoc JSON removes the need to compile crates; the registry supplies the target vocabulary; trait inference covers the long tail; DAInfer-level drafting accuracy means human review of every entry that ships. *Risk:* two RustCrypto generations with different definition paths; rustdoc format-version drift on docs.rs; aws-lc-rs features gating ML-KEM (not verified); the maintenance treadmill. *Test:* the seed's golden tests pass on both generations; drafting the next hundred crates and measuring the correction rate.

### F12. A labelled Rust benchmark

*Verdict: medium; the cost is labour, not uncertainty.* The format is settled (ground truth as a CycloneDX 1.7 CBOM, as Cryben does, with the three-category taxonomy); the harness exists (BF-CBOM); the misuse cases can be translated from the MIT-licensed CryptoAPI-Bench, since the EASE 2026 translations carry no licence. TNO's finding that no ground truth exists makes this publishable on its own. *Risk:* two-annotator labelling of 20 to 30 real crates is weeks of expert time; Cryptoscope reports heavy correction of LLM pre-labels. *Test:* inter-annotator agreement on the first five real crates before scaling.

### F13. Sandboxed analysis of untrusted code

*Verdict: medium.* The pieces exist (Hermeto vendoring, `--network none`, bubblewrap, cackle); cargo itself offers nothing, and `cargo metadata` honours the project's `.cargo/config.toml`. *Risk:* projects that cannot build offline; the sandbox adding friction that pushes users to run unsandboxed. *Test:* the benchmark corpus builds and analyses end to end with the network disabled.

### F14. No-build fallback on rust-analyzer

*Verdict: medium.* `ra_ap_hir` resolves method calls with generic substitutions and runs on stable; weekly 0.0.x releases mean pinning and periodic breakage; substitutions are local to the enclosing generic context, so generic wrappers stay unresolved. *Risk:* divergence from rustc inference. *Test:* the `syn`-only, `ra_ap_hir` and `rustc_public` front ends scored side by side on the synthetic corpus, which is also the ablation the paper needs.

### F15. CycloneDX 1.7 model and validation

*Verdict: high.* `serde-cyclonedx` already generates 1.6 types from the schema; adding 1.7 is adding a schema file; cdxrs validates both with crypto-specific rules. *Risk:* generated types from a large schema being awkward or failing to build (the 0.10.0 docs.rs failure). *Test:* round-trip the `bom-examples` CBOM fixtures in the first week.

### Overall

The four claims that carry the research contribution, F1, F2, F6 and F9, range from high to unknown, and F1 is the one everything else depends on. F6 and F9 are where the uncertainty concentrates, and both have a cheap version (intraprocedural slices; rules without a model) that ships first. Everything else is engineering on proven components.

## 15. Evaluation and benchmark

### 15.1 Corpus

1. **Synthetic micro-cases.** One crate per knowledge-base entry and per pattern: generics, trait objects, wrappers, macros, feature-selected backends, both RustCrypto generations, and non-security uses (hash tables, cache keys, content addressing, git IDs). Misuse and provenance cases translated by us from CryptoAPI-Bench (MIT).
2. **Real-world crates.** Twenty to thirty projects: TLS servers on rustls, authentication services, wallets and signers (where secp256k1, Ed25519 and BLS dominate, as the blockchain-focused qrp-mcp scanner targets), content-addressed storage, `no_std` firmware, and a project adopting PQC through aws-lc-rs or ml-kem.
3. **Labels** as CycloneDX 1.7 CBOMs in the Cryben style, with the three-category taxonomy, two annotators and adjudication, LLM pre-labelling allowed with full review.

### 15.2 Metrics per layer

- Layer 1: precision and recall of shipped crypto libraries and backends against the build graph.
- Layer 2: asset precision and recall; parameter completeness with `unresolved` as a miss; the ablation across `syn`, `ra_ap_hir` and `rustc_public` front ends.
- Layer 3: precision and recall for security versus non-security; undetermined share; residue share; accuracy with and without the model; local versus cloud.
- Layer 4: VEX correctness on advisories with known reachability; false `not_affected` rate.
- Layer 5: agreement with cbomctl and sbom-tools verdicts on the same CBOM, and with expert verdicts on the custom rules.
- Runtime: wall-clock and memory, sandboxed, per corpus crate.

### 15.3 Baselines

cdxgen with rusi (both backends), acdi, cipherscope, lens3329, CodeQL's three Rust crypto queries, Semgrep's Rust rules, and OSV-Scanner's call analysis for Layer 4, all run through a Rust worker added to BF-CBOM. Following Olewinski et al., the evaluation also reports which CBOM fields each tool fills.

## 16. Build plan

Phases are ordered, not dated; each ends at a gate on the benchmark.

0. **Phase 0, the spike (about two weeks).** A minimal `rustc_public` driver on one pinned nightly that resolves `Aes256Gcm` behind a generic wrapper, a `dyn Aead` call, and a ring constant in three real crates, under `cargo check` with `-Zalways-encode-mir` and a Miri sysroot. *Gate:* all three resolve; if not, Charon becomes the front end and the plan is re-costed.
1. **Phase 1, foundations.** `serde-cyclonedx` 1.6 types with the 1.7 schema added, cdxrs validation in CI, the run manifest, the knowledge-base schema and seed for both RustCrypto generations, the synthetic corpus with golden CBOMs. *Gate:* valid CBOMs for every micro-case; `bom-examples` fixtures round-trip.
2. **Phase 2, coarse CBOM.** Layer 1 with feature-resolved backends and native `links` components; RustSec matching without reachability; custom TOML rules; wrappers for cbomctl and sbom-tools; the sandbox with Hermeto. *Gate:* library detection at least on par with rusi, lens3329 and acdi; the corpus builds offline.
3. **Phase 3, type-resolved core.** The driver from the spike extended to call-site matching, parameter recovery, composition and intraprocedural provenance; the mono-item call graph from Kani's template. *Gate:* asset recall and parameter completeness beat rusi's compiler backend; the ablation shows the gain from monomorphisation.
4. **Phase 4, context.** Purpose rules; reachability-filtered VEX with the OSV-Scanner cross-check; then interprocedural slices and wrapper summaries; then the local-model residue stage. *Gate:* residue share measured; no false `not_affected`; Layer 3 accuracy with and without the model.
5. **Phase 5, scale and publish.** Long-tail knowledge base from docs.rs JSON; the real-world benchmark; SARIF and a CI action; the BF-CBOM worker; release, paper, and the knowledge base offered to cdxgen, CodeQL's Rust models and Crypistry.

Rough effort for one person with strong Rust and no prior rustc-internals experience: Phase 0 two weeks; Phases 1 and 2 one to two months; Phase 3 three to six months, with the variance driven by `rustc_public` churn; Phases 4 and 5 four to six months. About a year in total, or about six months to a first paper with Layers 1 and 2, intraprocedural provenance and a small benchmark.

Crate layout: `rcbom-model` (types, properties, validation), `rcbom-kb`, `rcbom-manifest` (Layer 1), `rcbom-driver` (the `rustc_public` wrapper; the only nightly crate), `rcbom-analysis` (matching, parameters, slices; takes the driver's facts, builds on stable), `rcbom-purpose`, `rcbom-vuln`, `rcbom-policy`, `cargo-cbom` (CLI; the name is free on crates.io), `rcbom-bench`.

## 17. Risks and open questions

- **`rustc_public` churn.** Pin per release, mirror Kani's and Charon's pin cadence, isolate all compiler-facing code in `rcbom-driver`, keep Charon as fallback.
- **Projects that do not build**, or do not build offline. Degrade to the `ra_ap_hir` quick scan plus Layer 1, mark the run partial.
- **Knowledge-base lag and the two-generation problem.** Report crates in the cryptography category without entries as `unknown-crypto-crate`; run golden tests on both generations.
- **Interprocedural analysis cost.** Adaptive inlining with depth limits reported as diagnostics; intraprocedural mode as the default.
- **Model misclassification.** Classify-never-delete, confidence on every label, metrics with and without the model.
- **FFI and `unsafe`.** Flag boundaries; link to native components; a binary pass with CBOM-Lens or cbom-generator later.
- **Attack-surface leakage.** Local by default; documented handling; an optional redaction profile.
- **Competition.** cdxgen's rusi ships monthly and already maps to the registry; the durable differentiators are monomorphised parameters, purpose, reachability and the benchmark. Contributing the knowledge base upstream may be better than competing on detection breadth.

Open questions:

- Whether to propose `usage:purpose` and provenance for CBOM 2.0, and whether to align the property names with cbomctl's expectations now.
- Whether aws-lc-rs gates ML-KEM behind its `unstable` feature (not verified) and how the KB should model unstable features.
- Which three local models to standardise, settled by the Layer 3 bake-off.
- Whether to build on Charon after all if the spike shows `rustc_public` churn is too costly.
- Whether FBK, the OTH Amberg-Weiden group behind Crypistry and the local-model work, or the Bern group behind BF-CBOM would collaborate; all three are complementary.

## 18. References

Standards, registry and regulation:

- CycloneDX Cryptography Registry. https://cyclonedx.org/registry/cryptography — definitions https://cyclonedx.org/schema/cryptography-defs.json — schema https://cyclonedx.org/schema/cryptography-defs.schema.json
- CycloneDX v1.6 release (CBOM). https://cyclonedx.org/news/cyclonedx-v1.6-released/
- CycloneDX CBOM 2.0 schema changes, PR #769. https://github.com/CycloneDX/specification/pull/769
- CycloneDX discussion #966 on intended use. https://github.com/CycloneDX/specification/discussions/966
- IBM CBOM. https://github.com/IBM/CBOM
- Executive Order 14412, Securing the Nation Against Advanced Cryptographic Attacks, 22 June 2026. https://www.whitehouse.gov/wp-content/uploads/2026/06/eo-14412.pdf
- NIST IR 8547 (initial public draft). https://csrc.nist.gov/pubs/ir/8547/ipd

Generators, scanners and infrastructure:

- sonar-cryptography (PQCA). https://github.com/PQCA/sonar-cryptography — Rust rules PR #474 https://github.com/PQCA/sonar-cryptography/pull/474
- CBOMkit (PQCA). https://github.com/PQCA/cbomkit
- cdxgen. https://github.com/CycloneDX/cdxgen — cdxgen-plugins-bin (rusi, golem, kosi, cdxrs) https://github.com/CycloneDX/cdxgen-plugins-bin
- BF-CBOM. https://github.com/SEG-UNIBE/BF-CBOM — preprint https://romanboegli.ch/assets/pdf/Boegli_2026_BFCBOM_ICPC.pdf
- Keylens. https://github.com/keylens/cbom — lens3329 https://github.com/3329lens/3329lens — acdi https://github.com/vral-parmar/acdi — cipherscope https://github.com/script3r/cipherscope — smp-pqc-testkit https://github.com/rwilliamspbg-ops/smp-pqc-testkit
- PostQuantum.CryptographicBillOfMaterials (.NET). https://github.com/systemslibrarian/PostQuantum.CryptographicBillOfMaterials
- CodeQL Rust GA. https://github.blog/changelog/2025-10-14-codeql-scanning-rust-and-c-c-without-builds-is-now-generally-available — Rust query help https://codeql.github.com/codeql-query-help/rust/ — cbom-action https://github.com/advanced-security/cbom-action
- Semgrep supported languages. https://docs.semgrep.dev/supported-languages — Rust rules https://github.com/semgrep/semgrep-rules
- rustc_public project goal. https://goals.rust-lang.org/2026/rustc-public.html — repository https://github.com/rust-lang/rustc_public — `Instance` docs https://doc.rust-lang.org/nightly/nightly-rustc/rustc_public/mir/mono/struct.Instance.html
- `-Zalways-encode-mir`. https://doc.rust-lang.org/nightly/unstable-book/compiler-flags/always-encode-mir.html — monomorphization collector https://doc.rust-lang.org/nightly/nightly-rustc/rustc_monomorphize/collector/index.html
- Kani. https://github.com/model-checking/kani
- Charon. https://github.com/AeneasVerif/charon — paper https://arxiv.org/abs/2410.18042
- Paralegal. https://github.com/brownsys/paralegal — paper https://justus.science/pdfs/paralegal.pdf — Flowistry https://github.com/willcrichton/flowistry — rustc_plugin https://github.com/cognitive-engineering-lab/rustc_plugin
- Dylint. https://github.com/trailofbits/dylint — RAPx https://github.com/Artisan-Lab/RAPx — Rupta https://github.com/rustanlys/rupta — MIRAI https://github.com/endorlabs/MIRAI — cargo-geiger https://github.com/geiger-rs/cargo-geiger
- rust-analyzer `ra_ap_hir`. https://docs.rs/ra_ap_hir/latest/ra_ap_hir/
- RustSec advisory-db. https://github.com/rustsec/advisory-db — OSV-Scanner call analysis https://google.github.io/osv-scanner/usage/scan-source/ — dep-scan Rust reachability https://depscan.readthedocs.io/languages/rust-reachability
- cbomctl. https://github.com/lvlrSajjad/cbomctl — sbom-tools https://github.com/sbom-tool/sbom-tools — FBK CBOMkit fork https://github.com/claudioforoncelli/cbomkit#custom-policies
- sbom-rs (serde-cyclonedx, cargo-sbom). https://github.com/psastras/sbom-rs — cyclonedx-rust-cargo https://github.com/CycloneDX/cyclonedx-rust-cargo
- cargo-auditable. https://github.com/rust-secure-code/cargo-auditable — auditable-info https://docs.rs/auditable-info/latest/auditable_info/
- Hermeto. https://github.com/hermetoproject/hermeto — cackle https://github.com/cackle-rs/cackle — Provenant https://getprovenant.dev/ — sandboxed build scripts goal https://goals.rust-lang.org/2024h2/sandboxed-build-script.html — cargo issue #5720 https://github.com/rust-lang/cargo/issues/5720
- docs.rs rustdoc JSON. https://docs.rs/about/rustdoc-json — rustdoc JSON tracking issue https://github.com/rust-lang/rust/issues/76578 — rustdoc-types https://docs.rs/rustdoc-types/latest/rustdoc_types/
- RustCrypto traits (aead, digest, cipher, signature, kem). https://github.com/RustCrypto/traits — aes-gcm https://docs.rs/aes-gcm — ring https://docs.rs/ring — aws-lc-rs https://docs.rs/aws-lc-rs — rustls CryptoProvider https://docs.rs/rustls/latest/rustls/crypto/struct.CryptoProvider.html — openssl https://docs.rs/openssl — ml-kem https://docs.rs/ml-kem — ml-dsa https://docs.rs/ml-dsa — libcrux https://github.com/cryspen/libcrux — pqcrypto https://github.com/rustpq/pqcrypto — liboqs-rust https://github.com/open-quantum-safe/liboqs-rust

Research:

- Näther, Hirsch. Hidden Ciphers and Where to Find Them. https://arxiv.org/abs/2608.04857
- Foroncelli, Tomasi, Piras, Dias Knob, De Matteis, Ranise. Towards Cryptography Bill of Materials Compliance. SSR 2025. https://cris.fbk.eu/handle/11582/367387
- Nocera, Scanniello. CBOM Generation and Consumption: A Mining Study from GitHub. SEAA 2026. https://link.springer.com/chapter/10.1007/978-3-032-36587-3_33
- Olewinski, Sandler, Ebinger. An Empirical Analysis of Open-Source Tools for Cryptographic Asset Discovery for PQC Readiness Assessment. ARES 2026 Workshops. https://link.springer.com/chapter/10.1007/978-3-032-35586-7_19
- Yamamuro, Uemura, Fukushima. SoK: Challenges for Implementing Automated Cryptography Discovery and Inventory Tools. ICISSP 2026. https://www.scitepress.org/Papers/2026/142271/142271.pdf
- Hess. The Anatomy of Cryptography Bills of Materials. Eurocrypt 2026 MAgiCS workshop. https://research.ibm.com/publications/the-anatomy-of-cryptography-bills-of-materials-standardization-and-practice-in-cyclonedx
- Moffie et al. Cryptoscope. https://arxiv.org/abs/2503.19531
- Hirsch, Raab, Bauer, Loebenberger. Detecting Cryptographically Relevant Software Packages with Collaborative LLMs. ICISSP 2026. https://arxiv.org/abs/2603.07204 — code https://github.com/OTH-AMiQuaSy/detecting-crypto-packages
- Elsayed, Fulton, Yang. An Empirical Security Evaluation of LLM-Generated Cryptographic Rust Code. EASE 2026. https://arxiv.org/abs/2604.27001
- Xia et al. Exploring Automatic Cryptographic API Misuse Detection in the Era of LLMs. ISSTA 2025. https://arxiv.org/abs/2407.16576
- Li, Dutta, Naik. IRIS: LLM-Assisted Static Analysis for Detecting Security Vulnerabilities. https://arxiv.org/abs/2405.17238
- Sijpesteijn, van Leuken, Kerling. Cryptographic Asset Discovery and Inventory. TNO 2025 P11921. https://publications.tno.nl/publication/34645425/j6EewK7a/TNO-2025-P11921-GB.pdf
- CryptoAPI-Bench. https://github.com/CryptoAPI-Bench/CryptoAPI-Bench — CamBench https://github.com/CROSSINGTUD/CamBench — MASC https://github.com/Secure-Platforms-Lab-W-M/MASC
- Ho, Boisseau, Franceschino, Prak, Fromherz, Protzenko. Charon: An Analysis Framework for Rust. CAV 2025. https://arxiv.org/abs/2410.18042
- Li, Wang, Sun, Lui. MirChecker. CCS 2021. https://dl.acm.org/doi/10.1145/3460120.3484541
- M. van Leuken. LinkedIn article on labelling 366 cryptographic assets (not readable by automated tools). https://www.linkedin.com/pulse/what-manually-labelling-366-cryptographic-assets-me-maaike-van-leuken-bbdre/
- IREKAI. https://irekai.nl/
