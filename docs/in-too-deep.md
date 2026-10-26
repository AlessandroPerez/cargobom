# How cargo-cbom Works

This document explains how `cargo cbom` works inside: what each stage computes, how it reasons about values, and the implementation choices behind it. What a CBOM is, the tool's design principles, its five layers and how it compares with other tools are in `poc_workflow.md`; this document picks up from there.

---

## 1. What a Run Produces

### 1.1 Running it

A run analyses the code `rustc` compiles for the host target, with the default features (or `--features`) and the `release` profile (or `--profile`). From the root of a workspace:

```
$ cargo cbom -o cbom.json
$ cargo cbom verify cbom.json --self-test
```

The first command writes the CBOM. The second reopens every source position the CBOM cites and checks that the code there says what the CBOM claims (chapter 8). For reading, `cargo xtask summary cbom.json` (from this repository) prints the CBOM as one line per piece of evidence. Here is one such line, wrapped for this page:

```
occ AES-256-GCM | crypto:algorithm:AES-256-GCM | src/main.rs:24:12 | ring::aead::unbound_key::UnboundKey::new
    [reachable] [call] in app::main; new: setup, not a use;
    algorithm from ring::aead::algorithm::AES_256_GCM in the arguments;
    key: rng (rand::SecureRandom::fill); line: `..`; code: `UnboundKey::new`
```

Read it left to right. There is an **asset**, AES-256-GCM. One **occurrence** of it sits at `src/main.rs`, line 24, column 12, where the code names `UnboundKey::new`. The details say the call is *reachable* from `main` and that it sets a key up rather than encrypting anything. They say the algorithm comes from the descriptor `AES_256_GCM` written in the call's own arguments, and that the key was filled from a random number generator.

### 1.2 What the output contains

Every finding is a CycloneDX component of type `cryptographic-asset`. There are three kinds:
- **Algorithms** (`crypto:algorithm:<name>`), named after the CycloneDX Cryptography Registry: `AES-256-GCM`, `HMAC-SHA-256`, `ECDSA-P-256-SHA-256`, `x25519`. Each has a family, a primitive (AE, hash, MAC, signature…), a mode, a curve or parameter set where it has one, and the functions the program uses it for (`encrypt`, `digest`, `sign`, `keygen`…). An algorithm computed *inside* another one is a **component** of it: the SHA-256 inside `Hmac<Sha256>`, or the BLAKE2b inside Argon2. It gets its own asset and an occurrence at the outer call ("part of PBKDF2-SHA-256-1000-32").
- **Key material** (`crypto:material:<kind>:<algorithm>`): the keys, nonces, salts and passwords handed to a crypto API, with where each one comes from (its *provenance*, section 6.7).
- **Unknowns** (`crypto:algorithm:unknown:<primitive>:<package>`): an operation the code performs whose algorithm the tool could not determine, with the reason (section 6.4).

Each occurrence is a source position plus an `additionalContext`, the text after the position in the line above, which says what was found there and why. Positions are relative to the workspace. They read `<package>-<version>/<path>` inside a dependency, and `target/<path>` in code a build script generated.

Properties named `rcbom:*` carry what CycloneDX has no field for. These include reachability, the provenance of each key role (`rcbom:provenance:key=hard-coded`), findings (`rcbom:finding=hard-coded-key`), parameters the registry name does not spell out (`rcbom:param:nonce_bytes=12`), and the run's toolchain, target, features and profile.

One package can build several binaries. rage, for instance, builds `rage` and `rage-keygen`. The document lists the artifacts it covers (`rcbom:run:artifact`), and when there are several, every occurrence and asset is tagged with the artifacts that use it (`[artifacts: bin rage-keygen]`, `rcbom:artifact`). That way the reader can see that `rage-keygen` only uses X25519, although the package as a whole uses about twenty algorithms. Section 5.5 explains where the tag comes from.

---

## 2. How the Stages Fit Together

### 2.1 The pipeline

```
cargo cbom
 |
 |- Layer 1: rcbom-manifest      cargo metadata + Cargo.toml + Cargo.lock   (nothing compiled)
 |     crypto packages, backends, native libraries, where each enters the build
 |
 |- Layer 2a: rcbom-driver       cargo +nightly check, with RUSTC_WRAPPER=rcbom-driver
 |     every crate compiles normally; the driver reads its MIR and writes "facts" (JSON):
 |     sites, where values come from, how they move between functions, what is reachable
 |
 |- Layer 2b: rcbom-analysis     stable Rust; reads the facts and the knowledge base
 |     matches sites, follows values, labels sets, finds provenance, builds assets
 |
 |- assembly                     CycloneDX 1.7 JSON, validated against the schema on every run
 |
cargo cbom verify               an independent check of every position the CBOM cites
```

**Layer 1** reads only manifests and the lockfile, so it is fast and runs no code. **Layer 2** compiles the project and looks at the code itself. Layer 2 is split into a *driver*, which needs the compiler, and an *analysis*, which does not.

### 2.2 Three decisions that shape everything

> **Why analyse MIR?** Rust code can be looked at in roughly three forms:
>
> - **Source text** is what you wrote, but macros, method resolution, type inference, trait dispatch and generics are all unresolved. To know that `h.update(x)` is `<Sha256 as Digest>::update`, you need the compiler.
> - **LLVM IR** is fully resolved, but types are lowered to bytes, generic names are mangled, and source positions are only approximate.
> - **MIR** (*Mid-level IR*) is in between. It is the compiler's own representation of each function body after type checking: every call names exactly which function it calls (with its generic arguments), every value has a type, and every statement keeps its source span.
>
> MIR is also where the borrow checker works, so it is designed to make data flow explicit. We ask the compiler for the least optimised MIR (`-Zmir-opt-level=0`), because optimisation merges and drops the definitions and spans we follow.

> **Why a compiler wrapper around `cargo check`?** Cargo lets you replace `rustc` with a wrapper (`RUSTC_WRAPPER`). Our wrapper, the driver, compiles every crate exactly as `rustc` would and additionally reads its MIR. That gives us the real build: the features Cargo resolved, the `#[cfg]`s that apply, the dependency versions in the lockfile, and the code build scripts generate. We use `cargo check` because we need type-checked MIR, not machine code. Cargo's own caching also works for us: a crate it does not rebuild keeps the facts we wrote for it.
> One consequence: building a project runs its build scripts and procedural macros, so only run Layer 2 on code you trust, or in a container.

> **Why split a nightly driver from a stable analysis?** Reading MIR needs the compiler's internal API (`rustc_private`), which exists only on nightly and changes between nightlies. So everything that touches the compiler lives in one binary, `rcbom-driver`, pinned to one nightly (`nightly-2026-09-25`). It uses `rustc_public`, the compiler's emerging stable MIR API, and drops to `rustc_middle` only where `rustc_public` does not expose something yet. The driver's output is plain, structured JSON (the *facts*, `crates/rcbom-facts`). The facts know nothing about cryptography; they describe code. Everything else (the knowledge base, matching, the CBOM, the verifier) builds on stable Rust and can be tested without a compiler.

### 2.3 How a run proceeds

`crates/cargo-cbom/src/main.rs` drives a run:

1. Load the knowledge base (`crates/rcbom-kb/data/seed.toml`) and run Layer 1.
2. Unless `--manifest-only` was given, run `cargo +nightly-2026-09-25 check --workspace --profile release` with `RUSTC_WRAPPER` pointing at the driver. Environment variables tell the driver which crates the knowledge base covers.
3. Load the facts of every unit Cargo reports (fresh or rebuilt) and run the analysis.
4. With `--check-walk`, build each binary once more, unoptimised, to check the walk against the linker (section 5.6).
5. Assemble the CBOM, validate it against the vendored CycloneDX schemas, and write it.

The facts live under the target directory (`rcbom/facts/<crate>.json`). A stamp file records every input of the driver other than the sources: the driver binary, the compiler, the crate lists, features, profile and options. If any of them changes, the cache is discarded. The facts also carry a format version (`FACTS_VERSION`), checked when they are loaded.

The driver adds three compiler flags. `-Zalways-encode-mir` puts every dependency's MIR in its metadata, so the walk can follow calls into dependencies. `-Zmir-opt-level=0` keeps MIR close to the source. `-Zspan-free-formats` names closures by path rather than by file position.

---

## 3. Layer 1: Reading the Manifest

Layer 1 (`crates/rcbom-manifest`) uses `cargo metadata` (the resolved dependency graph and features, nothing compiled) and reads the manifests and the lockfile as text. It finds:

- the crypto packages that ship, each matched against the knowledge base by package name and version range, with its role (`algorithm`, `trait` or `protocol`, chapter 4);
- crypto packages the knowledge base does not model, recognised from their metadata (a `cryptography` category, or a keyword such as crypto, encryption, tls, in any case, as crates.io's slugs are: rust-crypto's `Crypto`, snowstorm's `Cryptography`), an explicit list, or, when the package declares no category at all, a name that names an algorithm of the Cryptography Registry (its first part or all of it, after an affix that says the crate is Rust's: `blake2b_simd`, `sha1_smol`, `rust-argon2`; procedural macros never count; a web framework named `seed` declares what it is). These are reported as *unmodelled* crypto packages, so a long-tail library is at least named. Among them, encodings and parsers of crypto data (categories encoding, parser-implementations, memory-management: der, pkcs8) are `support`, and so are the helpers on a `support` list whose metadata says cryptography but which compute none (block-buffer, subtle, the constant-time crates cmov and ctutils). Metadata cannot tell every case: ssh-key, which signs, has der's categories, and totp-rs names no crypto at all, so an explicit `crypto` list holds those (with ssh-agent-lib, quinn-proto, age-core, hyper-rustls, and native-tls with its wrappers, which name no crypto either). A package that neither its metadata, the lists nor its name show to be crypto is a known limit (README, Limitations): the driver records calls only into the packages Layer 1 lists, so it is missed by both layers; one filed as support still has its operations in Layer 2, unknown or named, cited inside it;
- the backend that features select (for example rustls with ring or with aws-lc-rs), and the native libraries the build links;
- where each package enters the build: the `Cargo.toml` line of a direct dependency, or the `Cargo.lock` entry of a transitive one, with the chain that pulls it in (`reached via t1 -> aes-gcm`).

Each package in the knowledge base also lists *candidates*: the algorithms it can provide (`AES-GCM` for `aes-gcm`). Candidates become assets only when Layer 2 confirms nothing from that package. So a crate that is compiled in, but whose algorithms the code never visibly uses, is still listed, coarsely.

---

## 4. The Knowledge Base

The knowledge base (`crates/rcbom-kb/data/seed.toml`) tells the analysis which items of which crates are cryptography and how to name them. It is validated when it is loaded: its patterns must compile, its families must exist in the CycloneDX registry, and a boundary model must name an enum the knowledge base defines.

Matching is **structural**. Entries name items by their *defining path* (where the item is declared, crate first), not by how a program imports it. They also say which generic argument carries what, and which versions an entry covers. `use aes_gcm::Aes256Gcm` and a re-export of the same type through another crate are the same item to the matcher.

The main sections:

| section | what it says |
|---|---|
| `[[crate]]` | a crypto package: versions, role, Layer 1 candidates |
| `[[type]]` | a type that *is* an algorithm (`aes_gcm::AesGcm<Aes256, U12>`): a name template filled from its generic arguments (`AES-{key}-GCM`), family, primitive, parameters |
| `[[static]]` | descriptors: statics and constants that stand for an algorithm (`ring::aead::AES_256_GCM`, aws-lc-rs's constants) |
| `[[fn]]` | functions that are an algorithm by themselves (`pbkdf2::pbkdf2_hmac::<Sha256>`), and constructors whose arguments name parameters (`Params::new(m, t, p, len)`) |
| `[[operation]]` | calls that *perform* an operation, and which argument carries the algorithm (`ring::digest::digest` takes it as argument 0) |
| `[[use]]` | which method names are which function (`seal_in_place_append_tag` encrypts) |
| `[[role]]`, `[[source]]` | which argument is a key, nonce, salt or password; where key material may come from (environment, files, an RNG, a derivation) |
| `[[part]]` | algorithms a family computes inside itself (Argon2's BLAKE2b) |
| `[[boundary]]`, `[[enum]]` | *boundary models*: an API whose algorithm is a value the program chooses (jsonwebtoken's `Header.alg`) |
| `[[protocol]]` | protocol configuration (rustls versions, suites, groups) |
| `[unmodelled]` | Layer 1 for packages without entries: crypto and support lists, and types that compute no cryptography (`SmallRng`) |
| `[semantics]` | what some packages' APIs mean: those drawing from the generator they are given (rand), modes over a block cipher (ctr), types whose `Default` is a constant (generic-array) |

### 4.1 Roles and stop crates

A package's **role** decides how the code walk treats it:

- **`algorithm`** crates (ring, aes-gcm, sha2…) implement primitives. A call *into* one is evidence. The code inside it is not: it is how SHA-256 is computed, not a use of it.
- **`trait`** crates (`digest`, `aead`, `cipher`…) define the RustCrypto traits. They are treated like algorithm crates.
- **`protocol`** crates (rustls, jsonwebtoken) configure primitives. Their own code *is* evidence: rustls choosing a cipher suite is a use.

Algorithm and trait crates are **stop crates**: the walk (section 5.5) does not record sites inside them. It enters them only to learn which crates run, and to follow calls back into your code, such as a closure you pass in.

> **Why stop?** Without stop crates, every SHA-256 call in your program would also produce dozens of occurrences inside `sha2`'s compression function. Those are not decisions your program makes, and they would bury the ones it does. The call into the library is the fact that matters.

### 4.2 Parameters

An entry's name template has placeholders (`PBKDF2-{hash}-{iterations}-{length}`). The entry says where each one comes from:
- a type argument, mapped to a name or read as a `typenum` length;
- an integer constant argument, or an enum constant by its discriminant;
- an array argument's length;
- a fixed default of a constructor;
- the call the value is later passed to.

Parameters that are not part of the name are reported as properties (`rcbom:param:tag_bytes`). A placeholder that cannot be resolved stays open, with `rcbom:param:unresolved` and the reason, rather than being filled with a guess.

---

## 5. Inside the Driver: From MIR to Facts

This chapter follows the driver (`crates/rcbom-driver`) as it compiles one crate. It answers four questions about the code:
- *where* the program touches a crypto library (sites);
- *where each argument's value comes from* inside a function (origins);
- *how values move between functions* (links);
- *what code can run at all* (the walk).

### 5.1 A short primer on MIR

Take this function:

```rust
struct Config { hash: &'static ring::digest::Algorithm }

fn fingerprint(cfg: &Config, data: &[u8]) -> ring::digest::Digest {
    ring::digest::digest(cfg.hash, data)
}
```

Its MIR looks roughly like this (simplified):

```
fn fingerprint(_1: &Config, _2: &[u8]) -> Digest {
    let mut _0: Digest;                       // the return place
    let mut _3: &ring::digest::Algorithm;
    bb0: {
        _3 = copy ((*_1).0: &ring::digest::Algorithm);   // cfg.hash
        _0 = ring::digest::digest(move _3, copy _2) -> bb1;
    }
    bb1: { return; }
}
```

Three things to notice:
- **Locals.** Every value lives in a numbered local (`_1` is `cfg`, `_3` a temporary). A *place* is a local plus a path into it: `(*_1).0` is "field 0 of what `_1` points to".
- **Calls are resolved.** The call names `ring::digest::digest` exactly; a trait method call would name the trait method and its `Self` type.
- **Basic blocks** (`bb0`, `bb1`) are straight-line code ending in a jump, a call or a return. An `if` becomes two edges, and a loop becomes an edge back.

Generic functions have one MIR body, but at run time they exist as **instances**, one per set of type arguments (`seal::<Aes256Gcm>`). Producing those copies is called *monomorphization*. It matters because `seal::<Aes256Gcm>` and `seal::<ChaCha20Poly1305>` use different algorithms.

### 5.2 Sites: where the program names a crypto item

The driver scans every function body, and every static and const initializer, of every crate. It does not follow calls during this scan. A **site** is a place where code names an item of a crate the knowledge base covers. There are three kinds:

- **Call sites** (`UnboundKey::new`, `<Sha256 as Digest>::digest`, `Aead::encrypt`) record the callee's defining path, the `Self` type and generic arguments as type trees (`AesGcm<Aes256, U12>`), and where every argument's value comes from (its *origin*, next section).
- **Pointer sites** are calls through a function pointer or a `dyn Fn`. The driver records where the pointer comes from, so the analysis can find which functions it may be (section 6.6).
- **Static and const sites** are a descriptor named in code (`&ring::digest::SHA256`). These are read from the MIR *before* constant evaluation, because evaluation loses names: aws-lc-rs's algorithms are `pub const`s copied by value, and once evaluated they are just bytes.

Each site belongs to an *owner* (a function or a static) and gets a **tier**. It starts a `present` (compiled) and becomes `reachable` if the walk (section 5.5) reaches its owner.

### 5.3 Origins: where an argument comes from

For each argument of a call site, the driver builds an **origin tree** from the function's data flow. It runs a reaching-definitions analysis: for each use of a place, which assignments could have produced the value it holds there? An assignment *kills* earlier ones to the same place. Writes through references, and calls that take `&mut`, define what the reference points to.

The leaves and nodes of the tree say what kind of value it is:

| origin | meaning |
|---|---|
| `Data` | a static or const (`&SHA256`) |
| `Const` | literal data: its length, whether it is all zeros (`[0u8; 12]`) |
| `Unit` | a value of a field-less type or a function item (`OsRng`, `Algorithm::HS256`) |
| `Param` | a parameter of the function |
| `Call` | the result of a call, with its arguments' origins, and the body it actually runs when that differs from the callee's item (a trait method on a known type, a generic instance) |
| `Field`, `Set`, `Written` | a field read from a value; a write into a field; what a callee writes through a `&mut` argument |
| `Any` / `All` | one of several definitions (an `if`) / a value made of several parts |
| `Loop`, `Truncated`, `Unknown` | depends on its earlier value / a bound was hit / not known |

For `fingerprint` above, the origin of `digest`'s first argument is `Field(Param(cfg), hash)`: field `hash` of what the parameter `cfg` points to. The driver stops at the function's boundary. What `cfg.hash` holds is the subject of the next section.

The tree is bounded in depth and width, and in nodes: once a tree has read 400 operands, no further place is read either. Hitting a bound is recorded (`Truncated`), never silently cut. The node bound once covered only operands, so reading the value before each write through a raw pointer could recompute the same definitions without end. Rayon's `partition_in_blocks` took 45 minutes on its own and now takes a quarter of a second.

**Pointers are where precision is hard.** Consider:

```rust
let mut a = &SHA256;
let r = &mut a;
*r = &SHA512;
digest(a, data);
```

The write through `r` changes `a`. To see that, the driver follows `r` back to what it points to. The rule is simple to state:

> A write through a pointer is **exact** only when the driver proves the one place the pointer points to. In every other case it lands as a *possible unknown* on every place the write may reach: every place the function has lent out by `&mut`, and what each `&mut` parameter points to, whenever its type can hold the value written. Examples of other cases: a pointer taken from somewhere the driver does not follow, a search past its bound, a type that may hide a `&mut` (a closure's captures, a type parameter).

This rule is one of the main decisions in the tool. The driver handles many concrete shapes exactly:
- a `&mut` kept in a struct or tuple the function builds;
- a `&mut` kept in a `Vec`, `Option` or `Box` that the function only fills and empties through standard calls;
- a holder handed to one of the program's own functions;
- a borrow a function returns.

But the list of shapes is never complete. The rule guarantees that a shape the driver does not know about produces an honest unknown instead of a silently missing value.

**Interior mutability** gets the same treatment. A shared borrow of something holding a `Cell`, `RefCell`, `Mutex` or similar, handed to a function outside the standard library, may be written through, just like a `&mut`.

**Closures** are followed where the driver can see who runs them. A closure moved into `iter().map(..)`, `Option::map` or `and_then` runs on the receiver's values, so the driver records it as a call with those values. A closure handed somewhere the driver does not follow gets unknown inputs beside its known ones.

> **Why not just track every pointer precisely?** That is the job of a points-to analysis (chapter 7). It is expensive and, done flow-insensitively, imprecise in its own ways. The origins analysis is local and fast. It follows the shapes real code uses and, crucially, it knows when it does not know.

### 5.4 Links: values across functions

Origins end at a function's boundary. To continue across functions, each crate also records **links** for the values that can carry an algorithm or a key: types that involve a crypto crate's type, such as `&'static ring::aead::Algorithm`, `ring::hmac::Key` or `&dyn VerificationAlgorithm`.

- `fields`: what each function stores in each struct field (`Config { hash: &SHA256 }`, `x.hash = v`, writes through `&mut`).
- `returns`: what each function returns, whole and per field.
- `calls`: the program's calls of its own functions, with every argument's origin. This resolves a parameter: it holds whatever its callers pass, the algorithm and the key material beside it (`stretch(prf, password.as_bytes(), ..)`).
- `writes`: what a function leaves behind a `&mut` parameter when it returns. A function that re-points or lends the parameter gets "the value before, and an unknown".
- `statics`: what a static whose contents change at run time may hold (`static mut`, `OnceLock`, locks), and statics that are aliases or tables of others.
- `coercions` and `dyn_calls`: which types the code turns into which trait objects, and the calls made on trait objects (section 6.6).
- `named` and `opaque`: the program's functions made into function pointers or trait objects, and those handed to code the tool does not follow.
- *instance summaries*: the same records for the instances of generic functions that other records name, so that a trait method inside a generic function resolves for each type.

Back to the example. Suppose `main` does `let cfg = Config { hash: &SHA256 }; fingerprint(&cfg, b"hi")`. The links say that `main` stores `&SHA256` in `Config.hash` and that `main` calls `fingerprint`. The analysis can then answer `Field(Param(cfg), hash)` with SHA-256.

Links are **flow- and context-insensitive**. A field holds any value stored into it anywhere in the build, and a parameter holds any argument passed for it by any caller. That is an over-approximation: it may include values that never reach a given call. The analysis therefore labels every member of a set with *how* it reaches the call (section 6.5), so that "possibly" is never presented as "certainly".

### 5.5 The walk: what can run

Compiling a crate makes all of its code *present*. Most of it never runs in a given binary. The driver therefore **walks** the graph of instances from the program's entry points and marks what it reaches:

- **Roots.** For a binary: `main`, what the standard library runs with its result (`<T as Termination>::report`, which prints an `Err` with its `Debug`), and whatever the linker keeps regardless of callers (`#[no_mangle]`, `#[used]`). For a library in the workspace: its public, non-generic API, its public statics, and what its exported generic or inline functions call.
- **A library's generic functions.** Only their users instantiate them, so the walk sees no instance. What they run whatever their type arguments is still reached: a call in them whose callee and arguments are all known is a root (ssh-key's `PrivateKey::decrypt(&self, password: impl AsRef<[u8]>)` calls ssh-cipher's `Cipher::decrypt`), and a call whose arguments are the caller's types is followed into the callee's generic body, as are the closures and `async` bodies built there, outside the standard library. A trait method called on a type parameter has no body to follow: its type is the caller's. The independent review found the dependency case, where the code behind a library's generic API was reported as only compiled. The per-item scan, which normally keeps only calls whose generic arguments are concrete, keeps in these functions the calls into crypto crates whose types are the function's parameters. `Sha256::digest(d)` with `d: impl AsRef<[u8]>` is SHA-256; `a.encrypt(n, m)` on the caller's `A: Aead` and `v.shuffle(rng)` on the caller's generator are unknowns, "a type parameter of the library's generic API: its callers choose the type". Where the library instantiates the function itself (`tag_sha256` calling `tag::<Hmac<Sha256>>`), the instance's algorithm stands alone, as for any per-item site an instance covers. The held-out rustic_core found this: `ReadSubsetOption::apply_with_rng(packs, rng: &mut impl Rng)`, reached only through the generic `Repository<S>::check`, had its `shuffle` dropped.
- **Edges.** The walk follows:
  - calls;
  - function items turned into pointers;
  - closures and coroutines (`async`) built;
  - drop glue;
  - statics named;
  - the vtables of trait objects (below);
  - the formatting machinery, as a case of the pointers above: `format!` and `{}` build `fmt::Argument`s holding a pointer to the `Display` or `Debug` impl they print, which matters for error types that format themselves.
- **Stop crates** (section 4.1) are entered only to learn which crates run. The one way code could run without the walk seeing it is a stop crate calling back into a type it does not own through a trait it models (a program's own `Digest` impl handed to `pbkdf2`). That is hand-rolled cryptography, out of scope, and the check against the linker (section 5.6) would show it; none remains in the corpus. bcrypt-pbkdf, which runs Blowfish this way, is itself modelled as the construction it is.

Sites inside walked instances become `reachable`. The walk also records what it reached (`Reach` in the facts): the reached functions and statics, and which crates' code runs. The analysis uses these to decide whether a value stored somewhere can really reach a call. A member only stored by code no entry point reaches does not count.

Each binary is walked on its own, from its own `main`, and so is a workspace library's public API. That is what makes **artifact attribution** possible: an occurrence is tagged with the artifacts whose walk reaches it, an asset with the union of its occurrences' tags, and the document lists the artifacts walked. The tags appear only when a run has more than one artifact. One nuance: a member reaching a shared function from one binary's code is tagged with every artifact that reaches the call, not only that binary; the tags may say too much, never too little.

**An upper bound.** Reachable means reached by this walk, which errs towards reaching: a trait-object method is released for every coerced type once any call through that trait, or any escape of such an object, is seen (below), and a future's body counts as run where the future is built. So a vtable method no code calls, an `Arc<dyn Trait>` built and never called, or an `async` body never polled is `reachable`; `present` means compiled and certainly not reached. The check against the linker (5.6) bounds it from the other side. The second independent review measured it: on realapp, whose `main` only builds rustls's ring provider, 419 of 560 occurrences are reachable.

**Trait objects** need care. When code coerces a value to `dyn Trait`, the vtable makes all of the type's methods for that trait callable. A naive walk would treat all of them as reached at the coercion. The walk instead defers them until such an object *may be called*. That happens when:
- a call through `dyn Trait` appears anywhere in the walk;
- the program hands an object of that trait to code it does not walk (the standard library, a stop crate, a foreign function, a pointer);
- the object appears in a root's signature or a function's result.

A closure that is only boxed into a `dyn Fn` is deferred the same way.

> **Why defer?** A type coerced to `dyn Debug` for logging should not make its `Drop` or its crypto methods "reachable" through a `dyn Hasher` that nothing ever calls. Deferring keeps such code at `present`. Releasing the methods as soon as any call, or any escape to code we don't see, is possible keeps the walk sound. This is the classic *rapid type analysis* idea, applied to vtables.

The walk has a size limit (`RCBOM_MAX_INSTANCES`, default 200,000). If it is hit, the run says so (`truncated`), and the analysis does not treat "not reached" as "dead".

### 5.6 Checking the walk against the linker

The walk decides what is `reachable`. If it missed an edge, code that runs would be reported as merely `present`, and nothing downstream would notice. So the walk can be checked against an independent source of truth: **the linker**, which keeps exactly the code the artifact contains. `cargo cbom --check-walk` does it; it costs a second build, so it is a flag.

The CLI builds each binary once more, without the driver, unoptimised (so little is inlined) and with v0 symbol mangling (whose names carry full paths and generic arguments). It reads the binary's defined function symbols and subtracts every instance the walk reached, the compiler's shims it went through included (drop glue, a closure's `call_once`). What remains is **linked but not walked**. Each symbol is classified by the crate that defines it, which the v0 name encodes: the crate of the item, of the impl for a method, of the trait for a shim of a trait method.

| class | meaning |
|---|---|
| entry | `lang_start`, the standard library's glue around `main` |
| std | the standard library and the compiler's shims, whatever types they are instantiated with |
| modelled | a stop crate or a crate implementing one: the walk does not enter them |
| constructor | an enum variant's or tuple struct's constructor used as a function |
| other | a crate that is neither the program's nor a crypto one, and calls no crypto crate |
| **gap** | anything else: the program's crates, the crypto crates, and crates calling into one |

The run's `rcbom:run:walk-check` property gives the counts per binary, and the gaps are listed on standard error. The target is zero gaps, and each gap is a missing walk edge, so a bug. The root for `Termination::report` (section 5.5) was found this way: rage's error types' `Debug` and `Display` impls were linked and not walked. On the corpus's binaries (rage, rage-keygen, jwt, xh, realapp) no gap remains.

Why may `other` be left over? Code there that reached the program's code or a crypto call would make that code linked and not walked too, and so a gap itself. What `other` holds on the corpus is a handful of `Box<dyn ..>` dispatch impls in xh's HTTP stack.

Some nuance in the comparison: an instance shared between crates lives in one crate's object code but may be walked from another, and some small functions are inlined even without optimisation. So symbols are compared by demangled path and generic arguments, with crate hashes stripped (the two builds hash the dependencies differently), never by object file.

> **Why the linker?** It is the one component that must know precisely what code is in the artifact. Its view is an over-approximation of what runs: the linker keeps code that is referenced, even if no execution calls it. That makes it the right yardstick for a walk that must never be *smaller* than what runs.

### 5.7 The facts

The driver writes one JSON file per compiled unit: its sites, links, reachability and, for the crates the knowledge base covers, their structs' field names and enum variants. (A boundary model names a field like `Header.alg`, and field indexes change between versions.) The analysis reads the facts of every unit together, so a value stored in one crate and read in another is linked across them.

---

## 6. Inside the Analysis: From Facts to Findings

The analysis (`crates/rcbom-analysis`) is ordinary stable Rust. It reads the facts and the knowledge base and produces occurrences, then assets.

### 6.1 Binding and reachability

First, every crate in the build is bound to the package it comes from. This matters because two packages can have the same library name: the package `md-5`'s library is called `md5`, like the package `md5`'s. Then the analysis computes which statics are reachable (those that reachable code names, transitively) and collects every binary's reached functions.

### 6.2 Matching sites

Each site is matched by kind:

- **Typed calls**, where the type is the algorithm (`Aes256Gcm::encrypt`, `Hmac::<Sha256>::new_from_slice`). The asset comes from the `[[type]]` entry and the call's type tree. The SHA-256 inside `Hmac<Sha256>` becomes a component occurrence.
- **Functions and constructors.** A method whose parameters were fixed by a constructor takes them from the constructor that built its receiver. For example, `Argon2::default().hash_password(..)` is Argon2id with the default costs.
- **Descriptor calls** (ring, aws-lc-rs), where the algorithm is a value passed to the call. The *value search* finds which descriptors can reach the argument (section 6.3).
- **Boundary models** (jsonwebtoken). `encode(&header, ..)` signs with `header.alg`. `decode` verifies with `validation.algorithms`, narrowed by the key's family: an RSA key verifies only RS\*/PS\* tokens. The model follows those fields across functions as it follows any value.
- **Static sites**: a descriptor named directly, or a static leading to descriptors (a table of digests, a rustls cipher suite).
- **Protocol calls** (`ClientConfig::builder`): a TLS asset with the versions, suites and groups the build offers. The occurrence is marked as configuration, not a connection.
- **Parts**: at each *use* of an algorithm whose family has parts, the parts become component occurrences.

### 6.3 The value search

For descriptor calls, one function (`search.rs`) answers: *which algorithms can this argument be?* It reads the call's own code first: the argument's origin tree, covering branches (`if c { &SHA256 } else { &SHA512 }`), fallbacks (`unwrap_or(&SHA512)`) and container contents. Where that answer depends on something outside the function (a field, a parameter, a returned value), it continues through the links.

The search's central property is that **its match on `Origin` has a case for every kind of value**, and each case does one of two things:
1. it follows the value by a modelled rule. Standard-library calls are followed only through a table of their semantics (`Option::unwrap_or` returns the receiver's value *or* the default). An unlisted std function is never assumed to "pass its argument through";
2. or it records a **gap**, with a reason ("a field of `T` the analysis does not follow", "the search hit its bound").

A gap is never ignored. It becomes the unknown beside whatever members were found ("other algorithms than these may reach the call: ... is not followed").

> **Why insist on this?** Early versions had code paths that read "not recorded" as "not there": a list of handled cases with an implicit `_ => nothing`. Every such path eventually dropped a real algorithm on some program. The fix was not to add cases but to change the default: anything not proven becomes an explicit unknown. We call code with the old default a *closed-world default*. When the tool gets something wrong, the fix is to find the code point with such a default and make its default the unknown, rather than adding one more handled case: the next program would only need a neighbouring case.

### 6.4 Operations and unknowns

The knowledge base lists the calls that *perform* an operation (`[[operation]]`): hashing, encrypting, signing, deriving. For every reachable call to one of them, the CBOM contains an occurrence. If the search found algorithms, they are the members. If it found none, the occurrence is an **unknown** of that primitive, with the reason. For example: "a parameter, whose arguments name no algorithm".

A call that is not itself an operation but sets one up (`UnboundKey::new`, a `Params` constructor) gets no unknown occurrence of its own. Its members say instead that they may not be all the algorithms involved.

A call into a crypto package the knowledge base does not model, made from outside the crypto layer (the program, or a dependency that is no crypto package), is cited as an operation of an unknown algorithm: openssl's `sha256`, tiny-keccak's `finalize`, curve25519-dalek's `mul_clamped`, orion's `SecretKey::default()`. What it does is not known ("what the call does is not known"), but for the use its method names (`encrypt`, `sign`); a name that says nothing without a modelled type (`finish`, `finalize`, `write`: the `[unmodelled]` `generic_methods`) names none there, as age's `StreamWriter::finish` ends an encryption. A constructor or a conversion is cited too: orion's `SecretKey::default()` draws a key, age's `to_public` computes one. So is a standard-library trait's method a type of such a package runs (`<SecretKey as Default>::default`). Not cited: a step of a stream (`update`, `write`: the `steps`), whose operation is the call that ends it, and a call into a relay (`relays`), a crypto package whose own calls are no operations: tokio-rustls and hyper-rustls wrap rustls, whose operations are cited in rustls, and rustls-pki-types, rustls-pemfile and rustls-native-certs are types, parsers and loaders of PKI data. Calls between crypto packages (openssl's into openssl-sys, age's into age-core) are the internals of what the program asked of the outer one, and count only where their method names a use. The second independent review found a closed version of this rule dropping operations (five in a program calling openssl and tiny-keccak, and the X25519 agreement of a Noise library), the third the setup exceptions it then had dropping key generations (orion's `SecretKey::default()`, openssl's `PKey::generate_ed25519()`).

An API of a crate the knowledge base models, at a version it covers, that the knowledge base does not name is an unknown where its name is a use ("an API the knowledge base does not name"). Any other such call is a gap in the knowledge base, which the boundary check (6.10) cites itself as an operation of unknown algorithm until an entry names it or an `[[aside]]` says it is no operation: a covered crate's API is the knowledge base's to describe, and a missing description gives an unknown instead of dropping the call (p256's `ProjectivePoint * Scalar`). rand 0.9's free `fill` was such a gap, named since.

A package the knowledge base models at a version it does not cover (md5 0.8, ed25519-dalek 3, password-hash 0.6) is never dropped. A call into its API that the knowledge base does not list is an unknown with the reason "a version the knowledge base does not cover". What the knowledge base says the package computes scopes the use: md5's `finalize` is an unknown hash, ed25519-dalek's `sign` an unknown signature. Here a generic name counts, since the package scopes it, but a streaming step (`update`, `write`, `consume`) does not by its name alone: the operation is the call that ends the stream. The held-out dufs found this case, where 8 operations had been dropped.

Streaming steps the knowledge base lists as operations are reported, at any version: `Digest::update` and `Mac::update` are `digest` and `tag` uses beside the `finalize` that ends the stream, and ring's `Prk::expand` is a `keyderive` use beside `Okm::fill`. The labelling rules (R1.2, R1.3) count only the finishing call, so the scorers count these occurrences as unlabelled uses, never as wrong.

A draw is the call that takes the generator, whoever's API it is: rand's `seq` traits (`v.shuffle(&mut rng)`, `v.choose(&mut rng)`, `partial_shuffle`, the `choose_*` and `sample_*` methods) are `generate` uses of the generator they are given, ChaCha12-RNG for rand's thread generator. A draw from a generator that computes no cryptography (rand's `SmallRng`, `StepRng`) is no operation at all, not an unknown one; a key made with one still is.

A crate the knowledge base lists only as part of a construction it models whole is still named when a program, or a crate the walk enters, uses it on its own. Poly1305 inside chacha20poly1305 is part of the AEAD, which the walk does not enter; aes256ctr_poly1305aes calls it itself (`Poly1305::compute_unpadded`), and there it is Poly1305. GHASH and POLYVAL, which the registry does not name, are unknown MACs at the `UniversalHash` call, never dropped.

### 6.5 Sets, members and witnesses

Often several algorithms can reach one call. The CBOM then reports each as a **member** of the call's set, and says how it gets there in two places: the algorithm sentence, and a `member:` label that carries a *witness* (the function, static or coercion that shows the path).

| label | meaning |
|---|---|
| `algorithm from X in the arguments` | named in the call's own code; the only one |
| `algorithm one of N that may reach the call: X …` | one of several named here (branches, a fallback) |
| `member: fixed` / `caller, passed by f` / `object, from f` | set in this function / passed in by caller `f` / returned or written by `f` |
| `member: container, possible` | an element of a container the call reads (`v[i]` reads any element) |
| `member: type-join, possible` | a value the build stores in that field *somewhere*; not shown to reach this call |
| `member: dyn, possible` | through a trait object: one of the types coerced to it |
| `member: table, stored by static T` | read from a table that never changes |
| `one of N chosen at run time (selector: configuration)` | several values chosen by input (a CLI flag, a config file) |
| `beside others not followed` | found while other values were not followed (an unknown sits beside it) |

The set's *completeness* is explicit. With no unknown beside it, the members are claimed to be all the algorithms that may reach the call. With an unknown, they are the ones found.

### 6.6 Calls through pointers and trait objects

**Function pointers.** A pointer site's origin is followed across functions to the functions that were turned into pointers (stored in fields, statics, returned by closures). Each one becomes a call at the pointer site, with the site's arguments. If the pointer's origin is not fully understood, the site is *open*: it may call any of the program's functions of that signature that were made into pointers, and each of those gets unknown arguments.

**Trait objects.** A call on `dyn Trait` gives its arguments to the method of each type the build coerces to that trait object (`coercions`). The member is labelled `dyn`, and `possible` when several types are. The receiver itself is unknown, so a field the method reads on `self` falls back to what is stored in that type's field anywhere.

### 6.7 Provenance of key material

For each argument that plays a role (`[[role]]`: key, nonce, IV, salt, password ...) the origin
tree is classified by where its data comes from:
- `hard-coded`: a literal or a static, noted when it is all zeros;
- `partly hard-coded`: a value some of whose bytes are a literal, the rest coming from elsewhere (a zeroed key buffer half of which a call fills, a constant pepper beside the user's input): no finding, since the value is not a literal. Fills through literal index ranges that together cover the buffer replace the literal (rustls's TLS 1.2 nonce: `nonce[..4]`, then `nonce[4..]`, each by `copy_from_slice`); a loop's writes (element by element, through `chunks_mut`) are not counted, so the literal stays;
- `environment`, `file` or `rng`;
- `derived`, from a KDF's output;
- `computed`, from other inputs;
- `parameter`;
- `absent`, such as an empty salt;
- `unknown`.

The classification passes through ordinary plumbing (slices, conversions, `?`, fallbacks) and across functions: a parameter is also what the program's callers pass there, each classified in its caller (`seal(&[1u8; 32], msg)` makes the key `hard-coded` inside `seal`), the parameter staying for callers outside the program or through pointers. A field read from a parameter (`&self.kdf_salt`) is that field of what the callers pass, not the fields beside it, and a caller's own parameter is named by its function (`parameter (argument 1 of kdf::enroll)`). A literal is cited by its line, and by its file when it is in another one. A protocol crate's function combining two inputs or more (rustls's `Nonce::new(&self.iv, seq)`, `iv ^ seq`) gives a `computed` value, unless all of them are constants; an algorithm crate's call is the operation, its output a function of its input. A secret that may be hard-coded in reachable code produces a finding (`rcbom:finding=hard-coded-key`). So does a generator seeded predictably (`predictable-rng`), handed to an API the knowledge base gives an `rng` role: key generation (`SigningKey::generate`, `KeyInit::generate_key`, `SecretKey::random`, `RsaPrivateKey::new`), `generate_nonce`, randomized signing and encryption. A generator handed to an API without that role is not classified.

### 6.8 Assembling the document

Occurrences are grouped into assets by name, one per registry name, with the union of their functions and parameter values. Components are linked in the dependency graph (`HMAC-SHA-256` depends on `SHA-256`). Each asset lists the packages that provide it. Layer 1 candidates are added where Layer 2 confirmed nothing. The whole document is validated against the CycloneDX 1.7 schema before it is written: an invalid CBOM is a bug, never an output.

### 6.9 What the analysis does not follow

Where a value is not followed, the CBOM says `unknown` with the reason, so these show up as unknowns rather than as gaps in the inventory:
- a `&mut` parameter re-pointed before a write through it;
- a closure that writes through a `&mut` it was given (functions have write summaries, closures do not);
- `entry().or_insert`;
- cells and thread-locals;
- pointers and trait objects made in code the driver does not scan;
- mutual recursion;
- the search's bounds.

Two behaviours follow from the knowledge base rather than from the analysis:
- a crypto package without entries appears as an *unmodelled* package, with unknown operations where the code calls it;
- a crate the knowledge base does not model at its boundary (say, one wrapping ring) is walked into. Its calls into ring are found and cited inside that crate, not at the program's call into it.

What the tool leaves out on purpose (other targets, tests, hand-rolled cryptography, certificates loaded at run time) is listed in the README's Limitations.

### 6.10 The boundary check: accounting for every call into a crypto package

"Never drop an operation" was, until the third independent review, a property the rules were meant to have and reviewers tested by attacking them; each review found calls a rule dropped. The boundary check makes it a property every run checks, as the walk check (5.6) does for the walk, and since the fourth review one every run keeps: a call it cannot account for is cited by the check itself.

The driver records, in every body the walk reaches, each call whose callee resolves to a function of a crypto package (the knowledge base's crates and the unmodelled crypto packages) other than the caller's own crate: by the function the call resolves to, not by the name written (`<orion::aead::SecretKey as Default>::default` is orion's), at the position a site of it would have (`Reach::boundary`). An operator's call (`point * scalar`, `Mul::mul` on a curve's types) is at the operator. Three kinds of code need more than that:
- the standard library's bodies, whose MIR has no source positions: a call they make into the crypto set (`Option::unwrap_or_default` running orion's `SecretKey::default`, which draws a key) is recorded at the walked code's call into the standard library that leads there, through standard-library code only, and named by the function called there (`unwrap_or_default`); a function the walked code hands to it as a value (`repeat_with(SecretKey::default)`) is named where it is named;
- a library's generic functions, which no instance shows: their calls are recorded from the per-item scan, resolved for the function's own type parameters where they fix the callee (crypto_box's `secret.scalar * public.0` on curve25519-dalek's types), else by the function named (`<D as Digest>::update`: digest's);
- whose code the caller runs for: an algorithm's, when it is an algorithm crate's or a crate implementing one, or is reached only from such code (p384's `Scalar::random`, which only elliptic-curve's `SecretKey::random` calls); a crypto package's, when it is one's or is reached only from crypto code (nom's parser instantiated by age with age's closure); else the program's. The program's own code is the program's whatever calls it (a function handed to ring's `agree_ephemeral` as its key derivation). Every caller of every instance is kept for this, so the answer does not depend on the walk's order.

Each call carries which call it is (`CallId`: the call's whole expression and the function it names), as its site does. The analysis then accounts for each call: it is cited when an occurrence made from the call's own site is at its position (two calls at one position, `generator() * s` or two calls of one macro, are two), or it needs no occurrence for one of these reasons, each stated in the knowledge base or by the CBOM's contract:
- `entered`: a protocol crate (rustls, jsonwebtoken), whose code the walk enters; its own calls into the algorithm crates are calls of the check in turn;
- `internal`: a call made for the crypto layer: into an algorithm crate from an algorithm's implementation (the code of an algorithm or trait crate at any version, p521 0.13 into elliptic-curve; a crate implementing one; subtle's generic code run on curve25519-dalek's field elements), into a package without entries from another crypto package's code (openssl into openssl-sys, age through nom), or of a crypto package's own closure by the dependency it was handed to (a runtime, a parser combinator), the call making the closure being checked itself; a crypto package's calls into the algorithm crates are cited inside it;
- `relay` (`[unmodelled] relays`), and `step`: a step of a stream (`[unmodelled] steps`, and the methods of the stream traits, `io::Read` and `io::Write`), whose operation is the call that made or ends the stream;
- `awaited`: a future's body polled where it is awaited (`listen(..).await`), the call of the `async fn` that made it being the call into the package, checked itself;
- `named`: a function reaching the call as a value (`Some(blake3::hash)` called through a closure's parameter, `repeat_with(SecretKey::default)`), cited where it is named;
- `not crypto`: a draw from a generator that computes no cryptography (`[unmodelled] not_crypto`: `SmallRng`), as the analysis takes it;
- an `[[aside]]` kind: what the knowledge base says is no operation and sets up no asset, by trait or by a crate's path, each with its reason: `view` (`AsRef`, `Deref`), `copy`, `format`, `wipe` (a destructor, `Zeroize`), `error`, `encoding` (SEC1, PKCS#8, DER, a key's numbers, a hash as hex), `public half` (a key pair's public key, from the private key cited where it is made), `setup` (a nonce, the associated data, a key from its bytes, a context: the operations made with them are cited), `accessor` (a descriptor's lengths, an output read after it is computed), `generator setup` (a generator or a distribution made: its draws are cited), `comparison` (two values compared, `PartialEq`, `ConstantTimeEq`, ring's constant-time comparison of a tag already computed), `table key` (a value fed to a hash table's hasher, `Hash`).

A call neither cited nor excused is cited by the check itself: an operation of unknown algorithm of the callee's package at the call, `algorithm unresolved: the boundary check: ... a call nothing else in the CBOM accounts for: what it does is not known` (p256's `ProjectivePoint * Scalar`, curve25519-dalek's `&point * &scalar`, aws-lc-rs's streaming cipher), with the use an `[[operation]]` gives it when one names the call (ssh-key's generic `SshSig::sign` calling `Signer::try_sign` on its type parameter: `sign`). So nothing the walk reaches is left out of the CBOM, whatever the rules above miss; what the knowledge base does not name is an honest unknown. The CBOM states the result (`rcbom:run:boundary-check`: the calls, how many are cited, how many the check cites itself, how many are excused and why); `cargo cbom --boundary-list FILE` writes every call with its verdict, one per line (position, `cited`, `unknown` or the reason, callee, its trait, the calling function, on whose behalf), so each excuse can be read. The analysis takes its own decisions not to cite from the same knowledge-base facts, so a call it leaves out for another reason is one the check cites.

What the check found: its first runs (third review) found rustls's QUIC header protection (`HeaderProtectionKey::new_mask`, an AES or ChaCha20 operation on each packet, now an `[[operation]]`), password-hash's `SaltString::generate` (a draw), and every call of a version the knowledge base does not cover whose name is no use (sha2 0.11's `Sha256::default()`, scrypt 0.12's `Params::new`, now unknowns). The fourth review then broke the check as it stood in five ways, each fixed in the check: calls the standard library makes (above), a library's generic functions (above), a second call at a cited call's position, the program's function run as a crypto package's callback taken for the package's code, and operators on curve points and scalars it reported but did not cite.

What the check proves, and what it rests on: every call the walk reaches from code it walks into the crypto set, those the standard library makes on that code's behalf, and those of a library's generic functions are cited in the CBOM, by an occurrence of the call or by the check itself, or are one of the kinds above. It rests on the walk (an upper bound, 5.5, checked against the linker), on Layer 1's crypto set (a package neither its metadata, the lists nor its name show to be crypto is outside it), and on the knowledge base's word that an excused kind is no operation. Calls through a function pointer, a function-typed parameter, a generic field or a returned function are no edges: the function is cited where it is named (6.6). Hand-rolled cryptography is out of scope, and code without MIR (a C library under its Rust bindings) is seen through the bindings' calls.

---

## 7. The Points-to Engine

The analysis described so far is the default. There is also an optional, heavier component: a whole-program **points-to analysis** (`pta.rs`, `pta_solve.rs`, `pta_unify.rs` in the driver), enabled with `RCBOM_PTA=1`.

### 7.1 What a points-to analysis does

A points-to analysis computes, for every pointer in the program, the set of places it may point to. Ours is *inclusion-based* (Andersen-style). Each MIR statement becomes a constraint between sets:

```
p = &x      ->  $x \in pts(p)$
p = q       ->  $pts(q) \subseteq pts(p)$
p = *q      ->  $for each o in pts(q): pts(o) \subseteq pts(p)$
*p = q      ->  $for each o in pts(p): pts(q) \subseteq pts(o)$
```

A solver propagates sets until nothing changes. The result covers every program shape at once: swaps, containers, closures, trait objects, standard-library internals. No list of handled shapes is needed. That is exactly the weakness of the origins analysis (section 5.3) that the engine was built to address.

The model, briefly:
- **Objects** are the locals of each analysed body, statics, constant memory, heap allocations, functions, vtables, and a special `UNKNOWN` (any value). A location is an object plus a byte offset, so different fields stay apart.
- **Calls through `dyn`** dispatch on the vtable the pointer actually holds. Calls through function pointers bind as the pointer's set gains functions.
- **Unanalysable code**: a call the engine cannot translate (no MIR, a foreign function) writes `UNKNOWN` into everything reachable from its arguments.
- **Contexts.** The program's code is analysed once. Standard-library code is analysed once per place the program calls into it, so two unrelated uses of `Vec::push` do not merge.
- **Queries.** Every call into a stop crate is a query. For each pointer argument, the engine reports which knowledge-base descriptors it may point to, whether it may be `UNKNOWN`, and how many other objects.

**Scaling** comes from a worklist solver with compact sets and cycle collapsing. Where sets grow large, objects are merged; merging only ever *widens* sets, so the answer stays sound. Past a size threshold the engine switches to a cheaper unification-based tier (Steensgaard-style): coarser, but its memory grows with the program rather than with the sets.

To see inside the standard library, the engine needs its MIR. The shipped standard library only has MIR for generic and inline functions, so engine runs build it from source (`RCBOM_BUILD_STD=1`, which uses `cargo -Zbuild-std`).

### 7.2 How its answers are used: only removing doubt

The engine is **flow-insensitive**: it ignores the order of statements. Recall the example from section 5.3:

```rust
let mut a = &SHA256;
let r = &mut a;
*r = &SHA512;
digest(a, data);
```

The origins analysis proves the answer is SHA-512. The engine says `{SHA256, SHA512}`, because `a` held both at *some* point. Neither tool is simply better than the other: the engine sees shapes the origins analysis cannot, and the origins analysis sees order the engine cannot. So the two are combined under one rule:

> **The engine only removes doubt.** Its answer is *complete* when, in every analysed copy of the calling function, the argument can only point to descriptors the knowledge base names: no `UNKNOWN`, nothing built at run time.
> - A complete answer **within** the search's members drops the members it excludes and closes the search's gaps: the unknown goes away.
> - A complete answer with a descriptor **beyond** the search's members never adds that descriptor. If the search had a gap, its unknown already covers the case. If the search claimed to be complete, the call gets an unknown: the engine has shown something the search may have missed.
> - An incomplete answer changes nothing.

> **Why never add?** Adding the engine's extra members looked attractive, because it surfaced some values the search had hidden behind an unknown. But it also replaced honest unknowns with impossible algorithms: two `&mut` pointers swapped before a write, or receivers of two different callers merged. Under a zero-misclassification bar, an honest unknown beats an impossible candidate. Adding an *unknown* where the engine finds more is the safe counterpart: it can cost precision, never correctness.

The engine is off by default because of its cost: building the standard library from source, and up to tens of minutes on large programs. Its main role is as a **check on the default run**.

### 7.3 The engine as an oracle

With the engine on, the analysis also compares the engine's answers with the default analysis's, and prints where they disagree. On any project, labelled or not, this makes the engine an **oracle** for the default analysis: it points at answers that may be wrong without anyone having written down the truth. Two kinds of disagreement are printed:

- `rcbom-pta: outside the engine: <member> at <position>`: the search reports a member that the engine's complete answer excludes. This is a *candidate wrong member* of the default run.
- `rcbom-pta: beyond a complete search: <descriptor> at <position>`: the engine's complete answer has a descriptor that a search claiming completeness does not report. This is a *candidate silent drop*, and it is why the call gets the unknown in engine runs (7.2).

Two details keep these lines meaningful. The engine is asked about the argument that carries the algorithm, as the knowledge base's operation names it: in `prk.expand(info, &AES_256_GCM)` that is the key `prk`, not the length, and where the engine cannot name it there is no verdict. And a *beyond* line is printed only where the search claims a set, at a call with members or at an operation: a getter (`alg.output_len()`) or a constructor whose use is reported elsewhere claims nothing.

`cargo xtask pta-candidates OUT_DIR… [--against OLD.txt]` collects these lines from a set of runs and diffs them against a previous list, so a review covers only what changed.

Reading a candidate needs nuance. The truth at a call is judged by two sets: `must`, the algorithms that do reach it, and `may`, those a deliberately coarse *reference analysis* would also report (`docs/suite/RULES.md`, R4). That analysis is flow-insensitive, field-based, container-smashing and context-insensitive, and it takes every type coerced to a `dyn` as a possible target. Reporting a `may` algorithm is imprecise, not wrong. The engine is finer than that reference in places: it keeps fields apart, it analyses library code per call site, and it follows the vtables that actually flow. So:
- an *outside* candidate is wrong only if the member is also outside the reference analysis's `may`. A `dyn` member of a type that is coerced elsewhere is imprecise, not wrong;
- a *beyond* candidate is a real drop only if the descriptor is in `must`. Most are the engine's own flow-insensitivity: a value overwritten before the call.

A candidate that survives this reading is a bug in the default analysis. It is fixed there, at the code point that caused it (section 6.3), never by letting the engine's answer through.

The oracle has one blind spot, and it concerns the engine itself. Where the search reports a set with an unknown beside it and the engine's complete answer agrees with the set, the engine closes the gap and nothing is printed. If the engine's answer was wrong too, a real algorithm disappears silently, in engine runs. This happened once: the engine lost the vtable of a closure behind `Rc<dyn Fn>` and closed a call to SHA-256 alone, while SHA-1 reached it through the `Rc`. So after any change to the engine, the calls whose gaps it closes are compared with the default run and read against `must`, like the candidates.

---

## 8. Checking the Evidence: the Verifier

A CBOM is only as useful as its evidence. `cargo cbom verify cbom.json` (`crates/cargo-cbom/src/verify/`) reopens every file the CBOM cites and checks each claim against the source text.

> **Why a separate, text-based checker?** If the verifier used the driver's span handling, a bug in that handling would be invisible: both would agree on the wrong line. So the verifier has its own lexer and reads source as text, sharing no code with the driver. It is a second opinion, in the way a test written from the spec is. It shares the knowledge base with the analysis, and one function of it: how the knowledge base names a descriptor (`static_names`), so a descriptor the knowledge base names wrongly reads alike to both.

It checks that:
- the position starts a token in code (not in a comment or string), and begins a path whose last segment is the cited symbol or an import alias of it. Aliases are resolved through `use` items, re-exports, renamed dependencies and type aliases. An operator trait's method (`<P as core::ops::arith::Mul<S>>::mul`) is at its operator (`*`);
- the position is inside the item the context names: the function, its impl block (type and trait) or trait, and the module. rustc names a method of an impl written in another module than its type `m::<impl Trait for Type>::f`. That impl is not one of the modules, and its type may be written re-exported (`public::Key` for `public::sk::Key`) or through a dependency's generic alias (`Hmac<D>` for `CoreWrapper<HmacCore<D>>`);
- the recorded line text and code text match the file;
- the claims in the details hold. "Algorithm from X in the arguments" requires X to be named in the code the argument reads: its bindings, the stores that may reach it, the statics and constants it names. No other descriptor of that primitive may be read instead. A member "from another function" needs a witness that exists and can hold it, in the program or a dependency (the standard library's are not read). A coercion position must really make that type a trait object, and a table member must be the field the call reads;
- a member derived through a boundary model is a variant of the model's enum, at a call the knowledge base models, of a key family the occurrence lists, and one the program's code can put in the modelled field. A jsonwebtoken HMAC-SHA-256 at the program's `encode` is `Algorithm::HS256` reaching `Header.alg`: named by the function the label cites (a function naming only `HS384` gives no `HS256`), by the static of a table, or else in the code the call reads;
- an unknown occurrence is at an operation: a call the knowledge base lists, any call into a package that is crypto the knowledge base does not model (but a relay), or a use of the API of an algorithm or trait package that is not the program's own (a version it does not cover); one the boundary check cites itself names a crypto package of the build, not the program's own nor a relay;
- manifest positions are the right key in the right `Cargo.toml` table, or the right entry in `Cargo.lock`, and a library component's name, version and purl are its bom-ref's.

**The self-test** turns the verifier on itself. `--self-test` shifts every verified position by one line and by one column, and counts how many shifted positions the checker rejects. A checker that accepts a shifted position is too lenient, and every accepted shift is printed.

**Ranges.** Sometimes two candidates are textually identical, like two adjacent calls generated by one macro. Then the verifier reports "confirmed within lines a–b" rather than an exact confirmation. The CBOM's own positions always stay exact, since they come from the compiler; only the checker's verdict is a range.

**What it does not check.** Some claims come from the walk, the value search or the knowledge base, which a reader of the text cannot redo, and the verifier does not check them: the reachability tier (`reachable`, `present`) and the artifact tags; the provenance class of key material and the findings drawn from it; which of the functions an asset lists a call performs (a use is checked to be a function, not which one); a set's labels (member kind, `possible`, `one of N`, `selector`) beyond the witnesses above; the reason an unknown gives; an asset's registry name, except a boundary model's; the crate segment of the enclosing item's path. Nor can it see an operation the CBOM leaves out: it checks what is cited, not what is missing. The independent review measured this with one-change mutations of real CBOMs: every change to a position, a symbol, a descriptor, a witness, an `instantiated by` detail or a manifest entry was rejected, and the changes listed here were accepted.

The verifier is deliberately conservative: what it cannot check is listed at the top of `verify/mod.rs`. Two examples are writes made by code it does not read, and a store at a constant index read back at a variable index. A fixture may list known false mismatches in a `verify-known` file, and each one is checked by hand.

---

## Appendix A: Where Things Are

| path | content |
|---|---|
| `crates/cargo-cbom` | the CLI (`main.rs`), schema validation (`validate.rs`), the walk check against the linker (`walkcheck.rs`), the vendored CycloneDX schemas (`schema/`), the verifier (`verify/`: `files.rs`, `lex.rs`, `source.rs`, `reads.rs`, `stores.rs`, `types.rs`, `members.rs`, `check.rs`, `macros.rs`, `manifest.rs`) |
| `crates/rcbom-manifest` | Layer 1 |
| `crates/rcbom-driver` | the nightly driver: `main.rs` (the wrapper), `cx.rs` (its context), `names.rs` (paths and names), `scan.rs` (sites, and the boundary check's calls), `origins/` (argument origins, pointers and holders), `links.rs` (values across functions), `walk.rs` (reachability, and the calls the standard library makes for walked code), `statics.rs` (named data), `pta.rs`, `pta_solve.rs`, `pta_unify.rs` (the points-to engine) |
| `crates/rcbom-facts` | the facts format shared by driver and analysis |
| `crates/rcbom-kb` | the knowledge base loader; `data/seed.toml` (entries) and the CycloneDX Cryptography Registry |
| `crates/rcbom-analysis` | `run.rs` (the run), `sites.rs` (a site's occurrences), `search.rs` (the value search), `links.rs` (values across functions), `boundary.rs` (boundary models), `pointers.rs` (pointer and trait-object calls), `engine.rs` (the engine's answers), `unknowns.rs`, `coverage.rs` (the boundary check), `matcher.rs` (knowledge-base matching), `provenance.rs`, `assets.rs`, `cbom.rs` (CycloneDX assembly) |
| `xtask/` | checks, e2e, scorers, summaries |
| `tests/fixtures/` | test programs, goldens, labels |
| `results/` | committed outputs behind the reported numbers |

Building and running:

```
rustup toolchain install nightly-2026-09-25 \
    --component rustc-dev,llvm-tools,rust-src,clippy,rustfmt
(cd crates/rcbom-driver && cargo build)      # the driver, on the pinned nightly
cargo build                                   # the CLI and libraries, on stable
cd <project> && <repo>/target/debug/cargo-cbom cbom -o cbom.json
<repo>/target/debug/cargo-cbom cbom verify cbom.json --self-test
RCBOM_PTA=1 RCBOM_BUILD_STD=1 <repo>/target/debug/cargo-cbom cbom -o cbom.json   # with the engine
```

## Appendix B: Environment Variables

Passed by the CLI to the driver:

| variable | meaning |
|---|---|
| `RCBOM_OUT` | where to write the facts |
| `RCBOM_KB_CRATES` | crates the knowledge base covers, and unmodelled crypto packages: sites naming their items are recorded |
| `RCBOM_STOP_CRATES` | algorithm and trait crates: no sites recorded inside them |
| `RCBOM_IMPL_CRATES` | the stop crates' own dependencies (their implementation) |
| `RCBOM_LOCAL_DIRS` | the workspace's own packages: never stop crates |
| `RCBOM_SEMANTICS` | what the knowledge base's `[semantics]` says the driver needs: the random fills that write a whole buffer, how generators' type names end |
| `RCBOM_SYSROOT` | the pinned toolchain's sysroot |

Set by you:

| variable | meaning |
|---|---|
| `RCBOM_DRIVER` | the driver binary, when `--driver` is not given |
| `RCBOM_MAX_INSTANCES` | the walk's size limit (default 200,000) |
| `RCBOM_PTA=1` | run the points-to engine (chapter 7); `RCBOM_PTA_*` variables tune and trace it |
| `RCBOM_BUILD_STD=1` | build the standard library from source (for the engine) |
| `RCBOM_DEBUG`, `RCBOM_DEBUG_WALK` | print caught panics; print the walk's edges out of matching instances |

## Appendix C: Implementation Choices at a Glance

| decision | in one line |
|---|---|
| analyse MIR via a `cargo check` wrapper | resolved calls, types and spans, with the real build (2.2) |
| nightly driver, stable everything else | the compiler API is unstable; the rest stays testable (2.2) |
| match by defining path | imports and re-exports name the same item (4) |
| stop at algorithm crates | the call into the library is the fact; its internals are noise (4.1) |
| a write is exact only when its target is proven | unknown shapes give unknowns, not drops (5.3) |
| defer trait-object methods until callable | sound and far less over-reached (5.5) |
| tag occurrences with their artifacts | one package, several binaries, different crypto (1.2, 5.5) |
| every `Origin` case followed or a gap | no closed-world defaults (6.3) |
| the engine only removes doubt | flow-insensitive extras would be misclassifications (7.2) |
| an independent text-based verifier with a self-test | a shared bug cannot confirm itself (8) |
| check the walk against the linker | every linked-not-walked gap is a missing edge (5.6) |
| the engine as an oracle on every run | its disagreements with the default run are reviewed, never let through (7.3) |
| fix by code point, not by case | the next program needs only a neighbouring case (6.3) |

