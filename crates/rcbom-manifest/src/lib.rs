//! Layer 1: which crypto crates ship, through which backend, which native libraries they link,
//! and where in the manifests each of them enters the build.
//!
//! Reads `cargo metadata` (resolved graph and features, no compilation) and the manifests and
//! lockfile as text. Evidence points at manifest lines: the `Cargo.toml` line declaring a direct
//! dependency, or the `Cargo.lock` entry of a transitive one, with the dependency chain from a
//! workspace member. Code locations are Layer 2's job.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use cargo_metadata::{Dependency, DependencyKind, Metadata, MetadataCommand, Package, PackageId};
use rcbom_kb::{Kb, Role};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Scope {
    /// Linked into a workspace artifact.
    Required,
    /// Only compiled for build scripts or proc macros; runs on the build host, does not ship.
    Build,
}

/// A manifest position. `line` is 1-based, `col` 0-based (CycloneDX `offset`).
#[derive(Clone, Debug)]
pub struct Evidence {
    pub path: PathBuf,
    pub line: usize,
    pub col: usize,
    /// What the text at that position names (the dependency key, `links`, ...).
    pub symbol: String,
    pub context: String,
}

#[derive(Clone, Debug)]
pub struct Pkg {
    pub id: PackageId,
    pub name: String,
    pub version: semver::Version,
    pub manifest_dir: PathBuf,
    pub member: bool,
    /// The program's own code: a workspace member or a path dependency (no registry or git
    /// source).
    pub local: bool,
    pub scope: Scope,
    pub features: Vec<String>,
    pub links: Option<String>,
    /// Knowledge-base role, if this is a crypto crate (known by name, any version).
    pub role: Option<Role>,
    /// The knowledge base has entries for this version. A crypto crate in another version is
    /// still a crypto crate, but its APIs are not matched (`unsupported-version`).
    pub kb_supported: bool,
    pub candidates: Vec<String>,
    /// For protocol crates: the backend packages the enabled features select, sorted. More than
    /// one means the features alone do not decide; the code does (`crypto::ring::default_provider`).
    pub backends: Vec<String>,
    pub evidence: Vec<Evidence>,
    /// Shortest dependency chain from a workspace member, member first.
    pub chain: Vec<String>,
    /// Packages this one depends on (normal and build edges in the resolved graph).
    pub deps: Vec<PackageId>,
    /// The subset whose code ships with this package's: normal edges, unless this package is a
    /// procedural macro.
    pub runtime_deps: Vec<PackageId>,
}

pub struct Manifest {
    /// The package of the manifest given (`--manifest-path`), unless it is a virtual workspace.
    pub root: Option<PackageId>,
    pub workspace_root: PathBuf,
    pub target_directory: PathBuf,
    pub packages: Vec<Pkg>,
}

impl Manifest {
    pub fn by_name_version(&self, name: &str, version: &str) -> Option<&Pkg> {
        self.packages
            .iter()
            .find(|p| p.name == name && p.version.to_string() == version)
    }

    pub fn by_id(&self, id: &PackageId) -> Option<&Pkg> {
        self.packages.iter().find(|p| &p.id == id)
    }

    /// The package whose directory contains `path` (the most specific one).
    pub fn owner_of(&self, path: &Path) -> Option<&Pkg> {
        self.packages
            .iter()
            .filter(|p| path.starts_with(&p.manifest_dir))
            .max_by_key(|p| p.manifest_dir.as_os_str().len())
    }

    /// How a file is named in the CBOM: relative to the workspace root for workspace files,
    /// `<package>-<version>/<path>` inside a dependency, unchanged otherwise.
    pub fn location(&self, path: &Path) -> String {
        // `src/crypto/aws_lc_rs/../ring/kx.rs` (a `#[path]` include) is `src/crypto/ring/kx.rs`
        let normalized = normalize(path);
        let path = normalized.as_path();
        if let Some(p) = self.owner_of(path)
            && !p.member
        {
            let rel = path.strip_prefix(&p.manifest_dir).unwrap();
            return format!("{}-{}/{}", p.name, p.version, rel.display());
        }
        match path.strip_prefix(&self.workspace_root) {
            Ok(rel) => rel.display().to_string(),
            Err(_) => path.display().to_string(),
        }
    }

    /// Inverse of `location`.
    pub fn resolve(&self, location: &str) -> PathBuf {
        for p in &self.packages {
            let prefix = format!("{}-{}/", p.name, p.version);
            if let Some(rest) = location.strip_prefix(&prefix) {
                return p.manifest_dir.join(rest);
            }
        }
        let path = Path::new(location);
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.workspace_root.join(path)
        }
    }
}

/// Lexical normalization: drops `.` and folds `dir/..`, without touching the file system.
fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir if out.file_name().is_some() => {
                out.pop();
            }
            c => out.push(c),
        }
    }
    out
}

pub fn host_triple() -> Result<String> {
    let out = std::process::Command::new("rustc")
        .arg("-vV")
        .output()
        .context("running rustc -vV")?;
    let text = String::from_utf8(out.stdout)?;
    text.lines()
        .find_map(|l| l.strip_prefix("host: "))
        .map(str::to_string)
        .context("no host line in rustc -vV")
}

/// Runs `cargo metadata` and builds the Layer 1 view. `features` are passed as with cargo.
pub fn load(manifest_path: &Path, target: &str, features: &[String], kb: &Kb) -> Result<Manifest> {
    load_with(manifest_path, target, features, kb, false)
}

/// As `load`, but `cargo metadata --locked`: fails rather than update `Cargo.lock`, for
/// checking positions inside it.
pub fn load_locked(
    manifest_path: &Path,
    target: &str,
    features: &[String],
    kb: &Kb,
) -> Result<Manifest> {
    load_with(manifest_path, target, features, kb, true)
}

fn load_with(
    manifest_path: &Path,
    target: &str,
    features: &[String],
    kb: &Kb,
    locked: bool,
) -> Result<Manifest> {
    let mut cmd = MetadataCommand::new();
    cmd.manifest_path(manifest_path);
    let mut opts = vec!["--filter-platform".to_string(), target.to_string()];
    if locked {
        opts.push("--locked".into());
    }
    if !features.is_empty() {
        opts.push("--features".into());
        opts.push(features.join(","));
    }
    cmd.other_options(opts);
    let md = cmd.exec().context("cargo metadata")?;
    build(&md, kb, target, &target_cfg(target)?)
}

/// The `cfg` values of the target, for platform-specific dependency tables.
fn target_cfg(target: &str) -> Result<Vec<cargo_metadata::cargo_platform::Cfg>> {
    let out = std::process::Command::new("rustc")
        .args(["--print", "cfg", "--target", target])
        .output()
        .context("rustc --print cfg")?;
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.parse().ok())
        .collect())
}

fn build(
    md: &Metadata,
    kb: &Kb,
    target: &str,
    cfg: &[cargo_metadata::cargo_platform::Cfg],
) -> Result<Manifest> {
    let resolve = md
        .resolve
        .as_ref()
        .context("cargo metadata returned no resolve graph")?;
    let nodes: HashMap<&PackageId, &cargo_metadata::Node> =
        resolve.nodes.iter().map(|n| (&n.id, n)).collect();
    let pkgs: HashMap<&PackageId, &Package> = md.packages.iter().map(|p| (&p.id, p)).collect();

    // The declarations of `parent` that this resolve edge comes from: same package, a
    // matching version requirement, and a kind and target cargo applied on this platform.
    let declarations = |parent: &Package, d: &cargo_metadata::NodeDep| -> Vec<Dependency> {
        let dp = pkgs[&d.pkg];
        parent
            .dependencies
            .iter()
            .filter(|x| {
                x.name == dp.name.as_str()
                    && x.req.matches(&dp.version)
                    && d.dep_kinds.iter().any(|k| k.kind == x.kind)
                    // the edge lists every table it comes from; this one may be another
                    // platform's (`[target.'cfg(windows)'.dependencies]`)
                    && x.target.as_ref().is_none_or(|t| t.matches(target, cfg))
            })
            .cloned()
            .collect()
    };
    // Is the edge really part of the build? The resolve also lists an optional dependency
    // that a weak feature only mentions (`alloc = ["ring?/alloc"]` in rustls-webpki): it is
    // built only if an enabled feature of `parent` activates it (`dep:x`, `x`, `x/f`).
    let activated = |parent: &Package, node: &cargo_metadata::Node, d: &cargo_metadata::NodeDep| {
        let decls = declarations(parent, d);
        if decls.is_empty() || decls.iter().any(|x| !x.optional) {
            return true;
        }
        let keys: Vec<String> = decls
            .iter()
            .map(|x| x.rename.clone().unwrap_or_else(|| x.name.clone()))
            .collect();
        node.features.iter().any(|f| {
            keys.iter().any(|k| f.as_str() == k)
                || parent.features.get(f.as_str()).is_some_and(|vals| {
                    vals.iter().any(|v| {
                        keys.iter()
                            .any(|k| *v == format!("dep:{k}") || v.starts_with(&format!("{k}/")))
                    })
                })
        })
    };

    // Walk from the members: normal edges keep the scope, build edges (and anything below a
    // proc macro) only run on the host. Dev-dependencies do not ship and are not followed.
    let mut scope: HashMap<PackageId, Scope> = HashMap::new();
    let mut parent: HashMap<PackageId, PackageId> = HashMap::new();
    let mut queue: VecDeque<PackageId> = VecDeque::new();
    for m in &md.workspace_members {
        scope.insert(m.clone(), Scope::Required);
        queue.push_back(m.clone());
    }
    while let Some(id) = queue.pop_front() {
        let here = scope[&id];
        let proc_macro = pkgs[&id].targets.iter().any(|t| t.is_proc_macro());
        for d in &nodes[&id].deps {
            if !activated(pkgs[&id], nodes[&id], d) {
                continue;
            }
            let kinds: Vec<DependencyKind> = d.dep_kinds.iter().map(|k| k.kind).collect();
            let s = if kinds.contains(&DependencyKind::Normal) && !proc_macro {
                here
            } else if kinds.contains(&DependencyKind::Build)
                || (kinds.contains(&DependencyKind::Normal) && proc_macro)
            {
                Scope::Build
            } else {
                continue; // development only
            };
            let better = scope.get(&d.pkg).is_none_or(|old| s < *old);
            if better {
                scope.insert(d.pkg.clone(), s);
                parent.entry(d.pkg.clone()).or_insert_with(|| id.clone());
                queue.push_back(d.pkg.clone());
            }
        }
    }

    let lock_path = md.workspace_root.as_std_path().join("Cargo.lock");
    let lock = std::fs::read_to_string(&lock_path).unwrap_or_default();
    let mut toml_cache: BTreeMap<PathBuf, Option<String>> = BTreeMap::new();
    let mut read = |p: &Path| -> Option<String> {
        toml_cache
            .entry(p.to_path_buf())
            .or_insert_with(|| std::fs::read_to_string(p).ok())
            .clone()
    };

    let mut out = Vec::new();
    for (id, s) in &scope {
        let p = pkgs[id];
        let node = nodes[id];
        let member = md.workspace_members.contains(id);
        // the program's own packages, and local path packages, are not the crates the
        // knowledge base describes, whatever their names (a member called `signature`)
        let foreign = !member && p.source.is_some();
        let exact = kb.crate_by_package(&p.name, &p.version).filter(|_| foreign);
        let entry = exact.or_else(|| {
            kb.crates
                .iter()
                .find(|c| c.package == p.name.as_str())
                .filter(|_| foreign)
        });
        let mut chain = vec![p.name.to_string()];
        let mut cur = id;
        while let Some(par) = parent.get(cur) {
            chain.push(pkgs[par].name.to_string());
            cur = par;
        }
        chain.reverse();
        let features: Vec<String> = node.features.iter().map(|f| f.to_string()).collect();
        // the table describes the supported versions' features only
        let mut backends: Vec<String> = exact
            .map(|e| {
                e.backends
                    .iter()
                    .filter(|(feat, _)| features.contains(feat))
                    .map(|(_, b)| b.clone())
                    .collect()
            })
            .unwrap_or_default();
        backends.sort();
        backends.dedup();
        let proc_macro = p.targets.iter().any(|t| t.is_proc_macro());
        let edge = |d: &&cargo_metadata::NodeDep, normal_only: bool| {
            scope.contains_key(&d.pkg)
                && activated(p, node, d)
                && d.dep_kinds.iter().any(|k| match k.kind {
                    DependencyKind::Normal => !(normal_only && proc_macro),
                    DependencyKind::Build => !normal_only,
                    _ => false,
                })
        };

        let mut evidence = Vec::new();
        if entry.is_some() {
            // Direct dependency of a member: the declaring line(s).
            for m in &md.workspace_members {
                let mp = pkgs[m];
                // the declarations cargo applies on this platform (not a
                // `[target.'cfg(target_arch = "wasm32")'.dependencies]` table on another)
                let Some(nd) = nodes[m].deps.iter().find(|d| &d.pkg == id) else {
                    continue;
                };
                if !activated(mp, nodes[m], nd) {
                    continue;
                }
                for dep in &declarations(mp, nd) {
                    let key = dep.rename.clone().unwrap_or_else(|| dep.name.clone());
                    let path = mp.manifest_path.as_std_path().to_path_buf();
                    if let Some(text) = read(&path)
                        && let Some((line, col)) = find_dep_key(
                            &text,
                            &key,
                            dep.kind,
                            dep.target.as_ref().map(|t| t.to_string()),
                        )
                    {
                        let mut ctx = format!("declared by {} ({})", mp.name, kind_name(dep.kind));
                        if !dep.features.is_empty() {
                            ctx.push_str(&format!("; features {:?}", dep.features));
                        }
                        if !dep.uses_default_features {
                            ctx.push_str("; default-features = false");
                        }
                        evidence.push(Evidence {
                            path,
                            line,
                            col,
                            symbol: key.clone(),
                            context: ctx,
                        });
                    }
                }
            }
            // Always: the lockfile entry, with how the package is reached.
            if let Some(line) = find_lock_entry(&lock, &p.name, &p.version.to_string()) {
                evidence.push(Evidence {
                    path: lock_path.clone(),
                    line,
                    col: 0,
                    symbol: p.name.to_string(),
                    context: format!(
                        "locked {} {}; reached via {}",
                        p.name,
                        p.version,
                        chain.join(" -> ")
                    ),
                });
            }
        }
        if let Some(links) = &p.links {
            let path = p.manifest_path.as_std_path().to_path_buf();
            if let Some((line, col)) = read(&path).and_then(|t| find_links(&t)) {
                evidence.push(Evidence {
                    path,
                    line,
                    col,
                    symbol: "links".into(),
                    context: format!(
                        "native library `{links}`; code behind the FFI boundary is not analysed"
                    ),
                });
            }
        }
        out.push(Pkg {
            id: id.clone(),
            name: p.name.to_string(),
            version: p.version.clone(),
            manifest_dir: p
                .manifest_path
                .parent()
                .unwrap()
                .as_std_path()
                .to_path_buf(),
            member,
            local: !foreign,
            scope: *s,
            features,
            links: p.links.clone(),
            role: entry.map(|e| e.role),
            kb_supported: exact.is_some(),
            candidates: exact.map(|e| e.candidates.clone()).unwrap_or_default(),
            backends,
            evidence,
            chain,
            deps: node
                .deps
                .iter()
                .filter(|d| edge(d, false))
                .map(|d| d.pkg.clone())
                .collect(),
            runtime_deps: node
                .deps
                .iter()
                .filter(|d| edge(d, true))
                .map(|d| d.pkg.clone())
                .collect(),
        });
    }
    out.sort_by(|a, b| (&a.name, &a.version).cmp(&(&b.name, &b.version)));
    Ok(Manifest {
        root: resolve.root.clone(),
        workspace_root: md.workspace_root.as_std_path().to_path_buf(),
        target_directory: md.target_directory.as_std_path().to_path_buf(),
        packages: out,
    })
}

fn kind_name(k: DependencyKind) -> &'static str {
    match k {
        DependencyKind::Normal => "dependencies",
        DependencyKind::Build => "build-dependencies",
        DependencyKind::Development => "dev-dependencies",
        _ => "dependencies",
    }
}

/// 1-based line and 0-based char column of a byte offset.
fn line_col(text: &str, byte: usize) -> (usize, usize) {
    let before = &text[..byte];
    let line = before.matches('\n').count() + 1;
    let col = before.rsplit('\n').next().unwrap_or("").chars().count();
    (line, col)
}

/// The key of a dependency in `[dependencies]`, `[target.'cfg'.dependencies]`,
/// `[dependencies.<key>]`, ... Parsed with spans, so comments and layout do not matter.
fn find_dep_key(
    text: &str,
    key: &str,
    kind: DependencyKind,
    target: Option<String>,
) -> Option<(usize, usize)> {
    let doc = toml_edit::Document::parse(text.to_string()).ok()?;
    let root = doc.as_table();
    let table_name = kind_name(kind);
    let mut tables: Vec<&dyn toml_edit::TableLike> = Vec::new();
    // `[target.'cfg(target_os="linux")'.dependencies]`: cargo prints the platform as
    // `cfg(target_os = "linux")`, so compare without whitespace
    let squash = |s: &str| s.chars().filter(|c| !c.is_whitespace()).collect::<String>();
    if let Some(target) = &target
        && let Some(targets) = root.get("target").and_then(|t| t.as_table_like())
    {
        for (name, t) in targets.iter() {
            if squash(name) == squash(target)
                && let Some(d) = t
                    .as_table_like()
                    .and_then(|t| t.get(table_name))
                    .and_then(|d| d.as_table_like())
            {
                tables.push(d);
            }
        }
    }
    if let Some(d) = root.get(table_name).and_then(|d| d.as_table_like()) {
        tables.push(d);
    }
    for t in tables {
        if let Some((k, _)) = t.get_key_value(key) {
            let span = k.span()?;
            return Some(line_col(text, span.start));
        }
    }
    None
}

fn find_links(text: &str) -> Option<(usize, usize)> {
    let doc = toml_edit::Document::parse(text.to_string()).ok()?;
    let pkg = doc.as_table().get("package")?.as_table_like()?;
    let (k, _) = pkg.get_key_value("links")?;
    Some(line_col(text, k.span()?.start))
}

/// Line of `name = "<name>"` in the `[[package]]` entry whose version matches.
fn find_lock_entry(lock: &str, name: &str, version: &str) -> Option<usize> {
    let lines: Vec<&str> = lock.lines().collect();
    let want_name = format!("name = \"{name}\"");
    let want_version = format!("version = \"{version}\"");
    (0..lines.len())
        .find(|&i| lines[i] == want_name && lines.get(i + 1) == Some(&want_version.as_str()))
        .map(|i| i + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dependency_keys_are_found_whatever_the_layout() {
        let text = "[package]\nname = \"x\"\n\n# comment\n[dependencies]\n# aes = \"0\"\nring = \"0.17\"\nrustls = { version = \"0.23\", features = [\"ring\"] }\n\n[dependencies.sha2]\nversion = \"0.10\"\n";
        assert_eq!(
            find_dep_key(text, "ring", DependencyKind::Normal, None),
            Some((7, 0))
        );
        assert_eq!(
            find_dep_key(text, "rustls", DependencyKind::Normal, None),
            Some((8, 0))
        );
        assert_eq!(
            find_dep_key(text, "sha2", DependencyKind::Normal, None),
            Some((10, 14))
        );
        assert_eq!(
            find_dep_key(text, "aes", DependencyKind::Normal, None),
            None
        );
    }

    #[test]
    fn paths_are_normalized_lexically() {
        assert_eq!(
            normalize(Path::new("/r/rustls/src/crypto/aws_lc_rs/../ring/./kx.rs")),
            PathBuf::from("/r/rustls/src/crypto/ring/kx.rs")
        );
    }

    #[test]
    fn lock_entries_match_name_and_version() {
        let lock = "[[package]]\nname = \"sha2\"\nversion = \"0.10.9\"\n\n[[package]]\nname = \"sha2\"\nversion = \"0.11.0\"\n";
        assert_eq!(find_lock_entry(lock, "sha2", "0.11.0"), Some(6));
        assert_eq!(find_lock_entry(lock, "sha2", "0.9.0"), None);
    }
}
