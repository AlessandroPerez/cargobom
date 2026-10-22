//! The files and packages of the build: sources, modules, re-exports, aliases, the item a path names.

use super::*;

impl Files<'_> {
    pub(super) fn source(&mut self, path: &Path) -> Option<Rc<Source>> {
        self.cache
            .entry(path.to_path_buf())
            .or_insert_with(|| {
                let mut t = std::fs::read_to_string(path).ok()?;
                let rust = path.extension().is_some_and(|e| e == "rs");
                // rustc drops a byte-order mark before counting columns
                if rust && t.starts_with('\u{feff}') {
                    t.remove(0);
                }
                let toml = path.file_name().is_some_and(|n| n == "Cargo.toml");
                Some(Rc::new(Source::new(&t, rust, toml)))
            })
            .clone()
    }

    /// The `use` bindings of every Rust file of the package in `dir`: an alias may be defined
    /// in one file (`pub use ring::digest::digest as hash_it;` in `src/algs.rs`) and used in
    /// another.
    pub(super) fn package_binds(&mut self, dir: &Path) -> Rc<Vec<Binding>> {
        if let Some(b) = self.pkg_binds.get(dir) {
            return b.clone();
        }
        let mut out = Vec::new();
        for f in package_files(dir) {
            if let Ok(t) = std::fs::read_to_string(&f)
                && re!(r"\sas\s").is_match(&t)
            {
                out.extend(bindings(&lex(&t).1));
            }
        }
        let b = Rc::new(out);
        self.pkg_binds.insert(dir.to_path_buf(), b.clone());
        b
    }

    /// The type aliases the Rust files of the package in `dir` define (`pub type Sha256 =
    /// CoreWrapper<..>;`, hmac's `pub type Hmac<D> = CoreWrapper<HmacCore<D>>;`): name -> the
    /// types they stand for, as `norm_path` writes them, a generic one's parameters as written
    /// (`expand_aliases` leaves a name given arguments as it is).
    pub(super) fn package_aliases(&mut self, dir: &Path) -> Rc<HashMap<String, Vec<String>>> {
        if let Some(a) = self.pkg_aliases.get(dir) {
            return a.clone();
        }
        let mut out: HashMap<String, Vec<String>> = HashMap::new();
        for f in package_files(dir) {
            let Ok(t) = std::fs::read_to_string(&f) else {
                continue;
            };
            for m in re!(r"\btype\s+(\w+)\s*(?:<[^=;{}]*>)?\s*=\s*([^;{}]+);").captures_iter(&t) {
                out.entry(m[1].to_string())
                    .or_default()
                    .push(norm_path(&m[2]));
            }
        }
        let a = Rc::new(out);
        self.pkg_aliases.insert(dir.to_path_buf(), a.clone());
        a
    }

    /// Whether a standard-library path (`core::convert::From::from`, generics stripped) names a
    /// type or trait of the module it names (its file, or the files of its directory) with a
    /// function of the last name. True when the toolchain's sources cannot be read.
    pub(super) fn std_item(&mut self, path: &str) -> bool {
        if let Some(&k) = self.std_items.get(path) {
            return k;
        }
        let Some((sysroot, _)) = self.toolchain.get_or_insert_with(toolchain).clone() else {
            return true;
        };
        let segs: Vec<&str> = path.split("::").collect();
        let ok = match segs.as_slice() {
            [krate, mods @ .., ty, f] => {
                let base = sysroot
                    .join("lib/rustlib/src/rust/library")
                    .join(krate)
                    .join("src");
                let dir = mods.iter().fold(base.clone(), |d, m| d.join(m));
                let mut files = package_files(&dir);
                files.push(dir.with_extension("rs"));
                if mods.is_empty() {
                    files = vec![base.join("lib.rs")];
                }
                let ty_re = Regex::new(&format!(
                    r"\b(?:trait|struct|enum|union|type)\s+{}\b",
                    regex::escape(ty)
                ))
                .unwrap();
                let fn_re = Regex::new(&format!(r"\bfn\s+{}\b", regex::escape(f))).unwrap();
                let texts: Vec<String> = files
                    .iter()
                    .filter_map(|f| std::fs::read_to_string(f).ok())
                    .collect();
                // or a free function of the module the path names up to it (`alloc::io::copy::
                // copy`)
                let mut mod_files = package_files(&dir.join(ty));
                mod_files.push(dir.join(format!("{ty}.rs")));
                let in_module = mod_files
                    .iter()
                    .filter_map(|f| std::fs::read_to_string(f).ok())
                    .any(|t| fn_re.is_match(&t));
                texts.is_empty()
                    || (texts.iter().any(|t| ty_re.is_match(t))
                        && texts.iter().any(|t| fn_re.is_match(t)))
                    || in_module
            }
            _ => false,
        };
        self.std_items.insert(path.to_string(), ok);
        ok
    }

    /// The `#[path]` module declarations and `include!`d files of the package in `dir`.
    pub(super) fn package_mods(&mut self, dir: &Path) -> Rc<PkgMods> {
        if let Some(m) = self.pkg_mods.get(dir) {
            return m.clone();
        }
        let mut out = PkgMods::default();
        for f in package_files(dir) {
            let Ok(t) = std::fs::read_to_string(&f) else {
                continue;
            };
            let here = f.parent().unwrap_or(dir);
            for m in re!(r#"#\[path\s*=\s*"([^"]+)"\s*\]\s*(?:#\[[^\]]*\]\s*)*(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+(\w+)\s*;"#)
                .captures_iter(&t)
            {
                out.paths.push((f.clone(), rcbom_manifest::normalize(&here.join(&m[1])), m[2].to_string()));
            }
            for m in re!(r#"\binclude!\s*\(\s*"([^"]+)"\s*\)"#).captures_iter(&t) {
                out.included
                    .insert(rcbom_manifest::normalize(&here.join(&m[1])));
            }
        }
        let m = Rc::new(out);
        self.pkg_mods.insert(dir.to_path_buf(), m.clone());
        m
    }

    /// The module paths the code of a file is compiled as, from its crate's root:
    /// `src/crypto/ring/tls12.rs` is `crypto::ring::tls12` (a crate root is `[]`), also as a
    /// `#[path]` module of another file (rustls's `aws_lc_rs::kx` is `src/crypto/ring/kx.rs`).
    /// None when unknown: no `cargo metadata`, a file outside every target's directory, one an
    /// `include!` reads, or a build script's output.
    pub(super) fn module_chains(&mut self, path: &Path, depth: usize) -> Option<Vec<Vec<String>>> {
        let roots = self.roots.as_ref()?;
        // code a build script wrote (`<target>/build/<pkg>-<hash>/out/gen.rs`), included where
        // the crate says
        let comps: Vec<_> = path.components().map(|c| c.as_os_str()).collect();
        if comps.windows(3).any(|w| w[0] == "build" && w[2] == "out") {
            return None;
        }
        let mut out = Vec::new();
        if roots.iter().any(|r| r == path) {
            out.push(Vec::new());
        } else if let Some(dir) = roots
            .iter()
            .filter_map(|r| r.parent())
            .filter(|d| path.starts_with(d))
            .max_by_key(|d| d.as_os_str().len())
        {
            let rel = path.strip_prefix(dir).ok()?;
            let mut comps: Vec<String> = rel
                .components()
                .map(|c| c.as_os_str().to_string_lossy().to_string())
                .collect();
            let last = comps.pop()?;
            if last != "mod.rs" {
                comps.push(last.strip_suffix(".rs").unwrap_or(&last).to_string());
            }
            out.push(comps);
        }
        let dir = self.man.owner_of(path).map(|p| p.manifest_dir.clone())?;
        let mods = self.package_mods(&dir);
        if mods.included.contains(path) {
            return None;
        }
        if depth < 3 {
            for (decl, target, name) in &mods.paths {
                if target == path {
                    for mut c in self.module_chains(decl, depth + 1).unwrap_or_default() {
                        c.push(name.clone());
                        out.push(c);
                    }
                }
            }
        }
        (!out.is_empty()).then_some(out)
    }

    /// The types a name in a file of package `owner` may be an alias of: those its own
    /// package defines under that name, else those of the packages the file imports the name
    /// from (ssh-encoding's `impl Writer for Sha256` names sha2's alias).
    pub(super) fn alias_targets(
        &mut self,
        src: &Source,
        owner: Option<&rcbom_manifest::Pkg>,
        name: &str,
    ) -> Vec<String> {
        let mut dirs: Vec<PathBuf> = owner.map(|p| p.manifest_dir.clone()).into_iter().collect();
        let owner_id = owner.map(|p| p.id.repr.clone());
        for r in import_roots(&src.binds, name).into_iter().flatten() {
            for p in self.crate_refs(owner_id.as_deref(), &r) {
                if let Some(pkg) = self
                    .man
                    .packages
                    .iter()
                    .find(|k| pkg_ref(&k.name, &k.version.to_string()) == p)
                {
                    dirs.push(pkg.manifest_dir.clone());
                }
            }
        }
        let mut out = Vec::new();
        for d in dirs {
            if let Some(t) = self.package_aliases(&d).get(name) {
                out.extend(t.iter().cloned());
            }
        }
        out
    }

    /// A location's file. The standard library's sources are named as rustc names them
    /// (`/rustc/<commit>/library/core/src/ops/function.rs`); they are read from the pinned
    /// toolchain's rust-src component (`<sysroot>/lib/rustlib/src/rust/library/..`), and the
    /// commit must be that toolchain's.
    pub(super) fn resolve(&mut self, location: &str) -> Result<PathBuf, String> {
        let Some(rest) = location.strip_prefix("/rustc/") else {
            // as the generator writes them: relative, without `.`, `..` or empty segments
            if location.starts_with('/')
                || location
                    .split('/')
                    .any(|g| g.is_empty() || g == "." || g == "..")
            {
                return Err(format!(
                    "`{location}` is not a normalised relative location"
                ));
            }
            return Ok(self.man.resolve(location));
        };
        let (commit, rest) = rest
            .split_once('/')
            .ok_or_else(|| format!("no commit in {location}"))?;
        let Some((sysroot, pinned)) = self.toolchain.get_or_insert_with(toolchain).clone() else {
            return Err(format!(
                "toolchain {} not available to read {location}",
                crate::TOOLCHAIN
            ));
        };
        if commit != pinned {
            return Err(format!(
                "rustc commit {commit} cited, but the pinned toolchain {} is commit {pinned}",
                crate::TOOLCHAIN
            ));
        }
        Ok(sysroot.join("lib/rustlib/src/rust").join(rest))
    }

    /// The bom-refs of the packages a crate identifier names in the code of package `owner`
    /// (by package id): one of its dependencies under its extern name, or its own library.
    /// Without `cargo metadata`, or for a file of no package, every package of that name.
    pub(super) fn crate_refs(&self, owner: Option<&str>, ident: &str) -> Vec<String> {
        if let (Some(ext), Some(id)) = (&self.externs, owner)
            && let Some(m) = ext.get(id)
        {
            return m.get(ident).cloned().unwrap_or_default();
        }
        self.man
            .packages
            .iter()
            .filter(|p| p.name.replace('-', "_") == ident)
            .map(|p| pkg_ref(&p.name, &p.version.to_string()))
            .collect()
    }

    /// The packages of the CBOM a name in this file can come from: the crates its imports name
    /// (any of them, when it imports the name from several), or the crate of that name. None
    /// when the name may be the program's own (a definition or generic parameter in the file,
    /// an import relative to this crate or from one of its modules) or a crate outside the CBOM.
    pub(super) fn origins(
        &self,
        src: &Source,
        owner: Option<&str>,
        name: &str,
    ) -> Option<Vec<String>> {
        if src.locals.contains(name) {
            return None;
        }
        let mut out = Vec::new();
        for r in import_roots(&src.binds, name)? {
            let refs: Vec<String> = self
                .crate_refs(owner, &r)
                .into_iter()
                .filter(|p| self.graph.packages.contains(p))
                .collect();
            if refs.is_empty() {
                return None;
            }
            out.extend(refs);
        }
        Some(out)
    }

    /// The packages of the CBOM whose library is the crate `name` (the crate a symbol's path
    /// starts with).
    pub(super) fn lib_refs(&self, name: &str) -> Vec<String> {
        let refs = match &self.libs {
            Some(l) => l.get(name).cloned().unwrap_or_default(),
            None => self.crate_refs(None, name),
        };
        refs.into_iter()
            .filter(|r| self.graph.packages.contains(r))
            .collect()
    }

    /// The statics and consts named `item` in module `module` of the package in `dir`: those its
    /// files define there, else those a `use` item of that module re-exports under that name
    /// (`pub use inner::DEEP as SHALLOW;`, a glob `pub use inner::*;`), followed in turn: (file,
    /// the item's extent in its `code`, the item's module). None when the modules of the
    /// package's files are not known (no `cargo metadata`).
    #[allow(clippy::type_complexity)]
    pub(super) fn find_item(
        &mut self,
        dir: &Path,
        module: &[String],
        item: &str,
        depth: usize,
    ) -> Option<Vec<(PathBuf, (usize, usize), Vec<String>)>> {
        let files = package_files(dir);
        let mut out = Vec::new();
        let mut known = false;
        for f in &files {
            let Some(chains) = self.module_chains(f, 0) else {
                continue;
            };
            known = true;
            let Some(src) = self.source(f) else { continue };
            for it in src
                .items
                .iter()
                .filter(|it| it.kind == ItemKind::Static && it.name == item)
            {
                // (an associated const of an impl or trait is no module's item)
                if src.items.iter().any(|b| {
                    matches!(b.kind, ItemKind::Impl | ItemKind::Trait | ItemKind::Fn)
                        && b.contains(it.start)
                        && b.start != it.start
                }) {
                    continue;
                }
                for c in &chains {
                    let mut full = c.clone();
                    full.extend(modules_at(&src, it.start));
                    if full == module {
                        out.push((f.clone(), src.span(it), full));
                    }
                }
            }
        }
        if !known {
            return None;
        }
        if !out.is_empty() || depth == 0 {
            return Some(out);
        }
        // a re-export: a `use` of a file of that module binding the name (or a glob)
        for f in &files {
            let Some(chains) = self.module_chains(f, 0) else {
                continue;
            };
            if !chains.iter().any(|c| c == module) {
                continue;
            }
            let Some(src) = self.source(f) else { continue };
            let binds: Vec<Binding> = src
                .binds
                .iter()
                .filter(|b| b.name == item || b.name == "*")
                .cloned()
                .collect();
            for b in binds {
                let (target, name) = if b.name == "*" {
                    (b.path.clone(), item.to_string())
                } else {
                    let Some((last, head)) = b.path.split_last() else {
                        continue;
                    };
                    (head.to_vec(), last.clone())
                };
                let Some((d2, m2)) = self.module_of(dir, module, &target) else {
                    continue;
                };
                if let Some(found) = self.find_item(&d2, &m2, &name, depth - 1) {
                    out.extend(found);
                }
            }
        }
        Some(out)
    }

    /// The package and module a path written in module `here` of the package in `dir` names
    /// (`crate::a`, `self::a`, `super::a`, `a` a child module, `dep::a` another package's).
    pub(super) fn module_of(
        &self,
        dir: &Path,
        here: &[String],
        prefix: &[String],
    ) -> Option<(PathBuf, Vec<String>)> {
        let Some(first) = prefix.first() else {
            return Some((dir.to_path_buf(), here.to_vec()));
        };
        match first.as_str() {
            "crate" | "$crate" => Some((dir.to_path_buf(), prefix[1..].to_vec())),
            "self" => {
                let mut m = here.to_vec();
                m.extend(prefix[1..].iter().cloned());
                Some((dir.to_path_buf(), m))
            }
            "super" => {
                let mut m = here.to_vec();
                let mut k = 0;
                while prefix.get(k).is_some_and(|g| g == "super") {
                    m.pop();
                    k += 1;
                }
                m.extend(prefix[k..].iter().cloned());
                Some((dir.to_path_buf(), m))
            }
            _ => {
                // (a dependency the manifest renames: `algs = { package = "picklib" }`)
                let first = renamed_dep(dir, first).unwrap_or_else(|| first.clone());
                let pkg = self.man.packages.iter().find(|p| {
                    p.lib_name.as_deref() == Some(first.as_str())
                        || p.name.replace('-', "_") == first
                });
                match pkg {
                    // (another package's, unless a child module of the same name shadows it:
                    // the caller tries both)
                    Some(p) if p.manifest_dir != dir => {
                        Some((p.manifest_dir.clone(), prefix[1..].to_vec()))
                    }
                    _ => {
                        let mut m = here.to_vec();
                        m.extend(prefix.iter().cloned());
                        Some((dir.to_path_buf(), m))
                    }
                }
            }
        }
    }

    /// The supertraits the traits of the package of `path`, and of the crate `trait_path` names
    /// (`dyn tlib::Pick`), declare (`trait Sub: Super + Send`: `Sub` -> `[Super, Send]`).
    pub(super) fn supertraits(
        &mut self,
        path: &Path,
        trait_path: &str,
    ) -> HashMap<String, Vec<String>> {
        let mut dirs: Vec<PathBuf> = self
            .man
            .owner_of(path)
            .map(|p| p.manifest_dir.clone())
            .into_iter()
            .collect();
        let krate = trait_path
            .trim()
            .trim_start_matches("dyn ")
            .split("::")
            .next()
            .unwrap_or("")
            .to_string();
        if let Some(p) = self.man.packages.iter().find(|p| {
            p.lib_name.as_deref() == Some(krate.as_str()) || p.name.replace('-', "_") == krate
        }) && !dirs.contains(&p.manifest_dir)
        {
            dirs.push(p.manifest_dir.clone());
        }
        let mut out: HashMap<String, Vec<String>> = HashMap::new();
        for d in dirs {
            for f in package_files(&d) {
                let Some(src) = self.source(&f) else { continue };
                let text: String = src.code.iter().collect();
                for m in
                    re!(r"\btrait\s+(\w+)\s*(?:<[^>{]*>)?\s*:\s*([^{;]+?)\s*(?:\bwhere\b|\{|;)")
                        .captures_iter(&text)
                {
                    let e = out.entry(m[1].to_string()).or_default();
                    for b in split_top(&m[2].replace('+', ",")) {
                        let b = b.trim();
                        if !b.is_empty() && !b.starts_with('\'') && !b.starts_with('?') {
                            e.push(type_name(b));
                        }
                    }
                }
            }
        }
        out
    }

    /// A package that provides no asset by being named: the program's own, or an interface
    /// crate (`digest`, `aead`, `signature`: their traits are implemented by others).
    pub(super) fn neutral(&self, r: &str) -> bool {
        r.strip_prefix("pkg:cargo/")
            .and_then(|nv| nv.split_once('@'))
            .and_then(|(n, v)| self.man.by_name_version(n, v))
            .is_some_and(|p| p.local || matches!(p.role, Some(rcbom_kb::Role::Trait)))
    }

    /// Whether binding `b` (`use x::y::ident as name;`) is an alias of the item `ident` of crate
    /// `krate`: imported from that crate, from one that depends on it (a re-export), or from the
    /// program's own module when the package imports `ident` from such a crate (a local
    /// re-export); not an unrelated item that happens to share the last segment.
    pub(super) fn alias_of(
        &self,
        b: &Binding,
        ident: &str,
        krate: &str,
        owner: Option<&str>,
        binds: &[Binding],
    ) -> bool {
        if b.path.last().map(String::as_str) != Some(ident) || b.name == ident {
            return false;
        }
        let target = self.lib_refs(krate);
        // the symbol's crate is not a package of the CBOM (the standard library): no check
        if target.is_empty() {
            return true;
        }
        let from = |root: &str| {
            self.crate_refs(owner, root)
                .iter()
                .any(|r| target.iter().any(|t| self.graph.closure(r).contains(t)))
        };
        match b.path.first().map(String::as_str) {
            Some("crate" | "self" | "super") => binds.iter().any(|o| {
                o.name == ident
                    && o.path.last().map(String::as_str) == Some(ident)
                    && o.path.first().is_some_and(|r| {
                        !matches!(r.as_str(), "crate" | "self" | "super") && from(r)
                    })
            }),
            Some(root) => root == krate || from(root),
            None => false,
        }
    }
}
