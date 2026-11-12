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
    /// types they stand for, as `norm_path` writes them, a generic one's parameters as written.
    /// A generic one is also listed as `Name<>`, its parameters' names before the type as the
    /// file writes it (`D|CoreWrapper<HmacCore<D>>`), for `expand_aliases` to apply.
    pub(super) fn package_aliases(&mut self, dir: &Path) -> Rc<HashMap<String, Vec<String>>> {
        if let Some(a) = self.pkg_aliases.get(dir) {
            return a.clone();
        }
        let mut out: HashMap<String, Vec<String>> = HashMap::new();
        let mut texts: Vec<String> = package_files(dir)
            .iter()
            .filter_map(|f| std::fs::read_to_string(f).ok())
            .collect();
        texts.extend(self.macro_made_aliases(dir));
        for t in texts {
            for m in re!(r"\btype\s+(\w+)\s*(?:<([^=;{}]*)>)?\s*=\s*([^;{}]+);").captures_iter(&t) {
                out.entry(m[1].to_string())
                    .or_default()
                    .push(norm_path(&m[3]));
                // (type and const parameters by name; a lifetime is none of the arguments
                // `norm_path` keeps)
                let params: Vec<String> = m
                    .get(2)
                    .map(|g| split_top(g.as_str()))
                    .unwrap_or_default()
                    .iter()
                    .map(|p| p.trim().trim_start_matches("const ").trim())
                    .filter(|p| !p.starts_with('\'') && !p.is_empty())
                    .filter_map(|p| re!(r"^\w+").find(p).map(|w| w.as_str().to_string()))
                    .collect();
                if !params.is_empty() {
                    out.entry(format!("{}<>", &m[1])).or_default().push(format!(
                        "{}|{}",
                        params.join(","),
                        m[3].trim()
                    ));
                }
            }
        }
        let a = Rc::new(out);
        self.pkg_aliases.insert(dir.to_path_buf(), a.clone());
        a
    }

    /// What the package's invocations of its own `macro_rules!` that define type aliases expand
    /// to (sha3's `impl_sha3!(Sha3_256Core, Sha3_256, ..)`, whose rule writes `pub type
    /// $full_name = CoreWrapper<$name>;`): the alias is written nowhere else. A macro makes
    /// aliases when its text has `type $name`, or invokes one that does; an invocation's
    /// expansion is read three macros deep.
    fn macro_made_aliases(&mut self, dir: &Path) -> Vec<String> {
        let files: Vec<Rc<Source>> = package_files(dir)
            .iter()
            .filter_map(|f| self.source(f))
            .collect();
        let macros: Vec<(&Source, &Item)> = files
            .iter()
            .flat_map(|s| {
                s.items
                    .iter()
                    .filter(|i| i.kind == ItemKind::Macro)
                    .map(move |i| (s.as_ref(), i))
            })
            .collect();
        let text_of = |s: &Source, i: &Item| {
            let (a, b) = s.span(i);
            s.text(a, b)
        };
        let mut making: HashSet<String> = macros
            .iter()
            .filter(|(s, i)| re!(r"\btype\s+\$\w+").is_match(&text_of(s, i)))
            .map(|(_, i)| i.name.clone())
            .collect();
        if making.is_empty() {
            return Vec::new();
        }
        loop {
            let more: Vec<String> = macros
                .iter()
                .filter(|(_, i)| !making.contains(&i.name))
                .filter(|(s, i)| {
                    let t = text_of(s, i);
                    making.iter().any(|m| {
                        Regex::new(&format!(r"\b{}\s*!", regex::escape(m)))
                            .is_ok_and(|r| r.is_match(&t))
                    })
                })
                .map(|(_, i)| i.name.clone())
                .collect();
            if more.is_empty() {
                break;
            }
            making.extend(more);
        }
        let mut out = Vec::new();
        // the invocations to expand: (the source they are in, depth)
        let mut todo: Vec<(Rc<Source>, usize)> = files.iter().map(|s| (s.clone(), 0)).collect();
        while let Some((src, depth)) = todo.pop() {
            for call in src
                .items
                .iter()
                .filter(|i| i.kind == ItemKind::MacroCall && making.contains(&i.name))
            {
                let Some((name, args)) =
                    invocation_start(&src, call.start).and_then(|at| invocation_args(&src, at))
                else {
                    continue;
                };
                for (msrc, m) in macros.iter().filter(|(_, i)| i.name == name) {
                    let Some(text) = expansion_of(msrc, m, &args) else {
                        continue;
                    };
                    if depth < 2 {
                        todo.push((Rc::new(Source::new(&text, true, false)), depth + 1));
                    }
                    out.push(text);
                }
            }
        }
        out
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

    /// What a type alias of the standard library stands for, read from the pinned toolchain's
    /// sources (`std::convert::Infallible`, `pub type Infallible = !;` in core's `convert`
    /// module): the module the path names, in the crate it names or in core and alloc, which
    /// std re-exports. None where no such alias is written there.
    pub(super) fn std_alias(&mut self, path: &[String]) -> Option<String> {
        let key = path.join("::");
        if let Some(a) = self.std_aliases.get(&key) {
            return a.clone();
        }
        let found = (|| {
            let (sysroot, _) = self.toolchain.get_or_insert_with(toolchain).clone()?;
            let [krate, mods @ .., name] = path else {
                return None;
            };
            let re = Regex::new(&format!(
                r"\bpub\s+type\s+{}\s*=\s*([^;]+);",
                regex::escape(name)
            ))
            .ok()?;
            let lib = sysroot.join("lib/rustlib/src/rust/library");
            let mut crates = vec![krate.as_str()];
            crates.extend(["core", "alloc"].iter().filter(|c| **c != krate.as_str()));
            for c in crates {
                let base = lib.join(c).join("src");
                let dir = mods.iter().fold(base.clone(), |d, m| d.join(m));
                let files = if mods.is_empty() {
                    vec![base.join("lib.rs")]
                } else {
                    vec![dir.with_extension("rs"), dir.join("mod.rs")]
                };
                for f in files {
                    let Ok(t) = std::fs::read_to_string(&f) else {
                        continue;
                    };
                    if let Some(m) = re.captures(&t) {
                        return Some(m[1].trim().to_string());
                    }
                }
            }
            None
        })();
        self.std_aliases.insert(key, found.clone());
        found
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
            // (`#[path = "x.rs"] mod m;`, also under a condition this check does not evaluate:
            // `#[cfg_attr(unix, path = "unix.rs")] #[cfg_attr(windows, path = "windows.rs")]
            // mod platform;` makes either file the module)
            for m in re!(r"((?:#\[[^\]]*\]\s*)+)(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+(\w+)\s*;")
                .captures_iter(&t)
            {
                for a in re!(r#"(?:#\[|,)\s*path\s*=\s*"([^"]+)""#).captures_iter(&m[1]) {
                    out.paths.push((
                        f.clone(),
                        rcbom_manifest::normalize(&here.join(&a[1])),
                        m[2].to_string(),
                    ));
                }
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
    /// from (ssh-encoding's `impl Writer for Sha256` names sha2's alias), or of the crate its
    /// path starts at (`kem::Ciphertext`); and what the package imports under that name from
    /// another (`use Kem as KemTrait;` in one file, `impl KemTrait for X` in the next). A name
    /// ending in `<>` asks for a generic alias (`package_aliases`).
    pub(super) fn alias_targets(
        &mut self,
        src: &Source,
        owner: Option<&rcbom_manifest::Pkg>,
        name: &str,
    ) -> Vec<String> {
        let generic = name.ends_with("<>");
        let plain = name.trim_end_matches("<>");
        let (root, bare) = match plain.rsplit_once("::") {
            Some((q, b)) => (q.split("::").next().map(str::trim), b.trim()),
            None => (None, plain),
        };
        let key = if generic {
            format!("{bare}<>")
        } else {
            bare.to_string()
        };
        let mut dirs: Vec<PathBuf> = owner.map(|p| p.manifest_dir.clone()).into_iter().collect();
        let owner_id = owner.map(|p| p.id.repr.clone());
        for r in import_roots(&src.binds, root.unwrap_or(bare))
            .into_iter()
            .flatten()
        {
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
        for d in &dirs {
            if let Some(t) = self.package_aliases(d).get(&key) {
                out.extend(t.iter().cloned());
            }
        }
        // (a type alias of the standard library the file imports, `use std::convert::Infallible;`:
        // what the toolchain's sources say it stands for, `!`)
        if !generic && root.is_none() {
            let std_paths: Vec<Vec<String>> = src
                .binds
                .iter()
                .filter(|b| b.name == bare)
                .filter(|b| {
                    b.path
                        .first()
                        .is_some_and(|h| matches!(h.as_str(), "std" | "core" | "alloc"))
                })
                .map(|b| b.path.clone())
                .collect();
            for p in std_paths {
                if let Some(t) = self.std_alias(&p)
                    && !out.contains(&t)
                {
                    out.push(t);
                }
            }
        }
        // (a name a `use` gives another item: in the package, or in the package the file
        // imports the name from, async-std's `pub use futures_io::AsyncRead as Read;` for a
        // file's `use async_std::io::Read;`)
        if !generic {
            for d in &dirs {
                for b in self.package_binds(d).iter().filter(|b| b.name == bare) {
                    if let Some(l) = b.path.last()
                        && l != bare
                        && l != "self"
                        && !out.contains(l)
                    {
                        out.push(l.clone());
                    }
                }
            }
        }
        out
    }

    /// Whether two positions of a file are calls of one method on one variable: the same name
    /// after a `.`, on receivers written alike whose variable is the same binding (or the same
    /// function's parameter, `self`, or the same static). The variable has one type, so the two
    /// calls are of one type's method.
    pub(super) fn same_receiver(
        &mut self,
        location: &str,
        a: (usize, usize),
        b: (usize, usize),
    ) -> bool {
        let Ok(path) = self.resolve(location) else {
            return false;
        };
        let Some(src) = self.source(&path) else {
            return false;
        };
        let s = &src.code;
        let call = |at: (usize, usize)| -> Option<(String, String, (usize, usize, usize))> {
            if at.0 == 0 || at.0 > src.lines.len() || at.1 >= src.lines[at.0 - 1].chars().count() {
                return None;
            }
            let i = src.idx(at);
            if !word_start(s, i) {
                return None;
            }
            let dot = before_blank(s, i).filter(|&d| s[d] == '.')?;
            let (r, root, _) = receiver_at(s, dot)?;
            let text: String = src.text(r, dot).split_whitespace().collect();
            let item = |k: usize| {
                src.enclosing(src.pos(k), &[ItemKind::Fn])
                    .map_or(0, |f| src.idx(f.start))
            };
            let bound = match lookup(&src, r, &root)? {
                Found::Bind(bd) => (0, bd.stmt.0, bd.pat.0),
                Found::Param(_) => (1, item(r), 0),
                Found::Item(k) => (2, k, 0),
            };
            Some((word_of(s, i), text, bound))
        };
        matches!((call(a), call(b)), (Some(x), Some(y)) if x == y)
    }

    /// Whether two positions of a file start one closure or `async` body: its own first token
    /// (`async`, `move`, `|`) and the `&` or `(` before it, where the compiler may cite it.
    pub(super) fn same_closure(
        &mut self,
        location: &str,
        a: (usize, usize),
        b: (usize, usize),
    ) -> bool {
        let Ok(path) = self.resolve(location) else {
            return false;
        };
        let Some(src) = self.source(&path) else {
            return false;
        };
        let s = &src.code;
        let body = |at: (usize, usize)| {
            if at.0 == 0 || at.0 > src.lines.len() || at.1 >= src.lines[at.0 - 1].chars().count() {
                return None;
            }
            let i = src.idx(at);
            let i = if matches!(s.get(i), Some('&' | '(')) {
                skip_blank(s, i + 1)
            } else {
                i
            };
            closure_span(s, i).or_else(|| async_body_at(s, i))
        };
        matches!((body(a), body(b)), (Some(x), Some(y)) if x == y)
    }

    /// Whether two positions of a file are consecutive calls of one method in a chain
    /// (`H::default()\n.absorb(a)\n.absorb(b)`), the method one that returns its own type: the
    /// function around `inside` (a location, line and column in its body) is declared `-> Self`
    /// (or a reference to it). The second call's receiver is then of the first's type.
    pub(super) fn chained_call(
        &mut self,
        location: &str,
        a: (usize, usize),
        b: (usize, usize),
        inside: (&str, usize, usize),
    ) -> bool {
        let mut returns_self = || -> Option<bool> {
            let path = self.resolve(inside.0).ok()?;
            let src = self.source(&path)?;
            let f = src.enclosing((inside.1, inside.2), &[ItemKind::Fn])?;
            let ret = fn_sig(&src, f).ret?;
            let ret = re!(r"'\w+").replace_all(&ret, "");
            let ret = ret.trim().trim_start_matches('&').trim();
            Some(ret.strip_prefix("mut ").unwrap_or(ret).trim() == "Self")
        };
        if returns_self() != Some(true) {
            return false;
        }
        let Ok(path) = self.resolve(location) else {
            return false;
        };
        let Some(src) = self.source(&path) else {
            return false;
        };
        let s = &src.code;
        let at = |p: (usize, usize)| {
            (p.0 >= 1 && p.0 <= src.lines.len() && p.1 < src.lines[p.0 - 1].chars().count())
                .then(|| src.idx(p))
        };
        let (Some(x), Some(y)) = (at(a), at(b)) else {
            return false;
        };
        let (x, y) = (x.min(y), x.max(y));
        let name = word_of(s, x);
        if name.is_empty() || !word_start(s, x) || word_of(s, y) != name {
            return false;
        }
        // the first call's arguments end where the second's `.` follows
        let open = skip_blank(s, x + name.chars().count());
        let Some(close) = (s.get(open) == Some(&'('))
            .then(|| close_of_at(s, open))
            .flatten()
        else {
            return false;
        };
        let dot = skip_blank(s, close + 1);
        s.get(dot) == Some(&'.') && skip_blank(s, dot + 1) == y
    }

    /// Whether the definition of the constant `name`, which code of package `owner` names by
    /// the path `quals` before it, leads to a function named `target`, as far as the text
    /// shows and four steps deep: the constant's value, the macro that declares it or that it
    /// invokes, the functions those call, each read in its own package (sqlx's
    /// `sqlx_postgres::any::DRIVER`, declared by sqlx-core's `declare_driver!(DRIVER = ..)` as
    /// `AnyDriver::with_migrate::<DB>()`, whose body holds `AnyConnection::connect_with_db`).
    pub(super) fn constant_leads_to(
        &mut self,
        src: &Source,
        owner: Option<&rcbom_manifest::Pkg>,
        quals: &[String],
        name: &str,
        target: &str,
    ) -> bool {
        let own = owner.map(|p| p.manifest_dir.clone());
        let relative = |r: &str| matches!(r, "crate" | "self" | "super" | "$crate" | "Self");
        // the packages a path's first segment names from a package's code: that package for
        // a relative path or one of its modules, else the dependency of that name
        let dirs_of = |me: &Self, d: Option<&PathBuf>, root: Option<&str>| -> Vec<PathBuf> {
            let here: Vec<PathBuf> = d.into_iter().cloned().collect();
            let Some(root) = root.filter(|r| !relative(r)) else {
                return here;
            };
            let id = d.and_then(|d| {
                me.man
                    .packages
                    .iter()
                    .find(|p| p.manifest_dir == *d)
                    .map(|p| p.id.repr.clone())
            });
            let found: Vec<PathBuf> = me
                .crate_refs(id.as_deref(), root)
                .iter()
                .filter_map(|r| {
                    me.man
                        .packages
                        .iter()
                        .find(|k| pkg_ref(&k.name, &k.version.to_string()) == *r)
                        .map(|k| k.manifest_dir.clone())
                })
                .collect();
            if found.is_empty() { here } else { found }
        };
        let first = quals.first().map(String::as_str).or_else(|| {
            // (a name the file imports: from the crate its `use` starts at)
            src.binds
                .iter()
                .find(|b| b.name == name)
                .and_then(|b| b.path.first())
                .map(String::as_str)
        });
        let mut queue: Vec<(PathBuf, String)> = dirs_of(self, own.as_ref(), first)
            .into_iter()
            .map(|d| (d, name.to_string()))
            .collect();
        let word = |w: &str| Regex::new(&format!(r"\b{}\b", regex::escape(w))).ok();
        let Some(wanted) = word(target) else {
            return false;
        };
        let mut texts: HashMap<PathBuf, Rc<Vec<String>>> = HashMap::new();
        let mut seen: HashSet<(PathBuf, String)> = HashSet::new();
        // where the bracket opened at byte `open` closes
        let close = |t: &str, open: usize| -> usize {
            let mut depth = 0i32;
            for (i, c) in t[open..].char_indices() {
                match c {
                    '(' | '[' | '{' => depth += 1,
                    ')' | ']' | '}' => {
                        depth -= 1;
                        if depth <= 0 {
                            return open + i + 1;
                        }
                    }
                    _ => {}
                }
            }
            t.len()
        };
        for _ in 0..4 {
            let mut next: Vec<(PathBuf, String)> = Vec::new();
            for (d, n) in std::mem::take(&mut queue) {
                if seen.len() > 200 || !seen.insert((d.clone(), n.clone())) {
                    continue;
                }
                let files = texts
                    .entry(d.clone())
                    .or_insert_with(|| {
                        Rc::new(
                            package_files(&d)
                                .iter()
                                .filter_map(|f| std::fs::read_to_string(f).ok())
                                .collect(),
                        )
                    })
                    .clone();
                let Some(named) = word(&n) else { continue };
                let defs = Regex::new(&format!(
                    r"\b(?:(?:const|static)\s+(?:mut\s+)?{0}\s*:|fn\s+{0}\b|macro_rules!\s*{0}\b)",
                    regex::escape(&n)
                ));
                let Ok(defs) = defs else { continue };
                for t in files.iter().filter(|t| named.is_match(t)) {
                    // the definitions' texts: a constant's to its `;`, a function's or a
                    // macro's to the end of its block; and the macro invocations that are
                    // given the name (`declare_driver!(DRIVER = Postgres);`)
                    let mut regions: Vec<&str> = Vec::new();
                    for m in defs.find_iter(t) {
                        let rest = &t[m.start()..];
                        let end = if m.as_str().starts_with(['c', 's']) {
                            let mut depth = 0i32;
                            rest.char_indices()
                                .find(|&(_, c)| {
                                    match c {
                                        '(' | '[' | '{' => depth += 1,
                                        ')' | ']' | '}' => depth -= 1,
                                        _ => {}
                                    }
                                    c == ';' && depth <= 0
                                })
                                .map_or(rest.len(), |(i, _)| i)
                        } else {
                            match rest.find(['{', ';']) {
                                Some(o) if rest[o..].starts_with('{') => close(rest, o),
                                Some(o) => o,
                                None => rest.len(),
                            }
                        };
                        regions.push(&rest[..end]);
                    }
                    for m in re!(r"((?:[A-Za-z_$]\w*\s*::\s*)*[A-Za-z_]\w*)\s*!\s*[\(\[\{]")
                        .captures_iter(t)
                    {
                        let whole = m.get(0).map_or(0..0, |g| g.range());
                        let end = close(t, whole.end - 1);
                        if named.is_match(&t[whole.end..end]) && &m[1] != "macro_rules" {
                            let path: Vec<&str> = m[1].split("::").map(str::trim).collect();
                            let root = (path.len() > 1).then(|| path[0]);
                            let last = path[path.len() - 1].to_string();
                            for k in dirs_of(self, Some(&d), root) {
                                next.push((k, last.clone()));
                            }
                        }
                    }
                    for r in regions {
                        if wanted.is_match(r) {
                            return true;
                        }
                        // what the definition calls or invokes
                        for m in re!(
                            r"((?:[A-Za-z_$]\w*\s*::\s*)*[A-Za-z_]\w*)\s*(?:::\s*<[^;(){}]*>)?\s*[!(]"
                        )
                        .captures_iter(r)
                        {
                            let path: Vec<&str> = m[1].split("::").map(str::trim).collect();
                            let last = path[path.len() - 1];
                            if last == n
                                || matches!(last, "Some" | "Ok" | "Err" | "if" | "match" | "fn")
                            {
                                continue;
                            }
                            let root = (path.len() > 1).then(|| path[0]);
                            for k in dirs_of(self, Some(&d), root) {
                                next.push((k, last.to_string()));
                            }
                        }
                    }
                }
            }
            if next.is_empty() {
                return false;
            }
            queue = next;
        }
        false
    }

    /// Whether two positions of a file are one awaited call's: the name of the call that
    /// builds a future and the `await` that polls it (`.with_socket(..)\n.await`). An `async`
    /// function's body is made by the one and run by the other. Or one borrowed closure's:
    /// its `&` and its `|` (`by_ref(&|alg| ..)`).
    pub(super) fn awaited_pair(
        &mut self,
        location: &str,
        a: (usize, usize),
        b: (usize, usize),
    ) -> bool {
        let Ok(path) = self.resolve(location) else {
            return false;
        };
        let Some(src) = self.source(&path) else {
            return false;
        };
        let at = |p: (usize, usize)| {
            (p.0 >= 1 && p.0 <= src.lines.len() && p.1 < src.lines[p.0 - 1].chars().count())
                .then(|| src.idx(p))
        };
        let (Some(x), Some(y)) = (at(a), at(b)) else {
            return false;
        };
        let (lo, hi) = (x.min(y), x.max(y));
        awaited_call(&src.code, x) == Some(y)
            || awaited_call(&src.code, y) == Some(x)
            // (or a borrowed closure's `&` and the closure it borrows: one expression)
            || (src.code[lo] == '&'
                && skip_blank(&src.code, lo + 1) == hi
                && closure_span(&src.code, hi).is_some())
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

    /// Whether the function `sym` names (a path from its crate's root: `rand::rng::RngExt::random`,
    /// `rand::make_rng`), of one of the packages `refs`, runs for a type its caller gives: a
    /// method of a trait the package declares (the type it is called on implements the trait,
    /// in whatever crate), or a function declared with a type parameter (`fn make_rng<R:
    /// SeedableRng>() -> R`, `fn fill(rng: &mut impl Rng)`). The asset at a call of one may be
    /// that type's, whatever the function's package provides. Read from the package's source.
    pub(super) fn runs_for_a_type(&mut self, refs: &[String], sym: &[String]) -> bool {
        let Some(name) = sym.last() else {
            return false;
        };
        let parent = sym.len().checked_sub(2).and_then(|i| sym.get(i));
        for r in refs {
            let key = (r.clone(), sym.join("::"));
            if let Some(v) = self.open_fns.get(&key) {
                if *v {
                    return true;
                }
                continue;
            }
            let dir = self
                .man
                .packages
                .iter()
                .find(|k| pkg_ref(&k.name, &k.version.to_string()) == *r)
                .map(|k| k.manifest_dir.clone());
            let mut open = false;
            'files: for f in dir.iter().flat_map(|d| package_files(d)) {
                let Some(src) = self.source(&f) else { continue };
                for it in &src.items {
                    open = match it.kind {
                        ItemKind::Trait => parent == Some(&it.name),
                        ItemKind::Fn if it.name == *name => {
                            let (a, b) = src.span(it);
                            let head: String = src.code[a..b.min(src.code.len())]
                                .iter()
                                .take_while(|c| !matches!(c, '{' | ';'))
                                .collect();
                            generic_header(&head)
                        }
                        _ => false,
                    };
                    if open {
                        break 'files;
                    }
                }
            }
            self.open_fns.insert(key, open);
            if open {
                return true;
            }
        }
        false
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

/// Whether a function's header (`fn name<..>(..) -> ..`, up to its body) declares a type
/// parameter: one among its generic parameters (not a lifetime, not a constant), or an `impl
/// Trait` among its arguments.
pub(super) fn generic_header(head: &str) -> bool {
    let Some(m) = re!(r"\bfn\s+(?:r#)?\w+\s*").find(head) else {
        return false;
    };
    let mut rest = &head[m.end()..];
    if rest.starts_with('<') {
        let Some(close) = angle_close(rest, 0) else {
            return true;
        };
        if split_top(&rest[1..close]).iter().any(|p| {
            let p = p.trim();
            !p.is_empty() && !p.starts_with('\'') && !p.starts_with("const ")
        }) {
            return true;
        }
        rest = &rest[close + 1..];
    }
    let Some(open) = rest.find('(') else {
        return false;
    };
    let mut depth = 0i32;
    let mut end = rest.len();
    for (i, c) in rest[open..].char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    end = open + i;
                    break;
                }
            }
            _ => {}
        }
    }
    re!(r"\bimpl\b").is_match(&rest[open..end])
}
