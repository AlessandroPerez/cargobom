//! Positions in `Cargo.toml` and `Cargo.lock`, the CBOM's context fields, and the packages' files.

use super::*;

pub(super) fn pkg_ref(name: &str, version: &str) -> String {
    format!("pkg:cargo/{name}@{version}")
}
pub(super) fn load_externs(
    manifest_path: &Path,
    target: &str,
    features: &[String],
) -> Option<(Externs, Libs, Vec<PathBuf>)> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut cmd = Command::new(cargo);
    cmd.args([
        "metadata",
        "--format-version",
        "1",
        "--locked",
        "--filter-platform",
        target,
        "--manifest-path",
    ])
    .arg(manifest_path);
    if !features.is_empty() {
        cmd.arg("--features").arg(features.join(","));
    }
    let out = cmd.stderr(Stdio::null()).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let md: Value = serde_json::from_slice(&out.stdout).ok()?;
    let mut refs: HashMap<&str, String> = HashMap::new();
    let mut ext: Externs = HashMap::new();
    let mut libs: Libs = HashMap::new();
    let mut roots = Vec::new();
    for p in md["packages"].as_array()? {
        let (Some(id), Some(n), Some(v)) =
            (p["id"].as_str(), p["name"].as_str(), p["version"].as_str())
        else {
            continue;
        };
        let r = pkg_ref(n, v);
        refs.insert(id, r.clone());
        // its own library, as its binaries name it
        let own = ext.entry(id.to_string()).or_default();
        for t in p["targets"].as_array().into_iter().flatten() {
            // (a build script's modules are not the crate's)
            let build = t["kind"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|k| k == "custom-build");
            if let Some(sp) = t["src_path"].as_str()
                && !build
            {
                roots.push(PathBuf::from(sp));
            }
            let lib = t["kind"].as_array().into_iter().flatten().any(|k| {
                matches!(
                    k.as_str(),
                    Some("lib" | "rlib" | "dylib" | "cdylib" | "staticlib" | "proc-macro")
                )
            });
            if lib && let Some(tn) = t["name"].as_str() {
                own.entry(tn.replace('-', "_")).or_default().push(r.clone());
                libs.entry(tn.replace('-', "_"))
                    .or_default()
                    .push(r.clone());
            }
        }
    }
    for n in md["resolve"]["nodes"].as_array()? {
        let Some(id) = n["id"].as_str() else { continue };
        let m = ext.entry(id.to_string()).or_default();
        for d in n["deps"].as_array().into_iter().flatten() {
            if let (Some(name), Some(r)) = (
                d["name"].as_str(),
                d["pkg"].as_str().and_then(|p| refs.get(p)),
            ) {
                let v = m.entry(name.to_string()).or_default();
                if !v.contains(r) {
                    v.push(r.clone());
                }
            }
        }
    }
    Some((ext, libs, roots))
}
/// The pinned toolchain's sysroot and commit (`rustc -vV`).
pub(super) fn toolchain() -> Option<(PathBuf, String)> {
    let sysroot = crate::sysroot().ok()?;
    let out = Command::new("rustc")
        .arg(format!("+{}", crate::TOOLCHAIN))
        .arg("-vV")
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let commit = text
        .lines()
        .find_map(|l| l.strip_prefix("commit-hash: "))?
        .trim()
        .to_string();
    Some((PathBuf::from(sysroot), commit))
}
/// Reads a context back: the code text first, as the backquoted text at the very end; the line
/// is then what remains between `line: `` and the last backquote (it may hold backquotes).
pub(super) fn split_context(ctx: &str) -> Ctx<'_> {
    let tags = re!(r"^(?:\[[^\[\]]*\] ?)*")
        .find(ctx)
        .map_or("", |m| m.as_str());
    let (before_code, code) = match re!(r"; code: `([^`]*)`$").captures(ctx) {
        Some(m) => (
            &ctx[..m.get(0).map_or(0, |g| g.start())],
            m.get(1).map(|g| g.as_str()),
        ),
        None => (ctx, None),
    };
    let (details, line) = match re!(r"; line: `(.*)`$").captures(before_code) {
        Some(m) => (
            &before_code[..m.get(0).map_or(0, |g| g.start())],
            m.get(1).map(|g| g.as_str()),
        ),
        None => (before_code, None),
    };
    Ctx {
        tags,
        details,
        line,
        code,
    }
}
/// Whether `name` is a more specific name `parent` was merged into on a line (the generator
/// merges `PBKDF2-SHA-256` into `PBKDF2-SHA-256-1000-32`, and the family name `Argon2` into
/// `Argon2id-19456-2-1`): strictly longer, at a `-` boundary, or extending the family name it
/// belongs to.
pub(super) fn extends(name: &str, parent: &str, family: Option<&str>) -> bool {
    name.len() > parent.len()
        && name.starts_with(parent)
        && (name[parent.len()..].starts_with('-') || family == Some(parent))
}
/// The (name, version) of the package a component's manifest evidence is of: a package
/// (`pkg:cargo/<name>@<version>`), or the package a candidate algorithm is declared through
/// (`crypto:candidate:<name>@<version>:<asset>`).
pub(super) fn package_of(component: &str) -> Option<(&str, &str)> {
    if let Some(c) = component.strip_prefix("crypto:candidate:") {
        let (nv, _) = c.split_once(':')?;
        return nv.split_once('@');
    }
    component.strip_prefix("pkg:cargo/")?.split_once('@')
}
/// A `Cargo.lock` position: the `name = "<symbol>"` line, at column 0, whose next line is the
/// version the context names (`locked sha2 0.10.9; ..`), which is the package the occurrence
/// is evidence of: two locked versions are told apart.
pub(super) fn check_lock(
    lines: &[String],
    line: usize,
    offset: usize,
    symbol: &str,
    context: &str,
    component: &str,
) -> Result<(), String> {
    let m = re!(r"^\[manifest\] locked (\S+) (\S+);")
        .captures(context)
        .ok_or("a Cargo.lock occurrence whose context names no locked package")?;
    if &m[1] != symbol {
        return Err(format!("the context names {}, the symbol {symbol}", &m[1]));
    }
    if package_of(component) != Some((&m[1], &m[2])) {
        return Err(format!(
            "the context names {} {}, but this is evidence of {component}",
            &m[1], &m[2]
        ));
    }
    let text = lines.get(line.wrapping_sub(1)).ok_or("line out of range")?;
    let want = format!("name = \"{symbol}\"");
    let version = format!("version = \"{}\"", &m[2]);
    if offset == 0 && *text == want && lines.get(line).is_some_and(|l| *l == version) {
        Ok(())
    } else {
        Err(format!(
            "expected `{want}` at column 0, then `{version}`, in {text:?}"
        ))
    }
}
/// Every key of a TOML document, with where it starts and its full path.
pub(super) fn toml_keys(text: &str) -> Vec<TomlKey> {
    let mut t = Toml {
        s: text.chars().collect(),
        i: 0,
        line: 1,
        col: 0,
        keys: Vec::new(),
    };
    if t.peek(0) == Some('\u{feff}') {
        t.bump();
    }
    t.document();
    t.keys
}
impl Toml {
    pub(super) fn peek(&self, k: usize) -> Option<char> {
        self.s.get(self.i + k).copied()
    }

    pub(super) fn bump(&mut self) {
        if let Some(c) = self.peek(0) {
            if c == '\n' {
                self.line += 1;
                self.col = 0;
            } else {
                self.col += 1;
            }
            self.i += 1;
        }
    }

    pub(super) fn eat(&mut self, c: char) -> bool {
        let ok = self.peek(0) == Some(c);
        if ok {
            self.bump();
        }
        ok
    }

    /// spaces and tabs
    pub(super) fn blank(&mut self) {
        while matches!(self.peek(0), Some(' ' | '\t')) {
            self.bump();
        }
    }

    /// whitespace, line breaks and comments
    pub(super) fn skip(&mut self) {
        loop {
            match self.peek(0) {
                Some(' ' | '\t' | '\r' | '\n') => self.bump(),
                Some('#') => self.rest_of_line(),
                _ => return,
            }
        }
    }

    pub(super) fn rest_of_line(&mut self) {
        while self.peek(0).is_some_and(|c| c != '\n') {
            self.bump();
        }
    }

    pub(super) fn triple(&self, q: char) -> bool {
        (0..3).all(|k| self.peek(k) == Some(q))
    }

    /// A basic (`"`) or literal (`'`) string at the cursor; its text if it is on one line.
    pub(super) fn string(&mut self) -> Option<String> {
        let q = self.peek(0)?;
        if self.triple(q) {
            (0..3).for_each(|_| self.bump());
            loop {
                match self.peek(0) {
                    None => return None,
                    Some('\\') if q == '"' => {
                        self.bump();
                        self.bump();
                    }
                    Some(c) if c == q && self.triple(q) => {
                        (0..3).for_each(|_| self.bump());
                        // up to two more quotes end the content
                        for _ in 0..2 {
                            self.eat(q);
                        }
                        return None;
                    }
                    _ => self.bump(),
                }
            }
        }
        self.bump();
        let mut out = String::new();
        loop {
            match self.peek(0) {
                None | Some('\n') => return None,
                Some(c) if c == q => {
                    self.bump();
                    return Some(out);
                }
                Some('\\') if q == '"' => {
                    self.bump();
                    let e = self.peek(0)?;
                    self.bump();
                    match e {
                        'n' => out.push('\n'),
                        't' => out.push('\t'),
                        'r' => out.push('\r'),
                        'b' => out.push('\u{8}'),
                        'f' => out.push('\u{c}'),
                        'e' => out.push('\u{1b}'),
                        '"' | '\\' => out.push(e),
                        'x' | 'u' | 'U' => {
                            let n = match e {
                                'x' => 2,
                                'u' => 4,
                                _ => 8,
                            };
                            let mut h = String::new();
                            for _ in 0..n {
                                h.push(self.peek(0)?);
                                self.bump();
                            }
                            out.push(char::from_u32(u32::from_str_radix(&h, 16).ok()?)?);
                        }
                        _ => return None,
                    }
                }
                Some(c) => {
                    out.push(c);
                    self.bump();
                }
            }
        }
    }

    /// One segment of a key, bare (`A-Za-z0-9_-`) or quoted, and where it starts.
    pub(super) fn segment(&mut self) -> Option<(usize, usize, String)> {
        let (line, col) = (self.line, self.col);
        match self.peek(0)? {
            q @ ('"' | '\'') if !self.triple(q) => Some((line, col, self.string()?)),
            c if c.is_ascii_alphanumeric() || c == '_' || c == '-' => {
                let mut s = String::new();
                while let Some(c) = self
                    .peek(0)
                    .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
                {
                    s.push(c);
                    self.bump();
                }
                Some((line, col, s))
            }
            _ => None,
        }
    }

    /// A dotted key; blanks around the dots.
    pub(super) fn key(&mut self) -> Option<Vec<(usize, usize, String)>> {
        let mut segs = vec![self.segment()?];
        loop {
            self.blank();
            if !self.eat('.') {
                return Some(segs);
            }
            self.blank();
            segs.push(self.segment()?);
        }
    }

    pub(super) fn record(
        &mut self,
        prefix: &[String],
        segs: &[(usize, usize, String)],
    ) -> Vec<String> {
        let mut path = prefix.to_vec();
        for (line, col, s) in segs {
            path.push(s.clone());
            self.keys.push(TomlKey {
                line: *line,
                col: *col,
                path: path.clone(),
                value: None,
            });
        }
        path
    }

    pub(super) fn document(&mut self) {
        let mut table: Vec<String> = Vec::new();
        loop {
            self.skip();
            let at = self.i;
            match self.peek(0) {
                None => return,
                Some('[') => {
                    self.bump();
                    let array = self.eat('[');
                    self.blank();
                    // what follows a malformed header belongs to no table of interest
                    table = vec!["<malformed>".into()];
                    if let Some(segs) = self.key() {
                        let path = self.record(&[], &segs);
                        self.blank();
                        if self.eat(']') && (!array || self.eat(']')) {
                            table = path;
                        }
                    }
                    self.rest_of_line();
                }
                Some(_) => {
                    if !self.keyval(&table) {
                        self.rest_of_line();
                    }
                }
            }
            if self.i == at {
                self.bump();
            }
        }
    }

    pub(super) fn keyval(&mut self, prefix: &[String]) -> bool {
        let Some(segs) = self.key() else {
            return false;
        };
        let path = self.record(prefix, &segs);
        let k = self.keys.len() - 1;
        self.blank();
        if !self.eat('=') {
            return false;
        }
        self.blank();
        self.keys[k].value = self.value(&path);
        true
    }

    pub(super) fn value(&mut self, path: &[String]) -> Option<String> {
        match self.peek(0)? {
            '"' | '\'' => self.string(),
            '[' => {
                self.bump();
                // the elements' keys are not keys of the table
                let mut inner = path.to_vec();
                inner.push("[]".into());
                loop {
                    self.skip();
                    match self.peek(0) {
                        None => break,
                        Some(']') => {
                            self.bump();
                            break;
                        }
                        Some(',') => self.bump(),
                        Some(_) => {
                            let at = self.i;
                            self.value(&inner);
                            if self.i == at {
                                self.bump();
                            }
                        }
                    }
                }
                None
            }
            '{' => {
                self.bump();
                loop {
                    self.skip();
                    match self.peek(0) {
                        None => break,
                        Some('}') => {
                            self.bump();
                            break;
                        }
                        Some(',') => self.bump(),
                        Some(_) => {
                            let at = self.i;
                            if !self.keyval(path) && self.i == at {
                                self.bump();
                            }
                        }
                    }
                }
                None
            }
            _ => {
                while self
                    .peek(0)
                    .is_some_and(|c| !matches!(c, ',' | ']' | '}' | '#' | '\n'))
                {
                    self.bump();
                }
                None
            }
        }
    }
}
/// A `Cargo.toml` position: the start of a key (a quoted key at its opening quote, as the
/// generator writes it) whose last segment is the symbol, and:
/// - `declared by P (K)`: a dependency key in `[K]` (`[K] sym = ..`, `[K.sym]`, `K.sym = ..`,
///   `sym.version = ..`) or `[target.<platform>.K]`, in the manifest of package P, that names
///   the package the occurrence is evidence of: its name (`package = ..` if renamed), and a
///   version requirement its version meets;
/// - `native library `L``: the `links` key of `[package]`, with value L, in the manifest of the
///   package the occurrence is evidence of.
pub(super) fn check_toml(
    keys: &[TomlKey],
    text: &str,
    line: usize,
    offset: usize,
    symbol: &str,
    context: &str,
    component: &str,
) -> Result<(), String> {
    let (cname, cversion) = package_of(component)
        .ok_or_else(|| format!("a manifest occurrence of {component}, not a package"))?;
    let k = keys
        .iter()
        .find(|k| k.line == line && k.col == offset)
        .ok_or_else(|| format!("no key of `{symbol}` starts at this position in {text:?}"))?;
    let path: Vec<&str> = k.path.iter().map(String::as_str).collect();
    let dotted = path.join(".");
    if path.last() != Some(&symbol) {
        return Err(format!("the key here is `{dotted}`, not `{symbol}`"));
    }
    if let Some(m) = re!(r"^\[manifest\] declared by (\S+) \(([\w-]+)\)(?:;|$)").captures(context) {
        let (pkg, kind) = (&m[1], &m[2]);
        let in_table = match path.as_slice() {
            [t, _] | ["target", _, t, _] => *t == kind,
            _ => false,
        };
        if !in_table {
            return Err(format!(
                "the key here is `{dotted}`, not in [{kind}] or [target.<platform>.{kind}]"
            ));
        }
        let name = keys
            .iter()
            .find(|k| k.path == ["package", "name"])
            .and_then(|k| k.value.as_deref());
        if name != Some(pkg) {
            return Err(format!(
                "this is the manifest of {}, not of {pkg}",
                name.unwrap_or("no package")
            ));
        }
        // the dependency this key declares: its package and version requirement
        let field = |f: &str| {
            keys.iter().find(|x| {
                x.path.len() == k.path.len() + 1
                    && x.path.starts_with(&k.path)
                    && x.path.last().is_some_and(|l| l == f)
            })
        };
        let package = field("package")
            .and_then(|x| x.value.as_deref())
            .unwrap_or(symbol);
        if package != cname {
            return Err(format!(
                "the key here declares {package}, but this is evidence of {component}"
            ));
        }
        let req = k
            .value
            .as_deref()
            .or_else(|| field("version").and_then(|x| x.value.as_deref()));
        if let Some(req) = req
            && let (Ok(req), Ok(v)) = (
                semver::VersionReq::parse(req),
                semver::Version::parse(cversion),
            )
            && !req.matches(&v)
        {
            return Err(format!(
                "the key here requires {package} {req}, but this is evidence of {component}"
            ));
        }
        Ok(())
    } else if let Some(m) = re!(r"^\[manifest\] native library `([^`]*)`").captures(context) {
        if path != ["package", "links"] || k.value.as_deref() != Some(&m[1]) {
            return Err(format!(
                "expected `links = \"{}\"` in [package], found `{dotted}`",
                &m[1]
            ));
        }
        let name = keys
            .iter()
            .find(|k| k.path == ["package", "name"])
            .and_then(|k| k.value.as_deref());
        if name != Some(cname) {
            return Err(format!(
                "this is the manifest of {}, but this is evidence of {component}",
                name.unwrap_or("no package")
            ));
        }
        Ok(())
    } else {
        Err(format!("unrecognized manifest context {context:?}"))
    }
}
/// The package a dependency key of the manifest in `dir` renames (`algs = { package =
/// "picklib", .. }`: `picklib`, as a crate name), for the name the code writes.
pub(super) fn renamed_dep(dir: &Path, name: &str) -> Option<String> {
    let text = std::fs::read_to_string(dir.join("Cargo.toml")).ok()?;
    let key = regex::escape(name).replace('_', "[-_]");
    let re = Regex::new(&format!(
        r#"(?m)^\s*{key}\s*=\s*\{{[^}}\n]*\bpackage\s*=\s*"([^"]+)""#
    ))
    .ok()?;
    re.captures(&text).map(|c| c[1].replace('-', "_"))
}
/// Every Rust file under a package's directory, not in `target/`, a hidden directory or
/// another package's directory.
pub(super) fn package_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd.flatten() {
            let p = e.path();
            let name = e.file_name().to_string_lossy().to_string();
            let Ok(ft) = e.file_type() else {
                continue;
            };
            if ft.is_dir() {
                if name != "target" && !name.starts_with('.') && !p.join("Cargo.toml").exists() {
                    stack.push(p);
                }
            } else if name.ends_with(".rs") {
                out.push(p);
            }
        }
    }
    out
}
