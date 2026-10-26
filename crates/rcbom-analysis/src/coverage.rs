//! The boundary check: every call of the walked code into a crypto package (`Reach::boundary`,
//! by the function it resolves to) is cited by an occurrence of its own call, or needs none for
//! a reason stated here. A call neither cited nor excused is cited by the check itself, as an
//! operation of unknown algorithm: nothing the walk reaches is left out.

use super::*;

/// What the check found over all artifacts' walks.
#[derive(Debug, Default)]
pub struct Coverage {
    /// The calls into a crypto package, one per position, call and callee.
    pub edges: usize,
    pub cited: usize,
    /// Calls the check cited itself: neither an occurrence's nor excused, an unknown operation
    /// where the call is.
    pub floor: usize,
    /// Calls that need no occurrence, by why: `entered` (into a protocol crate, whose code the
    /// walk enters: its own calls are checked), `internal` (between crypto packages without
    /// entries: their internals), `relay` (into a crypto package whose own calls are no
    /// operations), `step` (a step of a computation the call that ends it stands for),
    /// `awaited` (a future's body, made by a call checked itself), `named` (a function reaching
    /// the call as a value, cited where it is named), `not crypto` (a draw from a
    /// generator computing no cryptography), and the
    /// `[[aside]]` kinds (no operation: a view, a wipe, an accessor).
    pub excused: BTreeMap<String, usize>,
    /// Calls left out (none: the check cites them itself): (location, line, 0-based column,
    /// callee, calling function).
    pub uncited: Vec<(String, usize, usize, String, String)>,
    /// Every call and how it is accounted for, by position (`cargo cbom --boundary-list`).
    pub calls: Vec<Checked>,
}

/// One call the check accounts for.
#[derive(Debug)]
pub struct Checked {
    pub location: String,
    pub line: usize,
    /// 0-based, as an occurrence's offset.
    pub offset: usize,
    /// `cited`, `unknown` (cited by the check), or the reason it needs no occurrence.
    pub verdict: String,
    pub callee: String,
    /// The trait the callee is a method of or implements.
    pub trait_path: Option<String>,
    pub owner: String,
    /// Whose code the caller runs for (`Algorithm`, `Package`), when the crypto layer's.
    pub on_behalf: Option<rcbom_facts::Behalf>,
}

impl Checked {
    /// One tab-separated line: position, verdict, callee, trait, caller, on behalf of.
    pub fn line(&self) -> String {
        format!(
            "{}:{}:{}\t{}\t{}\t{}\t{}\t{}",
            self.location,
            self.line,
            self.offset,
            self.verdict,
            self.callee,
            self.trait_path.as_deref().unwrap_or("-"),
            self.owner,
            match self.on_behalf {
                Some(rcbom_facts::Behalf::Algorithm) => "algorithm",
                Some(rcbom_facts::Behalf::Package) => "package",
                None => "-",
            }
        )
    }
}

impl Coverage {
    /// `N calls into crypto packages: C cited, F cited by the check as unknown, E excused
    /// (entered a, internal b, ..)`.
    pub fn summary(&self) -> String {
        let excused: usize = self.excused.values().sum();
        let why: Vec<String> = self
            .excused
            .iter()
            .map(|(k, n)| format!("{k} {n}"))
            .collect();
        let left = if self.uncited.is_empty() {
            String::new()
        } else {
            format!(", {} not cited", self.uncited.len())
        };
        format!(
            "{} calls into crypto packages: {} cited, {} cited by the check as unknown, \
             {excused} excused ({}){left}",
            self.edges,
            self.cited,
            self.floor,
            why.join(", "),
        )
    }
}

/// An impl's method by its type's path: `<T as Tr>::m` is `T::m` (generic arguments removed:
/// `<Uniform<X> as From<Range<X>>>::from` is `Uniform::from`).
fn by_type(path: &str) -> String {
    if let Some(rest) = path.strip_prefix('<') {
        // the bracket's end and its top-level ` as `
        let (mut depth, mut close, mut as_at) = (0usize, None, None);
        for (i, c) in rest.char_indices() {
            match c {
                '<' => depth += 1,
                '>' if depth == 0 => {
                    close = Some(i);
                    break;
                }
                '>' => depth -= 1,
                ' ' if depth == 0 && as_at.is_none() && rest[i..].starts_with(" as ") => {
                    as_at = Some(i)
                }
                _ => {}
            }
        }
        if let (Some(c), Some(a)) = (close, as_at)
            && let Some(m) = rest[c..].strip_prefix(">::")
        {
            return format!(
                "{}::{}",
                matcher::strip_generics(&rest[..a]),
                matcher::strip_generics(m)
            );
        }
    }
    matcher::strip_generics(path)
}

/// Why a call into a crypto package needs no occurrence, if it needs none.
fn excuse<'k>(ctx: &'k Ctx<'_>, e: &rcbom_facts::BoundaryEdge) -> Option<&'k str> {
    let callee = &e.callee.krate;
    let path = by_type(&e.callee.path);
    let method = path.rsplit("::").next().unwrap_or_default().to_string();
    let in_crate = path
        .strip_prefix(&format!("{}::", callee.name))
        .unwrap_or(&path);
    // what the knowledge base says is no operation (`[[aside]]`: a view, a wipe, an accessor)
    if let Some(a) = ctx
        .kb
        .aside(&callee.name, in_crate, e.trait_path.as_deref())
    {
        return Some(&a.name);
    }
    // a draw from a generator that computes no cryptography (`SmallRng`: `[unmodelled]
    // not_crypto`) is no operation
    if e.types.iter().any(|t| {
        let name = t.rsplit("::").next().unwrap_or(t);
        ctx.kb.not_crypto.iter().any(|n| n == name)
    }) {
        return Some("not crypto");
    }
    // a function reaching the call as a value (`Some(blake3::hash)` called through the
    // closure's parameter): cited where it is named (`Call::value`)
    if e.through_value {
        return Some("named");
    }
    let caller = &e.owner.krate;
    // a closure (or `async` body) the crypto package made, run by a dependency it was handed to
    // (a runtime, a parser combinator): the package's own code, whose calls are checked, made
    // by a call into the package that is checked too (not the program's own call of it)
    let program_caller = ctx
        .package_of_crate(&caller.name, &caller.stable_id)
        .is_none_or(|p| ctx.local.contains(&p));
    if path.contains("{closure") && !program_caller {
        return Some("internal");
    }
    // a future's body polled where it is awaited (`listen(..).await`): the call of the `async
    // fn` making it is the call into the package, checked itself
    if e.coroutine {
        return Some("awaited");
    }
    // the code of an algorithm or trait crate, any version (p521 0.13 into elliptic-curve):
    // an algorithm's implementation
    let algorithm_caller = ctx
        .kb_entry(caller)
        .is_some_and(|c| matches!(c.role, Role::Algorithm | Role::Trait));
    let step = ctx.kb.step(&method) || ctx.kb.step_trait(e.trait_path.as_deref());
    match ctx.kb_entry(callee).map(|c| c.role) {
        Some(Role::Protocol) => Some("entered"),
        // an algorithm or trait crate: the call is the fact, but inside an algorithm's own
        // implementation (subtle's generic code run on curve25519-dalek's field elements), and
        // for a stream's step at a version not covered (at one covered, it is cited beside the
        // call ending the stream)
        Some(_) if algorithm_caller || e.on_behalf == Some(rcbom_facts::Behalf::Algorithm) => {
            Some("internal")
        }
        Some(_) => (!ctx.supported(callee) && step).then_some("step"),
        None => {
            let crypto_caller = (ctx.is_unmodelled(caller) || ctx.kb_entry(caller).is_some())
                && ctx
                    .package_of_crate(&caller.name, &caller.stable_id)
                    .is_some_and(|p| !ctx.local.contains(&p));
            if crypto_caller || e.on_behalf.is_some() {
                Some("internal")
            } else if ctx.kb.relay(&callee.name) {
                Some("relay")
            } else if step {
                Some("step")
            } else {
                None
            }
        }
    }
}

/// The check over the walks of `facts`, against the occurrences of `assets` and `protocols`;
/// a call neither cited nor excused gets an occurrence in `assets` (and its package `usage`).
pub(super) fn check(
    ctx: &Ctx<'_>,
    man: &Manifest,
    facts: &[CrateFacts],
    assets: &mut BTreeMap<String, Asset>,
    protocols: &BTreeMap<String, Protocol>,
    usage: &mut HashMap<(String, String), Usage>,
) -> Coverage {
    // (an occurrence cites the calls it stands for; one without, a position)
    let mut cited: HashSet<(String, usize, usize, Option<rcbom_facts::CallId>)> = HashSet::new();
    for o in assets
        .values()
        .flat_map(|a| &a.occurrences)
        .chain(protocols.values().flat_map(|p| &p.occurrences))
    {
        let at = (o.location.clone(), o.line, o.offset);
        cited.insert((at.0.clone(), at.1, at.2, None));
        for c in &o.calls {
            cited.insert((at.0.clone(), at.1, at.2, Some(c.clone())));
        }
    }
    let mut out = Coverage::default();
    // the calls, once each (the same call in two artifacts' walks is one), with the artifacts
    // reaching it
    let mut calls: Vec<(String, &rcbom_facts::BoundaryEdge, BTreeSet<String>)> = Vec::new();
    let mut index: HashMap<(String, usize, usize, String, Option<rcbom_facts::CallId>), usize> =
        HashMap::new();
    for f in facts {
        let Some(reach) = &f.reach else { continue };
        let cwd = Path::new(&f.krate.cwd);
        for e in &reach.boundary {
            let path = {
                let p = PathBuf::from(&e.span.file);
                if p.is_absolute() { p } else { cwd.join(p) }
            };
            let location = man.location(&path);
            let key = (
                location.clone(),
                e.span.line,
                e.span.col.saturating_sub(1),
                e.callee.path.clone(),
                e.call.clone(),
            );
            match index.get(&key) {
                Some(&i) => {
                    calls[i].2.insert(reach.artifact.clone());
                }
                None => {
                    index.insert(key, calls.len());
                    calls.push((location, e, BTreeSet::from([reach.artifact.clone()])));
                }
            }
        }
    }
    for (location, e, artifacts) in calls {
        let offset = e.span.col.saturating_sub(1);
        out.edges += 1;
        let own = cited.contains(&(location.clone(), e.span.line, offset, e.call.clone()))
            || (e.call.is_none() && cited.contains(&(location.clone(), e.span.line, offset, None)));
        let verdict = if own {
            out.cited += 1;
            "cited".to_string()
        } else if let Some(why) = excuse(ctx, e) {
            *out.excused.entry(why.to_string()).or_default() += 1;
            why.to_string()
        } else {
            out.floor += 1;
            floor(ctx, e, &location, artifacts, assets, usage);
            "unknown".to_string()
        };
        out.calls.push(Checked {
            location,
            line: e.span.line,
            offset,
            verdict,
            callee: e.callee.path.clone(),
            trait_path: e.trait_path.clone(),
            owner: e.owner.path.clone(),
            on_behalf: e.on_behalf,
        });
    }
    out.calls.sort_by(|a, b| {
        (&a.location, a.line, a.offset, &a.callee).cmp(&(&b.location, b.line, b.offset, &b.callee))
    });
    out
}

/// A call the check cites itself: an operation of unknown algorithm of the callee's package,
/// at the call, saying the knowledge base gives the call no meaning. A call the standard
/// library makes on the program's behalf is cited at the program's call into it, by the
/// function called there.
fn floor(
    ctx: &Ctx<'_>,
    e: &rcbom_facts::BoundaryEdge,
    location: &str,
    artifacts: BTreeSet<String>,
    assets: &mut BTreeMap<String, Asset>,
    usage: &mut HashMap<(String, String), Usage>,
) {
    let provider = ctx.package_of_crate(&e.callee.krate.name, &e.callee.krate.stable_id);
    let package = ctx
        .package_of_crate(&e.owner.krate.name, &e.owner.krate.stable_id)
        .unwrap_or_default();
    let of = match &provider {
        Some((n, v)) => format!(" of {n} {v}"),
        None => String::new(),
    };
    // what the knowledge base says the call does, when it names it as an operation
    // (`Signer::try_sign`: a signature) the analysis gave no occurrence
    let bare = by_type(&e.callee.path);
    let op = ctx.kb.operation(
        &e.callee.krate.name,
        bare.strip_prefix(&format!("{}::", e.callee.krate.name))
            .unwrap_or(&bare),
    );
    let (primitive, function) = match op {
        Some(op) if !op.setup && !op.function.is_empty() => {
            (op.primitive.clone(), op.function.clone())
        }
        _ => (UNKNOWN.to_string(), UNKNOWN.to_string()),
    };
    let does = if function == UNKNOWN {
        ": what it does is not known".to_string()
    } else {
        String::new()
    };
    let reason = match &e.std_entry {
        Some(f) => format!(
            "the boundary check: the standard library's `{}` runs `{}`{of} here, a call \
             nothing else in the CBOM accounts for{does}",
            short(f),
            short(&e.callee.path)
        ),
        None => format!(
            "the boundary check: `{}`{of}, a call nothing else in the CBOM accounts for{does}",
            short(&e.callee.path)
        ),
    };
    let mut m = Match {
        name: UNKNOWN.to_string(),
        algo: Algo {
            asset: UNKNOWN.to_string(),
            primitive: primitive.clone(),
            functions: vec![function.clone()],
            ..Algo::default()
        },
        params: BTreeMap::new(),
        values: BTreeMap::new(),
        components: BTreeSet::new(),
        providers: BTreeSet::new(),
        provider_crates: Vec::new(),
    };
    m.providers.extend(provider.clone());
    if let Some(p) = provider {
        usage.insert(p, Usage::Reachable);
    }
    let occ = Occurrence {
        location: location.to_string(),
        line: e.span.line,
        offset: e.span.col.saturating_sub(1),
        symbol: without_lifetimes(e.std_entry.as_ref().unwrap_or(&e.callee.path)),
        kind: Kind::Call,
        tier: Tier::Reachable,
        function: Some(function.clone()),
        owner: short(&e.owner.name),
        macro_tag: e
            .expansion
            .as_ref()
            .filter(|x| x.kind != rcbom_facts::MacroKind::Desugaring)
            .map(|x| (x.kind, x.macro_name.clone())),
        line_text: e.line_text.clone(),
        code: e.text.clone(),
        detail: vec![format!("algorithm unresolved: {reason}")],
        package,
        provenance: Vec::new(),
        note: None,
        generic_body: e.owner.kind == OwnerKind::Fn && is_def_hash(&e.owner.id),
        via: Vec::new(),
        artifacts,
        calls: e.call.iter().cloned().collect(),
    };
    let a = assets.entry(m.key()).or_insert_with(|| Asset {
        key: m.key(),
        name: m.name.clone(),
        algo: m.algo.clone(),
        params: BTreeMap::new(),
        occurrences: Vec::new(),
        components: BTreeSet::new(),
        providers: BTreeSet::new(),
        entry_notes: BTreeSet::new(),
    });
    a.entry_notes.insert(None);
    a.providers.extend(m.providers.iter().cloned());
    if !a.algo.functions.contains(&function) {
        a.algo.functions.push(function);
        a.algo.functions.sort();
    }
    match a.occurrences.iter_mut().find(|o| {
        o.location == occ.location
            && o.line == occ.line
            && o.offset == occ.offset
            && o.symbol == occ.symbol
    }) {
        Some(o) => {
            o.artifacts.extend(occ.artifacts);
            o.calls.extend(occ.calls);
            for d in occ.detail {
                if !o.detail.contains(&d) {
                    o.detail.push(d);
                }
            }
        }
        None => a.occurrences.push(occ),
    }
}

/// A path without its lifetimes (`<&'a EdwardsPoint as Mul<&'b Scalar>>::mul`: `<&EdwardsPoint
/// as Mul<&Scalar>>::mul`), as code names it.
fn without_lifetimes(path: &str) -> String {
    let mut out = String::new();
    let mut chars = path.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\'' {
            while chars
                .next_if(|c| c.is_alphanumeric() || *c == '_')
                .is_some()
            {}
            // (`'a ` before a type, `'_, ` in a list)
            if chars.next_if_eq(&' ').is_none() {
                chars.next_if_eq(&',');
                chars.next_if_eq(&' ');
            }
            continue;
        }
        out.push(c);
    }
    // (generic arguments that were lifetimes only)
    out.replace("::<>", "").replace("<>", "")
}

#[cfg(test)]
mod tests {
    use super::by_type;

    #[test]
    fn paths_without_lifetimes() {
        assert_eq!(
            super::without_lifetimes(
                "<&'a curve25519_dalek::edwards::EdwardsPoint as core::ops::arith::Mul<&'b \
                 curve25519_dalek::scalar::Scalar>>::mul"
            ),
            "<&curve25519_dalek::edwards::EdwardsPoint as core::ops::arith::Mul<&\
             curve25519_dalek::scalar::Scalar>>::mul"
        );
        assert_eq!(
            super::without_lifetimes("aws_lc_rs::cipher::streaming::BufferUpdate::<'_>::written"),
            "aws_lc_rs::cipher::streaming::BufferUpdate::written"
        );
    }

    #[test]
    fn impl_methods_by_their_type() {
        assert_eq!(
            by_type("<ring::hkdf::Algorithm as ring::hkdf::KeyType>::len"),
            "ring::hkdf::Algorithm::len"
        );
        assert_eq!(
            by_type(
                "<rand::distributions::uniform::Uniform<X> as \
                 core::convert::From<core::ops::range::Range<X>>>::from"
            ),
            "rand::distributions::uniform::Uniform::from"
        );
        assert_eq!(
            by_type("ring::aead::Aad::<[u8; 12]>::from"),
            "ring::aead::Aad::from"
        );
    }
}
