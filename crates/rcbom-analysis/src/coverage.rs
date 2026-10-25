//! The boundary check: every call of the walked code into a crypto package (`Reach::boundary`,
//! by the function it resolves to) is cited by an occurrence at its position, or needs none for
//! a reason stated here. A call neither cited nor excused is one the CBOM may leave out.

use super::*;

/// What the check found over all artifacts' walks.
#[derive(Debug, Default)]
pub struct Coverage {
    /// The calls into a crypto package, one per position and callee.
    pub edges: usize,
    pub cited: usize,
    /// Calls that need no occurrence, by why: `entered` (into a protocol crate, whose code the
    /// walk enters: its own calls are checked), `internal` (between crypto packages without
    /// entries: their internals), `relay` (into a crypto package whose own calls are no
    /// operations), `step` (a step of a computation the call that ends it stands for),
    /// `awaited` (a future's body, made by a call checked itself), `named` (a function reaching
    /// the call as a value, cited where it is named), `not crypto` (a draw from a
    /// generator computing no cryptography), and the
    /// `[[aside]]` kinds (no operation: a view, a wipe, an accessor).
    pub excused: BTreeMap<String, usize>,
    /// The others: (location, line, 0-based column, callee, calling function).
    pub uncited: Vec<(String, usize, usize, String, String)>,
}

impl Coverage {
    /// `N calls into crypto packages: C cited, E excused (entered a, internal b, ..), U not
    /// cited`.
    pub fn summary(&self) -> String {
        let excused: usize = self.excused.values().sum();
        let why: Vec<String> = self
            .excused
            .iter()
            .map(|(k, n)| format!("{k} {n}"))
            .collect();
        format!(
            "{} calls into crypto packages: {} cited, {excused} excused ({}), {} not cited",
            self.edges,
            self.cited,
            why.join(", "),
            self.uncited.len()
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

/// The check over the walks of `facts`, against the occurrences of `assets` and `protocols`.
pub(super) fn check(
    ctx: &Ctx<'_>,
    man: &Manifest,
    facts: &[CrateFacts],
    assets: &BTreeMap<String, Asset>,
    protocols: &BTreeMap<String, Protocol>,
) -> Coverage {
    let cited: HashSet<(&str, usize, usize)> = assets
        .values()
        .flat_map(|a| &a.occurrences)
        .chain(protocols.values().flat_map(|p| &p.occurrences))
        .map(|o| (o.location.as_str(), o.line, o.offset))
        .collect();
    let mut out = Coverage::default();
    let mut seen = HashSet::new();
    for f in facts {
        let Some(reach) = &f.reach else { continue };
        let cwd = PathBuf::from(&f.krate.cwd);
        for e in &reach.boundary {
            let path = {
                let p = PathBuf::from(&e.span.file);
                if p.is_absolute() { p } else { cwd.join(p) }
            };
            let location = man.location(&path);
            let offset = e.span.col.saturating_sub(1);
            // (the same call in two artifacts' walks is one)
            if !seen.insert((location.clone(), e.span.line, offset, e.callee.path.clone())) {
                continue;
            }
            out.edges += 1;
            if cited.contains(&(location.as_str(), e.span.line, offset)) {
                out.cited += 1;
            } else if let Some(why) = excuse(ctx, e) {
                *out.excused.entry(why.to_string()).or_default() += 1;
            } else {
                out.uncited.push((
                    location,
                    e.span.line,
                    offset,
                    e.callee.path.clone(),
                    e.owner.path.clone(),
                ));
            }
        }
    }
    out.uncited.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::by_type;

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
