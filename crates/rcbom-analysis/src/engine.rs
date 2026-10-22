//! The points-to engine's answers at a call: whether they close the search's gaps or narrow its
//! members.

use super::*;

pub(super) fn pta_verdict(ctx: &Ctx<'_>, site: &Site, at: &std::path::Path) -> Option<PtaVerdict> {
    let Target::Call { callee, method, .. } = &site.target else {
        return None;
    };
    let calls: Vec<&rcbom_facts::PtaCall> = ctx
        .pta
        .get(&(at.to_path_buf(), site.span.line, site.span.col))?
        .iter()
        // the copies of this site's own instance (two instances of a generic function at one
        // position are two sites), or of every instance of the item for its per-item site
        .filter(|c| {
            c.live
                && c.callee == callee.path
                && (c.owner == site.owner.id || c.owner_def == site.owner.id)
        })
        .copied()
        .collect();
    let descriptor = |a: &rcbom_facts::PtaArg| {
        a.direct
            && a.pointee
                .as_ref()
                .is_some_and(|t| ctx.descriptor_types.contains(t))
    };
    let given = |k: usize| {
        calls.iter().any(|c| {
            c.args
                .get(k)
                .and_then(Option::as_ref)
                .is_some_and(descriptor)
        })
    };
    // the argument that carries the algorithm: an operation's, as the knowledge base names it
    // (`prk.expand(info, &AES_256_GCM)` takes it in its receiver, a key the engine cannot name,
    // not in the length), else the first given a descriptor by reference
    let k = match operation_algorithm(ctx, site) {
        Some(k) => given(k).then_some(k)?,
        None => {
            let nargs = calls.iter().map(|c| c.args.len()).max().unwrap_or(0);
            (0..nargs).find(|&k| given(k))?
        }
    };
    let answers: Vec<&rcbom_facts::PtaArg> = calls
        .iter()
        .filter_map(|c| c.args.get(k)?.as_ref())
        .collect();
    let supported = |k: &rcbom_facts::CrateRef| ctx.supported(k);
    let mut found: Vec<rcbom_facts::DefRef> = Vec::new();
    let mut unnamed = false;
    for d in answers.iter().flat_map(|a| &a.statics) {
        if matcher::match_static_called(ctx.kb, d, Some(method), &supported).is_some() {
            if !found.contains(d) {
                found.push(d.clone());
            }
        } else {
            unnamed = true;
        }
    }
    let complete = !unnamed
        && answers
            .iter()
            .all(|a| !a.unknown && !a.statics.is_empty() && a.others == 0);
    Some(PtaVerdict { found, complete })
}
/// What the points-to analysis' verdict does to a call's members (`pta_members`).
#[derive(PartialEq)]
pub(super) enum Settled {
    /// Nothing: the search's answer stands.
    No,
    /// The members are within the engine's complete answer: the call's gaps close.
    Closed,
    /// The engine's complete answer holds a descriptor beyond a search answer that claims
    /// completeness: one the search may drop, so the call gets the unknown (never the descriptor).
    Beyond,
}
/// The unknown's reason where the engine's complete answer holds a descriptor beyond a search
/// answer that claims completeness (`Settled::Beyond`).
pub(super) const BEYOND: &str = "other algorithms than these may reach the call: the points-to \
                                 analysis finds a value the search does not";
/// What the points-to analysis' verdict (`pta_verdict`) does to a call's members: it only
/// removes doubt. A complete answer within the value search's members drops those it shows
/// cannot reach the call, and the call's gaps close (the caller); the members' sentences count
/// the new set, and where the search had a gap (`search_gap`) several are each only possibly
/// reaching the call: the engine is flow-insensitive, and its set holds a value the program
/// overwrites before the call (`a = &SHA256; *r = &SHA512` through a chain of reborrows). A
/// descriptor beyond the search's members is such a value, a candidate the engine cannot tell
/// apart (two pointers swapped before a write through one), or a value the search misses: it is
/// never added; where the search had a gap its unknown covers it, and where the search claimed
/// completeness the call gets the unknown (`Settled::Beyond`). An incomplete answer settles
/// nothing.
///
/// The engine is also a check on the default run, printed for review (`rcbom-pta: outside the
/// engine` and `beyond a complete search`, collected and compared between runs by `cargo xtask
/// pta-candidates`): a member outside a complete answer is a candidate wrong member, a
/// descriptor beyond a search that claims completeness a candidate drop.
pub(super) fn pta_members(
    ctx: &Ctx<'_>,
    site: &Site,
    v: &PtaVerdict,
    search_gap: bool,
    out: &mut Vec<SiteMatch>,
) -> Settled {
    let Target::Call { method, .. } = &site.target else {
        return Settled::No;
    };
    if !v.complete {
        return Settled::No;
    }
    let supported = |k: &rcbom_facts::CrateRef| ctx.supported(k);
    // a member of the call's algorithm set (not one only dead code names)
    let member = |o: &SiteMatch| {
        !o.5 && o.1 == Kind::Call
            && o.0.name != UNKNOWN
            && o.4.iter().any(|d| d.starts_with("algorithm "))
    };
    let have: HashSet<String> = out
        .iter()
        .filter(|o| member(o))
        .map(|o| o.0.key())
        .collect();
    let mut keys: HashSet<String> = HashSet::new();
    let mut beyond = Vec::new();
    for d in &v.found {
        let Some(m) = matcher::match_static_called(ctx.kb, d, Some(method), &supported) else {
            continue;
        };
        if !have.contains(&m.key()) {
            beyond.push(short(&d.path));
        }
        keys.insert(m.key());
    }
    let at = format!("{}:{}:{}", site.span.file, site.span.line, site.span.col);
    for o in out
        .iter()
        .filter(|o| member(o) && !keys.contains(&o.0.key()))
    {
        eprintln!("rcbom-pta: outside the engine: {} at {at}", o.0.name);
    }
    if !beyond.is_empty() {
        // a search that claims a set: the call has members, or is an operation (whose members
        // all reach it only through dead code); a getter (`alg.output_len()`) or a constructor
        // whose use is reported where the value is used (`Context::new`) claims nothing
        if search_gap || (have.is_empty() && unresolved_operation(ctx, site).is_none()) {
            return Settled::No;
        }
        for d in beyond {
            eprintln!("rcbom-pta: beyond a complete search: {d} at {at}");
        }
        return Settled::Beyond;
    }
    if keys.is_empty() {
        return Settled::No;
    }
    out.retain(|o| !member(o) || keys.contains(&o.0.key()));
    let n = out.iter().filter(|o| member(o)).count();
    for o in out.iter_mut().filter(|o| member(o)) {
        if let Some(s) = o.4.iter_mut().find(|s| s.starts_with("algorithm ")) {
            *s = renumber(s, n);
            if n > 1 && search_gap && !s.contains(" possibly ") {
                *s = s.replacen(
                    "that may reach the call",
                    "that may possibly reach the call",
                    1,
                );
            }
        }
    }
    Settled::Closed
}
/// A member's sentence for a set of `n` members: "algorithm from X in the arguments" is one of
/// `n` when there are several, "one of 2 that may reach the call: X" is "from X" when it is alone.
pub(super) fn renumber(s: &str, n: usize) -> String {
    if let Some(rest) = s.strip_prefix("algorithm one of ")
        && let Some((k, tail)) = rest.split_once(' ')
        && k.parse::<usize>().is_ok()
        && tail.starts_with("that ")
    {
        if n > 1 {
            return format!("algorithm one of {n} {tail}");
        }
        if let Some(m) = tail.strip_prefix("that may reach the call: ")
            && m.ends_with(" in the arguments")
            && !m.contains(", ")
        {
            return format!("algorithm from {m}");
        }
        if let Some(m) = tail.strip_prefix("that may reach the call from other functions: ")
            && !m.contains(", ")
        {
            return format!("algorithm from {m}, reaching the call from another function");
        }
        return s.to_string();
    }
    if n > 1
        && let Some(r) = s.strip_prefix("algorithm from ")
    {
        if let Some(m) = r.strip_suffix(" in the arguments") {
            return format!("algorithm one of {n} that may reach the call: {m} in the arguments");
        }
        if let Some(m) = r.strip_suffix(", reaching the call from another function") {
            return format!(
                "algorithm one of {n} that may reach the call from other functions: {m}"
            );
        }
    }
    s.to_string()
}
