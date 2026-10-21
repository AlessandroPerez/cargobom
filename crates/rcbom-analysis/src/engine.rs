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
    let nargs = calls.iter().map(|c| c.args.len()).max().unwrap_or(0);
    let k = (0..nargs).find(|&k| {
        calls.iter().any(|c| {
            c.args
                .get(k)
                .and_then(Option::as_ref)
                .is_some_and(descriptor)
        })
    })?;
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
/// Whether the points-to analysis' verdict (`pta_verdict`) settles a call's members: it only
/// removes doubt. A complete answer within the value search's members drops those it shows
/// cannot reach the call, and the call's gaps close (the caller); the members' sentences count
/// the new set, and where the search had a gap (`search_gap`) several are each only possibly
/// reaching the call: the engine is flow-insensitive, and its set holds a value the program
/// overwrites before the call (`a = &SHA256; *r = &SHA512` through a chain of reborrows). A
/// descriptor beyond the search's members is such a value, a candidate the engine cannot tell
/// apart (two pointers swapped before a write through one), or a value the search misses: the
/// search's answer stands, and the descriptor is reported (`rcbom-pta: beyond the search`) to be
/// looked at. An incomplete answer settles nothing.
pub(super) fn pta_members(
    ctx: &Ctx<'_>,
    site: &Site,
    v: &PtaVerdict,
    search_gap: bool,
    out: &mut Vec<SiteMatch>,
) -> bool {
    let Target::Call { method, .. } = &site.target else {
        return false;
    };
    if !v.complete {
        return false;
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
    if !beyond.is_empty() || keys.is_empty() {
        for d in beyond {
            eprintln!(
                "rcbom-pta: beyond the search: {d} at {}:{}:{}",
                site.span.file, site.span.line, site.span.col
            );
        }
        return false;
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
    true
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
