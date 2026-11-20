//! Macro invocations: their text, the rule an invocation matches, its metavariables and expansion.

use super::*;

/// The macro an invocation at or around `at` calls, and the invocation's text from its path to
/// its closing bracket.
pub(super) fn invocation_text(src: &Source, at: (usize, usize)) -> Option<(String, String)> {
    let start = invocation_start(src, at)?;
    let (mut text, mut depth, mut opened) = (String::new(), 0i32, false);
    for l in start.0..=src.lines.len().min(start.0 + 400) {
        let chars: Vec<char> = src.lines[l - 1].chars().collect();
        let from = if l == start.0 { start.1 } else { 0 };
        for (ci, &ch) in chars.iter().enumerate().skip(from) {
            text.push(ch);
            let code = src
                .class
                .get(l - 1)
                .and_then(|k| k.get(ci))
                .is_some_and(|k| *k == Class::Code);
            if !code {
                continue;
            }
            match ch {
                '(' | '[' | '{' => {
                    depth += 1;
                    opened = true;
                }
                ')' | ']' | '}' => {
                    depth -= 1;
                    if opened && depth == 0 {
                        let name = re!(r"^(?:\w+::)*(\w+)\s*!").captures(text.trim_start())?[1]
                            .to_string();
                        return Some((name, text));
                    }
                }
                _ => {}
            }
        }
        text.push('\n');
    }
    None
}
/// Where the macro invocation at or around `at` starts: its path (`sel!(..)`, `a::m!(..)`).
pub(super) fn invocation_start(src: &Source, at: (usize, usize)) -> Option<(usize, usize)> {
    if macro_call_at(src, at) {
        return Some(at);
    }
    let s = &src.code;
    let b = src.idx(src.enclosing(at, &[ItemKind::MacroCall])?.start);
    let bang = before_blank(s, b).filter(|&k| s[k] == '!')?;
    let mut w = bang;
    while w > 0 && (is_ident(s[w - 1]) || s[w - 1] == ':') {
        w -= 1;
    }
    Some(src.pos(w))
}
/// Does the macro invocation at `at` make the item `path` names rather than another invocation
/// of the same macro in the file: the macro is invoked once, or no other invocation names as
/// many of the path's words in what it expands to (the transcriber of the rule it matches, its
/// arguments put in; its own code when that is not known: `nistp_dhkex!("P-256", DhP256, p256,
/// ..)` for `<..::p256::DhP256 as DhKeyExchange>::dh`, not the P-384 invocation), with the
/// modules it declares in the path's order (`sel!(gamma, delta, 256)` makes
/// `gamma::delta::run`, `sel!(delta, gamma, 384)` `delta::gamma::run`)? Another that does as
/// well: a range. `extra`: other words the item's code names (the descriptor of the asset).
pub(super) fn invocation_names(
    src: &Source,
    at: (usize, usize),
    path: &str,
    extra: &[String],
) -> Pick {
    let Some(start) = invocation_start(src, at) else {
        return Pick::Exact;
    };
    let Some((name, mine)) = invocation_text(src, start) else {
        return Pick::Exact;
    };
    let call = Regex::new(&format!(r"\b{}\s*!\s*[(\[{{]", regex::escape(&name))).ok();
    let mut others = Vec::new();
    for (l, text) in src.lines.iter().enumerate() {
        for m in call.iter().flat_map(|r| r.find_iter(text)) {
            let c = text[..m.start()].chars().count();
            let code = src
                .class
                .get(l)
                .and_then(|k| k.get(c))
                .is_some_and(|k| *k == Class::Code);
            // (an identical invocation in another module is another candidate: `mod a { h!(run); }`
            // and `mod b { h!(run); }`; the modules around each tell them apart)
            // (one a `macro_rules!` writes in its own rules makes no item where it stands:
            // `$( define_oid! { $u => $l => $v } )+`)
            if code
                && src.enclosing((l + 1, c), &[ItemKind::Macro]).is_none()
                && (l + 1, c) != start
                && let Some((_, t)) = invocation_text(src, (l + 1, c))
            {
                others.push(((l + 1, c), t));
            }
        }
    }
    if others.is_empty() {
        return Pick::Exact;
    }
    // the words of the code (not of comments inside the invocation)
    let words = |t: &str| -> HashSet<String> {
        let code = re!(r"(?s)//[^\n]*|/\*.*?\*/").replace_all(t, " ");
        re!(r"[A-Za-z_]\w*")
            .find_iter(&code)
            .map(|m| m.as_str().to_string())
            .collect()
    };
    // the path's segments, after its crate, as `mod` declarations in order
    // (a qualified path's are its type's: `<m::sha2::Sha2_256 as Default>::default`)
    let plain = match path.trim_start().strip_prefix('<') {
        Some(q) => q
            .trim_start_matches('&')
            .trim_start_matches("mut ")
            .split(" as ")
            .next()
            .unwrap_or(path),
        None => path,
    };
    let segs: Vec<String> = strip_generics(plain)
        .split("::")
        .skip(1)
        .map(|g| g.trim().to_string())
        .filter(|g| !g.is_empty() && g.chars().all(is_ident))
        .collect();
    // (a one-letter word only as a type's name, `<A as Tr>::f`, or a segment of the path, the
    // module `a` of `app::a::run`)
    let mut wanted: Vec<String> = words(path)
        .into_iter()
        .filter(|w| w.len() > 1 || w.chars().all(|c| c.is_ascii_uppercase()) || segs.contains(w))
        .collect();
    for e in extra {
        if !wanted.contains(e) {
            wanted.push(e.clone());
        }
    }
    let order = |t: &str| -> usize {
        let at: Vec<Option<usize>> = segs
            .iter()
            .map(|g| {
                Regex::new(&format!(r"\bmod\s+{}\b", regex::escape(g)))
                    .ok()
                    .and_then(|r| r.find(t))
                    .map(|m| m.start())
            })
            .collect();
        at.windows(2)
            .filter(|w| matches!((w[0], w[1]), (Some(a), Some(b)) if a < b))
            .count()
    };
    // what an invocation writes, as far as it is read
    let written = |p: (usize, usize), inv: &str| {
        // in the modules around the invocation (`mod alpha { h!(run); }` makes `alpha::run`)
        let mut mods: Vec<&Item> = src
            .items
            .iter()
            .filter(|i| i.kind == ItemKind::Mod && i.contains(p))
            .collect();
        mods.sort_by_key(|i| i.start);
        let mut t = mods
            .iter()
            .map(|m| format!("mod {} {{ ", m.name))
            .collect::<String>();
        // (its rule with the arguments put in, and the arguments themselves: of those a
        // rule repeats, the expansion read here holds the first)
        if let Some(e) = expansion(src, p) {
            t.push_str(&e);
            t.push(' ');
        }
        t.push_str(inv);
        t
    };
    let score = |p: (usize, usize), inv: &str| {
        let t = written(p, inv);
        let w = words(&t);
        (wanted.iter().filter(|x| w.contains(*x)).count(), order(&t))
    };
    // the types of the item's own crate its path names, which no item of the file outside a
    // macro defines: an invocation makes the item only if it names them. Where this one does,
    // another that does not is no candidate, whatever else of the path its rule writes
    // (picky-asn1's `asn1_wrapper! { auto struct ObjectIdentifierAsn1(..), .. }` for `<impl
    // Deserialize for wrapper::ObjectIdentifierAsn1>::..::visit_newtype_struct`, not the
    // `auto collection` invocations whose rule writes that impl out)
    let krate = re!(r"[A-Za-z_]\w*")
        .find(path)
        .map(|m| m.as_str().to_string())
        .unwrap_or_default();
    let own_types: Vec<String> = Regex::new(&format!(
        r"\b{}::(?:[a-z_]\w*::)*([A-Z]\w*)",
        regex::escape(&krate)
    ))
    .ok()
    .into_iter()
    .flat_map(|r| {
        r.captures_iter(path)
            .map(|m| m[1].to_string())
            .collect::<Vec<_>>()
    })
    .filter(|t| {
        !src.items.iter().any(|i| {
            matches!(i.kind, ItemKind::TypeDef | ItemKind::Trait)
                && i.name == *t
                && src
                    .enclosing(i.start, &[ItemKind::MacroCall, ItemKind::Macro])
                    .is_none()
        })
    })
    .collect();
    let names_types = |p: (usize, usize), inv: &str| {
        let w = words(&written(p, inv));
        own_types.iter().all(|t| w.contains(t))
    };
    let mine_names = !own_types.is_empty() && names_types(start, &mine);
    // an invocation inside `mod` items makes items in those modules: the path names them all
    let in_modules = |p: (usize, usize)| {
        src.items
            .iter()
            .filter(|i| i.kind == ItemKind::Mod && i.contains(p))
            .all(|m| segs.contains(&m.name))
    };
    if !in_modules(start) {
        return Pick::No;
    }
    // the invocation naming most of the path's words (others naming as many: the range)
    let mine = score(start, &mine);
    if mine.0 == 0 {
        return Pick::No;
    }
    let mut tie = false;
    for (p, t) in others
        .iter()
        .filter(|(p, _)| in_modules(*p))
        .filter(|(p, t)| !mine_names || names_types(*p, t))
    {
        let o = score(*p, t);
        if o > mine {
            return Pick::No;
        }
        tie |= o == mine;
    }
    if tie { Pick::Range } else { Pick::Exact }
}
/// The metavariables of a `macro_rules!` (`body`) that the invocation on `call` binds to a
/// token matching `word`, for a rule whose matcher lists only metavariables (`($m:ident,
/// $alg:ident)`) and as many as the invocation's arguments; `None` when no rule says.
pub(super) fn metavars_of(body: &str, call: &str, word: &Regex) -> Option<Vec<String>> {
    let args_text = re!(r"\w+\s*!\s*[(\[{](.*)[)\]}]").captures(call)?;
    let mut args = Vec::new();
    let (mut depth, mut cur) = (0i32, String::new());
    for c in args_text[1].chars() {
        match c {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            ',' if depth == 0 => {
                args.push(std::mem::take(&mut cur));
                continue;
            }
            _ => {}
        }
        cur.push(c);
    }
    if !cur.trim().is_empty() {
        args.push(cur);
    }
    for m in re!(r"\(\s*((?:\$\w+\s*:\s*\w+\s*,?\s*)+)\)\s*=>").captures_iter(body) {
        let names: Vec<String> = re!(r"\$(\w+)\s*:")
            .captures_iter(&m[1])
            .map(|n| n[1].to_string())
            .collect();
        if names.len() == args.len() {
            let bound: Vec<String> = names
                .into_iter()
                .zip(&args)
                .filter(|(_, a)| word.is_match(a))
                .map(|(n, _)| n)
                .collect();
            return Some(bound);
        }
    }
    None
}
/// Does a macro invocation's path start exactly at `at` (`impl_dhkem!(`,
/// `primeorder::impl_mont_field_element!(`)?
pub(super) fn macro_call_at(src: &Source, at: (usize, usize)) -> bool {
    let Some(text) = src.lines.get(at.0.wrapping_sub(1)) else {
        return false;
    };
    let chars: Vec<char> = text.chars().collect();
    let c = at.1;
    c < chars.len()
        && (c == 0 || !is_ident(chars[c - 1]))
        && src
            .class
            .get(at.0 - 1)
            .and_then(|k| k.get(c))
            .is_some_and(|k| *k == Class::Code)
        && re!(r"^(?:\w+::)*\w+!\s*[(\[{]").is_match(&chars[c..].iter().collect::<String>())
}
/// The `macro_rules!` of a file whose expansion a macro of it writes: the macro itself and
/// those its body invokes, in turn.
pub(super) fn macros_invoked(src: &Source, name: &str) -> Vec<String> {
    let mut out = vec![name.to_string()];
    let mut i = 0;
    while i < out.len() {
        let body: Vec<&Item> = src
            .items
            .iter()
            .filter(|m| m.kind == ItemKind::Macro && m.name == out[i])
            .collect();
        for m in body {
            let text = src
                .lines
                .get(m.start.0.saturating_sub(1)..m.end.0.min(src.lines.len()))
                .unwrap_or_default()
                .join("\n");
            for other in src.items.iter().filter(|o| o.kind == ItemKind::Macro) {
                if !out.contains(&other.name)
                    && Regex::new(&format!(r"\b{}!", regex::escape(&other.name)))
                        .unwrap()
                        .is_match(&text)
                {
                    out.push(other.name.clone());
                }
            }
        }
        i += 1;
    }
    out
}
/// A matcher's elements; None for one not read (a `$` followed by anything else).
pub(super) fn matcher_els(toks: &[Tok]) -> Option<Vec<El>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < toks.len() {
        match &toks[i] {
            Tok::Punct('$') => match (toks.get(i + 1), toks.get(i + 2), toks.get(i + 3)) {
                (Some(Tok::Word(n)), Some(Tok::Punct(':')), Some(Tok::Word(f))) => {
                    out.push(El::Var(n.clone(), f.clone()));
                    i += 4;
                    continue;
                }
                // a repetition: `$( .. ),*`, `$( .. )+`, `$( .. )?`
                (Some(Tok::Group('(', inner)), Some(a), b) => {
                    let inner = matcher_els(inner)?;
                    let op = |t: &Tok| match t {
                        Tok::Punct(c @ ('*' | '+' | '?')) => Some(*c),
                        _ => None,
                    };
                    match (op(a), b.and_then(op)) {
                        (Some(o), _) => {
                            out.push(El::Rep(inner, None, o));
                            i += 3;
                        }
                        (None, Some(o)) => {
                            out.push(El::Rep(inner, Some(a.clone()), o));
                            i += 4;
                        }
                        _ => return None,
                    }
                    continue;
                }
                _ => return None,
            },
            Tok::Group(d, inner) => out.push(El::Group(*d, matcher_els(inner)?)),
            t => out.push(El::Lit(t.clone())),
        }
        i += 1;
    }
    Some(out)
}
/// Whether tokens `t` are a fragment of kind `frag` (`ident`, `literal`, `expr`, ..): an
/// expression, type or path runs to the next `,`, `;` or `=>`.
pub(super) fn frag_ok(frag: &str, t: &[Tok]) -> bool {
    match frag {
        "ident" => matches!(t, [Tok::Word(w)] if w != "_"),
        "literal" => {
            matches!(t, [Tok::Lit(_)] | [Tok::Punct('-'), Tok::Lit(_)])
                || matches!(t, [Tok::Word(w)] if w == "true" || w == "false")
        }
        "lifetime" => matches!(t, [Tok::Punct('\''), Tok::Word(_)]),
        "tt" => t.len() == 1,
        "block" => matches!(t, [Tok::Group('{', _)]),
        _ => {
            !t.is_empty()
                && !t.iter().enumerate().any(|(k, x)| {
                    matches!(x, Tok::Punct(';' | ','))
                        || (matches!(x, Tok::Punct('='))
                            && matches!(t.get(k + 1), Some(Tok::Punct('>'))))
                })
        }
    }
}
/// Matches an invocation's tokens against a matcher, binding its metavariables.
pub(super) fn match_els(p: &[El], t: &[Tok], out: &mut Metavars) -> bool {
    let Some(first) = p.first() else {
        return t.is_empty();
    };
    match first {
        El::Lit(x) => t.first() == Some(x) && match_els(&p[1..], &t[1..], out),
        El::Group(d, inner) => {
            let n = out.len();
            let ok = matches!(t.first(), Some(Tok::Group(d2, sub)) if d2 == d && match_els(inner, sub, out))
                && match_els(&p[1..], &t[1..], out);
            if !ok {
                out.truncate(n);
            }
            ok
        }
        // a repetition: its elements `n` times (separated), then the rest
        El::Rep(inner, sep, op) => {
            let (min, max) = match op {
                '?' => (0, 1),
                '+' => (1, t.len().max(1)),
                _ => (0, t.len()),
            };
            for n in (min..=max).rev() {
                let mut expanded: Vec<El> = Vec::new();
                for k in 0..n {
                    if k > 0
                        && let Some(sp) = sep
                    {
                        expanded.push(El::Lit(sp.clone()));
                    }
                    expanded.extend(inner.iter().cloned());
                }
                expanded.extend(p[1..].iter().cloned());
                let m = out.len();
                if match_els(&expanded, t, out) {
                    return true;
                }
                out.truncate(m);
            }
            false
        }
        El::Var(name, frag) => {
            let max = if matches!(frag.as_str(), "ident" | "tt" | "block") {
                t.len().min(1)
            } else {
                t.len()
            };
            for k in (1..=max).rev() {
                if !frag_ok(frag, &t[..k]) {
                    continue;
                }
                let n = out.len();
                out.push((name.clone(), t[..k].to_vec()));
                if match_els(&p[1..], &t[k..], out) {
                    return true;
                }
                out.truncate(n);
            }
            frag == "vis" && match_els(&p[1..], t, out)
        }
    }
}
pub(super) fn rules_of(src: &Source, m: &Item) -> Vec<Rule> {
    let s = &src.code;
    let (b, e) = src.span(m);
    let mut out = Vec::new();
    let mut k = b + 1;
    while k < e {
        k = skip_blank(s, k);
        if !matches!(s.get(k), Some('(' | '[' | '{')) {
            break;
        }
        let Some(mc) = close_of_at(s, k) else { break };
        let arrow = skip_blank(s, mc + 1);
        if !(s.get(arrow) == Some(&'=') && s.get(arrow + 1) == Some(&'>')) {
            break;
        }
        let t = skip_blank(s, arrow + 2);
        let Some(tc) = close_of_at(s, t) else { break };
        out.push(Rule {
            matcher: matcher_els(&tokens(&src.orig(k + 1, mc))),
            body: (t + 1, tc),
        });
        k = skip_blank(s, tc + 1);
        if s.get(k) == Some(&';') {
            k += 1;
        }
    }
    out
}
/// The arguments of the macro invocation at `at`: its name and the tokens inside its brackets.
pub(super) fn invocation_args(src: &Source, at: (usize, usize)) -> Option<(String, Vec<Tok>)> {
    let (name, text) = invocation_text(src, at)?;
    let toks = tokens(&text);
    let k = toks.iter().position(|t| *t == Tok::Punct('!'))?;
    match toks.get(k + 1)? {
        Tok::Group(_, inner) => Some((name, inner.clone())),
        _ => None,
    }
}
/// The rule of `macro_rules! m` the invocation `args` matches (the first that does, as rustc
/// picks it), with the metavariables it binds; None when a rule before it is not read.
pub(super) fn rule_for(src: &Source, m: &Item, args: &[Tok]) -> Option<(Rule, Metavars)> {
    for r in rules_of(src, m) {
        let mut out = Vec::new();
        if match_els(r.matcher.as_ref()?, args, &mut out) {
            return Some((r, out));
        }
    }
    None
}
/// The rules an invocation of `m` with `args` expands through: the one it matches, then those the
/// invocations of the file's macros in that rule's transcriber match in turn, a rule that hands
/// its arguments on (picky's `( $( $u:ident => $l:ident => $v:literal, )+ ) => { $( define_oid! {
/// $u => $l => $v } )+ }` reaching the rule that writes the function), each with the
/// metavariables it binds. An invocation there is read with its metavariables replaced by what
/// the rule binds them to first; where that matches no rule that can be read, all of that
/// macro's rules are reached. None when the invocation itself matches none.
pub(super) fn rules_reached(
    src: &Source,
    m: &Item,
    args: &[Tok],
    depth: usize,
) -> Option<Vec<(Rule, Metavars)>> {
    // `$name` replaced by its first binding; a repetition `$( .. )` by its tokens once
    fn put(toks: &[Tok], binds: &Metavars) -> Vec<Tok> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < toks.len() {
            match (&toks[i], toks.get(i + 1)) {
                (Tok::Punct('$'), Some(Tok::Word(v))) => {
                    match binds.iter().find(|(n, _)| n == v) {
                        Some((_, t)) => out.extend(t.iter().cloned()),
                        None => out.extend([toks[i].clone(), toks[i + 1].clone()]),
                    }
                    i += 2;
                }
                (Tok::Punct('$'), Some(Tok::Group('(', inner))) => {
                    out.extend(put(inner, binds));
                    i += 2;
                    // (its separator and operator)
                    let end = toks[i..]
                        .iter()
                        .take(2)
                        .position(|t| matches!(t, Tok::Punct('*' | '+' | '?')));
                    i += end.map_or(0, |k| k + 1);
                }
                (Tok::Group(d, inner), _) => {
                    out.push(Tok::Group(*d, put(inner, binds)));
                    i += 1;
                }
                (t, _) => {
                    out.push(t.clone());
                    i += 1;
                }
            }
        }
        out
    }
    // the invocations a transcriber writes: `name ! ( .. )`, at any depth
    fn invoked(toks: &[Tok], out: &mut Vec<(String, Vec<Tok>)>) {
        for (i, t) in toks.iter().enumerate() {
            if let Tok::Group(_, inner) = t {
                match (
                    i.checked_sub(2).map(|k| &toks[k]),
                    i.checked_sub(1).map(|k| &toks[k]),
                ) {
                    (Some(Tok::Word(n)), Some(Tok::Punct('!'))) => {
                        out.push((n.clone(), inner.clone()));
                    }
                    _ => invoked(inner, out),
                }
            }
        }
    }
    let (r, binds) = rule_for(src, m, args)?;
    let mut calls = Vec::new();
    if depth > 0 {
        invoked(&tokens(&src.orig(r.body.0, r.body.1)), &mut calls);
    }
    let mut more = Vec::new();
    for (name, inner) in calls {
        let Some(m2) = src
            .items
            .iter()
            .find(|i| i.kind == ItemKind::Macro && i.name == name)
        else {
            continue;
        };
        match rules_reached(src, m2, &put(&inner, &binds), depth - 1) {
            Some(reached) => more.extend(reached),
            None => more.extend(rules_of(src, m2).into_iter().map(|r| (r, Vec::new()))),
        }
    }
    let mut out = vec![(r, binds)];
    out.extend(more);
    Some(out)
}
/// The file with its item-level invocations of its own `macro_rules!` that name one of `words`
/// (the item's type, its function) expanded in place: what the macros write there, among the
/// file's imports and items. None when no such invocation expands. Positions in it are not the
/// file's: for reading an item's code, not for placing an occurrence.
pub(super) fn macro_made(src: &Source, words: &[String]) -> Option<Rc<Source>> {
    let mut text: String = src.lines.join("\n");
    let mut any = false;
    // from the last invocation back, so that the offsets before it hold
    let mut calls: Vec<&Item> = src
        .items
        .iter()
        .filter(|i| {
            i.kind == ItemKind::MacroCall && src.enclosing(i.start, &[ItemKind::Fn]).is_none()
        })
        .collect();
    calls.sort_by_key(|i| std::cmp::Reverse(i.start));
    for c in calls {
        let Some(start) = invocation_start(src, c.start) else {
            continue;
        };
        let Some((_, call)) = invocation_text(src, start) else {
            continue;
        };
        let names = |w: &String| {
            Regex::new(&format!(r"\b{}\b", regex::escape(w))).is_ok_and(|r| r.is_match(&call))
        };
        if !words.iter().any(names) {
            continue;
        }
        let Some(made) = expansion(src, start) else {
            continue;
        };
        // the invocation's place in the text: its line's offset, then its column
        let line_at: usize = src.lines[..start.0 - 1]
            .iter()
            .map(|l| l.chars().count() + 1)
            .sum();
        let from = text.char_indices().nth(line_at + start.1).map(|(b, _)| b);
        let Some(from) = from.filter(|b| text[*b..].starts_with(&call)) else {
            continue;
        };
        text.replace_range(from..from + call.len(), &made);
        any = true;
    }
    any.then(|| Rc::new(Source::new(&text, true, false)))
}
/// What the invocation at `at` of the file's `macro_rules!` expands to: the transcriber of the
/// rule it matches with its metavariables replaced; None when that is not known.
pub(super) fn expansion(src: &Source, at: (usize, usize)) -> Option<String> {
    // (an invocation is cited by every step of long instantiation chains: once per source)
    thread_local! {
        static EXPANSIONS: std::cell::RefCell<HashMap<(usize, usize, usize), Option<String>>> =
            std::cell::RefCell::new(HashMap::new());
    }
    let key = (src as *const Source as usize, at.0, at.1);
    if let Some(e) = EXPANSIONS.with(|c| c.borrow().get(&key).cloned()) {
        return e;
    }
    let e = expansion_uncached(src, at);
    EXPANSIONS.with(|c| c.borrow_mut().insert(key, e.clone()));
    e
}
pub(super) fn expansion_uncached(src: &Source, at: (usize, usize)) -> Option<String> {
    let (name, args) = invocation_args(src, at)?;
    let m = src
        .items
        .iter()
        .find(|i| i.kind == ItemKind::Macro && i.name == name)?;
    expansion_of(src, m, &args)
}
/// What an invocation with the arguments `args` of the `macro_rules!` item `m` of `src` expands
/// to (the macro may be another file's than the invocation's).
pub(super) fn expansion_of(src: &Source, m: &Item, args: &[Tok]) -> Option<String> {
    let (r, binds) = rule_for(src, m, args)?;
    let mut text = src.orig(r.body.0, r.body.1);
    // longer names first (`$alg` before `$a`)
    let mut binds = binds;
    binds.sort_by_key(|(n, _)| std::cmp::Reverse(n.len()));
    for (n, t) in binds {
        text = text.replace(&format!("${n}"), &toks_text(&t));
    }
    Some(text)
}
