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
            if code
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
    let segs: Vec<String> = strip_generics(path)
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
    let score = |p: (usize, usize), inv: &str| {
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
        t.push_str(&expansion(src, p).unwrap_or_else(|| inv.to_string()));
        let w = words(&t);
        (wanted.iter().filter(|x| w.contains(*x)).count(), order(&t))
    };
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
    for (p, t) in others.iter().filter(|(p, _)| in_modules(*p)) {
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
    let (r, binds) = rule_for(src, m, &args)?;
    let mut text = src.orig(r.body.0, r.body.1);
    // longer names first (`$alg` before `$a`)
    let mut binds = binds;
    binds.sort_by_key(|(n, _)| std::cmp::Reverse(n.len()));
    for (n, t) in binds {
        text = text.replace(&format!("${n}"), &toks_text(&t));
    }
    Some(text)
}
