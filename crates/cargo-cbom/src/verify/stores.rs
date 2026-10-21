//! Stores that may reach a read: through pointers and aliases, swaps, replaces, projections of values.

use super::*;

/// What the file's function `f` returns of its parameter `param` (its tail expression): the
/// path in the result to it (`""` the parameter, `.r` a field of the struct literal returned,
/// `.0` a tuple's element, `?` an `Option`'s value), the part of it a borrow returned names
/// (`&mut self.alg`: `.alg`), and whether it returns that on every way (no `return` before).
pub(super) fn returns_part(src: &Source, f: &Item, param: &str) -> Option<(String, String, bool)> {
    let s = &src.code;
    let sc = src.fn_scope(f);
    let (o, c) = sc.body;
    if c < o + 2 {
        return None;
    }
    let mut tail_at = o + 1;
    let mut k = o + 1;
    while k < c - 1 {
        let e = scan_to(s, k, c - 1, |m| s[m] == ';');
        if e >= c - 1 {
            break;
        }
        tail_at = e + 1;
        k = e + 1;
    }
    let tail = src.text(tail_at, c - 1);
    let tail = tail.trim();
    let definite = !(o..c).any(|m| kw(s, m, "return") || s[m] == '?');
    let p = regex::escape(param);
    // `x`, `&mut *x`, `&mut x.f.g`, `&mut self.alg`
    if let Some(m) = Regex::new(&format!(
        r"^(?:&\s*mut\s+\**\s*)?\(?\s*\**{p}\s*\)?((?:\s*\.\s*\w+)*)$"
    ))
    .ok()?
    .captures(tail)
    {
        let sub: String = m[1].chars().filter(|c| !c.is_whitespace()).collect();
        if !sub.is_empty() && !tail.starts_with('&') {
            return None;
        }
        return Some((String::new(), sub, definite));
    }
    if Regex::new(&format!(r"^Some\s*\(\s*{p}\s*\)$"))
        .ok()?
        .is_match(tail)
    {
        return Some(("?".into(), String::new(), definite));
    }
    // `W { r: x, .. }`, `Self { r: x }`, `W { r: &mut self.alg }`, `W1 { r }`
    if let Some(m) = Regex::new(&format!(
        r"^(?:\w+::)*[A-Z]\w*\s*\{{(?:[^{{}}]*,)?\s*(\w+)\s*:\s*(&\s*mut\s+\**\s*)?{p}((?:\s*\.\s*\w+)*)\s*(?:,[^{{}}]*)?\}}$"
    ))
    .ok()?
    .captures(tail)
    {
        let sub: String = m[3].chars().filter(|c| !c.is_whitespace()).collect();
        if !sub.is_empty() && m.get(2).is_none() {
            return None;
        }
        return Some((format!(".{}", &m[1]), sub, definite));
    }
    if Regex::new(&format!(
        r"^(?:\w+::)*[A-Z]\w*\s*\{{(?:[^{{}}]*,)?\s*{p}\s*(?:,[^{{}}]*)?\}}$"
    ))
    .ok()?
    .is_match(tail)
    {
        return Some((format!(".{param}"), String::new(), definite));
    }
    // `(x, ..)`, `(&mut self.a, &mut self.b)`
    if tail.starts_with('(') && tail.ends_with(')') {
        let parts = split_top(&tail[1..tail.len() - 1]);
        let elem = Regex::new(&format!(r"^(&\s*mut\s+\**\s*)?{p}((?:\s*\.\s*\w+)*)$")).ok()?;
        if parts.len() > 1 {
            for (k, e) in parts.iter().enumerate() {
                if let Some(m) = elem.captures(e.trim()) {
                    let sub: String = m[2].chars().filter(|c| !c.is_whitespace()).collect();
                    if !sub.is_empty() && m.get(1).is_none() {
                        continue;
                    }
                    return Some((format!(".{k}"), sub, definite));
                }
            }
        }
    }
    None
}
/// A pointer to the variable `name` (`&mut name..`, `is` telling its binding), or one of the
/// `aliases` already found, handed to a method of binding `b` that stores it
/// (`CONTAINER_STORES`: `v.push(&mut x)`, `o.insert(r)`): `b` may hold it, as an alias of no
/// known path (`*`) and the variable's part it points to; or a borrow of it assigned to a field
/// of `b` (`w.slot = &mut x`): at that field.
pub(super) fn lent_into(
    src: &Source,
    b: &Bind,
    name: &str,
    is_var: &dyn Fn(usize) -> bool,
    aliases: &[(Bind, String, String, bool)],
    is: &dyn Fn(usize, &Bind) -> bool,
) -> Option<(String, String, bool)> {
    let s = &src.code;
    let mut i = b.scope.0;
    while i < b.scope.1.min(s.len()) {
        if !kw(s, i, &b.name)
            || !is(i, b)
            || before_blank(s, i).is_some_and(|p| s[p] == '.' || s[p] == ':')
        {
            i += 1;
            continue;
        }
        let dot = skip_blank(s, i + b.name.chars().count());
        i += b.name.chars().count();
        if s.get(dot) != Some(&'.') {
            continue;
        }
        let m = skip_blank(s, dot + 1);
        let method = word_of(s, m);
        let open = skip_blank(s, m + method.chars().count());
        // (or a field of it pointed there: `w.slot = &mut x;`)
        if s.get(open) == Some(&'=') && s.get(open + 1) != Some(&'=') {
            let e = scan_to(s, open + 1, b.scope.1.min(s.len()), |q| s[q] == ';');
            let rhs = skip_blank(s, open + 1);
            if s.get(rhs) == Some(&'&') {
                let k = skip_blank(s, rhs + 1);
                let k = if kw(s, k, "mut") {
                    skip_blank(s, k + 3)
                } else {
                    k
                };
                if k < e && kw(s, k, name) && is_var(k) {
                    let (pl, _) = read_place(s, k);
                    return Some((format!(".{method}"), pl[name.len()..].to_string(), false));
                }
            }
            continue;
        }
        if !CONTAINER_STORES.contains(&method.as_str()) || s.get(open) != Some(&'(') {
            continue;
        }
        let Some(close) = close_of_at(s, open) else {
            continue;
        };
        for k in open + 1..close {
            if !word_start(s, k) || before_blank(s, k).is_some_and(|p| s[p] == '.' || s[p] == ':') {
                continue;
            }
            if kw(s, k, name) && is_var(k) {
                let borrowed = word_before_at(s, k) == "mut"
                    && before_blank(s, k)
                        .and_then(|m| before_blank(s, m + 1 - 3))
                        .is_some_and(|a| s[a] == '&');
                if borrowed {
                    let (pl, _) = read_place(s, k);
                    return Some(("*".into(), pl[name.len()..].to_string(), false));
                }
            }
            if let Some(a) = aliases.iter().find(|a| kw(s, k, &a.0.name) && is(k, &a.0)) {
                return Some(("*".into(), a.2.clone(), false));
            }
        }
    }
    None
}
/// The stores through other bindings of the function that may point to the variable bound by
/// `bd` (or a part of it): `let r = &mut a; *r = v;`, reborrows and copies of such a pointer
/// (`let r1 = &mut *r0;`, `let r2 = r1;`), values holding one (`Holder { r: &mut x }`, `(&mut x,
/// ..)`, `Some(&mut x)`, `[&mut x]`, and the patterns and loops binding what they hold), a
/// pointer the file's function or method returns (`let r = s.slot();`, `let w = wrap(&mut x);`,
/// `*slot_of(&mut s) = v;`), and a field written through a pointer (`r.alg = v`).
/// The file's functions a binding that may hold a pointer to the variable bound by `bd`
/// (`ptr_aliases`) is handed to before the read at `start` (`set1(w)`, `set1(&mut w)`).
pub(super) fn alias_lends<'a>(src: &'a Source, bd: &Bind, start: usize) -> Vec<&'a Item> {
    let s = &src.code;
    let is = |k: usize, b: &Bind| matches!(lookup(src, k, &b.name), Some(Found::Bind(x)) if x.stmt == b.stmt && x.name == b.name);
    let mut out: Vec<&Item> = Vec::new();
    for (b, ..) in ptr_aliases(src, bd, start) {
        let mut i = b.scope.0;
        while i < b.scope.1.min(start).min(s.len()) {
            if !kw(s, i, &b.name) || !is(i, &b) {
                i += 1;
                continue;
            }
            // an argument (`f(w)`, `f(&mut w)`): the bracket it is in
            let mut a = before_blank(s, i);
            if a.is_some_and(|p| s[p] == 't') && word_before_at(s, i) == "mut" {
                a = before_blank(s, i).and_then(|m| before_blank(s, m + 1 - 3));
            }
            if a.is_some_and(|p| s[p] == '&') {
                a = a.and_then(|p| before_blank(s, p));
            }
            let after = skip_blank(s, i + b.name.chars().count());
            if a.is_some_and(|p| matches!(s[p], '(' | ','))
                && matches!(s.get(after), Some(',' | ')'))
            {
                let mut depth = 0;
                let mut j = i;
                let open = loop {
                    if j == 0 {
                        break None;
                    }
                    j -= 1;
                    match s[j] {
                        ')' | ']' | '}' => depth += 1,
                        '(' if depth == 0 => break Some(j),
                        '(' | '[' | '{' => {
                            if depth == 0 {
                                break None;
                            }
                            depth -= 1;
                        }
                        ';' if depth == 0 => break None,
                        _ => {}
                    }
                };
                if let Some(open) = open {
                    let head = word_before_at(s, open);
                    let head_at = open - head.chars().count();
                    if let Some(fi) = free_fn_called(src, head_at, &head, &path_before(s, head_at))
                        && !out.iter().any(|o| o.start == fi.start)
                    {
                        out.push(fi);
                    }
                }
            }
            i += b.name.chars().count();
        }
    }
    out
}
/// The bindings of the function that may hold a pointer to the variable bound by `bd` (or a part
/// of it), as `pointer_stores` finds them: each with the path in it to the pointer, the
/// variable's part it points to, and whether it points there on every way.
pub(super) fn ptr_aliases(
    src: &Source,
    bd: &Bind,
    start: usize,
) -> Vec<(Bind, String, String, bool)> {
    let s = &src.code;
    let Some(f) = src.enclosing(src.pos(start), &[ItemKind::Fn]) else {
        return Vec::new();
    };
    let sc = src.fn_scope(f);
    let is = |k: usize, b: &Bind| matches!(lookup(src, k, &b.name), Some(Found::Bind(x)) if x.stmt == b.stmt && x.name == b.name);
    // (binding, path in it to the pointer, the variable's part it points to, definite)
    let mut aliases: Vec<(Bind, String, String, bool)> = Vec::new();
    // the holder an expression at `e0..e1` of a binding's initializer `x..y` is in: the path to
    // it, and whether the initializer is that holder itself
    let holder = |x: usize, y: usize, e0: usize, e1: usize| -> Option<(String, bool)> {
        let x = skip_blank(s, x);
        let y = before_blank(s, y).map_or(y, |q| q + 1);
        if e0 == x && e1 >= y {
            return Some((String::new(), true));
        }
        // the bracket around it
        let mut depth = 0;
        let mut ob = None;
        let mut k = e0;
        while k > x {
            k -= 1;
            match s[k] {
                ')' | ']' | '}' => depth += 1,
                '(' | '[' | '{' => {
                    if depth == 0 {
                        ob = Some(k);
                        break;
                    }
                    depth -= 1;
                }
                _ => {}
            }
        }
        let ob = ob?;
        let cb = close_of_at(s, ob)?;
        let head = word_before_at(s, ob);
        let whole_from = |from: usize| skip_blank(s, from) == x && cb + 1 >= y;
        let head_at = ob - head.chars().count();
        let head_at =
            before_blank(s, ob).map_or(head_at, |p| p + 1 - head.chars().count().min(p + 1));
        // its element index (top-level commas before it)
        let idx = (ob + 1..e0)
            .filter(|&m| s[m] == ',' && scan_to(s, ob + 1, m + 1, |q| q == m) == m)
            .count();
        match s[ob] {
            '(' if head.is_empty() => Some((format!(".{idx}"), whole_from(ob))),
            '(' if head == "Some" => Some(("?".into(), false)),
            '{' if head.starts_with(char::is_uppercase) => {
                let p = before_blank(s, e0)?;
                if s[p] != ':' {
                    return None;
                }
                let fld = word_before_at(s, p);
                Some((format!(".{fld}"), whole_from(head_at)))
            }
            '[' => Some(("[]".into(), false)),
            '(' => {
                // a call of the file's function returning the pointer
                let fi = free_fn_called(src, head_at, &head, &path_before(s, head_at))?;
                let pn = src.fn_scope(fi).params.get(idx)?.clone();
                let (path, _, def) = returns_part(src, fi, &pn)?;
                Some((path, def && whole_from(head_at)))
            }
            _ => None,
        }
    };
    for _ in 0..12 {
        let mut grew = false;
        for b in &sc.binds {
            if (b.stmt == bd.stmt && b.name == bd.name)
                || aliases
                    .iter()
                    .any(|a| a.0.stmt == b.stmt && a.0.name == b.name)
            {
                continue;
            }
            // (one bound without a value, `let mut v;`, by what is put in it below)
            let (x, y) = b.init.unwrap_or((0, 0));
            let simple = b.kind == BindKind::Let && {
                let p = src.text(b.pat.0, b.pat.1);
                let p = p.split(':').next().unwrap_or("").trim();
                p.trim_start_matches("mut ").trim() == b.name
            };
            let mut found: Option<(String, String, bool)> = None;
            for k in x..y.min(s.len()) {
                if found.is_some() {
                    break;
                }
                // `&mut NAME..`
                if kw(s, k, &bd.name) && is(k, bd) {
                    let (pl, end) = read_place(s, k);
                    let sub = pl[bd.name.len()..].to_string();
                    let borrow = (word_before_at(s, k) == "mut")
                        .then(|| before_blank(s, k).and_then(|m| before_blank(s, m + 1 - 3)))
                        .flatten()
                        .filter(|&a| s[a] == '&');
                    if let Some(a) = borrow {
                        match holder(x, y, a, end) {
                            Some((path, whole)) => {
                                found = Some((path, sub, whole && simple));
                            }
                            None => found = Some(("*".into(), String::new(), false)),
                        }
                    } else if s.get(skip_blank(s, end)) == Some(&'.') {
                        // `NAME.m()`: the file's method returning a borrow of a part of it
                        let m = skip_blank(s, skip_blank(s, end) + 1);
                        let name = word_of(s, m);
                        if s.get(skip_blank(s, m + name.chars().count())) == Some(&'(')
                            && let Some(fi) = method_for(src, &m, &name)
                            && let Some((path, sub2, def)) = returns_part(src, fi, "self")
                        {
                            let c = close_of_at(s, skip_blank(s, m + name.chars().count()));
                            let whole = c.is_some_and(|c| skip_blank(s, c + 1) >= y)
                                && k == skip_blank(s, x);
                            found = Some((path, format!("{sub}{sub2}"), def && whole && simple));
                        }
                    }
                    continue;
                }
                // a pointer already found: a copy, a reborrow, a part of a holder
                if !word_start(s, k)
                    || before_blank(s, k).is_some_and(|p| s[p] == '.' || s[p] == ':')
                {
                    continue;
                }
                let Some(a) = aliases.iter().find(|a| kw(s, k, &a.0.name) && is(k, &a.0)) else {
                    continue;
                };
                let (pl, end) = read_place(s, k);
                let acc = pl[a.0.name.len()..].to_string();
                let rest = if a.1 == "*" {
                    "*".to_string()
                } else if let Some(r) = a.1.strip_prefix(acc.as_str()) {
                    r.to_string()
                } else {
                    continue;
                };
                // (`&mut *r0`, `&mut **r0`, `r0`)
                let mut e0 = k;
                while let Some(p) = before_blank(s, e0).filter(|&p| s[p] == '*') {
                    e0 = p;
                }
                if word_before_at(s, e0) == "mut"
                    && let Some(m) = before_blank(s, e0)
                    && let Some(amp) = before_blank(s, m + 1 - 3).filter(|&q| s[q] == '&')
                {
                    e0 = amp;
                } else if let Some(amp) = before_blank(s, e0).filter(|&q| s[q] == '&') {
                    e0 = amp;
                }
                match holder(x, y, e0, end) {
                    Some((path, whole)) if rest != "*" => {
                        found =
                            Some((format!("{path}{rest}"), a.2.clone(), whole && simple && a.3));
                    }
                    _ => found = Some(("*".into(), a.2.clone(), false)),
                }
            }
            // a container the variable's borrow, or a pointer already found, is put in by one
            // of its methods (`v.push(&mut x)`, `o.insert(&mut x)`, `o.replace(r)`): what it
            // holds, or hands out, may point there
            if found.is_none() {
                found = lent_into(src, b, &bd.name, &|k| is(k, bd), &aliases, &is);
            }
            if let Some((path, sub, def)) = found {
                let path = if simple { path } else { "*".to_string() };
                aliases.push((b.clone(), path, sub, def));
                grew = true;
            }
        }
        if !grew {
            break;
        }
    }
    aliases
}
pub(super) fn pointer_stores(src: &Source, bd: &Bind, start: usize) -> Vec<PtrStore> {
    let s = &src.code;
    if src.enclosing(src.pos(start), &[ItemKind::Fn]).is_none() {
        return Vec::new();
    }
    let is = |k: usize, b: &Bind| matches!(lookup(src, k, &b.name), Some(Found::Bind(x)) if x.stmt == b.stmt && x.name == b.name);
    let aliases = ptr_aliases(src, bd, start);
    let mut out = Vec::new();
    let assign_at = |end: usize| {
        let j = skip_blank(s, end);
        (s.get(j) == Some(&'=') && !matches!(s.get(j + 1), Some('=' | '>'))).then_some(j)
    };
    let stmt_start = |k: usize| before_blank(s, k).is_none_or(|p| matches!(s[p], ';' | '{' | '}'));
    for (b, path, sub, def) in &aliases {
        let mut stores = Vec::new();
        let mut retargeted = false;
        let mut i = b.scope.0;
        while i < b.scope.1.min(s.len()) {
            if !kw(s, i, &b.name) || !is(i, b) {
                i += 1;
                continue;
            }
            let mut st = i;
            let mut derefs = 0;
            while let Some(p) = before_blank(s, st).filter(|&p| s[p] == '*') {
                st = p;
                derefs += 1;
            }
            let (pl, end) = read_place(s, i);
            let acc = pl[b.name.len()..].to_string();
            i = end.max(i + 1);
            if !stmt_start(st) {
                continue;
            }
            let Some(eq) = assign_at(end) else { continue };
            let e = scan_to(s, eq + 1, b.scope.1, |m| s[m] == ';');
            let place = if derefs == 0 && acc.is_empty() {
                retargeted = true;
                continue;
            } else if derefs == 0 && !path.is_empty() && path != "*" && acc == *path {
                // (its pointer field pointed elsewhere: `w.slot = &mut other`)
                retargeted = true;
                continue;
            } else if path == "*" || path.starts_with('?') || path.starts_with("[]") {
                bd.name.clone()
            } else if derefs >= 1 && acc == *path {
                format!("{}{sub}", bd.name)
            } else if derefs == 0 && path.is_empty() && acc.starts_with('.') {
                format!("{}{sub}{acc}", bd.name)
            } else {
                continue;
            };
            stores.push((st, (eq + 1, e), place));
        }
        for (at, value, place) in stores {
            out.push(PtrStore {
                at,
                value,
                place,
                definite: *def && !retargeted && path != "*",
            });
        }
    }
    // `*f(.., &mut v.x, ..) = x;` with the file's `f` returning that borrow
    let (from, to) = bd.scope;
    let mut i = from;
    while i < to.min(s.len()) {
        if s[i] != '*' || !stmt_start(i) {
            i += 1;
            continue;
        }
        let w0 = skip_blank(s, i + 1);
        let mut j = w0;
        while j < to && (is_ident(s[j]) || s[j] == ':') {
            j += 1;
        }
        let name = src.text(w0, j);
        let name = name.rsplit("::").next().unwrap_or("").to_string();
        let open = skip_blank(s, j);
        if s.get(open) != Some(&'(') || name.is_empty() {
            i += 1;
            continue;
        }
        let Some(close) = close_of_at(s, open) else {
            i += 1;
            continue;
        };
        if let Some(eq) = assign_at(close + 1)
            && let Some(fi) =
                free_fn_called(src, w0, &name, &path_before(s, open - name.chars().count()))
        {
            let mut a = open + 1;
            let mut idx = 0;
            while a < close {
                let e2 = scan_to(s, a, close, |m| s[m] == ',');
                let k = skip_blank(s, a);
                let n = if s.get(k) == Some(&'&') {
                    skip_blank(s, k + 1)
                } else {
                    k
                };
                let n = if kw(s, n, "mut") {
                    skip_blank(s, n + 3)
                } else {
                    n
                };
                if kw(s, n, &bd.name)
                    && is(n, bd)
                    && let Some(pn) = src.fn_scope(fi).params.get(idx)
                    && let Some((path, sub, def)) = returns_part(src, fi, pn)
                    && path.is_empty()
                {
                    let (pl, _) = read_place(s, n);
                    let e = scan_to(s, eq + 1, to, |m| s[m] == ';');
                    out.push(PtrStore {
                        at: i,
                        value: (eq + 1, e),
                        place: format!("{pl}{sub}"),
                        definite: def,
                    });
                }
                idx += 1;
                a = e2 + 1;
            }
            i = close + 1;
            continue;
        }
        i += 1;
    }
    out
}
/// After a value at `i`: a `map`, `and_then`, `map_or`, `map_or_else` or `filter_map` whose
/// function (its last argument) ignores the value: a closure whose body names none of its
/// parameters, or a function of the file whose body names no first parameter.
pub(super) fn mapper_drops_value(src: &Source, i: usize) -> bool {
    let s = &src.code;
    let j = skip_blank(s, i);
    if s.get(j) != Some(&'.') {
        return false;
    }
    let k = skip_blank(s, j + 1);
    let name = word_of(s, k);
    if !matches!(
        name.as_str(),
        "map" | "and_then" | "map_or" | "map_or_else" | "filter_map"
    ) {
        return false;
    }
    let o = skip_blank(s, k + name.chars().count());
    let Some(c) = (s.get(o) == Some(&'('))
        .then(|| close_of_at(s, o))
        .flatten()
    else {
        return false;
    };
    let mut last = o + 1;
    let mut x = o + 1;
    while x < c {
        let e = scan_to(s, x, c, |m| s[m] == ',');
        last = x;
        x = e + 1;
    }
    let m = skip_blank(s, last);
    let names_any = |text: &str, ps: &[String]| {
        ps.iter().any(|p| {
            p != "_"
                && Regex::new(&format!(r"\b{}\b", regex::escape(p))).is_ok_and(|r| r.is_match(text))
        })
    };
    if s.get(m) == Some(&'|') {
        let Some((params, (b0, b1))) = closure_parts(s, m, c) else {
            return false;
        };
        let ps = params
            .map(|(a, b)| params_names(s, a, b))
            .unwrap_or_default();
        return !names_any(&src.text(b0, b1), &ps);
    }
    let f = word_of(s, m);
    let mut e = m + f.chars().count();
    let mut last_seg = f;
    while s.get(skip_blank(s, e)) == Some(&':') {
        let q = skip_blank(s, skip_blank(s, e) + 2);
        last_seg = word_of(s, q);
        e = q + last_seg.chars().count();
    }
    if skip_blank(s, e) != c && s.get(skip_blank(s, e)) != Some(&',') {
        return false;
    }
    src.items
        .iter()
        .filter(|it| it.kind == ItemKind::Fn && it.name == last_seg)
        .any(|it| {
            let sig = fn_sig(src, it);
            let (a, b) = src.span(it);
            let body_at = scan_to(s, a, b, |q| s[q] == '{');
            let p = sig
                .params
                .first()
                .map(|p| p.0.trim_start_matches("mut ").trim().to_string());
            match p {
                Some(p) if p != "self" => !names_any(&src.text(body_at, b), &[p]),
                _ => false,
            }
        })
}
/// The `swap`, `take` and `replace` calls the variable bound by `bd` is lent to as `&mut` in its
/// scope (before the read at `start`, or after it in a loop around both: the caller tells),
/// whole (`&mut a`) or a field of it related to the place read (`&mut s.a` for a read of
/// `s.a`, `s`): their argument lists (brackets), names, and where the argument lending it is.
pub(super) fn swaps_of(src: &Source, bd: &Bind, place: &str) -> Vec<(usize, usize, String, usize)> {
    let s = &src.code;
    let mut out = Vec::new();
    // (a variable that is an `Option`: made `None` or `Some(..)`, or annotated so)
    let option_like = bd.init.is_some_and(|(a, b)| {
        let t = src.text(a, b);
        let t = t.trim_start();
        t.starts_with("None") || t.starts_with("Some(")
    }) || src
        .text(bd.stmt.0, bd.init.map_or(bd.stmt.1, |(a, _)| a))
        .contains("Option<");
    for i in bd.scope.0..bd.scope.1.min(s.len()) {
        let lent = || {
            let next = s.get(skip_blank(s, i + bd.name.chars().count()));
            match next {
                Some('[') => false,
                Some('.') => {
                    let p = read_place(s, i).0;
                    p == place
                        || place.starts_with(&format!("{p}."))
                        || p.starts_with(&format!("{place}."))
                }
                _ => true,
            }
        };
        // an `Option` set by its own method (`o.replace(v)`, `o.insert(v)`): `v` replaces what
        // it held, as `mem::replace(&mut o, v)` (the whole argument list is the value)
        if option_like
            && kw(s, i, &bd.name)
            && matches!(lookup(src, i, &bd.name), Some(Found::Bind(b)) if b.stmt == bd.stmt)
            && s.get(skip_blank(s, i + bd.name.chars().count())) == Some(&'.')
        {
            let k = skip_blank(s, skip_blank(s, i + bd.name.chars().count()) + 1);
            let m = word_of(s, k);
            let open = skip_blank(s, k + m.chars().count());
            if matches!(m.as_str(), "replace" | "insert")
                && s.get(open) == Some(&'(')
                && !src
                    .items
                    .iter()
                    .any(|it| it.kind == ItemKind::Fn && it.name == m)
                && let Some(c) = close_of_at(s, open)
                && scan_to(s, open + 1, c, |x| s[x] == ',') >= c
            {
                out.push((open, c, "set".to_string(), i));
            }
        }
        if kw(s, i, &bd.name)
            && matches!(lookup(src, i, &bd.name), Some(Found::Bind(b)) if b.stmt == bd.stmt)
            && word_before_at(s, i) == "mut"
            && before_blank(s, i)
                .and_then(|m| before_blank(s, m + 1 - 3))
                .is_some_and(|a| s[a] == '&')
            && lent()
            && swapping_call(src, i)
        {
            let mut depth = 0;
            let mut j = i;
            while j > 0 {
                j -= 1;
                match s[j] {
                    ')' | ']' | '}' => depth += 1,
                    '(' if depth == 0 => break,
                    '(' | '[' | '{' => depth -= 1,
                    _ => {}
                }
            }
            if let Some(c) = close_of_at(s, j) {
                out.push((j, c, word_before_at(s, j), i));
            }
        }
    }
    out
}
/// Is the argument at `i` passed to `swap`, `take` or `replace` that is not the file's own
/// function (`mem::swap(&mut a, &mut b)`)?
pub(super) fn swapping_call(src: &Source, i: usize) -> bool {
    let s = &src.code;
    let mut depth = 0;
    let mut j = i;
    let open = loop {
        if j == 0 {
            return false;
        }
        j -= 1;
        match s[j] {
            ')' | ']' | '}' => depth += 1,
            '(' if depth == 0 => break j,
            '(' | '[' | '{' => {
                if depth == 0 {
                    return false;
                }
                depth -= 1;
            }
            ';' if depth == 0 => return false,
            _ => {}
        }
    };
    let f = word_before_at(s, open);
    let fb = open - f.chars().count();
    let own = before_blank(s, fb).is_none_or(|p| s[p] != ':' && s[p] != '.')
        && src
            .items
            .iter()
            .any(|x| x.kind == ItemKind::Fn && x.name == f);
    // (another value's `replace` or `take` method, `o.replace(&mut a)`, stores the borrow or
    // hands one back: `a` is not replaced)
    let method = before_blank(s, fb).is_some_and(|p| s[p] == '.');
    matches!(f.as_str(), "swap" | "take" | "replace") && !own && !(method && f != "swap")
}
/// A call before the read at `start`, in a block around it, that replaces the place read on
/// every way through it: of the file's function the variable is passed to by `&mut`
/// (`outer(&mut a7)`), or the file's method called on it (`c4.upgrade()`), whose body assigns
/// that place at its top level (`*slot = ..`, `self.alg = ..`), itself or through such a call,
/// with no `return` or `?` before: where the call is, and the value assigned.
pub(super) fn call_kills(
    src: &Source,
    bd: &Bind,
    start: usize,
    place: &str,
    sc: &FnScope,
) -> Option<(usize, (usize, usize))> {
    let s = &src.code;
    let mut best = None;
    let mut i = bd.scope.0;
    while i < start {
        if !kw(s, i, &bd.name)
            || !matches!(lookup(src, i, &bd.name), Some(Found::Bind(b)) if b.stmt == bd.stmt)
        {
            i += 1;
            continue;
        }
        let arg = read_place(s, i).0;
        // `f(.., &mut v.x, ..)`
        let by_mut = word_before_at(s, i) == "mut"
            && before_blank(s, i)
                .and_then(|m| before_blank(s, m + 1 - 3))
                .is_some_and(|a| s[a] == '&');
        let mut kills: Vec<(String, (usize, usize))> = Vec::new();
        let mut at = i;
        if by_mut {
            // the call it is an argument of
            let mut depth = 0;
            let mut j = i;
            let open = loop {
                if j == 0 {
                    break None;
                }
                j -= 1;
                match s[j] {
                    ')' | ']' | '}' => depth += 1,
                    '(' if depth == 0 => break Some(j),
                    '(' | '[' | '{' => {
                        if depth == 0 {
                            break None;
                        }
                        depth -= 1;
                    }
                    ';' if depth == 0 => break None,
                    _ => {}
                }
            };
            if let Some(open) = open {
                let f = word_before_at(s, open);
                let fb = open - f.len();
                let free = before_blank(s, fb).is_none_or(|p| s[p] != '.');
                let idx = (open + 1..i)
                    .filter(|&k| s[k] == ',' && scan_to(s, open + 1, k + 1, |m| m == k) == k)
                    .count();
                if free && let Some(fi) = free_fn_called(src, fb, &f, &path_before(s, fb)) {
                    let fs = src.fn_scope(fi);
                    if let Some(pn) = fs.params.get(idx) {
                        kills = body_assigns(src, fi, pn, 3)
                            .into_iter()
                            .map(|(sub, v)| (format!("{arg}{sub}"), v))
                            .collect();
                        at = open;
                    }
                }
            }
        } else {
            // `v.m(..)`, a method of the file's taking `self`
            let d = skip_blank(s, i + arg.chars().count());
            let m = skip_blank(s, d + 1);
            let name = word_of(s, m);
            if s.get(d) == Some(&'.')
                && s.get(skip_blank(s, m + name.len())) == Some(&'(')
                && let Some(fi) = method_for(src, &m, &name)
            {
                kills = body_assigns(src, fi, "self", 3)
                    .into_iter()
                    .map(|(sub, v)| (format!("{arg}{sub}"), v))
                    .collect();
                at = m;
            }
        }
        if sc.every_way(s, at, start) {
            for (k, v) in kills {
                if place == k || place.starts_with(&format!("{k}.")) {
                    best = Some((at, v));
                }
            }
        }
        i += bd.name.len();
    }
    best
}
/// What the body of the function `f` assigns through its parameter `param` at its top level,
/// before any `return` or `?`: the place under the parameter (`""` for `*slot = ..`, `.alg` for
/// `self.alg = ..`) and the value, also through the file's functions it passes the parameter
/// to there (`inner(slot)`, `self.set()`).
pub(super) fn body_assigns(
    src: &Source,
    f: &Item,
    param: &str,
    depth: usize,
) -> Vec<(String, (usize, usize))> {
    let s = &src.code;
    let sc = src.fn_scope(f);
    let (b0, b1) = sc.body;
    // a parameter the body points elsewhere (`slot = other;`, `mem::swap(&mut slot, ..)`):
    // what it writes through it is not the caller's place
    let body = src.text(b0, b1);
    if param != "self"
        && Regex::new(&format!(
            r"(?:^|[;{{}}]\s*){p}\s*=[^=]|&\s*mut\s+{p}\b",
            p = regex::escape(param)
        ))
        .is_ok_and(|r| r.is_match(&body))
    {
        return Vec::new();
    }
    // a way out before the end
    let exit = (b0..b1)
        .find(|&k| kw(s, k, "return") || (s[k] == '?' && k > 0 && !s[k - 1].is_whitespace()));
    let mut out = Vec::new();
    // the places under the parameter a local reborrows (`let r = &mut self.alg;`)
    let mut aliases: HashMap<String, String> = HashMap::new();
    let under = |x: &str, aliases: &HashMap<String, String>| -> Option<String> {
        let x = x
            .trim()
            .trim_start_matches("&mut")
            .trim()
            .trim_start_matches('*')
            .trim();
        let (head, rest) = x.split_once('.').map_or((x, ""), |(h, r)| (h, r));
        let rest = if rest.is_empty() {
            String::new()
        } else {
            format!(".{rest}")
        };
        if head == param {
            Some(rest)
        } else {
            aliases.get(head).map(|a| format!("{a}{rest}"))
        }
    };
    let mut k = b0 + 1;
    while k < b1.saturating_sub(1) && exit.is_none_or(|e| k < e) {
        let e = scan_to(s, k, b1 - 1, |m| s[m] == ';');
        let st = skip_blank(s, k);
        let st = if s.get(st) == Some(&'*') {
            skip_blank(s, st + 1)
        } else {
            st
        };
        if exit.is_some_and(|x| x < e) {
            break;
        }
        let stmt = src.text(st, e);
        // `std::mem::replace(slot, v)`
        let replace = re!(r"\bmem\s*::\s*replace\s*\(").find(&stmt).and_then(|m| {
            let open = st + stmt[..m.end()].chars().count() - 1;
            let c = close_of_at(s, open)?;
            let comma = scan_to(s, open + 1, c, |x| s[x] == ',');
            Some((under(&src.text(open + 1, comma), &aliases)?, (comma + 1, c)))
        });
        if let Some(r) = replace {
            out.push(r);
        } else if kw(s, st, "let")
            && let Some(m) = re!(r"^let\s+(?:mut\s+)?(\w+)\s*(?::[^=]*)?=\s*&\s*mut\s+([\w.]+)\s*$")
                .captures(stmt.trim())
            && let Some(sub) = under(&m[2], &aliases)
        {
            aliases.insert(m[1].to_string(), sub);
        } else if let Some(pl) = assigned_place(src, (st, e))
            && let Some(sub) = under(&pl, &aliases)
        {
            let v = scan_to(s, st, e, |m| s[m] == '=') + 1;
            out.push((sub, (v, e)));
        } else if depth > 0 {
            // `g(.., param, ..)`, `self.m(..)`
            let w = word_of(s, st);
            let n = skip_blank(s, st + w.len());
            if kw(s, st, param) && s.get(n) == Some(&'.') {
                let m = skip_blank(s, n + 1);
                let name = word_of(s, m);
                // (the method it calls: the only one of that name, or `self`'s, in the impl
                // around; on a value of a type parameter, several types' may run: not followed)
                let methods: Vec<&Item> = src
                    .items
                    .iter()
                    .filter(|x| {
                        x.kind == ItemKind::Fn
                            && x.name == name
                            && src.fn_scope(x).params.first().is_some_and(|p| p == "self")
                    })
                    .collect();
                let own_impl = src.items.iter().find(|b| {
                    b.kind == ItemKind::Impl && b.contains(f.start) && b.start != f.start
                });
                let g = match methods.as_slice() {
                    [one] => Some(*one),
                    _ if param == "self" => {
                        own_impl.and_then(|b| methods.iter().copied().find(|g| b.contains(g.start)))
                    }
                    _ => None,
                };
                if let Some(g) = g {
                    out.extend(body_assigns(src, g, "self", depth - 1));
                }
            } else if !w.is_empty()
                && s.get(n) == Some(&'(')
                && let Some(c) = close_of_at(s, n)
                && let Some(g) = src
                    .items
                    .iter()
                    .find(|x| x.kind == ItemKind::Fn && x.name == w)
            {
                let mut a = n + 1;
                let mut idx = 0;
                while a < c {
                    let e2 = scan_to(s, a, c, |m| s[m] == ',');
                    let arg = src.text(a, e2);
                    let arg = arg
                        .trim()
                        .trim_start_matches("&mut")
                        .trim()
                        .trim_start_matches('*')
                        .trim();
                    if arg == param
                        && let Some(pn) = src.fn_scope(g).params.get(idx)
                    {
                        out.extend(body_assigns(src, g, pn, depth - 1));
                    }
                    idx += 1;
                    a = e2 + 1;
                }
            }
        }
        k = e + 1;
    }
    out
}
/// The place a read at `start` reads: the variable and the fields and literal indexes after it
/// (`c9.alg`, `t.0`, `v10[0]`), and where it ends.
/// The values the body of the file's function `f` may store through its parameter `param`,
/// anywhere in it (`*slot = v`, `slot.alg = v`, `slot[0] = v`): `None` when the body does more
/// with the parameter than store through it and read what it points to (hands it on, borrows
/// it, calls a method on it, points it elsewhere), where what reaches the caller's place is not
/// read so.
pub(super) fn param_stores(src: &Source, f: &Item, param: &str) -> Option<Vec<(usize, usize)>> {
    let s = &src.code;
    let sc = src.fn_scope(f);
    let (b0, b1) = sc.body;
    let mut out = Vec::new();
    let mut i = b0;
    while i < b1.min(s.len()) {
        if !kw(s, i, param)
            || before_blank(s, i).is_some_and(|p| s[p] == '.' || s[p] == ':')
            || !matches!(lookup(src, i, param), Some(Found::Param(_)))
        {
            i += 1;
            continue;
        }
        let deref = before_blank(s, i).is_some_and(|p| s[p] == '*');
        let (place, end) = read_place(s, i);
        let next = skip_blank(s, end);
        let assign = s.get(next) == Some(&'=') && !matches!(s.get(next + 1), Some('=' | '>'));
        // (a store through it, at a statement's start)
        let at = if deref {
            before_blank(s, i).unwrap_or(i)
        } else {
            i
        };
        let stmt_start = before_blank(s, at).is_none_or(|p| matches!(s[p], ';' | '{' | '}'));
        // (borrowed again, `&mut *p`, `&p.alg`: handed on)
        let borrowed = before_blank(s, at).is_some_and(|p| s[p] == '&')
            || (word_before_at(s, at) == "mut"
                && before_blank(s, at)
                    .and_then(|m| before_blank(s, m + 1 - 3))
                    .is_some_and(|a| s[a] == '&'));
        if borrowed {
            return None;
        }
        if assign && stmt_start && (deref || place != param) {
            let e = scan_to(s, next + 1, b1, |m| s[m] == ';');
            out.push((next + 1, e));
        } else if assign
            || !(deref || place != param)
            || matches!(s.get(next), Some('.' | '['))
            || (place != param && s.get(next) == Some(&'('))
        {
            // pointed elsewhere, handed on whole, a method called on it, an index not read
            return None;
        }
        i = end.max(i + 1);
    }
    Some(out)
}
/// The parameter of the file's function `fi` a variable at `at` is handed to: its argument's
/// (`f(&mut x)`: by the commas before it), or the receiver, `self` (`x.m()`).
pub(super) fn param_at(src: &Source, at: usize, fi: &Item) -> Option<String> {
    let s = &src.code;
    let params = &src.fn_scope(fi).params;
    let after = skip_blank(s, at + word_of(s, at).chars().count());
    if s.get(after) == Some(&'.') {
        return params.first().filter(|p| *p == "self").cloned();
    }
    let mut depth = 0;
    let mut j = at;
    let mut commas = 0;
    while j > 0 {
        j -= 1;
        match s[j] {
            ')' | ']' | '}' => depth += 1,
            '(' if depth == 0 => {
                let f = word_before_at(s, j);
                let fb = j - f.chars().count();
                let method = before_blank(s, fb).is_some_and(|p| s[p] == '.');
                let k = commas + usize::from(method && params.first().is_some_and(|p| p == "self"));
                return params.get(k).cloned();
            }
            '(' | '[' | '{' => depth -= 1,
            ',' if depth == 0 => commas += 1,
            ';' if depth == 0 => return None,
            _ => {}
        }
    }
    None
}
pub(super) fn read_place(s: &[char], start: usize) -> (String, usize) {
    let mut out = word_of(s, start);
    let mut j = start + out.len();
    loop {
        let d = skip_blank(s, j);
        match s.get(d) {
            Some('.') => {
                let f = skip_blank(s, d + 1);
                let w = word_of(s, f);
                if w.is_empty() || s.get(skip_blank(s, f + w.len())) == Some(&'(') {
                    break;
                }
                out.push('.');
                out.push_str(&w);
                j = f + w.len();
            }
            Some('[') => {
                let Some(c) = close_of_at(s, d) else { break };
                let k: String = s[d + 1..c].iter().filter(|c| !c.is_whitespace()).collect();
                if k.is_empty() || !k.chars().all(|c| c.is_ascii_digit()) {
                    break;
                }
                out.push_str(&format!("[{k}]"));
                j = c + 1;
            }
            _ => break,
        }
    }
    (out, j)
}
/// The fields read after a variable or static ending at `end`, past its indexes, as a path
/// (`TABLE[i].h`: `h`; `NESTED.inner.h`: `inner.h`; `TS.1.h`: `1.h`), not a method called.
pub(super) fn field_read(s: &[char], end: usize) -> Option<String> {
    let mut out: Vec<String> = Vec::new();
    let mut j = skip_blank(s, end);
    loop {
        while s.get(j) == Some(&'[') {
            j = skip_blank(s, close_of_at(s, j)? + 1);
        }
        if s.get(j) != Some(&'.') {
            break;
        }
        let f = skip_blank(s, j + 1);
        let w = word_of(s, f);
        let n = skip_blank(s, f + w.chars().count());
        if w.is_empty() || matches!(s.get(n), Some('(' | ':')) {
            break;
        }
        j = n;
        out.push(w);
    }
    (!out.is_empty()).then(|| out.join("."))
}
/// Where a pattern at `a..b` binds `name` in the value it matches, as a path of fields (`(x, _)`:
/// `0`; `[a, b]`: `[1]` for `b`; `Two { h, l }`: `l`; `((x, _), y)`: `0.0` for `x`; `S(a, b)`:
/// `1`); empty for the pattern itself (`x`, `mut x`, `x @ ..`); None where it does not say (a
/// rest `..` before it, an or-pattern).
pub(super) fn pattern_path(s: &[char], a: usize, b: usize, name: &str) -> Option<Vec<String>> {
    let mut a = skip_blank(s, a);
    let mut b = b.min(s.len());
    // (its type annotation: not the pattern's)
    let colon = scan_to(s, a, b, |k| {
        s[k] == ':' && s.get(k + 1) != Some(&':') && (k == 0 || s[k - 1] != ':')
    });
    b = colon.min(b);
    while b > a && s[b - 1].is_whitespace() {
        b -= 1;
    }
    loop {
        if s.get(a) == Some(&'&') {
            a = skip_blank(s, a + 1);
        } else if kw(s, a, "mut") || kw(s, a, "ref") {
            a = skip_blank(s, a + 3);
        } else {
            break;
        }
    }
    if a >= b {
        return None;
    }
    if word_start(s, a) && word_of(s, a) == name {
        let e = skip_blank(s, a + name.chars().count());
        return (e >= b || s.get(e) == Some(&'@')).then(Vec::new);
    }
    let elems_in = |o: usize, c: usize| list_elems(s, o + 1, c);
    let rest_before = |els: &[(usize, usize)], k: usize| {
        els[..k].iter().any(|&(x, y)| src_text_is(s, x, y, ".."))
    };
    let mut head_end = a;
    while head_end < b && (is_ident(s[head_end]) || s[head_end] == ':') {
        head_end += 1;
    }
    let o = skip_blank(s, head_end);
    let c = close_of_at(s, o)?;
    if skip_blank(s, c + 1) < b {
        return None;
    }
    let els = elems_in(o, c);
    for (k, &(x, y)) in els.iter().enumerate() {
        match s[o] {
            '(' | '[' => {
                if let Some(mut p) = pattern_path(s, x, y, name) {
                    // (after a rest `..`: counted from the end, `[_, .., c]`: `[-1]`)
                    let k = if rest_before(&els, k) {
                        if els[k + 1..]
                            .iter()
                            .any(|&(x2, y2)| src_text_is(s, x2, y2, ".."))
                        {
                            return None;
                        }
                        format!("-{}", els.len() - k)
                    } else {
                        k.to_string()
                    };
                    let step = if s[o] == '[' { format!("[{k}]") } else { k };
                    p.insert(0, step);
                    return Some(p);
                }
            }
            '{' => {
                let x0 = skip_blank(s, x);
                let fname = word_of(s, x0);
                let n = skip_blank(s, x0 + fname.chars().count());
                let sub = if s.get(n) == Some(&':') {
                    pattern_path(s, n + 1, y, name)
                } else {
                    pattern_path(s, x, y, name)
                };
                if let Some(mut p) = sub {
                    p.insert(0, fname);
                    return Some(p);
                }
            }
            _ => return None,
        }
    }
    None
}
/// The parts of an expression at `a..b` that give its value, through the `Option` and `Result`
/// combinators a closure decides (`o.map_or(&SHA512, |_| &SHA1)`: the default and the closure's
/// body, not `o`'s value unless the closure reads its parameter; `.map(f)`, `.and_then(f)`,
/// `.map_or_else(d, f)` likewise; `.unwrap_or(d)` adds `d`); the whole where it says no more.
pub(super) fn value_parts(s: &[char], a: usize, b: usize) -> Vec<(usize, usize)> {
    let b = b.min(s.len());
    let mut end = b;
    while end > a && s[end - 1].is_whitespace() {
        end -= 1;
    }
    let mut extra = Vec::new();
    // trailing calls keeping the value (`.unwrap()`, `.copied()`, `?`), or adding one
    loop {
        if end > a && s[end - 1] == '?' {
            end -= 1;
            continue;
        }
        if end == 0 || s[end - 1] != ')' {
            break;
        }
        let Some(o) = open_of_at(s, end - 1) else {
            break;
        };
        let name = word_before_at(s, o);
        let nb = before_blank(s, o).map_or(o, |p| p + 1 - name.chars().count().min(p + 1));
        let Some(dot) = before_blank(s, nb).filter(|&d| s[d] == '.' && d > a) else {
            break;
        };
        match name.as_str() {
            "unwrap" | "expect" | "copied" | "cloned" | "unwrap_or_default" | "as_ref"
            | "as_deref" => end = dot,
            "unwrap_or" | "or" => {
                extra.push((o + 1, end - 1));
                end = dot;
            }
            "unwrap_or_else" | "or_else" => {
                extra.extend(closure_value(s, o + 1, end - 1).unwrap_or(vec![(o + 1, end - 1)]));
                end = dot;
            }
            "map" | "and_then" | "map_or" | "map_or_else" => {
                let args = list_elems(s, o + 1, end - 1);
                let f = args.last().copied();
                let Some(f) = f else { break };
                let Some(body) = closure_value(s, f.0, f.1) else {
                    // a function item: what it makes of the receiver's value
                    return [(a, b)].into_iter().chain(extra).collect();
                };
                let mut out = body;
                if let Some(&d) = args.first().filter(|_| args.len() == 2) {
                    out.extend(closure_value(s, d.0, d.1).unwrap_or(vec![d]));
                }
                // a closure reading its parameter: what it makes of the receiver's value
                if closure_reads_param(s, f.0, f.1) {
                    out.push((a, dot));
                }
                out.extend(extra);
                return out;
            }
            _ => break,
        }
    }
    [(a, b)].into_iter().chain(extra).collect()
}
/// The body of a closure written at `a..b` (`|_| &SHA1`, `|| x`), None for another expression.
pub(super) fn closure_value(s: &[char], a: usize, b: usize) -> Option<Vec<(usize, usize)>> {
    let k = skip_blank(s, a);
    let k = if kw(s, k, "move") {
        skip_blank(s, k + 4)
    } else {
        k
    };
    if !closure_at(s, k) {
        return None;
    }
    let (_, (x, y)) = closure_parts(s, k, b)?;
    Some(vec![(x, y.min(b))])
}
/// Whether the closure written at `a..b` reads one of its parameters in its body.
pub(super) fn closure_reads_param(s: &[char], a: usize, b: usize) -> bool {
    let k = skip_blank(s, a);
    let k = if kw(s, k, "move") {
        skip_blank(s, k + 4)
    } else {
        k
    };
    let Some((Some((pa, pb)), (x, y))) = closure_parts(s, k, b) else {
        return false;
    };
    let names = params_names(s, pa, pb);
    (x..y.min(b)).any(|i| names.iter().any(|n| n != "_" && kw(s, i, n)))
}
/// The top-level elements of a list at `a..b` (between brackets): their extents.
pub(super) fn list_elems(s: &[char], a: usize, b: usize) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut x = a;
    while x < b {
        let e = scan_to(s, x, b, |k| s[k] == ',');
        if s[x..e].iter().any(|c| !c.is_whitespace()) {
            out.push((x, e));
        }
        x = e + 1;
    }
    out
}
/// What the code at `a..b` (an expression, or a static's or const's item) gives the field path
/// `fields` (`h`, `inner.h`, `1`, `0.1`) of the value it makes: the field's value in a struct
/// literal (through `..base`), a tuple literal's element, through each element of an array
/// literal or `vec![..]`, and through a constant or static of the file it names (`[BASE, ..]`,
/// `Outer { inner: BASE }`, `FIX`, `&FIX`); the whole code where it says no more (a call, a
/// `const fn`, another crate's constant); nothing where a literal has no such field. `via`
/// collects the constants and statics passed through.
pub(super) fn project(
    src: &Source,
    a: usize,
    b: usize,
    fields: &[&str],
    depth: usize,
    via: &mut BTreeSet<String>,
) -> Vec<(usize, usize)> {
    let s = &src.code;
    let mut a = skip_blank(s, a);
    let mut b = b.min(s.len());
    if fields.is_empty() || depth == 0 || a >= b {
        return vec![(a, b)];
    }
    // an item: its initializer
    if (kw(s, a, "static") || kw(s, a, "const"))
        && let Some(eq) = let_eq_at(s, a, b)
    {
        a = skip_blank(s, eq + 1);
    }
    while b > a && (s[b - 1].is_whitespace() || s[b - 1] == ';') {
        b -= 1;
    }
    while a < b && s[a] == '&' {
        a = skip_blank(s, a + 1);
        if kw(s, a, "mut") {
            a = skip_blank(s, a + 3);
        }
    }
    if a >= b {
        return Vec::new();
    }
    let (f, rest) = (fields[0], &fields[1..]);
    let index: Option<usize> = f.parse().ok();
    // (an index counted from the end, after a pattern's rest: `-1`)
    let from_end: Option<usize> = f.strip_prefix('-').and_then(|x| x.parse().ok());
    let whole = |o: usize| close_of_at(s, o) == Some(b - 1);
    match s[a] {
        '(' if whole(a) => {
            // (its elements at the top-level commas, a blanked literal's slot kept: `("a", &S1)`)
            let mut elems = Vec::new();
            let mut x = a + 1;
            while x < b - 1 {
                let e = scan_to(s, x, b - 1, |k| s[k] == ',');
                elems.push((x, e));
                x = e + 1;
            }
            let tuple = scan_to(s, a + 1, b - 1, |k| s[k] == ',') < b - 1;
            if !tuple {
                return project(src, a + 1, b - 1, fields, depth - 1, via);
            }
            let index = index.or_else(|| from_end.and_then(|m| elems.len().checked_sub(m)));
            match index.and_then(|k| elems.get(k)) {
                Some(&(x, y)) => project(src, x, y, rest, depth - 1, via),
                None => Vec::new(),
            }
        }
        '[' if whole(a) => {
            let semi = scan_to(s, a + 1, b - 1, |k| s[k] == ';');
            let elems = if semi < b - 1 {
                vec![(a + 1, semi)]
            } else {
                list_elems(s, a + 1, b - 1)
            };
            // a slice pattern's element (`[k]`): that one; a field: each element's
            let pos = f.strip_prefix('[').and_then(|x| x.strip_suffix(']'));
            let k = pos.and_then(|x| x.parse::<usize>().ok()).or_else(|| {
                pos.and_then(|x| x.strip_prefix('-'))
                    .and_then(|x| x.parse::<usize>().ok())
                    .and_then(|m| elems.len().checked_sub(m))
            });
            if let Some(k) = k {
                let el = if semi < b - 1 {
                    elems.first()
                } else {
                    elems.get(k)
                };
                return match el {
                    Some(&(x, y)) => project(src, x, y, rest, depth - 1, via),
                    None => Vec::new(),
                };
            }
            elems
                .into_iter()
                .flat_map(|(x, y)| project(src, x, y, fields, depth - 1, via))
                .collect()
        }
        _ if word_start(s, a) => {
            // a path
            let mut e = a;
            let mut last;
            loop {
                last = word_of(s, e);
                e += last.chars().count();
                let j = skip_blank(s, e);
                if s.get(j) == Some(&':')
                    && s.get(j + 1) == Some(&':')
                    && word_start(s, skip_blank(s, j + 2))
                {
                    e = skip_blank(s, j + 2);
                    continue;
                }
                break;
            }
            let n = skip_blank(s, e);
            // `vec![..]`
            if last == "vec" && s.get(n) == Some(&'!') {
                let o = skip_blank(s, n + 1);
                if s.get(o) == Some(&'[') && whole(o) {
                    return project(src, o, b, fields, depth - 1, via);
                }
                return vec![(a, b)];
            }
            // a constant or static of the file, or an element of one (`TABLE[i]`: each; its
            // iteration, `TABLE.iter()`, a `for` loop's element: each)
            let indexed = s.get(n) == Some(&'[')
                && close_of_at(s, n).is_some_and(|c| skip_blank(s, c + 1) >= b);
            let iterated = s.get(n) == Some(&'.')
                && re!(r"^\.\s*(?:iter|into_iter|iter_mut)\s*\(\s*\)(?:\s*\.\s*(?:copied|cloned)\s*\(\s*\))?$")
                    .is_match(src.text(n, b).trim_end());
            if (n >= b || indexed || iterated)
                && last.chars().next().is_some_and(char::is_uppercase)
                && last
                    .chars()
                    .all(|c| c.is_uppercase() || c.is_ascii_digit() || c == '_')
            {
                let items: Vec<&Item> = src
                    .items
                    .iter()
                    .filter(|it| it.kind == ItemKind::Static && it.name == last)
                    .collect();
                if items.is_empty() {
                    return vec![(a, b)];
                }
                via.insert(last.clone());
                return items
                    .into_iter()
                    .flat_map(|it| {
                        let (x, y) = src.span(it);
                        project(src, x, y, fields, depth - 1, via)
                    })
                    .collect();
            }
            // a variable bound by a `let` of the whole value and not stored into after: its
            // initializer (`let t = (..); let (_, (_, a)) = t;`)
            if n >= b
                && e == a + last.chars().count()
                && last.starts_with(|c: char| c.is_lowercase() || c == '_')
                && let Some(Found::Bind(vb)) = lookup(src, a, &last)
                && vb.kind == BindKind::Let
                && pattern_path(s, vb.pat.0, vb.pat.1, &last).is_some_and(|p| p.is_empty())
                && writes_to(src, &vb).is_empty()
                && let Some((x, y)) = vb.init
            {
                return project(src, x, y, fields, depth - 1, via);
            }
            match s.get(n) {
                // a struct literal: the field's value, or its base's
                Some('{') if whole(n) && index.is_none() => {
                    let mut vals = Vec::new();
                    let mut base = None;
                    for (x, y) in list_elems(s, n + 1, b - 1) {
                        let x = skip_blank(s, x);
                        if s.get(x) == Some(&'.') && s.get(x + 1) == Some(&'.') {
                            base = Some((x + 2, y));
                        } else if kw(s, x, f) {
                            let c = skip_blank(s, x + f.len());
                            if s.get(c) == Some(&':') {
                                vals.push((c + 1, y));
                            } else if c >= y {
                                // shorthand `S { h }`
                                vals.push((x, y));
                            }
                        }
                    }
                    if vals.is_empty()
                        && let Some((x, y)) = base
                    {
                        return project(src, x, y, fields, depth - 1, via);
                    }
                    vals.into_iter()
                        .flat_map(|(x, y)| project(src, x, y, rest, depth - 1, via))
                        .collect()
                }
                // a call of the file's function (`make()`, a `const fn`): what its tail
                // expression gives, where it has no other way out
                Some('(')
                    if whole(n) && last.starts_with(|c: char| c.is_lowercase() || c == '_') =>
                {
                    let Some(f) =
                        free_fn_called(src, a, &last, &path_before(s, e - last.chars().count()))
                    else {
                        return vec![(a, b)];
                    };
                    let (o, c) = src.fn_scope(f).body;
                    if c < o + 2 || (o..c).any(|m| kw(s, m, "return") || s[m] == '?') {
                        return vec![(a, b)];
                    }
                    let mut tail = o + 1;
                    let mut k = o + 1;
                    while k < c - 1 {
                        let e2 = scan_to(s, k, c - 1, |m| s[m] == ';');
                        if e2 >= c - 1 {
                            break;
                        }
                        tail = e2 + 1;
                        k = e2 + 1;
                    }
                    // (a tail that is a parameter, `const fn wrap(c: Cfg) -> Cfg { c }`: the
                    // call's argument for it)
                    let t = src.text(tail, c - 1);
                    let t = t.trim();
                    if !t.is_empty()
                        && t.chars().all(is_ident)
                        && let Some(k) = fn_sig(src, f)
                            .params
                            .iter()
                            .position(|(p, _)| p.trim_start_matches("mut ").trim() == t)
                        && let Some(&(x, y)) = list_elems(s, n + 1, b - 1).get(k)
                    {
                        return project(src, x, y, fields, depth - 1, via);
                    }
                    project(src, tail, c - 1, fields, depth - 1, via)
                }
                // a tuple struct's constructor: its element
                Some('(') if whole(n) && last.starts_with(char::is_uppercase) => {
                    match index.and_then(|k| list_elems(s, n + 1, b - 1).get(k).copied()) {
                        Some((x, y)) => project(src, x, y, rest, depth - 1, via),
                        None => vec![(a, b)],
                    }
                }
                _ => vec![(a, b)],
            }
        }
        _ => vec![(a, b)],
    }
}
/// The place a statement (`writes_to`) assigns (`c9.alg = ..`, `v10[0] = ..`), if it is an
/// assignment.
pub(super) fn assigned_place(src: &Source, w: (usize, usize)) -> Option<String> {
    let s = &src.code;
    let (place, end) = read_place(s, w.0);
    let mut j = skip_blank(s, end);
    // `*v.a_mut() = x`: through the borrow of a field a method of the file returns (`&mut
    // self.a`): that field
    let mut place = place;
    if s.get(j) == Some(&'.') {
        let k = skip_blank(s, j + 1);
        let m = word_of(s, k);
        let o = skip_blank(s, k + m.chars().count());
        let c = (s.get(o) == Some(&'('))
            .then(|| close_of_at(s, o))
            .flatten()?;
        if skip_blank(s, o + 1) != c {
            return None;
        }
        let sub = src
            .items
            .iter()
            .filter(|it| it.kind == ItemKind::Fn && it.name == m)
            .filter_map(|f| returns_part(src, f, "self"))
            .find(|(path, sub, definite)| path.is_empty() && !sub.is_empty() && *definite)?
            .1;
        place.push_str(&sub);
        j = skip_blank(s, c + 1);
    }
    (j < w.1 && s.get(j) == Some(&'=') && !matches!(s.get(j + 1), Some('=' | '>'))).then_some(place)
}
/// For a `match` arm binding a field of a variant (`Pick::A(x) => ..`) of a variable (`match
/// p`): the arguments of that variant's constructions in what the variable holds (`Pick::A(&
/// SHA384)`), where it has some.
pub(super) fn variant_parts(src: &Source, bd: &Bind) -> Option<Vec<(usize, usize)>> {
    if bd.kind != BindKind::Arm {
        return None;
    }
    let s = &src.code;
    let (a, b) = bd.pat;
    let at = (a..b).find(|&i| kw(s, i, &bd.name))?;
    let mut depth = 0;
    let mut j = at;
    let open = loop {
        if j <= a {
            return None;
        }
        j -= 1;
        match s[j] {
            ')' => depth += 1,
            '(' if depth == 0 => break j,
            '(' => depth -= 1,
            _ => {}
        }
    };
    let v = word_before_at(s, open);
    if !v.chars().next()?.is_uppercase() {
        return None;
    }
    let (x, y) = bd.init?;
    let var = src.text(x, y).trim().to_string();
    if var.is_empty() || !var.chars().all(is_ident) {
        return None;
    }
    let k = (x..y).find(|&i| kw(s, i, &var))?;
    let Some(Found::Bind(vb)) = lookup(src, k, &var) else {
        return None;
    };
    let mut texts: Vec<(usize, usize)> = vb.init.into_iter().collect();
    texts.extend(writes_to(src, &vb).into_iter().map(|w| (w.1, w.2)));
    let mut out = Vec::new();
    for (p, q) in texts {
        for i in p..q {
            if kw(s, i, &v) {
                let o = skip_blank(s, i + v.len());
                if s.get(o) == Some(&'(')
                    && let Some(c) = close_of_at(s, o)
                {
                    out.push((o + 1, c));
                }
            }
        }
    }
    (!out.is_empty()).then_some(out)
}
/// Does the variable bound by `bd` hold a cell (`Cell::new(..)`, `RefCell`, `Mutex`, `RwLock`,
/// a once-cell, an atomic; behind an `Rc` or `Arc` too): what it holds changes through shared
/// borrows of it?
pub(super) fn cell_binding(src: &Source, bd: &Bind) -> bool {
    let cell = re!(
        r"\b(?:Cell|RefCell|OnceCell|OnceLock|LazyCell|LazyLock|Mutex|RwLock|UnsafeCell|Atomic\w+)\b"
    );
    let made = re!(
        r"\b(?:Cell|RefCell|OnceCell|OnceLock|Mutex|RwLock|UnsafeCell|Atomic\w+)\s*::\s*(?:new|default)\b"
    );
    bd.init.is_some_and(|(x, y)| made.is_match(&src.text(x, y)))
        || src
            .text(bd.pat.0, bd.pat.1)
            .split_once(':')
            .is_some_and(|(_, t)| cell.is_match(t))
}
/// A store at `i` (the cell variable's name) replacing what a cell holds: `c.set(v)`,
/// `c.replace(v)` (also inside an expression, `let old = c.replace(v)`), a statement `*c.
/// borrow_mut() = v`, `*m.lock().unwrap() = v`, `*l.write().unwrap() = v`, `*c.get_mut() = v`:
/// where the value is.
pub(super) fn cell_set(src: &Source, bd: &Bind, i: usize) -> Option<(usize, usize)> {
    let s = &src.code;
    let end = i + bd.name.chars().count();
    let deref = before_blank(s, i).is_some_and(|p| s[p] == '*');
    if !deref {
        let d = skip_blank(s, end);
        let m = skip_blank(s, d + 1);
        let name = word_of(s, m);
        let open = skip_blank(s, m + name.chars().count());
        if s.get(d) != Some(&'.') || !matches!(name.as_str(), "set" | "replace") {
            return None;
        }
        let close = close_of_at(s, open)?;
        return Some((open + 1, close));
    }
    let at = before_blank(s, i)?;
    if !before_blank(s, at).is_none_or(|p| matches!(s[p], ';' | '{' | '}')) {
        return None;
    }
    let e = scan_to(s, i, s.len(), |k| s[k] == ';');
    let stmt = src.text(end, e);
    let stmt = stmt.trim();
    re!(r"^\.\s*(?:borrow_mut\s*\(\s*\)|get_mut\s*\(\s*\)|(?:lock|write)\s*\(\s*\)\s*\.\s*(?:unwrap\s*\(\s*\)|expect\s*\([^)]*\)))\s*=[^=]")
        .is_match(stmt)
        .then(|| {
            let eq = scan_to(s, i, e, |k| s[k] == '=');
            (eq + 1, e)
        })
}
/// The stores into the cell variable bound by `bd` before `start` (`cell_set`): where each is,
/// and its value.
pub(super) fn cell_stores(src: &Source, bd: &Bind, start: usize) -> Vec<(usize, (usize, usize))> {
    let s = &src.code;
    let mut out = Vec::new();
    let mut i = bd.scope.0;
    while i < start.min(s.len()) {
        if kw(s, i, &bd.name)
            && !before_blank(s, i).is_some_and(|p| s[p] == '.' || s[p] == ':')
            && matches!(lookup(src, i, &bd.name), Some(Found::Bind(b)) if b.stmt == bd.stmt)
            && let Some(v) = cell_set(src, bd, i)
        {
            out.push((i, v));
        }
        i += 1;
    }
    out
}
/// Is the cell variable bound by `bd` written before `start` in a way the stores read do not
/// say: a method that may write it (not one that reads it: `get`, `borrow`, `read`, `load`,
/// `clone`, nor a `cell_set`), a guard taken and kept (`let g = m.lock()..`), a shared borrow of
/// it handed on (`set(&c)`)?
pub(super) fn cell_lent(src: &Source, bd: &Bind, start: usize) -> bool {
    let s = &src.code;
    let mut i = bd.scope.0;
    while i < start.min(s.len()) {
        if !kw(s, i, &bd.name)
            || before_blank(s, i).is_some_and(|p| s[p] == '.' || s[p] == ':')
            || !matches!(lookup(src, i, &bd.name), Some(Found::Bind(b)) if b.stmt == bd.stmt)
        {
            i += 1;
            continue;
        }
        let end = i + bd.name.chars().count();
        let next = skip_blank(s, end);
        if cell_set(src, bd, i).is_some() {
            i = end;
            continue;
        }
        if s.get(next) == Some(&'.') {
            let m = skip_blank(s, next + 1);
            let name = word_of(s, m);
            let reads = [
                "get",
                "borrow",
                "try_borrow",
                "read",
                "load",
                "clone",
                "get_ref",
            ];
            // (a guard only read through, `*m.lock().unwrap()` in an expression)
            let read_through = before_blank(s, i).is_some_and(|p| s[p] == '*')
                && !src
                    .text(m, scan_to(s, m, s.len(), |k| s[k] == ';'))
                    .contains(" = ");
            if !reads.contains(&name.as_str()) && !read_through {
                return true;
            }
        } else if before_blank(s, i).is_some_and(|p| s[p] == '&') {
            return true;
        }
        i = end;
    }
    false
}
/// Is the store at `i` a closure's body without braces (`|_| v = ..`)? It runs if and when the
/// closure does: it replaces nothing on the way to a read.
pub(super) fn closure_store(s: &[char], i: usize) -> bool {
    let mut p = before_blank(s, i);
    if p.is_some_and(|p| s[p] == '*') {
        p = before_blank(s, p.unwrap_or(0));
    }
    p.is_some_and(|p| s[p] == '|')
}
/// The statements of its scope that store into a variable: those that start with it
/// (`v = ..;`, `v.f = ..;`, `*v = ..;`, `m.insert(k, ..);`, `m.entry(k).or_insert(..);`), or
/// a closure's body without braces (`|_| v = ..`, run when the closure is: `closure_store`), the
/// variable read there being this binding: where each starts, where what it stores starts
/// (the value assigned, the method's arguments), and its end.
pub(super) fn writes_to(src: &Source, bd: &Bind) -> Vec<(usize, usize, usize)> {
    let s = &src.code;
    let mut out = Vec::new();
    let (from, to) = bd.scope;
    let mut i = from;
    while i < to.min(s.len()) {
        if !kw(s, i, &bd.name) {
            i += 1;
            continue;
        }
        let mut p = before_blank(s, i);
        if p.is_some_and(|p| s[p] == '*') {
            p = before_blank(s, p.unwrap_or(0));
        }
        let starts = p.is_none_or(|p| matches!(s[p], ';' | '{' | '}' | '|'));
        if starts && matches!(lookup(src, i, &bd.name), Some(Found::Bind(b)) if b.stmt == bd.stmt) {
            let e = scan_to(s, i, to, |k| s[k] == ';');
            // what it stores: an assignment's value, a method's arguments
            let from = match assigned_place(src, (i, e)) {
                Some(_) => scan_to(s, i, e, |k| s[k] == '=') + 1,
                None => i + bd.name.len(),
            };
            out.push((i, from, e));
            i = e.max(i + 1);
            continue;
        }
        i += bd.name.len();
    }
    // `*f(.., &mut v, ..) = x;`: a store through the borrow a call returns, which may be `v`
    let lent = Regex::new(&format!(r"&\s*mut\s+{}\b", regex::escape(&bd.name))).ok();
    let mut i = from;
    while i < to.min(s.len()) {
        if s[i] != '*' || !before_blank(s, i).is_none_or(|p| matches!(s[p], ';' | '{' | '}')) {
            i += 1;
            continue;
        }
        let mut j = skip_blank(s, i + 1);
        while j < to && (is_ident(s[j]) || s[j] == ':') {
            j += 1;
        }
        j = skip_blank(s, j);
        if s.get(j) == Some(&'<') {
            let cls = vec![Class::Code; s.len() - j];
            match skip_angle(&s[j..], &cls, 0) {
                Some(e) => j = skip_blank(s, j + e),
                None => {
                    i += 1;
                    continue;
                }
            }
        }
        if s.get(j) != Some(&'(') {
            i += 1;
            continue;
        }
        let Some(close) = close_of_at(s, j) else {
            i += 1;
            continue;
        };
        let eq = skip_blank(s, close + 1);
        if s.get(eq) == Some(&'=')
            && s.get(eq + 1) != Some(&'=')
            && lent
                .as_ref()
                .is_some_and(|r| r.is_match(&src.text(j, close)))
        {
            let e = scan_to(s, eq, to, |k| s[k] == ';');
            out.push((i, eq + 1, e));
            i = e.max(i + 1);
            continue;
        }
        i += 1;
    }
    out.sort();
    out
}
