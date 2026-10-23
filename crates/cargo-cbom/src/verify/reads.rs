//! What the code a call reads names: its arguments, the variables, stores and constants they read.

use super::*;

/// What the call at `p` reads: its callee (a path, or an expression through a pointer), its
/// arguments and its receiver, followed through variables, statics and the file's functions
/// (`names_read`); `None` when no call starts there. `strict`, `smashed`: see `Reads`.
pub(super) fn call_reads(
    src: &Source,
    kb: &Kb,
    p: usize,
    (strict, smashed): (bool, bool),
    inst: &[(String, String)],
    alg: Option<usize>,
) -> Option<Reads> {
    let s = &src.code;
    let mut seen = HashSet::new();
    let mut call = Reads {
        strict,
        smashed,
        inst: inst.to_vec(),
        ..Reads::default()
    };
    // the call: its callee (a path, or an expression through a pointer: `(h.f)`, `FNS[i]`,
    // `get()`), then its arguments; the receiver of a method
    let mut j = p;
    let mut groups = Vec::new();
    loop {
        j = skip_blank(s, j);
        if word_start(s, j) {
            j += word_of(s, j).len();
        } else if s.get(j) == Some(&':') && s.get(j + 1) == Some(&':') {
            j += 2;
        } else if s.get(j) == Some(&'<') && groups.is_empty() {
            let cls = vec![Class::Code; s.len() - j];
            match skip_angle(&s[j..], &cls, 0) {
                Some(e) => j += e,
                None => break,
            }
        } else if matches!(s.get(j), Some('(' | '[')) || (s.get(j) == Some(&'*') && j == p) {
            if s[j] == '*' {
                j += 1;
                continue;
            }
            let Some(c) = close_of_at(s, j) else { break };
            groups.push((j, c));
            j = c + 1;
        } else {
            break;
        }
    }
    if !groups.iter().any(|&(o, _)| s[o] == '(') {
        return None;
    }
    let receiver = before_blank(s, p)
        .filter(|&d| s[d] == '.')
        .and_then(|dot| receiver_at(s, dot).map(|(r, _, _)| (r, dot)));
    // the argument that carries the algorithm (`alg`, the knowledge base's: the receiver is 0 of
    // a method): only that one is read, beside the callee's own groups (`FNS[i]`), where the
    // call has it; the data argument is no value of the algorithm
    let args = groups.iter().rev().find(|&&(o, _)| s[o] == '(').copied();
    let target: Option<Option<(usize, usize)>> = match (alg, receiver, args) {
        (Some(0), Some(_), _) => Some(None),
        (Some(k), Some(_), Some((o, c))) => list_elems(s, o + 1, c).get(k - 1).map(|&a| Some(a)),
        (Some(k), None, Some((o, c))) => list_elems(s, o + 1, c).get(k).map(|&a| Some(a)),
        _ => None,
    };
    match target {
        Some(arg) => {
            for &(o, c) in groups.iter().filter(|&&g| Some(g) != args) {
                names_read(src, kb, o + 1, c, 4, &mut seen, &mut call, true);
            }
            match (arg, receiver) {
                (Some((x, y)), _) => {
                    for (x, y) in value_parts(s, x, y) {
                        names_read(src, kb, x, y, 4, &mut seen, &mut call, true);
                    }
                }
                (None, Some((r, dot))) => {
                    names_read(src, kb, r, dot, 4, &mut seen, &mut call, true)
                }
                (None, None) => {}
            }
        }
        None => {
            for &(o, c) in &groups {
                names_read(src, kb, o + 1, c, 4, &mut seen, &mut call, true);
            }
            if let Some((r, dot)) = receiver {
                names_read(src, kb, r, dot, 4, &mut seen, &mut call, true);
            }
        }
    }
    Some(call)
}
/// The value argument of a call of `symbol` that carries the algorithm, from the knowledge
/// base's operation the symbol is (`ring::digest::digest`: 0; the receiver is 0 of a method);
/// None for another call, or an algorithm that is the call's type.
pub(super) fn alg_arg(kb: &Kb, symbol: &str) -> Option<usize> {
    let sym = strip_generics(symbol);
    let (krate, rest) = sym.split_once("::")?;
    kb.operations
        .iter()
        .find(|e| e.krates.iter().any(|k| k == krate) && e.pattern.is_match(rest) && !e.self_type)
        .map(|e| e.algorithm)
}
/// Follows what the code at `a..b` reads (`depth` steps): the upper-case names it writes, the
/// statics and consts it names (their initializers), the file's functions it calls (their
/// bodies: a `const fn`'s value), the variables it reads (their initializers, scrutinees or
/// iterators, and the statements of the function that store into them: `v = ..`, `v.f = ..`,
/// `m.insert(..)`). With `own`, the code is the function's own: a parameter it reads is a value
/// from elsewhere (`open`).
#[allow(clippy::too_many_arguments)]
pub(super) fn names_read(
    src: &Source,
    kb: &Kb,
    a: usize,
    b: usize,
    depth: usize,
    seen: &mut Seen,
    r: &mut Reads,
    own: bool,
) {
    let s = &src.code;
    let mut i = a;
    while i < b.min(s.len()) {
        // an index picks an element (`TABLE[i]`): it is no value read
        if s[i] == '['
            && before_blank(s, i)
                .is_some_and(|p| p >= a && (is_ident(s[p]) || matches!(s[p], ')' | ']')))
            && let Some(c) = close_of_at(s, i)
        {
            i = c + 1;
            continue;
        }
        if !word_start(s, i) {
            i += 1;
            continue;
        }
        let start = i;
        let w = word_of(s, i);
        i += w.len();
        let prev = before_blank(s, start);
        // (`..BASE`, a struct update or a range: no field)
        let after_dot = prev.is_some_and(|p| s[p] == '.' && !(p > 0 && s[p - 1] == '.'));
        let after_colons = prev.is_some_and(|p| s[p] == ':' && p > 0 && s[p - 1] == ':');
        let n = skip_blank(s, i);
        let path_head = s.get(n) == Some(&':') && s.get(n + 1) == Some(&':');
        let call =
            s.get(n) == Some(&'(') || (path_head && s.get(skip_blank(s, n + 2)) == Some(&'<'));
        if call
            && !after_dot
            && matches!(w.as_str(), "replace" | "take" | "swap")
            && !src
                .items
                .iter()
                .any(|it| it.kind == ItemKind::Fn && it.name == w)
            && let Some(close) = close_of_at(s, n)
        {
            // `mem::replace(&mut x, v)`, `mem::take(&mut x)`: x's value before; `swap`: none
            if w != "swap" {
                let comma = scan_to(s, n + 1, close, |k| s[k] == ',');
                names_read(src, kb, n + 1, comma, depth, seen, r, own);
            }
            i = close + 1;
            continue;
        }
        if after_dot
            && call
            && depth > 0
            && src
                .items
                .iter()
                .any(|it| it.kind == ItemKind::Fn && it.name == w)
        {
            // a method of the file's (`q.pick()` on a `Plain`): what its body names; on a
            // value whose type the code does not say, or whose method another crate gives
            // (a trait's default body), what it returns is not read
            match exact_method(src, &start, &w) {
                Some(f) => {
                    let (fa, fb) = src.span(f);
                    let fa = scan_to(s, fa, fb, |k| s[k] == '{');
                    if seen.insert((fa, fb, String::new())) {
                        names_read(src, kb, fa, fb, depth - 1, seen, r, false);
                    }
                }
                None => r.lent = true,
            }
            continue;
        }
        // `o.replace(v)`, `c.replace(v)`, `o.take()` of the standard library: the value the place
        // held before, the receiver's, not the argument
        if after_dot
            && call
            && matches!(w.as_str(), "replace" | "take")
            && !src
                .items
                .iter()
                .any(|it| it.kind == ItemKind::Fn && it.name == w)
            && let Some(close) = close_of_at(s, n)
        {
            i = close + 1;
            continue;
        }
        if after_dot || s.get(n) == Some(&'!') {
            // a field or a method, a macro
            continue;
        }
        // `T::ALG` in an instance whose `T` is known: that type's `ALG`
        if path_head
            && !after_colons
            && let Some((_, ty)) = r.inst.iter().find(|(p, _)| *p == w).cloned()
        {
            let k = skip_blank(s, n + 2);
            let item = word_of(s, k);
            if item.starts_with(char::is_uppercase)
                && s.get(skip_blank(s, k + item.chars().count())) != Some(&'(')
            {
                if !r.assoc.contains(&(ty.clone(), item.clone())) {
                    r.assoc.push((ty, item.clone()));
                }
                i = k + item.chars().count();
            }
            continue;
        }
        let first = w.chars().next().unwrap_or('_');
        let upper = first.is_uppercase()
            && w.chars()
                .all(|c| c.is_uppercase() || c.is_ascii_digit() || c == '_');
        if first.is_uppercase() && !upper {
            r.types.insert(w);
            // a method named as a value (`o.map(Pick::alg)`): what the file's methods of that
            // name return (the implementation the value's type picks is one of them)
            let k = skip_blank(s, n + 2);
            let m = word_of(s, k);
            let after = skip_blank(s, k + m.chars().count());
            if path_head
                && !call
                && m.starts_with(|c: char| c.is_lowercase())
                && !matches!(s.get(after), Some('(' | ':'))
            {
                for f in src
                    .items
                    .iter()
                    .filter(|it| it.kind == ItemKind::Fn && it.name == m)
                {
                    let sp = src.span(f);
                    if depth > 0 && seen.insert((sp.0, sp.1, String::new())) {
                        names_read(src, kb, sp.0, sp.1, depth - 1, seen, r, false);
                    }
                }
                i = k + m.chars().count();
            }
            continue;
        }
        if upper {
            // (`D::digest`: a type parameter's path)
            if path_head {
                continue;
            }
            // an import alias: its item
            let w0 = w.clone();
            let item = src
                .binds
                .iter()
                .find(|bd| bd.name == w)
                .and_then(|bd| bd.path.last().cloned())
                .unwrap_or(w);
            // (a definition's own name, `const X: ..`, `static mut X`, is no read of it)
            let before = word_before_at(s, start);
            if matches!(before.as_str(), "const" | "static")
                || (matches!(before.as_str(), "mut" | "ref")
                    && before_blank(s, start)
                        .is_some_and(|p| word_before_at(s, p + 1 - before.len()) == "static"))
            {
                continue;
            }
            let mut statics: Vec<&Item> = src
                .items
                .iter()
                .filter(|it| it.kind == ItemKind::Static && it.name == item)
                .collect();
            // of several of that name in the file's modules, those of the module the path
            // written (or the import) leads to from the read's (`twin::CALG` beside `CALG`)
            if statics.len() > 1 {
                let here = modules_at(src, src.pos(start));
                let prefix = match src.binds.iter().find(|bd| bd.name == w0) {
                    Some(bd) => bd.path[..bd.path.len().saturating_sub(1)].to_vec(),
                    None => path_before(s, start),
                };
                let want: Option<Vec<String>> = match prefix.first().map(String::as_str) {
                    Some("crate" | "$crate") => None,
                    Some("self") => Some(here.iter().chain(&prefix[1..]).cloned().collect()),
                    Some("super") => {
                        let k = prefix.iter().take_while(|g| *g == "super").count();
                        Some(
                            here[..here.len().saturating_sub(k)]
                                .iter()
                                .chain(&prefix[k..])
                                .cloned()
                                .collect(),
                        )
                    }
                    _ => Some(here.iter().chain(&prefix).cloned().collect()),
                };
                if let Some(want) = want {
                    let pick: Vec<&Item> = statics
                        .iter()
                        .copied()
                        .filter(|it| modules_at(src, it.start) == want)
                        .collect();
                    if !pick.is_empty() {
                        statics = pick;
                    }
                }
            }
            if !statics.is_empty() {
                // a field of its elements (`TABLE[i].h`): the values its literals give it
                let field = field_read(s, i);
                r.fields |= field.is_some();
                for it in statics {
                    let sp = src.span(it);
                    let key = (sp.0, sp.1, field.clone().unwrap_or_default());
                    if depth > 0 && seen.insert(key) {
                        let parts = field
                            .as_deref()
                            .map(|f| {
                                project(
                                    src,
                                    sp.0,
                                    sp.1,
                                    &f.split('.').collect::<Vec<_>>(),
                                    8,
                                    &mut r.names,
                                )
                            })
                            .unwrap_or(vec![sp]);

                        for (x, y) in parts {
                            names_read(src, kb, x, y, depth - 1, seen, r, false);
                        }
                    }
                }
            } else if src.locals.contains(&item)
                || (item.chars().count() == 1
                    && path_before(s, start).is_empty()
                    && !src.binds.iter().any(|bd| bd.name == w0 || bd.name == "*"))
            {
                // a type parameter (`h::<T>`: one letter, not a path's, imported by no `use`), a
                // type of the file (`struct S1;`)
                r.types.insert(item);
                continue;
            } else if !kb.statics.iter().any(|e| e.pattern.is_match(&item)) {
                r.foreign = true;
                let prefix = match src.binds.iter().find(|bd| bd.name == w0) {
                    Some(bd) => bd.path[..bd.path.len().saturating_sub(1)].to_vec(),
                    None => path_before(s, start),
                };
                let key = (prefix, item.clone(), field_read(s, i));
                if !r.foreign_items.contains(&key) {
                    r.foreign_items.push(key);
                }
            }
            r.names.insert(item);
            continue;
        }
        // (a generic function named with its arguments, `pick::<Fast>`, is no module path)
        let turbofish = path_head && s.get(skip_blank(s, n + 2)) == Some(&'<');
        if after_colons
            || (path_head && !turbofish)
            || is_keyword(&w)
            || !(first.is_lowercase() || first == '_')
        {
            continue;
        }
        // a variable whose value a combinator's function ignores (`o.map(fixed)` with `fixed`
        // naming no parameter, `o.map(|_| X)`): the result is not its value
        if !call && mapper_drops_value(src, i) {
            continue;
        }
        let found = lookup(src, start, &w);
        // (a function item passed as a value, `o.map(fixed)`: what it returns, as a call)
        let fn_item = !call
            && found.is_none()
            && src
                .items
                .iter()
                .any(|it| it.kind == ItemKind::Fn && it.name == w);
        if (call && !matches!(found, Some(Found::Bind(_)))) || fn_item {
            // the file's function: what its body names
            for f in src
                .items
                .iter()
                .filter(|it| it.kind == ItemKind::Fn && it.name == w)
            {
                let sp = src.span(f);
                if depth > 0 && seen.insert((sp.0, sp.1, String::new())) {
                    names_read(src, kb, sp.0, sp.1, depth - 1, seen, r, false);
                }
            }
            continue;
        }
        match found {
            Some(Found::Bind(bd)) if bd.kind == BindKind::Closure => r.open |= own,
            Some(Found::Bind(bd)) => {
                if depth == 0 {
                    continue;
                }
                // the stores that may reach the read: before it, or in a loop around both; one
                // into the place read, in a block around the read, replaces what was there
                let sc = src
                    .enclosing(src.pos(start), &[ItemKind::Fn])
                    .map(|f| src.fn_scope(f));
                let place = read_place(s, start).0;
                let field = field_read(s, i);
                // (or a part a pattern binds of a struct or a variant, `let E::V(a) = e`, `if let
                // S { a, .. } = s`: a field of it)
                let head = src.text(bd.stmt.0, bd.stmt.1);
                let head = head.split('=').next().unwrap_or("");
                let part = re!(r"[A-Za-z_]\w*\s*[({]").is_match(head);
                r.fields |= field.is_some() || (bd.kind != BindKind::Closure && part);
                let in_loop = |w: usize| {
                    sc.as_ref().is_some_and(|sc| {
                        sc.loops
                            .iter()
                            .any(|&(o, c)| o <= w && w < c && o <= start && start < c)
                    })
                };
                // (not the store whose value the read is in: `z = if c { &SHA1 } else { z };`
                // reads the value before)
                let writes: Vec<(usize, usize, usize)> = writes_to(src, &bd)
                    .into_iter()
                    .filter(|w| (w.0 < start || in_loop(w.0)) && !(w.0 <= start && start < w.2))
                    .collect();
                // (a cell: what it holds is replaced by `c.set(v)`, `*c.borrow_mut() = v`, ..;
                // written otherwise, or lent, it holds what code not read put there)
                let cell = cell_binding(src, &bd);
                if cell && cell_lent(src, &bd, start) {
                    r.lent = true;
                }
                let cell_sets: Vec<(usize, (usize, usize))> = if cell {
                    cell_stores(src, &bd, start)
                } else {
                    Vec::new()
                };
                // (one replaces what the cell held for a claim that the values are all, as a
                // store through a pointer does; else the value before may be read beside it)
                let cell_dom = cell_sets
                    .iter()
                    .filter(|c| {
                        r.strict
                            && place == bd.name
                            && sc.as_ref().is_some_and(|sc| sc.every_way(s, c.0, start))
                    })
                    .max()
                    .copied();
                let dom = writes
                    .iter()
                    .filter(|w| {
                        w.0 < start
                            && !closure_store(s, w.0)
                            && (assigned_place(src, (w.0, w.2)).is_some_and(|a| {
                                (place == a
                                    || place.starts_with(&format!("{a}."))
                                    || place.starts_with(&format!("{a}[")))
                                    // (an element's store, for a container's elements: R4.3)
                                    && !(r.smashed && a.contains('['))
                            }))
                            && sc.as_ref().is_some_and(|sc| sc.every_way(s, w.0, start))
                    })
                    .map(|w| (w.0, (w.1, w.2)))
                    .max();
                let dom = match cell_dom {
                    Some(c) if dom.is_none_or(|d| c.0 > d.0) => Some(c),
                    _ => dom,
                };
                // (the cell's other stores before the read: values it may hold)
                for (at, (x, y)) in &cell_sets {
                    if dom.is_none_or(|d| *at > d.0) && seen.insert((*x, *y, String::new())) {
                        names_read(src, kb, *x, *y, depth - 1, seen, r, own);
                    }
                }
                // or a call of the file's function that replaces it on every way through it
                let dom = match sc
                    .as_ref()
                    .and_then(|sc| call_kills(src, &bd, start, &place, sc))
                {
                    Some(k) if dom.is_none_or(|d| k.0 > d.0) => Some(k),
                    _ => dom,
                };
                let around = |o: usize| sc.as_ref().is_some_and(|sc| sc.every_way(s, o, start));
                // stores through another binding pointing to it (`let r = &mut a; *r = v;`):
                // of the place read or of what holds it; one on every way to the read replaces
                // it for a claim that the values are all (`strict`), else it may or may not
                let pstores: Vec<PtrStore> = pointer_stores(src, &bd, start)
                    .into_iter()
                    .filter(|p| {
                        (p.at < start || in_loop(p.at))
                            && (place == p.place
                                || place.starts_with(&format!("{}.", p.place))
                                || place.starts_with(&format!("{}[", p.place))
                                || p.place.starts_with(&format!("{place}.")))
                    })
                    .collect();
                let pdom = pstores
                    .iter()
                    .filter(|p| {
                        r.strict
                            && p.definite
                            && p.at < start
                            && around(p.at)
                            && !p.place.starts_with(&format!("{place}."))
                            && dom.is_none_or(|d| p.at > d.0)
                    })
                    .max_by_key(|p| p.at)
                    .map(|p| (p.at, p.value));
                let dom = pdom.or(dom);
                // lent whole as `&mut` to `mem::swap(&mut a, &mut b)` or `mem::replace(&mut a,
                // v)`: it may hold what the call's other arguments hold; to `mem::take`, a
                // default not read
                // (the last such call in a block around the read replaces it: after it, the
                // variable holds the other argument's value, or the default)
                // (not the call the read is an argument of)
                let swaps: Vec<(usize, usize, String, usize)> = swaps_of(src, &bd, &place)
                    .into_iter()
                    .filter(|&(o, c, _, _)| !(o < start && start < c))
                    .collect();
                // (one lending a field replaces only a read of that field: `mem::swap(&mut s.a,
                // &mut s.b)` for `s.a`)
                let whole_or_same = |at: usize| {
                    read_place(s, at).0 == place
                        || !matches!(
                            s.get(skip_blank(s, at + bd.name.chars().count())),
                            Some('.')
                        )
                };
                let swap = swaps
                    .iter()
                    .rev()
                    .find(|&&(o, _, _, at)| {
                        o < start && dom.is_none_or(|d| o > d.0) && around(o) && whole_or_same(at)
                    })
                    .cloned();
                // the other argument: `swap`'s other place, `replace`'s value, an `Option`'s
                // own `replace`'s or `insert`'s argument
                let other = |o: usize, c: usize, f: &str, at: usize| {
                    if f == "set" {
                        return (o + 1, c);
                    }
                    let comma = scan_to(s, o + 1, c, |k| s[k] == ',');
                    if f == "replace" || at < comma {
                        (comma + 1, c)
                    } else {
                        (o + 1, comma)
                    }
                };
                if let Some((o, c, f, at)) = &swap {
                    match f.as_str() {
                        "take" => {
                            r.open |= own;
                            r.replaced |= own;
                        }
                        _ => {
                            let (x, y) = other(*o, *c, f, *at);
                            names_read(src, kb, x, y, depth - 1, seen, r, own);
                        }
                    }
                }
                // one that may or may not run on the way to the read (in an `if`, in a loop
                // around the read, after the one that replaces it): it may hold the other
                // argument's value too, beside its own
                for (o, c, f, at) in &swaps {
                    if swap.as_ref().is_some_and(|w| w.0 >= *o) || dom.is_some_and(|d| d.0 > *o) {
                        continue;
                    }
                    if !(*o < start || in_loop(*o)) || f == "take" {
                        continue;
                    }
                    let (x, y) = other(*o, *c, f, *at);
                    names_read(src, kb, x, y, depth - 1, seen, r, own);
                    r.replaced |= own;
                }
                let dom = match &swap {
                    Some((o, _, _, _)) => Some((*o, (*o, *o))),
                    None => dom,
                };
                // (per name bound: `let (p, q) = pair;` binds two parts of one statement)
                if !seen.insert((
                    bd.stmt.0,
                    dom.map_or(bd.stmt.1, |d| d.0),
                    format!("{}@{}", field.clone().unwrap_or_default(), bd.name),
                )) {
                    continue;
                }
                if dom.is_none()
                    && let Some((x, y)) = bd.init
                {
                    // a `match` arm's variant: what that variant is made with; a field read:
                    // what the literals give that field (`v11[0].h` of `vec![E { h: .. }]`)
                    let parts = variant_parts(src, &bd)
                        .or_else(|| {
                            // where the pattern binds it in the value (`let (p, q) = (..)`,
                            // `let Two { h, l } = ..`; a condition's, loop's or arm's only when
                            // it binds the whole), then the fields read of it
                            let mut path: Vec<String> =
                                match pattern_path(s, bd.pat.0, bd.pat.1, &bd.name) {
                                    Some(p) if bd.kind == BindKind::Let || p.is_empty() => p,
                                    _ => return None,
                                };
                            path.extend(
                                field
                                    .as_deref()
                                    .into_iter()
                                    .flat_map(|f| f.split('.'))
                                    .map(str::to_string),
                            );
                            if path.is_empty() {
                                return None;
                            }
                            let path: Vec<&str> = path.iter().map(String::as_str).collect();
                            Some(project(src, x, y, &path, 8, &mut r.names))
                        })
                        .unwrap_or_else(|| value_parts(s, x, y));
                    for (x, y) in parts {
                        names_read(src, kb, x, y, depth - 1, seen, r, own);
                    }
                }
                if let Some((_, (x, y))) = dom {
                    names_read(src, kb, x, y, depth - 1, seen, r, own);
                }
                // `#[cfg(unix)] let a = ..;` beside `#[cfg(not(unix))] let a = ..;`: the build
                // has one of them, whichever the configuration selects: both are read
                if dom.is_none()
                    && cfg_before(s, bd.stmt.0)
                    && let Some(sc) = &sc
                {
                    for b2 in &sc.binds {
                        if b2.name == bd.name
                            && b2.stmt != bd.stmt
                            && cfg_before(s, b2.stmt.0)
                            && let Some((x, y)) = b2.init
                            && seen.insert((
                                b2.stmt.0,
                                b2.stmt.1,
                                field.clone().unwrap_or_default(),
                            ))
                        {
                            names_read(src, kb, x, y, depth - 1, seen, r, own);
                        }
                    }
                }
                // (not a store into another field of it)
                let other_field = |w: &(usize, usize, usize)| {
                    assigned_place(src, (w.0, w.2)).is_some_and(|a| {
                        a.contains('.') && !place.starts_with(&a) && !a.starts_with(&place)
                    })
                };
                for (_, x, y) in writes
                    .into_iter()
                    .filter(|w| dom.is_none_or(|d| w.0 > d.0) && !other_field(w))
                {
                    names_read(src, kb, x, y, depth - 1, seen, r, own);
                }
                for p in pstores.iter().filter(|p| dom.is_none_or(|d| p.at > d.0)) {
                    names_read(src, kb, p.value.0, p.value.1, depth - 1, seen, r, own);
                }
                // what the file's functions it is lent to (`maybe(&mut z, c)`, `b.up()`) may
                // write there; lent to another crate's function, it may hold what that puts
                // (what it stores through the parameter the variable is lent as, when that is
                // all it does with it; else whatever its body names)
                for (i, f) in lent_to(src, &bd, start) {
                    match f {
                        Some(fi) => {
                            let stores =
                                param_at(src, i, fi).and_then(|p| param_stores(src, fi, &p));
                            let spans = stores.unwrap_or_else(|| vec![src.span(fi)]);
                            for (x, y) in spans {
                                if seen.insert((x, y, String::new())) {
                                    names_read(src, kb, x, y, depth - 1, seen, r, false);
                                }
                            }
                        }
                        None => {
                            let _ = i;
                            r.lent = true;
                        }
                    }
                }
                // and the file's functions a value holding a pointer to it is handed to (`let w =
                // wrap1(&mut a); set1(w);`): what they may write through it
                for fi in alias_lends(src, &bd, start) {
                    let sp = src.span(fi);
                    if seen.insert((sp.0, sp.1, String::new())) {
                        names_read(src, kb, sp.0, sp.1, depth - 1, seen, r, false);
                    }
                }
            }
            Some(Found::Param(_)) => r.open |= own,
            Some(Found::Item(k)) => {
                let sp = src.span(&src.items[k]);
                if depth > 0 && seen.insert((sp.0, sp.1, String::new())) {
                    names_read(src, kb, sp.0, sp.1, depth - 1, seen, r, false);
                }
            }
            None => {}
        }
    }
}
