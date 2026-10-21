//! A source file's items, scopes and bindings: `use` trees, locals, patterns, closures, attributes, the functions a body calls.

use super::*;

impl Item {
    pub(super) fn contains(&self, at: (usize, usize)) -> bool {
        self.start <= at && at < self.end
    }
}
impl Source {
    pub(super) fn new(text: &str, rust: bool, toml: bool) -> Source {
        // a CRLF file: the `\r` is not part of the line
        let lines: Vec<String> = text
            .split('\n')
            .map(|l| l.strip_suffix('\r').unwrap_or(l).to_string())
            .collect();
        if !rust {
            return Source {
                class: lines
                    .iter()
                    .map(|l| vec![Class::Code; l.chars().count()])
                    .collect(),
                lines,
                binds: Vec::new(),
                locals: HashSet::new(),
                toml: if toml { toml_keys(text) } else { Vec::new() },
                use_spans: Vec::new(),
                items: Vec::new(),
                code: Vec::new(),
                line_start: Vec::new(),
                scopes: Default::default(),
            };
        }
        let (mut class, code_text) = lex(text);
        for (c, l) in class.iter_mut().zip(&lines) {
            c.truncate(l.chars().count());
        }
        // char index -> (line, col)
        let mut starts = vec![0usize];
        for (i, c) in code_text.chars().enumerate() {
            if c == '\n' {
                starts.push(i + 1);
            }
        }
        let at = |i: usize| {
            let l = starts.partition_point(|&s| s <= i) - 1;
            (l + 1, i - starts[l])
        };
        let char_of = |b: usize| code_text[..b].chars().count();
        let use_spans = USE_ITEM
            .find_iter(&code_text)
            .map(|m| (at(char_of(m.start())), at(char_of(m.end()))))
            .collect();
        let chars: Vec<char> = code_text.chars().collect();
        let items = items(&chars)
            .into_iter()
            .map(|(kind, name, trait_name, a, b)| Item {
                kind,
                name,
                trait_name,
                start: at(a),
                end: at(b),
            })
            .collect();
        Source {
            lines,
            class,
            binds: bindings(&code_text),
            locals: locals(&code_text),
            toml: Vec::new(),
            use_spans,
            items,
            code: chars,
            line_start: starts,
            scopes: Default::default(),
        }
    }

    /// The index in `code` of (line, col) (1-based line, 0-based char column).
    pub(super) fn idx(&self, at: (usize, usize)) -> usize {
        self.line_start
            .get(at.0.wrapping_sub(1))
            .map_or(self.code.len(), |s| s + at.1)
            .min(self.code.len())
    }

    /// The (line, col) of an index in `code`.
    pub(super) fn pos(&self, i: usize) -> (usize, usize) {
        let l = self.line_start.partition_point(|&s| s <= i).max(1) - 1;
        (l + 1, i - self.line_start[l])
    }

    /// The code from `a` to `b` (indexes in `code`).
    pub(super) fn text(&self, a: usize, b: usize) -> String {
        self.code[a.min(self.code.len())..b.min(self.code.len())]
            .iter()
            .collect()
    }

    /// An item's extent in `code`.
    pub(super) fn span(&self, i: &Item) -> (usize, usize) {
        (self.idx(i.start), self.idx(i.end))
    }

    /// The source text (comments and literals kept) from `a` to `b`, indexes in `code`.
    pub(super) fn orig(&self, a: usize, b: usize) -> String {
        let ((la, ca), (lb, cb)) = (self.pos(a), self.pos(b));
        let mut out = String::new();
        for l in la..=lb.min(self.lines.len()) {
            let chars: Vec<char> = self.lines[l - 1].chars().collect();
            let from = if l == la { ca } else { 0 };
            let to = if l == lb {
                cb.min(chars.len())
            } else {
                chars.len()
            };
            out.extend(&chars[from.min(to)..to]);
            if l != lb {
                out.push('\n');
            }
        }
        out
    }

    /// The innermost item of one of `kinds` that contains the position.
    pub(super) fn enclosing(&self, at: (usize, usize), kinds: &[ItemKind]) -> Option<&Item> {
        self.items
            .iter()
            .filter(|i| kinds.contains(&i.kind) && i.contains(at))
            .max_by_key(|i| i.start)
    }
}
/// The items of a Rust file with comments and literals blanked: (kind, name, trait, start, end)
/// in chars. A keyword counts at an item's place (not `-> impl Trait`, `*const T`, `<const N>`,
/// `const { .. }`); a function without a body (a trait's declaration) has none.
#[allow(clippy::type_complexity)]
pub(super) fn items(s: &[char]) -> Vec<(ItemKind, String, Option<String>, usize, usize)> {
    let word_at = |i: usize| -> String {
        s[i..]
            .iter()
            .take_while(|c| is_ident(**c))
            .collect::<String>()
    };
    let skip_ws = |mut i: usize| {
        while i < s.len() && s[i].is_whitespace() {
            i += 1;
        }
        i
    };
    // the code before `i`: its last non-blank char, and the word ending there
    let prev = |i: usize| s[..i].iter().rev().find(|c| !c.is_whitespace()).copied();
    let prev_word = |i: usize| -> String {
        let mut j = i;
        while j > 0 && s[j - 1].is_whitespace() {
            j -= 1;
        }
        let end = j;
        while j > 0 && is_ident(s[j - 1]) {
            j -= 1;
        }
        s[j..end].iter().collect()
    };
    // an item's place: after another item, a block's start, an attribute, a visibility or a
    // qualifier
    let item_place = |i: usize| {
        matches!(prev(i), None | Some('}' | ';' | '{' | ']' | ')'))
            || matches!(
                prev_word(i).as_str(),
                "pub" | "unsafe" | "default" | "extern" | "auto"
            )
    };
    // the matching close of the bracket at `open`
    let close_of = |open: usize| -> Option<usize> {
        let (o, c) = match s[open] {
            '{' => ('{', '}'),
            '(' => ('(', ')'),
            '[' => ('[', ']'),
            _ => return None,
        };
        let mut depth = 0;
        for (j, ch) in s.iter().enumerate().skip(open) {
            if *ch == o {
                depth += 1;
            } else if *ch == c {
                depth -= 1;
                if depth == 0 {
                    return Some(j + 1);
                }
            }
        }
        None
    };
    // from `i`, the first `{` (or `;` when `semi`) outside parentheses, brackets and generic
    // arguments: a body, or the end of a declaration
    let body_or_end = |i: usize| -> Option<(usize, bool)> {
        let mut depth = 0i32;
        let mut j = i;
        while j < s.len() {
            match s[j] {
                '(' | '[' => depth += 1,
                ')' | ']' => depth -= 1,
                '<' => depth += 1,
                '>' if j > 0 && s[j - 1] != '-' && s[j - 1] != '=' => depth -= 1,
                '{' if depth <= 0 => return Some((j, true)),
                ';' if depth <= 0 => return Some((j, false)),
                _ => {}
            }
            j += 1;
        }
        None
    };
    let last_segment = type_name;
    let mut out = Vec::new();
    let mut i = 0;
    while i < s.len() {
        if !is_ident(s[i]) || (i > 0 && is_ident(s[i - 1])) {
            i += 1;
            continue;
        }
        let w = word_at(i);
        let after = skip_ws(i + w.len());
        match w.as_str() {
            "fn" if after < s.len() && is_ident(s[after]) => {
                // a raw identifier (`fn r#type`) is named without its `r#`
                let raw = s.get(after + 1) == Some(&'#') && s[after] == 'r';
                let name = word_at(if raw { after + 2 } else { after });
                let len = name.len() + if raw { 2 } else { 0 };
                if let Some((b, true)) = body_or_end(after + len)
                    && let Some(e) = close_of(b)
                {
                    out.push((ItemKind::Fn, name, None, i, e));
                }
            }
            "static" | "const"
                if after < s.len()
                    && is_ident(s[after])
                    && item_place(i)
                    && !matches!(
                        word_at(after).as_str(),
                        "fn" | "unsafe" | "extern" | "async"
                    ) =>
            {
                let mut n = after;
                // `static mut X`, `lazy_static!`'s `static ref X`
                if matches!(word_at(n).as_str(), "mut" | "ref") {
                    n = skip_ws(n + word_at(n).len());
                }
                let name = word_at(n);
                // `static NAME: T = ..;`: to the `;` outside all brackets
                let mut depth = 0i32;
                let mut j = n;
                while j < s.len() {
                    match s[j] {
                        '(' | '[' | '{' => depth += 1,
                        ')' | ']' | '}' => depth -= 1,
                        ';' if depth == 0 => break,
                        _ => {}
                    }
                    if depth < 0 {
                        break;
                    }
                    j += 1;
                }
                if !name.is_empty() {
                    out.push((ItemKind::Static, name, None, i, (j + 1).min(s.len())));
                }
            }
            "impl" if item_place(i) && prev(i) != Some(')') => {
                if let Some((b, true)) = body_or_end(i + 4)
                    && let Some(e) = close_of(b)
                {
                    let mut header: String = s[i + 4..b].iter().collect();
                    // the impl's own generic parameters
                    let mut params = Vec::new();
                    if header.trim_start().starts_with('<') {
                        let h = header.trim_start().to_string();
                        let hc: Vec<char> = h.chars().collect();
                        let cls = vec![Class::Code; hc.len()];
                        if let Some(end) = skip_angle(&hc, &cls, 0) {
                            let inner: String = hc[1..end.saturating_sub(1)].iter().collect();
                            params = strip_generics(&inner)
                                .split(',')
                                .filter_map(|p| {
                                    let p = p.trim().trim_start_matches("const ").trim();
                                    let n: String =
                                        p.chars().take_while(|c| is_ident(*c)).collect();
                                    (!n.is_empty() && !p.starts_with('\'')).then_some(n)
                                })
                                .collect();
                        }
                        header = strip_generics(&h).to_string();
                    }
                    // blanks collapsed: a `where` or `for` may start a line
                    let one_line = |h: &str| h.split_whitespace().collect::<Vec<_>>().join(" ");
                    let header = one_line(&header);
                    let header = header.split(" where ").next().unwrap_or("").to_string();
                    let header_full: String = one_line(&s[i + 4..b].iter().collect::<String>());
                    let header_full = header_full
                        .split(" where ")
                        .next()
                        .unwrap_or("")
                        .to_string();
                    let (tr, ty) = match header.split_once(" for ") {
                        Some((_, y)) => {
                            // the trait with its arguments (`TryFrom<&PrivateKeyDer<'_>>`),
                            // unless they are the impl's own parameters: then its name
                            let t = header_full
                                .split_once(" for ")
                                .map(|(t, _)| t.trim().to_string())
                                .unwrap_or_default();
                            let t = if t.starts_with('<') {
                                let tc: Vec<char> = t.chars().collect();
                                let cls = vec![Class::Code; tc.len()];
                                skip_angle(&tc, &cls, 0)
                                    .map(|e| tc[e..].iter().collect::<String>())
                                    .unwrap_or(t)
                            } else {
                                t
                            };
                            let generic = re!(r"\w+")
                                .find_iter(&t)
                                .any(|m| params.iter().any(|p| p == m.as_str()));
                            let t = if generic {
                                last_segment(&t)
                            } else {
                                norm_path(&t)
                            };
                            (Some(t), y.to_string())
                        }
                        None => (None, header.clone()),
                    };
                    // a blanket impl (`impl<T: Foo> Bar for T`): any type, named by its trait
                    let ty = last_segment(&ty);
                    let ty = if params.contains(&ty) {
                        String::new()
                    } else if ty.starts_with(['(', '[']) {
                        // the impl's parameters in a tuple or array are any type or value
                        // (`[u8; N]`): `?`
                        re!(r"\b\w+\b")
                            .replace_all(&ty, |m: &regex::Captures| {
                                if params.iter().any(|p| p == &m[0]) {
                                    "?".to_string()
                                } else {
                                    m[0].to_string()
                                }
                            })
                            .to_string()
                    } else {
                        ty
                    };
                    out.push((ItemKind::Impl, ty, tr, i, e));
                }
            }
            "struct" | "enum" | "union" | "type"
                if after < s.len() && is_ident(s[after]) && item_place(i) =>
            {
                out.push((ItemKind::TypeDef, word_at(after), None, i, i + w.len()));
            }
            "trait" | "mod" if after < s.len() && is_ident(s[after]) && item_place(i) => {
                let name = word_at(after);
                if let Some((b, true)) = body_or_end(after + name.len())
                    && let Some(e) = close_of(b)
                {
                    let kind = if w == "trait" {
                        ItemKind::Trait
                    } else {
                        ItemKind::Mod
                    };
                    out.push((kind, name, None, i, e));
                }
            }
            "macro_rules" if s.get(after) == Some(&'!') => {
                let n = skip_ws(after + 1);
                let name = word_at(n);
                let b = skip_ws(n + name.len());
                if b < s.len()
                    && let Some(e) = close_of(b)
                {
                    // the body: inside its brackets
                    out.push((ItemKind::Macro, name, None, b, e));
                }
            }
            // `name! (..)`, `name! [..]`, `name! { .. }`
            _ if after < s.len()
                && s[after] == '!'
                && w != "macro_rules"
                && s.get(skip_ws(after + 1))
                    .is_some_and(|c| matches!(c, '(' | '[' | '{')) =>
            {
                let b = skip_ws(after + 1);
                if let Some(e) = close_of(b) {
                    out.push((ItemKind::MacroCall, w.clone(), None, b, e));
                }
            }
            _ => {}
        }
        i += w.len().max(1);
    }
    out
}
/// Every name the `use` and `extern crate` items of a source bind (comments and literals
/// blanked: `as` renames there, not in casts).
pub(super) fn bindings(code_text: &str) -> Vec<Binding> {
    USE_ITEM
        .find_iter(code_text)
        .flat_map(|m| use_bindings(m.as_str()))
        .collect()
}
/// The names one item binds: `use a::{b::c as d, e, f::*};` binds `d` (to `a::b::c`), `e` (to
/// `a::e`) and `*` (to `a::f`, a glob); `extern crate x as y;` binds `y` to `x`. `as _` binds
/// no name.
pub(super) fn use_bindings(item: &str) -> Vec<Binding> {
    let s: Vec<char> = item.chars().collect();
    let mut toks: Vec<String> = Vec::new();
    let mut i = 0;
    while i < s.len() {
        let c = s[i];
        if c.is_whitespace() {
            i += 1;
        } else if c == ':' && s.get(i + 1) == Some(&':') {
            toks.push("::".into());
            i += 2;
        } else if is_ident(c) || c == '$' {
            let st = if c == 'r' && s.get(i + 1) == Some(&'#') {
                i + 2
            } else {
                i
            };
            let mut e = st.max(i + 1);
            while e < s.len() && is_ident(s[e]) {
                e += 1;
            }
            toks.push(s[st..e].iter().collect());
            i = e;
        } else {
            toks.push(c.to_string());
            i += 1;
        }
    }
    let mut out = Vec::new();
    let t = |k: usize| toks.get(k).map_or("", String::as_str);
    if t(0) == "extern" && t(1) == "crate" {
        let name = if t(3) == "as" { t(4) } else { t(2) };
        if !name.is_empty() && name != "_" {
            out.push(Binding {
                name: name.into(),
                path: vec![t(2).into()],
            });
        }
        return out;
    }
    if t(0) == "use" {
        let mut k = 1;
        use_tree(&toks, &mut k, &mut Vec::new(), &mut out);
    }
    out
}
pub(super) fn use_tree(
    toks: &[String],
    k: &mut usize,
    prefix: &mut Vec<String>,
    out: &mut Vec<Binding>,
) {
    let start = prefix.len();
    let t = |k: usize| toks.get(k).map_or("", String::as_str);
    if t(*k) == "::" {
        *k += 1;
    }
    loop {
        match t(*k) {
            "{" => {
                *k += 1;
                loop {
                    if t(*k) == "}" {
                        *k += 1;
                        break;
                    }
                    let at = *k;
                    use_tree(toks, k, prefix, out);
                    if t(*k) == "," {
                        *k += 1;
                    } else if t(*k) == "}" {
                        *k += 1;
                        break;
                    } else if *k == at || *k >= toks.len() {
                        break;
                    }
                }
                break;
            }
            // a glob (`use b::sub::*;`): a binding named `*` to its module, which the lookups
            // of a name the file does not bind otherwise follow
            "*" => {
                *k += 1;
                if !prefix.is_empty() {
                    out.push(Binding {
                        name: "*".into(),
                        path: prefix.clone(),
                    });
                }
                break;
            }
            id if id.chars().next().is_some_and(|c| is_ident(c) || c == '$') => {
                prefix.push(id.to_string());
                *k += 1;
                if t(*k) == "::" {
                    *k += 1;
                    continue;
                }
                // `a::b::{self}` binds `b`
                let mut path = prefix.clone();
                if path.last().is_some_and(|l| l == "self") && path.len() > 1 {
                    path.pop();
                }
                let name = if t(*k) == "as" {
                    *k += 2;
                    t(*k - 1).to_string()
                } else {
                    path.last().cloned().unwrap_or_default()
                };
                if !name.is_empty() && name != "_" {
                    out.push(Binding { name, path });
                }
                break;
            }
            _ => break,
        }
    }
    prefix.truncate(start);
}
/// The names a source defines as types, traits or modules, or declares as generic parameters
/// (`fn f<D: Digest>`, `impl<T>`): such a name may shadow an import.
pub(super) fn locals(code_text: &str) -> HashSet<String> {
    let mut out: HashSet<String> = re!(r"\b(?:struct|enum|union|type|trait|mod)\s+(?:r#)?(\w+)")
        .captures_iter(code_text)
        .map(|c| c[1].to_string())
        .collect();
    for m in
        re!(r"\b(?:(?:fn|struct|enum|union|trait|type)\s+(?:r#)?\w+|impl)\s*<").find_iter(code_text)
    {
        let s: Vec<char> = code_text[m.end() - 1..].chars().take(4000).collect();
        let cls = vec![Class::Code; s.len()];
        let Some(end) = skip_angle(&s, &cls, 0) else {
            continue;
        };
        // the parameters, split at top-level commas
        let mut depth = 0i32;
        let mut params = vec![String::new()];
        for k in 1..end - 1 {
            match s[k] {
                '<' | '(' | '[' => depth += 1,
                '>' if s[k - 1] != '-' => depth -= 1,
                ')' | ']' => depth -= 1,
                ',' if depth == 0 => {
                    params.push(String::new());
                    continue;
                }
                _ => {}
            }
            params.last_mut().unwrap().push(s[k]);
        }
        for p in params {
            let p = p.trim();
            let p = p.strip_prefix("const ").unwrap_or(p).trim_start();
            let name: String = p.chars().take_while(|&c| is_ident(c)).collect();
            if !name.is_empty() {
                out.insert(name);
            }
        }
    }
    out
}
/// The first segments of the paths the imports bind `name` to (`use sha2::Sha256 as H;` gives
/// `sha2` for `H`; two imports of `H` from different crates give both), or `name` itself when
/// no import binds it. None when an import is relative to this crate (`crate::`, `self::`,
/// `super::`).
pub(super) fn import_roots(binds: &[Binding], name: &str) -> Option<BTreeSet<String>> {
    let mut roots = BTreeSet::new();
    for b in binds.iter().filter(|b| b.name == name) {
        let head = b.path.first()?;
        if matches!(
            head.as_str(),
            "crate" | "self" | "super" | "Self" | "$crate"
        ) {
            return None;
        }
        roots.insert(head.clone());
    }
    if roots.is_empty() {
        roots.insert(name.to_string());
    }
    Some(roots)
}
/// Where the variable `name`, read at `at`, is bound (`lookup`): the nearest binding in scope
/// in its function, its parameters, then the statics and consts.
pub(super) fn binding(src: &Source, at: usize, name: &str) -> Option<Bound> {
    Some(match lookup(src, at, name)? {
        Found::Bind(b) if b.kind == BindKind::Closure => Bound::ClosureParam,
        Found::Bind(b) => {
            let (i0, i1) = b.init.unwrap_or(b.stmt);
            Bound::Let {
                first: src.pos(b.stmt.0).0,
                last: src.pos(b.stmt.1.saturating_sub(1).max(b.stmt.0)).0,
                // (a macro's binding holds what the invocation's line names)
                init: if b.kind == BindKind::Macro {
                    String::new()
                } else {
                    src.text(i0, i1)
                },
                at: i0,
            }
        }
        Found::Param(fun) => Bound::Param { fun },
        Found::Item(k) => Bound::Item {
            start: src.items[k].start.0,
            end: src.items[k].end.0,
        },
    })
}
/// Is a function pointer held by variable `name`, read at `at`, the one named at line `named`:
/// the variable bound where the function is named (a `let`, a pattern of `if let`, `while let`,
/// `for` or a `match` arm, over lines; the binding in scope, so a block's or a closure's own
/// `let` of the name is another variable), or copied from one that is (`let f = f;`: the one
/// before), or from the result of the file's function or method whose body names it, or of a
/// closure that does; a parameter of a function called where it is named (in the call's
/// arguments or its receiver's binding); a static or const whose value (or another static it
/// refers to) names it? A variable bound by a closure's parameter is not checked.
pub(super) fn pointer_bound(
    src: &Source,
    at: usize,
    name: &str,
    named: usize,
) -> Result<(), String> {
    let mut cur = (at, name.to_string());
    let file_fns = |n: &str| -> Vec<&Item> {
        src.items
            .iter()
            .filter(|i| i.kind == ItemKind::Fn && i.name == n)
            .collect()
    };
    for _ in 0..8 {
        let bound = binding(src, cur.0, &cur.1);
        // the file's function (`get()(..)`): named in its body
        if bound.is_none()
            && let Some(f) = file_fns(&cur.1).first()
        {
            return if (f.start.0..=f.end.0).contains(&named) {
                Ok(())
            } else {
                Err(format!(
                    "`{}` is the function at lines {}-{}",
                    cur.1, f.start.0, f.end.0
                ))
            };
        }
        let bound =
            bound.ok_or_else(|| format!("`{}` is not bound in its function or its file", cur.1))?;
        let (first, last, init, init_at) = match bound {
            Bound::ClosureParam => return Ok(()),
            Bound::Param { fun } => return param_passes(src, &fun, &cur.1, named),
            Bound::Item { start, end } => {
                if (start..=end).contains(&named) {
                    return Ok(());
                }
                // a static of another static (`static B: &HashFn = &A`)
                let text: String = (start..=end)
                    .map(|l| src.lines[l - 1].as_str())
                    .collect::<Vec<_>>()
                    .join("\n");
                let refers = src.items.iter().any(|i| {
                    i.kind == ItemKind::Static
                        && i.name != cur.1
                        && (i.start.0..=i.end.0).contains(&named)
                        && Regex::new(&format!(r"\b{}\b", regex::escape(&i.name)))
                            .is_ok_and(|r| r.is_match(&text))
                });
                return if refers {
                    Ok(())
                } else {
                    Err(format!("`{}` is the item at lines {start}-{end}", cur.1))
                };
            }
            Bound::Let {
                first,
                last,
                init,
                at,
            } => (first, last, init, at),
        };
        // the statement names it
        if (first..=last).contains(&named) {
            return Ok(());
        }
        let init = init.trim();
        // a call of the file's function or method (`get()`, `pk.pick()`, `Reg::make()`; not
        // `HashMap::new()`, another type's): named in its body
        let fns = file_fns_called(src, init);
        if fns.iter().any(|f| (f.start.0..=f.end.0).contains(&named)) {
            return Ok(());
        }
        // a container in a field of it the function fills (`t.map.insert(1, digest)` with `let
        // mut t = Table::new();`): the statement storing it names it
        if container_stores(src, init_at, &cur.1)
            .iter()
            .any(|&(a, b)| (a..=b).contains(&named))
        {
            return Ok(());
        }
        // a container the function fills (`map.insert("a", digest)`, `v.push(digest)`): one of
        // the statements storing into it names it
        if re!(r"^(?:\w+\s*::\s*)*(?:Vec|VecDeque|HashMap|BTreeMap|HashSet|BTreeSet|IndexMap)\s*(?:::\s*<[^>]*>\s*)?::\s*(?:new|with_capacity|default)\s*\(|^vec!\s*\[\s*\]|^Vec\s*::\s*from").is_match(init)
        {
            let stores = container_stores(src, init_at, &cur.1);
            if stores.iter().any(|&(a, b)| (a..=b).contains(&named)) {
                return Ok(());
            }
            return Err(if stores.is_empty() {
                format!("`{}` is bound at lines {first}-{last}", cur.1)
            } else {
                format!(
                    "`{}` is given its values at lines {}",
                    cur.1,
                    stores
                        .iter()
                        .map(|(a, b)| if a == b { format!("{a}") } else { format!("{a}-{b}") })
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            });
        }
        // a copy of another variable (`if let Some(f) = o`, `let h = p;`, `let f = f;`: the
        // one before), or a method of it (`it.next()`, `fs.iter()`): where that one is bound
        if let Some(v) = re!(
            r"^&?\s*(?:mut\s+)?\*?\s*([A-Za-z_]\w*)(?:\s*\.\s*\w+\s*(?:\([^()]*\))?|\s*\[[^\[\]]*\])*\s*\??$"
        )
        .captures(init)
        {
            let v = v[1].to_string();
            if binding(src, init_at, &v).is_none() && file_fns(&v).is_empty() {
                // an imported function item (`let f = digest;`): this statement names it
                return Err(format!("`{}` is bound at lines {first}-{last}", cur.1));
            }
            cur = (init_at, v);
            continue;
        }
        // the result of a call of a closure of the function (`let k = mk();`): named in the
        // closure's statement; a tuple struct's or variant's constructor (`Some(digest::
        // digest)`) holds what it is given, named in the statement
        if let Some(c) = re!(r"^(?:\w+::)*([a-z_]\w*)\s*\(").captures(init) {
            if !fns.is_empty() {
                return Err(format!(
                    "`{}` holds what `{}` returns (lines {first}-{last})",
                    cur.1, &c[1]
                ));
            }
            match binding(src, init_at, &c[1]) {
                Some(Bound::Let {
                    first: f, last: l, ..
                }) if !(f..=l).contains(&named) => {
                    return Err(format!(
                        "`{}` holds what `{}` returns (lines {f}-{l})",
                        cur.1, &c[1]
                    ));
                }
                Some(Bound::Let { .. }) => return Ok(()),
                _ => {}
            }
        }
        // a value the statement computes from others not followed (another crate's function,
        // a labelled block): one of the variables it reads is bound where the function is named
        if re!(r"\w\s*\(|\w!|'\w+\s*:").is_match(init)
            && !re!(r"^(?:\w+::)*[A-Z]\w*\s*[({]|^vec!|^\[").is_match(init)
        {
            let reads_bound = re!(r"\b([a-z_]\w*)\b").captures_iter(init).any(|v| {
                !is_keyword(&v[1])
                    && matches!(
                        binding(src, init_at, &v[1]),
                        Some(Bound::Let { first: f, last: l, .. }) if (f..=l).contains(&named)
                    )
            });
            if reads_bound {
                return Ok(());
            }
        }
        return Err(format!("`{}` is bound at lines {first}-{last}", cur.1));
    }
    Ok(())
}
/// The file's method taking `self` that a method call at `m` (`v.reset()`) names: of the impl
/// for the receiver's type when the code says which (`let v = B { .. }`), else the first.
pub(super) fn method_for<'a>(src: &'a Source, m: &usize, name: &str) -> Option<&'a Item> {
    let methods: Vec<&Item> = src
        .items
        .iter()
        .filter(|x| {
            x.kind == ItemKind::Fn
                && x.name == name
                && src.fn_scope(x).params.first().is_some_and(|p| p == "self")
        })
        .collect();
    let ty = receiver_type(src, *m);
    ty.as_deref()
        .and_then(|t| {
            methods.iter().copied().find(|f| {
                src.items.iter().any(|b| {
                    b.kind == ItemKind::Impl
                        && b.name == t
                        && b.contains(f.start)
                        && b.start != f.start
                })
            })
        })
        .or_else(|| methods.first().copied())
}
/// Is the `&mut` taken at `i` into a `let` binding (`let r = &mut s1;`, `let S { a, .. } = &mut
/// s5;`) used, before `end`, as a method's receiver or a call's argument (not only stored
/// through or copied)? Also when the binding is not a `let`'s.
pub(super) fn borrow_used_unfollowed(src: &Source, i: usize, end: usize) -> bool {
    let s = &src.code;
    // the statement's start and its `let` pattern
    let mut k = i;
    let mut depth = 0;
    while k > 0 {
        k -= 1;
        match s[k] {
            ')' | ']' | '}' => depth += 1,
            '(' | '[' | '{' => {
                if depth == 0 {
                    break;
                }
                depth -= 1;
            }
            ';' if depth == 0 => break,
            _ => {}
        }
    }
    let st = skip_blank(s, k + 1);
    if !kw(s, st, "let") {
        return true;
    }
    let eq = scan_to(s, st, i, |m| s[m] == '=');
    let names = pattern_names(s, st + 3, eq);
    let stmt_end = scan_to(s, i, end.min(s.len()), |m| s[m] == ';');
    names.iter().any(|n| {
        (stmt_end..end.min(s.len())).any(|m| {
            if !kw(s, m, n) {
                return false;
            }
            let after = skip_blank(s, m + n.chars().count());
            let before = before_blank(s, m);
            // a method call on it, or an argument of a call
            (s.get(after) == Some(&'.') && {
                let w = skip_blank(s, after + 1);
                let name = word_of(s, w);
                s.get(skip_blank(s, w + name.chars().count())) == Some(&'(')
            }) || before.is_some_and(|p| matches!(s[p], '(' | ','))
        })
    })
}
/// The calls the variable bound by `bd` is lent to before the read at `start`, as `&mut` (`f(&mut
/// v)`) or as a method's receiver (`v.up()`): the file's function or method called (its body
/// may write it), or None for another crate's function taking `&mut v` (`mem::swap` aside, which
/// `lent_mut` reads).
pub(super) fn lent_to<'a>(
    src: &'a Source,
    bd: &Bind,
    start: usize,
) -> Vec<(usize, Option<&'a Item>)> {
    let s = &src.code;
    let mut out = Vec::new();
    let mut i = bd.scope.0;
    while i < start.min(s.len()) {
        if !kw(s, i, &bd.name)
            || !matches!(lookup(src, i, &bd.name), Some(Found::Bind(b)) if b.stmt == bd.stmt)
        {
            i += 1;
            continue;
        }
        let after = skip_blank(s, i + bd.name.chars().count());
        let by_mut = word_before_at(s, i) == "mut"
            && before_blank(s, i)
                .and_then(|m| before_blank(s, m + 1 - 3))
                .is_some_and(|a| s[a] == '&');
        if by_mut && !swapping_call(src, i) {
            // the call it is an argument of
            let mut depth = 0;
            let mut j = i;
            let mut open = None;
            while j > 0 {
                j -= 1;
                match s[j] {
                    ')' | ']' | '}' => depth += 1,
                    '(' if depth == 0 => {
                        open = Some(j);
                        break;
                    }
                    '(' | '[' | '{' => {
                        if depth == 0 {
                            break;
                        }
                        depth -= 1;
                    }
                    ';' if depth == 0 => break,
                    _ => {}
                }
            }
            match open {
                Some(o) => {
                    let f = word_before_at(s, o);
                    let fb = o - f.chars().count();
                    let method = before_blank(s, fb).is_some_and(|p| s[p] == '.');
                    let fi = if method {
                        exact_method(src, &fb, &f)
                    } else {
                        free_fn_called(src, fb, &f, &path_before(s, fb))
                    };
                    out.push((i, fi.filter(|g| !dispatches(src, g))));
                }
                // lent into a binding (`let u: &mut dyn Up = &mut a2;`): written through it in
                // ways not followed when the binding is a method's receiver or a call's argument
                // (`u.up()`); stores through it (`*r = v`, `r.a = v`) are followed
                // (`pointer_stores`)
                None => {
                    if borrow_used_unfollowed(src, i, bd.scope.1) {
                        out.push((i, None));
                    }
                }
            }
        } else if s.get(after) == Some(&'.') {
            let m = skip_blank(s, after + 1);
            let name = word_of(s, m);
            if s.get(skip_blank(s, m + name.chars().count())) == Some(&'(') && !name.is_empty() {
                // the file's method of the value's type, else one not known (a trait's,
                // dispatched on a type the code does not say)
                let fi = exact_method(src, &m, &name).filter(|g| !dispatches(src, g));
                if fi.is_some()
                    || src
                        .items
                        .iter()
                        .any(|x| x.kind == ItemKind::Fn && x.name == name)
                {
                    out.push((i, fi));
                }
            }
        }
        i += bd.name.chars().count();
    }
    out
}
/// The file's method a call at `m` names, when the receiver's type is one of the file's and it
/// implements the method (or the trait's default body it runs): none otherwise.
pub(super) fn exact_method<'a>(src: &'a Source, m: &usize, name: &str) -> Option<&'a Item> {
    let t = receiver_type(src, *m)?;
    let methods: Vec<&Item> = src
        .items
        .iter()
        .filter(|x| x.kind == ItemKind::Fn && x.name == name)
        .collect();
    methods.iter().copied().find(|f| {
        src.items.iter().any(|b| {
            b.kind == ItemKind::Impl && b.name == t && b.contains(f.start) && b.start != f.start
        })
    })
}
/// Does the function's body call a method on one of its parameters (`t.up()`, `self.set(..)`),
/// which a type parameter or the receiver's type dispatches?
pub(super) fn dispatches(src: &Source, f: &Item) -> bool {
    let s = &src.code;
    let sc = src.fn_scope(f);
    let (a, b) = sc.body;
    (a..b).any(|k| {
        s[k] == '.' && receiver_at(s, k).is_some_and(|(_, w, _)| sc.params.contains(&w)) && {
            let m = skip_blank(s, k + 1);
            let w = word_of(s, m);
            !w.is_empty()
                && s.get(skip_blank(s, m + w.chars().count())) == Some(&'(')
                && src
                    .items
                    .iter()
                    .any(|it| it.kind == ItemKind::Fn && it.name == w)
        }
    })
}
/// The module path of the items around `at` (`mod a { mod b { .. } }`: `[a, b]`).
pub(super) fn modules_at(src: &Source, at: (usize, usize)) -> Vec<String> {
    let mut mods: Vec<&Item> = src
        .items
        .iter()
        .filter(|i| i.kind == ItemKind::Mod && i.contains(at))
        .collect();
    mods.sort_by_key(|i| i.start);
    mods.into_iter().map(|m| m.name.clone()).collect()
}
/// The file's free function (not a method) a call at `at` names `name` with the path `prefix`
/// written before it (`other::fill`, `fill`, `crate::m::f`): the one in the module the path
/// leads to from the call's, else the only one of that name.
pub(super) fn free_fn_called<'a>(
    src: &'a Source,
    at: usize,
    name: &str,
    prefix: &[String],
) -> Option<&'a Item> {
    let free: Vec<&Item> = src
        .items
        .iter()
        .filter(|i| {
            i.kind == ItemKind::Fn
                && i.name == name
                && !src.items.iter().any(|o| {
                    matches!(o.kind, ItemKind::Impl | ItemKind::Trait) && o.contains(i.start)
                })
        })
        .collect();
    let here = modules_at(src, src.pos(at));
    let want: Vec<String> = match prefix.first().map(String::as_str) {
        Some("crate") => prefix[1..].to_vec(),
        Some("self") => here
            .iter()
            .cloned()
            .chain(prefix[1..].iter().cloned())
            .collect(),
        Some("super") => here[..here.len().saturating_sub(1)]
            .iter()
            .cloned()
            .chain(prefix[1..].iter().cloned())
            .collect(),
        _ => here.iter().cloned().chain(prefix.iter().cloned()).collect(),
    };
    free.iter()
        .find(|f| modules_at(src, f.start) == want)
        .or_else(|| {
            free.iter()
                .find(|f| modules_at(src, f.start).ends_with(prefix))
        })
        .or_else(|| (free.len() == 1).then(|| &free[0]))
        .copied()
}
/// The file's functions a piece of code calls: a method (`pk.pick()`: of any impl), a path call
/// qualified by a type (`Reg::make()`: of that type's impl; `HashMap::new()` is no function of the
/// file unless the file implements `HashMap`), a function of the file or of one of its modules.
pub(super) fn file_fns_called<'a>(src: &'a Source, code: &str) -> Vec<&'a Item> {
    let mut out: Vec<&Item> = Vec::new();
    for c in re!(r"(\.\s*)?(?:([A-Za-z_]\w*)\s*::\s*)?([a-z_]\w*)\s*(?:::\s*<[^>]*>\s*)?\(")
        .captures_iter(code)
    {
        let name = &c[3];
        for f in src
            .items
            .iter()
            .filter(|i| i.kind == ItemKind::Fn && i.name == name)
        {
            let in_impl = |ty: Option<&str>| {
                src.items.iter().any(|i| {
                    i.kind == ItemKind::Impl
                        && ty.is_none_or(|t| i.name == t)
                        && i.contains(f.start)
                        && i.start != f.start
                })
            };
            let ok = match (c.get(1), c.get(2)) {
                (Some(_), _) => in_impl(None),
                // a type's (`Self::f`, `Reg::make`), or a module's
                (None, Some(q)) if q.as_str() == "Self" => in_impl(None),
                (None, Some(q)) if q.as_str().starts_with(char::is_uppercase) => {
                    in_impl(Some(q.as_str()))
                }
                _ => true,
            };
            if ok && !out.iter().any(|o| std::ptr::eq(*o, f)) {
                out.push(f);
            }
        }
    }
    out
}
/// The statements of the function around `at` that store into the container `var`
/// (`var.insert(..)`, `var.push(..)`, `var.extend(..)`, `var.entry(..).or_insert(..)`): their
/// lines.
pub(super) fn container_stores(src: &Source, at: usize, var: &str) -> Vec<(usize, usize)> {
    let s = &src.code;
    let Some(f) = src.enclosing(src.pos(at), &[ItemKind::Fn]) else {
        return Vec::new();
    };
    let (a, b) = src.span(f);
    let text = src.text(a, b);
    // (of the variable, or of a field of it: `t.map.insert(..)`)
    let Ok(r) = Regex::new(&format!(
        r"(?:^|[^\w.])({})(?:\s*\.\s*\w+)*?\s*\.\s*(?:insert|push|push_back|push_front|extend|append|entry\s*\([^)]*\)\s*\.\s*or_insert(?:_with)?)\s*\(",
        regex::escape(var)
    )) else {
        return Vec::new();
    };
    r.captures_iter(&text)
        .filter_map(|c| {
            let (m, v) = (c.get(0)?, c.get(1)?);
            let i = a + text[..v.start()].chars().count();
            let open = a + text[..m.end()].chars().count() - 1;
            let close = close_of_at(s, open)?;
            Some((src.pos(i).0, src.pos(close).0))
        })
        .collect()
}
/// Is a parameter `var` of the function `fun` given the pointer named at line `named`: by a
/// call of `fun` in the function around the naming whose arguments name it (over lines), or
/// pass a variable bound where it is named, or whose receiver is (`ho.run(&d)` with `let ho =
/// Holder { f: digest::digest };` for `self`)?
pub(super) fn param_passes(src: &Source, fun: &str, var: &str, named: usize) -> Result<(), String> {
    let call = Regex::new(&format!(
        r"\b{}\b\s*(?:::\s*<[^>]*>\s*)?\(",
        regex::escape(fun)
    ))
    .map_err(|e| e.to_string())?;
    let caller = src.enclosing((named, 0), &[ItemKind::Fn]);
    let (from, to) = caller
        .map(|c| (c.start.0, c.end.0))
        .unwrap_or((named, named));
    let s = &src.code;
    let bound_here = |at: usize, v: &str| matches!(binding(src, at, v), Some(Bound::Let { first, last, .. }) if (first..=last).contains(&named));
    for l in from..=to.min(src.lines.len()) {
        let text = &src.lines[l - 1];
        for m in call.find_iter(text) {
            let open = src.idx((l, text[..m.end()].chars().count() - 1));
            let Some(close) = close_of_at(s, open) else {
                continue;
            };
            if (l..=src.pos(close).0).contains(&named) {
                return Ok(());
            }
            let args = src.text(open, close);
            for v in re!(r"\b([a-z_]\w*)\b").captures_iter(&args) {
                if bound_here(open, &v[1]) {
                    return Ok(());
                }
            }
            // a method's receiver
            let name_at = src.idx((l, text[..m.start()].chars().count()));
            if let Some(dot) = before_blank(s, name_at).filter(|&d| s[d] == '.')
                && let Some((r, root, _)) = receiver_at(s, dot)
                && bound_here(r, &root)
            {
                return Ok(());
            }
        }
    }
    Err(format!(
        "`{var}` is a parameter of `{fun}`, whose calls do not pass it"
    ))
}
/// The first line of the attribute (`#[derive(..)]`, `#[hashed]`) or the macro invocation
/// (`hash_it!(..)`) a line of a file is in: the line itself when it starts one, else the
/// nearest line above, within a few, that starts one and that no other line in between does.
pub(super) fn attribute_start(files: &mut Files<'_>, path: &Path, line: usize) -> Option<usize> {
    let src = files.source(path)?;
    let starts = |l: usize| {
        src.lines.get(l.wrapping_sub(1)).is_some_and(|t| {
            let t = t.trim_start();
            t.starts_with("#[")
                || t.starts_with("#![")
                || re!(r"^[\w:]+!\s*[\(\[\{]").is_match(t)
                || re!(r"[=(,]\s*[\w:]+!\s*[\(\[\{]").is_match(t)
        })
    };
    (line.saturating_sub(12).max(1)..=line)
        .rev()
        .find(|&l| starts(l))
}
/// A method the language calls without naming it: `.await` polls, a scope's end drops, `?`
/// branches, `for` iterates, operators and indexing, closures called through a variable.
pub(super) fn by_syntax(item: &InItem) -> bool {
    const TRAITS: &[&str] = &[
        "Future",
        "IntoFuture",
        "Drop",
        "Deref",
        "DerefMut",
        "Fn",
        "FnMut",
        "FnOnce",
        "AsyncFn",
        "AsyncFnMut",
        "AsyncFnOnce",
        "Iterator",
        "IntoIterator",
        "Try",
        "FromResidual",
        "Index",
        "IndexMut",
        "Add",
        "Sub",
        "Mul",
        "Div",
        "Rem",
        "Neg",
        "Not",
        "BitAnd",
        "BitOr",
        "BitXor",
        "Shl",
        "Shr",
        "AddAssign",
        "SubAssign",
        "MulAssign",
        "DivAssign",
        "RemAssign",
        "BitAndAssign",
        "BitOrAssign",
        "BitXorAssign",
        "ShlAssign",
        "ShrAssign",
        "PartialEq",
        "PartialOrd",
        "Coroutine",
    ];
    matches!(item.name.as_str(), "drop_in_place" | "drop_glue")
        || item
            .trait_name
            .as_deref()
            .is_some_and(|t| TRAITS.contains(&t.split('<').next().unwrap_or(t)))
}
/// The function an attribute on a line belongs to (`#[tokio::main]` above `async fn main`): the
/// line holds an attribute, and the next item after it and any further attributes is that
/// function.
pub(super) fn attribute_of(src: &Source, line: usize) -> Option<&Item> {
    let text = src.lines.get(line.wrapping_sub(1))?;
    if !text.trim_start().starts_with("#[") {
        return None;
    }
    src.items
        .iter()
        .filter(|i| i.kind == ItemKind::Fn && i.start.0 >= line && i.start.0 <= line + 8)
        .min_by_key(|i| i.start)
        .filter(|i| {
            (line + 1..i.start.0).all(|l| {
                let t = src.lines[l - 1].trim_start();
                t.is_empty() || t.starts_with("#[") || t.starts_with("//")
            })
        })
}
/// The item a closure or `async` body is written in: `t2::o1` for `t2::o1::{closure#0}`.
pub(super) fn closure_parent(path: &str) -> Option<&str> {
    let p = path.trim_end();
    let i = p.rfind("::{closure#")?;
    p[i..].ends_with('}').then(|| &p[..i])
}
/// The function item `init` (`<Over as Local>::alg`, `Local::alg`, `Over::alg`) runs `callee`'s
/// body: the same type's, a trait's path (dispatched on the argument), or a type's not
/// overriding the trait's default body `callee`.
pub(super) fn fn_item_runs(src: &Source, callee: &str, init: &str) -> bool {
    let (Some(c), Some(i)) = (in_item(callee), in_item(init)) else {
        return true;
    };
    let ty = |n: &InItem| {
        n.self_ty
            .clone()
            .or_else(|| n.owner.as_ref().map(|(t, _)| t.clone()))
            .map(|t| type_name(&t))
    };
    let (Some(ct), Some(it)) = (ty(&c), ty(&i)) else {
        return true;
    };
    let is_trait = |t: &str| {
        src.items
            .iter()
            .any(|x| x.kind == ItemKind::Trait && x.name == t)
    };
    if ct == it || is_trait(&it) {
        return true;
    }
    // `<Def as Local>::alg` (or `Def::alg`) runs `Local::alg` when Def's impl does not write `alg`
    is_trait(&ct)
        && i.trait_name.as_deref().is_none_or(|t| type_name(t) == ct)
        && !src.items.iter().any(|b| {
            b.kind == ItemKind::Impl
                && b.name == it
                && b.trait_name.as_deref().map(type_name) == Some(ct.clone())
                && src.items.iter().any(|f| {
                    f.kind == ItemKind::Fn
                        && f.name == c.name
                        && b.contains(f.start)
                        && b.start != f.start
                })
        })
}
pub(super) fn in_item(item: &str) -> Option<InItem> {
    // the path's segments, generic arguments kept whole
    let chars: Vec<char> = item.chars().collect();
    let mut segs = Vec::new();
    let (mut depth, mut cur, mut k) = (0i32, String::new(), 0);
    while k < chars.len() {
        let c = chars[k];
        match c {
            '<' => depth += 1,
            '>' if k == 0 || chars[k - 1] != '-' => depth -= 1,
            _ => {}
        }
        if depth == 0 && c == ':' && chars.get(k + 1) == Some(&':') {
            segs.push(std::mem::take(&mut cur));
            k += 2;
            continue;
        }
        cur.push(c);
        k += 1;
    }
    segs.push(cur);
    let last_of = type_name;
    // generic arguments (`<J>`, `<..>`) and what the compiler makes (`{closure#0}`) are not
    // items written in the source; the arguments belong to the segment before them
    // (`Inner::<u8>::hash` is a method of `Inner<u8>`)
    let mut kept: Vec<(String, String)> = Vec::new();
    for g in segs {
        if g.starts_with('{') {
            continue;
        }
        if g.starts_with('<') && !g.contains(" as ") && !g.starts_with("<impl ") {
            if let Some((_, full)) = kept.last_mut() {
                full.push_str(&g);
            }
            continue;
        }
        kept.push((g.clone(), g));
    }
    let (name, _) = kept.pop()?;
    let name = name.strip_prefix("r#").unwrap_or(&name).to_string();
    // the modules: a plain path's segments after the crate, up to a type's or trait's
    let module = |g: &str| g.strip_prefix("r#").unwrap_or(g).to_string();
    let path_mods = |segs: &[String]| -> Vec<String> {
        segs.iter()
            .skip(1)
            .filter(|g| *g != "_")
            .map(|g| module(g))
            .collect()
    };
    let (mut mods, mut owner) = (None, None);
    let plain: Vec<String> = kept.iter().map(|(g, _)| g.clone()).collect();
    if plain.first().is_some_and(|g| !g.starts_with('<')) {
        match plain
            .iter()
            .skip(1)
            .position(|g| g.chars().next().is_some_and(char::is_uppercase))
        {
            Some(i) => owner = Some((plain[i + 1].clone(), path_mods(&plain[..=i]))),
            None => mods = Some(path_mods(&plain)),
        }
    } else if let Some(inner) = plain
        .last()
        .and_then(|g| g.strip_prefix('<'))
        .and_then(|g| g.strip_suffix('>'))
    {
        let t = inner.strip_prefix("impl ").unwrap_or(inner);
        let t = t.split(" as ").next().unwrap_or(t);
        let t = strip_generics(t);
        let segs: Vec<String> = t.trim().split("::").map(str::to_string).collect();
        if segs.len() >= 2
            && segs
                .iter()
                .all(|g| g.chars().all(is_ident) && !g.is_empty())
        {
            let ty = segs.last().cloned().unwrap_or_default();
            owner = Some((ty, path_mods(&segs[..segs.len() - 1])));
        }
    }
    let (mut self_ty, mut self_full, mut trait_name) = (None, None, None);
    if let Some((g, full)) = kept.last() {
        if let Some(inner) = g.strip_prefix('<').and_then(|g| g.strip_suffix('>')) {
            if let Some(t) = inner.strip_prefix("impl ") {
                self_ty = Some(last_of(t));
                self_full = Some(norm_path(t));
            } else if let Some((t, tr)) = inner.split_once(" as ") {
                self_ty = Some(last_of(t));
                self_full = Some(norm_path(t));
                trait_name = Some(norm_path(tr));
            }
        } else if g.chars().next().is_some_and(char::is_uppercase) {
            self_ty = Some(last_of(g));
            self_full = Some(norm_path(full));
        }
    }
    Some(InItem {
        path: item.to_string(),
        name: strip_generics(&name),
        self_ty,
        self_full,
        trait_name,
        mods,
        owner,
    })
}
/// The text of the attribute a position is in, from after its `#[` (or `#![`) to the position:
/// the code before the position, over a few lines, back to the last `#[` with its brackets still
/// open. None when the position is in no attribute.
pub(super) fn attribute_before(src: &Source, line: usize, offset: usize) -> Option<String> {
    let mut code = String::new();
    for l in (line.saturating_sub(12).max(1)..=line).rev() {
        let chars: Vec<char> = src.lines[l - 1].chars().collect();
        let end = if l == line {
            offset.min(chars.len())
        } else {
            chars.len()
        };
        let part: String = chars[..end]
            .iter()
            .zip(&src.class[l - 1])
            .map(|(&c, k)| if *k == Class::Code { c } else { ' ' })
            .collect();
        code = format!("{part}\n{code}");
        if let Some(i) = code.rfind("#[").or_else(|| code.rfind("#![")) {
            let open = code[i..].find('[').unwrap() + i + 1;
            let inner = &code[open..];
            let depth: i32 = inner
                .chars()
                .map(|c| match c {
                    '[' | '(' => 1,
                    ']' | ')' => -1,
                    _ => 0,
                })
                .sum();
            return (depth >= 0 && !inner.contains(']')).then(|| inner.trim_start().to_string());
        }
    }
    None
}
/// Whether, in an attribute's text up to a position, a `name(` is still open there.
pub(super) fn open_in(attr: &str, name: &str) -> bool {
    let Some(i) = attr.rfind(&format!("{name}(")).or_else(|| {
        Regex::new(&format!(r"{}\s+\(", regex::escape(name)))
            .unwrap()
            .find_iter(attr)
            .last()
            .map(|m| m.start())
    }) else {
        return false;
    };
    let mut depth = 0i32;
    for c in attr[i..].chars() {
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            _ => {}
        }
    }
    depth >= 1
}
impl FnScope {
    /// The innermost block around `i`.
    pub(super) fn block_of(&self, i: usize) -> (usize, usize) {
        self.blocks
            .iter()
            .filter(|&&(o, c)| o < i && i < c)
            .max()
            .copied()
            .unwrap_or(self.body)
    }
}
/// The names a pattern binds (`(a, b)`, `Some(f)`, `S { f, g: h }`, `ref mut x`, `x @ ..`),
/// its type annotation left out.
pub(super) fn pattern_names(s: &[char], a: usize, b: usize) -> Vec<String> {
    let end = scan_to(s, a, b, |i| {
        s[i] == ':' && s.get(i + 1) != Some(&':') && (i == 0 || s[i - 1] != ':')
    });
    let mut out = Vec::new();
    let mut i = a;
    while i < end {
        if !word_start(s, i) {
            i += 1;
            continue;
        }
        let w = word_of(s, i);
        let e = i + w.len();
        let first = w.chars().next().unwrap_or('_');
        // (the type annotation's `:` is not the pattern's)
        let next = Some(skip_blank(s, e))
            .filter(|&n| n < end)
            .and_then(|n| s.get(n))
            .copied();
        let path_seg = before_blank(s, i).is_some_and(|p| {
            s[p] == '.' || (s[p] == ':' && p > 0 && s[p - 1] == ':') || s[p] == '\''
        });
        let keyword = matches!(
            w.as_str(),
            "mut" | "ref" | "box" | "true" | "false" | "_" | "if" | "in" | "dyn" | "impl"
        );
        let follows = matches!(next, Some('(' | '{' | '!' | ':' | '<'));
        if !keyword
            && !path_seg
            && !follows
            && (first.is_lowercase() || (first == '_' && w.len() > 1))
        {
            out.push(w);
        }
        i = e;
    }
    out
}
/// The names a parameter list binds (`a: u8, (b, c): (T, T)`, `&mut self`): each parameter's
/// pattern, before its type.
pub(super) fn params_names(s: &[char], a: usize, b: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut p = a;
    while p < b {
        let e = scan_to(s, p, b, |i| s[i] == ',');
        let colon = scan_to(s, p, e, |i| {
            s[i] == ':' && s.get(i + 1) != Some(&':') && (i == 0 || s[i - 1] != ':')
        });
        if (p..colon).any(|i| kw(s, i, "self")) {
            out.push("self".to_string());
        } else {
            out.extend(pattern_names(s, p, colon));
        }
        p = e + 1;
    }
    out
}
/// Whether a `|` at `k` starts a closure (`|x| ..`, `|| ..`, `move |x|`), not an or-pattern or
/// an operator.
pub(super) fn closure_at(s: &[char], k: usize) -> bool {
    if s.get(k) != Some(&'|') || s.get(k + 1) == Some(&'=') {
        return false;
    }
    match before_blank(s, k) {
        None => true,
        Some(p) => match s[p] {
            '(' | ',' | '{' | ';' | '[' => true,
            '=' => !matches!(p.checked_sub(1).map(|q| s[q]), Some('=' | '!' | '<' | '>')),
            '>' => p > 0 && s[p - 1] == '=',
            ':' => !(p > 0 && s[p - 1] == ':'),
            c if is_ident(c) => matches!(
                word_before_at(s, k).as_str(),
                "move" | "async" | "return" | "static" | "else"
            ),
            _ => false,
        },
    }
}
/// A closure starting at the `|` at `k` (`closure_at`): its parameters' extent (none for `||`)
/// and its body's.
#[allow(clippy::type_complexity)]
pub(super) fn closure_parts(
    s: &[char],
    k: usize,
    limit: usize,
) -> Option<(Option<(usize, usize)>, (usize, usize))> {
    let (params, after) = if s.get(k + 1) == Some(&'|') {
        (None, k + 2)
    } else {
        let c = scan_to(s, k + 1, limit, |i| s[i] == '|');
        if s.get(c) != Some(&'|') {
            return None;
        }
        (Some((k + 1, c)), c + 1)
    };
    let mut j = skip_blank(s, after);
    if s.get(j) == Some(&'-') && s.get(j + 1) == Some(&'>') {
        j = scan_to(s, j + 2, limit, |i| s[i] == '{');
    }
    // (a turbofish's commas are no end: `|_| Ok::<_, ()>(&SHA1)`)
    let mut i = j;
    let end = loop {
        let e = scan_to(s, i, limit, |m| {
            s[m] == ','
                || s[m] == ';'
                || (s[m] == '<' && m >= 2 && s[m - 1] == ':' && s[m - 2] == ':')
        });
        if e < limit && s.get(e) == Some(&'<') {
            let cls = vec![Class::Code; s.len() - e];
            match skip_angle(&s[e..], &cls, 0) {
                Some(n) => {
                    i = e + n;
                    continue;
                }
                None => break e,
            }
        }
        break e;
    };
    Some((params, (j, end)))
}
/// Where `k` starts the body of an `async` closure (`async move |d| expr`: at `expr`): that
/// body's extent.
pub(super) fn async_body_at(s: &[char], k: usize) -> Option<(usize, usize)> {
    let p = before_blank(s, k).filter(|&p| s[p] == '|')?;
    let open = if p > 0 && s[p - 1] == '|' {
        p - 1
    } else {
        (0..p).rev().find(|&o| s[o] == '|')?
    };
    let asynch = match word_before_at(s, open).as_str() {
        "async" => true,
        "move" => {
            let m = before_blank(s, open)?;
            word_before_at(s, m + 1 - 4) == "async"
        }
        _ => false,
    };
    if !asynch || !closure_at(s, open) {
        return None;
    }
    let (_, (j, end)) = closure_parts(s, open, s.len())?;
    (j == k).then_some((k, end))
}
/// The extent of the closure or `async` block starting at `k` (`|x| ..`, `move || ..`, `async
/// move { .. }`, an `async fn`'s body `{ .. }`): from its first token to its body's end.
pub(super) fn closure_span(s: &[char], k: usize) -> Option<(usize, usize)> {
    let mut i = k;
    while ["async", "move", "static"].iter().any(|w| kw(s, i, w)) {
        i = skip_blank(s, i + word_of(s, i).len());
    }
    match s.get(i)? {
        '|' => {
            let (_, (_, end)) = closure_parts(s, i, s.len())?;
            Some((k, end))
        }
        '{' => Some((k, close_of_at(s, i)? + 1)),
        _ => None,
    }
}
impl Source {
    /// The bindings and parameters of the function `f`, an item of this file.
    pub(super) fn fn_scope(&self, f: &Item) -> Rc<FnScope> {
        let (a, b) = self.span(f);
        if let Some(sc) = self.scopes.borrow().get(&a) {
            return sc.clone();
        }
        let sc = Rc::new(scan_fn(self, a, b));
        self.scopes.borrow_mut().insert(a, sc.clone());
        sc
    }
}
/// Reads the bindings of the function at `a..b` of `src.code` (its `fn` keyword to its body's
/// end): those of its body, not of the functions nested in it, which see none of them.
pub(super) fn scan_fn(src: &Source, a: usize, b: usize) -> FnScope {
    let s = &src.code;
    let mut out = FnScope::default();
    // the signature: `fn name<..>(params) -> T where .. {`
    let name_at = skip_blank(s, a + 2);
    let mut i = skip_blank(s, name_at + word_of(s, name_at).len());
    if s.get(i) == Some(&'<') {
        let mut depth = 0;
        while i < b {
            match s[i] {
                '<' => depth += 1,
                '>' if s[i - 1] != '-' => {
                    depth -= 1;
                    if depth == 0 {
                        i += 1;
                        break;
                    }
                }
                _ => {}
            }
            i += 1;
        }
        i = skip_blank(s, i);
    }
    if s.get(i) == Some(&'(')
        && let Some(close) = close_of_at(s, i)
    {
        out.params = params_names(s, i + 1, close);
        i = close + 1;
    }
    let open = scan_to(s, i, b, |k| s[k] == '{');
    let Some(close) = close_of_at(s, open) else {
        return out;
    };
    out.body = (open, close + 1);
    // the blocks, for a `let`'s scope
    let mut blocks = Vec::new();
    let mut stack = Vec::new();
    for (k, &c) in s.iter().enumerate().take(close + 1).skip(open) {
        match c {
            '{' => stack.push(k),
            '}' => {
                if let Some(o) = stack.pop() {
                    blocks.push((o, k + 1));
                }
            }
            _ => {}
        }
    }
    let block_end = |k: usize| {
        blocks
            .iter()
            .filter(|&&(o, c)| o < k && k < c)
            .max()
            .map_or(close + 1, |&(_, c)| c)
    };
    let nested: Vec<(usize, usize)> = src
        .items
        .iter()
        .filter(|it| it.kind == ItemKind::Fn)
        .map(|it| src.span(it))
        .filter(|&(x, _)| x > open && x < close)
        .collect();
    // the file's macros whose expansion binds a name the invocation gives (`bind!(m)`)
    let letting: Vec<&str> = src
        .items
        .iter()
        .filter(|it| {
            it.kind == ItemKind::Macro && {
                let (x, y) = src.span(it);
                re!(r"\blet\s+(?:mut\s+)?\$").is_match(&src.text(x, y))
            }
        })
        .map(|it| it.name.as_str())
        .collect();
    let binds = &mut out.binds;
    let mut loops = Vec::new();
    let mut push = |pat: (usize, usize), kind, stmt, init, scope| {
        let names = if kind == BindKind::Closure {
            params_names(s, pat.0, pat.1)
        } else {
            pattern_names(s, pat.0, pat.1)
        };
        for name in names {
            binds.push(Bind {
                name,
                kind,
                stmt,
                pat,
                init,
                scope,
            });
        }
    };
    let mut k = open + 1;
    while k < close {
        if let Some(&(_, e)) = nested.iter().find(|&&(x, _)| x == k) {
            k = e;
            continue;
        }
        if closure_at(s, k)
            && let Some((params, body)) = closure_parts(s, k, close)
        {
            let pat = params.unwrap_or((k + 1, k + 1));
            push(pat, BindKind::Closure, (k, body.0), None, body);
            k = body.0.max(k + 1);
            continue;
        }
        if !word_start(s, k) {
            k += 1;
            continue;
        }
        let w = word_of(s, k);
        match w.as_str() {
            "let" => {
                let cond = matches!(word_before_at(s, k).as_str(), "if" | "while")
                    || before_blank(s, k).is_some_and(|p| s[p] == '&' && p > 0 && s[p - 1] == '&');
                let pat = k + 3;
                match let_eq_at(s, pat, close) {
                    None => {
                        // `let x;`: assigned later
                        let semi = scan_to(s, pat, close, |i| s[i] == ';');
                        push(
                            (pat, semi),
                            BindKind::Let,
                            (k, semi + 1),
                            None,
                            (semi + 1, block_end(k)),
                        );
                    }
                    Some(eq) if cond => {
                        let init_end = scan_to(s, eq + 1, close, |i| {
                            s[i] == '{' || (s[i] == '&' && s.get(i + 1) == Some(&'&'))
                        });
                        let blk = scan_to(s, init_end, close, |i| s[i] == '{');
                        let blk_end = close_of_at(s, blk).map_or(close, |c| c + 1);
                        if word_before_at(s, k) == "while" {
                            loops.push((blk, blk_end));
                        }
                        push(
                            (pat, eq),
                            BindKind::Cond,
                            (k, blk),
                            Some((eq + 1, init_end)),
                            (blk, blk_end),
                        );
                    }
                    Some(eq) => {
                        let init_end = scan_to(s, eq + 1, close, |i| {
                            s[i] == ';'
                                || (kw(s, i, "else")
                                    && before_blank(s, i).is_some_and(|p| s[p] != '}'))
                        });
                        let semi = scan_to(s, eq + 1, close, |i| s[i] == ';');
                        push(
                            (pat, eq),
                            BindKind::Let,
                            (k, semi + 1),
                            Some((eq + 1, init_end)),
                            (semi + 1, block_end(k)),
                        );
                    }
                }
            }
            "for" if s.get(skip_blank(s, k + 3)) != Some(&'<') => {
                let p = k + 3;
                let pin = scan_to(s, p, close, |i| {
                    kw(s, i, "in") || s[i] == '{' || s[i] == ';'
                });
                if kw(s, pin, "in") {
                    let blk = scan_to(s, pin + 2, close, |i| s[i] == '{');
                    if let Some(bc) = close_of_at(s, blk) {
                        loops.push((blk, bc + 1));
                        push(
                            (p, pin),
                            BindKind::For,
                            (k, blk),
                            Some((pin + 2, blk)),
                            (blk, bc + 1),
                        );
                    }
                }
            }
            "match" if before_blank(s, k).is_none_or(|p| s[p] != '.') => {
                let blk = scan_to(s, k + 5, close, |i| s[i] == '{');
                if let Some(mc) = close_of_at(s, blk) {
                    let scrut = (k + 5, blk);
                    let mut arm = blk + 1;
                    loop {
                        arm = skip_blank(s, arm);
                        if arm >= mc {
                            break;
                        }
                        let arrow =
                            scan_to(s, arm, mc, |i| s[i] == '=' && s.get(i + 1) == Some(&'>'));
                        if arrow >= mc {
                            break;
                        }
                        let pend = scan_to(s, arm, arrow, |i| kw(s, i, "if"));
                        let b0 = skip_blank(s, arrow + 2);
                        let (arm_end, next) = if s.get(b0) == Some(&'{') {
                            let e = close_of_at(s, b0).map_or(mc, |c| c + 1);
                            let n2 = skip_blank(s, e);
                            match s.get(n2) {
                                Some('.' | '?') => {
                                    let e = scan_to(s, b0, mc, |i| s[i] == ',');
                                    (e, e + 1)
                                }
                                Some(',') => (e, n2 + 1),
                                _ => (e, e),
                            }
                        } else {
                            let e = scan_to(s, b0, mc, |i| s[i] == ',');
                            (e, e + 1)
                        };
                        push(
                            (arm, pend),
                            BindKind::Arm,
                            (k, arrow + 2),
                            Some(scrut),
                            (arrow + 2, arm_end),
                        );
                        arm = next.max(arm + 1);
                    }
                }
            }
            _ if letting.contains(&w.as_str())
                && s.get(skip_blank(s, k + w.len())) == Some(&'!') =>
            {
                let ob = skip_blank(s, skip_blank(s, k + w.len()) + 1);
                if let Some(cb) = close_of_at(s, ob) {
                    let n2 = skip_blank(s, cb + 1);
                    let end = if s.get(n2) == Some(&';') {
                        n2 + 1
                    } else {
                        cb + 1
                    };
                    push(
                        (ob + 1, cb),
                        BindKind::Macro,
                        (k, end),
                        Some((k, cb + 1)),
                        (end, block_end(k)),
                    );
                }
            }
            "while" | "loop" if s.get(skip_blank(s, k + w.len())) != Some(&'!') => {
                // (a `while let`'s block is pushed with its binding)
                let n = skip_blank(s, k + w.len());
                if !kw(s, n, "let") {
                    let blk = scan_to(s, n, close, |i| s[i] == '{');
                    if let Some(bc) = close_of_at(s, blk) {
                        loops.push((blk, bc + 1));
                    }
                }
            }
            _ => {}
        }
        k += w.len();
    }
    out.blocks = blocks;
    out.loops = loops;
    out
}
