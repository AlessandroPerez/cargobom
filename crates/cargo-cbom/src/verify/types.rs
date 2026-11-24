//! Types the code says: of expressions, receivers, fields, returns and generic arguments; trait objects and coercions.

use super::*;

/// A type as an impl header or a context names it: a path's last segment without its
/// arguments (`&'a mut path::Type<A, B>` -> `Type`), a tuple, array or slice whole, blanks
/// and paths dropped (`(u8, u8)` -> `(u8,u8)`, `[u8; 32]` -> `[u8;32]`).
pub(super) fn type_name(t: &str) -> String {
    let t = t.trim().trim_start_matches(['&', '*']).trim();
    let t = t
        .strip_prefix("mut ")
        .or_else(|| t.strip_prefix("const "))
        .unwrap_or(t)
        .trim();
    let t = re!(r"^'\w+\s+").replace(t, "");
    let t = t.strip_prefix("mut ").unwrap_or(&t).trim();
    if t.starts_with('(') || t.starts_with('[') {
        return norm_path(t);
    }
    let t = strip_generics(t);
    let t = t
        .split_whitespace()
        .rfind(|w| !w.starts_with('\'') && *w != "mut" && *w != "dyn" && *w != "const")
        .unwrap_or("");
    t.rsplit("::").next().unwrap_or(t).trim().to_string()
}
/// A type that holds no algorithm: an integer, a float, `bool`, `char`, a string, bytes, a path
/// (`&[u8]`, `String`, `Vec<u8>`, `&mut [u8; 32]`).
pub(super) fn neutral_type(t: &str) -> bool {
    let d = deref_type(t);
    let d: String = d.chars().filter(|c| !c.is_whitespace()).collect();
    re!(r"^(?:u8|u16|u32|u64|u128|usize|i8|i16|i32|i64|i128|isize|f32|f64|bool|char|str|String|\[u8(?:;\w+)?\]|Vec<u8>|Path|PathBuf|OsStr|OsString)$")
        .is_match(&d)
}
/// A type or trait path as compared between a context and the source: paths cut to their last
/// segment at every level, lifetimes and blanks dropped (`core::convert::TryFrom<&rustls_pki_types::
/// PrivateKeyDer<'_>>` -> `TryFrom<&PrivateKeyDer>`).
pub(super) fn norm_path(t: &str) -> String {
    let t = re!(r"\b\w+::").replace_all(t.trim(), "");
    let t = re!(r"'\w+\s*,?").replace_all(&t, "");
    let t: String = t.chars().filter(|c| !c.is_whitespace()).collect();
    t.replace("<>", "").replace(",>", ">")
}
/// A type as written, then with the aliases it names replaced one, two and three levels deep.
/// Each is a candidate: an alias's own names are those of the file that defines it, and may be
/// other things where it is used (`type Aead = ChaCha20Poly1305;` of hpke's struct, used in a
/// file that imports chacha20poly1305's alias of that name).
pub(super) fn expansions(t: &str, aliases: &mut dyn FnMut(&str) -> Vec<String>) -> Vec<String> {
    let mut out = vec![t.to_string()];
    for depth in 1..=3 {
        let e = expand_aliases(t, aliases, depth);
        if !out.contains(&e) {
            out.push(e);
        }
    }
    out
}
/// A type with the aliases it names replaced by what they stand for, `depth` levels deep. A
/// name given arguments is a type, or a generic alias whose parameters they replace
/// (`kem::Ciphertext<XWingKem>` with kem's `type Ciphertext<K> = Array<u8, <K as Kem>::
/// CiphertextSize>;`: `aliases` is asked for `kem::Ciphertext<>` and answers
/// `K|Array<u8, <K as Kem>::CiphertextSize>`).
pub(super) fn expand_aliases(
    t: &str,
    aliases: &mut dyn FnMut(&str) -> Vec<String>,
    depth: usize,
) -> String {
    let mut out = String::new();
    let mut last = 0;
    let deeper = |e: &str, aliases: &mut dyn FnMut(&str) -> Vec<String>| {
        if depth > 1 {
            expand_aliases(e, aliases, depth - 1)
        } else {
            e.to_string()
        }
    };
    for m in re!(r"\b[A-Za-z_]\w*\b").find_iter(t) {
        if m.start() < last {
            continue;
        }
        if t[m.end()..].starts_with('<') {
            let Some(close) = angle_close(t, m.end()) else {
                continue;
            };
            // the path whole, for the package the alias is of
            let head = re!(r"(?:\b\w+\s*::\s*)*$")
                .find(&t[last..m.start()])
                .map_or(m.start(), |h| last + h.start());
            let args = split_top(&t[m.end() + 1..close]);
            let key = format!("{}<>", t[head..m.end()].replace(' ', ""));
            let found = aliases(&key).into_iter().find_map(|e| {
                let (params, target) = e.split_once('|')?;
                let params: Vec<String> = params.split(',').map(str::to_string).collect();
                (params.len() == args.len()).then(|| (params, target.to_string()))
            });
            if let Some((params, target)) = found {
                let names: Vec<String> = params.iter().map(|p| regex::escape(p)).collect();
                let replaced = match super::compiled(&format!(r"\b(?:{})\b", names.join("|"))) {
                    Ok(re) => re
                        .replace_all(&target, |c: &regex::Captures| {
                            params
                                .iter()
                                .position(|p| *p == c[0])
                                .map_or(c[0].to_string(), |k| args[k].trim().to_string())
                        })
                        .to_string(),
                    Err(_) => target,
                };
                out.push_str(&t[last..head]);
                out.push_str(&deeper(&replaced, aliases));
                last = close + 1;
            }
            continue;
        }
        if let Some(e) = aliases(m.as_str()).first()
            && e != m.as_str()
        {
            out.push_str(&t[last..m.start()]);
            out.push_str(&deeper(e, aliases));
            last = m.end();
        }
    }
    out.push_str(&t[last..]);
    out
}
/// Where the `<` at byte `open` of a type's text closes (not at a function type's `->`).
pub(super) fn angle_close(t: &str, open: usize) -> Option<usize> {
    let mut depth = 0i32;
    for (i, c) in t[open..].char_indices() {
        match c {
            '<' => depth += 1,
            '>' if !t[..open + i].ends_with('-') => {
                depth -= 1;
                if depth == 0 {
                    return Some(open + i);
                }
            }
            _ => {}
        }
    }
    None
}
/// typenum's unsigned integers as their aliases name them: `UInt<UInt<UTerm,B1>,B0>` is `U2`
/// (rustc prints the type, the source its alias).
pub(super) fn fold_typenum(t: &str) -> String {
    let mut t = t.replace("UTerm", "U0");
    loop {
        let n = re!(r"UInt<U(\d+),B([01])>")
            .replace_all(&t, |c: &regex::Captures| {
                let v: u128 = c[1].parse().unwrap_or(0);
                format!("U{}", v * 2 + u128::from(&c[2] == "1"))
            })
            .to_string();
        if n == t {
            return t;
        }
        t = n;
    }
}
pub(super) fn lookup(src: &Source, at: usize, name: &str) -> Option<Found> {
    let p = src.pos(at);
    let f = src.enclosing(p, &[ItemKind::Fn]);
    // (or the static whose value's code it is in: `static T: LazyLock<..> = LazyLock::new(|| {
    // let mut h = ..; h.insert(..); h });`)
    if let Some(f) = f.or_else(|| src.enclosing(p, &[ItemKind::Static])) {
        let sc = src.fn_scope(f);
        if let Some(b) = sc
            .binds
            .iter()
            .filter(|b| b.name == name && b.scope.0 <= at && at < b.scope.1)
            .max_by_key(|b| (b.scope.0, b.stmt.0))
        {
            return Some(Found::Bind(b.clone()));
        }
        if sc.params.iter().any(|n| n == name) && at >= sc.body.0 {
            return Some(Found::Param(f.name.clone()));
        }
    }
    src.items
        .iter()
        .enumerate()
        .filter(|(_, i)| i.kind == ItemKind::Static && i.name == name)
        .min_by_key(|(_, i)| !f.is_some_and(|f| f.contains(i.start)))
        .map(|(k, _)| Found::Item(k))
}
/// The receiver of a method called after the `.` at `dot`: the variable (or path) its
/// expression starts with (`ho` of `ho.run(..)`, `keys` of `keys["a"].seal(..)`), and the
/// expression's extent.
pub(super) fn receiver_at(s: &[char], dot: usize) -> Option<(usize, String, usize)> {
    let mut j = dot;
    let mut root = None;
    while let Some(p) = before_blank(s, j) {
        match s[p] {
            ')' | ']' => j = open_of_at(s, p)?,
            '?' => j = p,
            c if is_ident(c) => {
                let mut b = p + 1;
                while b > 0 && is_ident(s[b - 1]) {
                    b -= 1;
                }
                root = Some(b);
                match before_blank(s, b) {
                    Some(q) if s[q] == '.' => j = q,
                    Some(q) if s[q] == ':' && q > 0 && s[q - 1] == ':' => j = q - 1,
                    _ => break,
                }
            }
            _ => break,
        }
    }
    let r = root?;
    Some((r, word_of(s, r), dot))
}
/// The type the code says the receiver of the method call at `i` has, as it writes it
/// (`StreamDecryptorInner<Aes128, R>`, with its arguments).
pub(super) fn receiver_written(src: &Source, i: usize) -> Option<String> {
    let s = &src.code;
    let dot = before_blank(s, i).filter(|&d| s[d] == '.')?;
    // (a parenthesized receiver, `(&e1).ext()`: what is inside)
    let r = match before_blank(s, dot).filter(|&p| s[p] == ')') {
        Some(p) => {
            let mut depth = 0;
            let mut k = p + 1;
            loop {
                k = k.checked_sub(1)?;
                match s[k] {
                    ')' => depth += 1,
                    '(' => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    _ => {}
                }
            }
            if before_blank(s, k).is_some_and(|q| is_ident(s[q])) {
                receiver_at(s, dot)?.0
            } else {
                k
            }
        }
        None => receiver_at(s, dot)?.0,
    };
    expr_type(src, r, dot, 5)
}
/// The type of the value a method called at `i` (`E1.ext()`, `W(S1).alg()`, `g.alg()` with `let
/// g = &W(S2);`, `p.b.ext()` with `p` a `Pair` whose `b` is an `E2`, `mk1().ext()`, `e.ext()` with
/// `let e = E1.upgrade();`) is called on, when the code says which type of the file it is: `None`
/// when it does not (a parameter of a type parameter, a trait object, a value of another crate's
/// type).
pub(super) fn receiver_type(src: &Source, i: usize) -> Option<String> {
    let mut ty = type_name(&deref_type(&receiver_written(src, i)?));
    // (a type alias of the file: `type A2 = E2;`; an associated type is the one of the impl
    // around the call, `Self::SigningKey` in `impl Algorithm for Hs384` being that impl's
    // `type SigningKey = Hs384Key;`, not another impl's of the same name)
    let around = src.enclosing(src.pos(i), &[ItemKind::Impl]);
    let code: String = src.code.iter().collect();
    for _ in 0..4 {
        // (also one with parameters: `type RequestSendInner<'a> = request_native::RequestSend<'a>;`)
        let Ok(re) = super::compiled(&format!(
            r"\btype\s+{}\s*(?:<[^=;{{}}]*>)?\s*=\s*([^;<]+)",
            regex::escape(&ty)
        )) else {
            break;
        };
        let defs: Vec<((usize, usize), String)> = re
            .captures_iter(&code)
            .map(|m| {
                let at = code[..m.get(0).map_or(0, |g| g.start())].chars().count();
                (src.pos(at), type_name(m[1].trim()))
            })
            .collect();
        let in_block = |p: (usize, usize)| {
            src.items
                .iter()
                .any(|o| matches!(o.kind, ItemKind::Impl | ItemKind::Trait) && o.contains(p))
        };
        let own = defs
            .iter()
            .find(|(p, _)| around.is_some_and(|b| b.contains(*p)));
        match own.or_else(|| defs.iter().find(|(p, _)| !in_block(*p))) {
            Some((_, t)) => ty = t.clone(),
            None => break,
        }
    }
    src.items
        .iter()
        .any(|it| it.kind == ItemKind::TypeDef && it.name == ty)
        .then_some(ty)
}
/// The type arguments of a generic function's instance as a context names it (`g2::pass::<g2::A>`:
/// `[g2::A]`); `None` for a method, a closure or an item without them.
pub(super) fn instance_args(path: &str) -> Option<Vec<String>> {
    let p = path.trim();
    if p.starts_with('<') || !p.ends_with('>') {
        return None;
    }
    let chars: Vec<char> = p.chars().collect();
    let mut depth = 0i32;
    let mut open = None;
    for k in (0..chars.len()).rev() {
        match chars[k] {
            '>' if k == 0 || chars[k - 1] != '-' => depth += 1,
            '<' => {
                depth -= 1;
                if depth == 0 {
                    open = Some(k);
                    break;
                }
            }
            _ => {}
        }
    }
    let o = open?;
    if o < 2 || chars[o - 1] != ':' || chars[o - 2] != ':' {
        return None;
    }
    // the segment before: a function's name, not a type's
    let before: String = chars[..o - 2].iter().collect();
    let name = before.rsplit("::").next().unwrap_or("");
    if !name.starts_with(|c: char| c.is_lowercase() || c == '_') {
        return None;
    }
    let inner: String = chars[o + 1..chars.len() - 1].iter().collect();
    // (`<..>`: arguments the context leaves out)
    if inner.contains("..") {
        return None;
    }
    Some(
        split_top(&inner)
            .into_iter()
            .map(|a| a.trim().to_string())
            .collect(),
    )
}
/// A type as a method or field is looked up on: references, `mut`, lifetimes and the smart
/// pointers a method call sees through (`Box`, `Rc`, `Arc`) dropped, a path cut to its last
/// segment with its arguments (`&'a mut Box<m::Vec<E2>>` -> `Vec<E2>`). A trait object (`dyn`,
/// `impl`) is no type of the file: empty.
pub(super) fn deref_type(t: &str) -> String {
    let t = deref_path(t);
    if t.is_empty() {
        return t;
    }
    // the last segment of the path, outside its arguments
    let chars: Vec<char> = t.chars().collect();
    let (mut depth, mut cut) = (0i32, 0);
    for (k, &c) in chars.iter().enumerate() {
        match c {
            '<' | '(' | '[' => depth += 1,
            '>' | ')' | ']' => depth -= 1,
            ':' if depth == 0 && chars.get(k + 1) == Some(&':') => cut = k + 2,
            _ => {}
        }
    }
    chars[cut.min(chars.len())..]
        .iter()
        .collect::<String>()
        .trim()
        .to_string()
}
/// `deref_type` with the path kept whole (`&m::K` -> `m::K`).
pub(super) fn deref_path(t: &str) -> String {
    let mut t = t.trim().to_string();
    loop {
        let before = t.clone();
        t = t.trim_start_matches('&').trim().to_string();
        t = re!(r"^'\w+\s*").replace(&t, "").trim().to_string();
        if let Some(r) = t.strip_prefix("mut ") {
            t = r.trim().to_string();
        }
        if let Some(m) = re!(r"^(?:\w+\s*::\s*)*(?:Box|Rc|Arc)\s*<(.*)>$").captures(&t) {
            t = m[1].trim().to_string();
        }
        if t == before {
            break;
        }
    }
    if t.starts_with("dyn ") || t.starts_with("impl ") {
        return String::new();
    }
    t
}
/// The arguments of a type (`Vec<E2>`: `[E2]`; `HashMap<K, V>`: `[K, V]`).
pub(super) fn type_args(t: &str) -> Vec<String> {
    let t = t.trim();
    match (t.find('<'), t.ends_with('>')) {
        (Some(o), true) => split_top(&t[o + 1..t.len() - 1])
            .into_iter()
            .map(|a| a.trim().to_string())
            .filter(|a| !a.starts_with('\''))
            .collect(),
        _ => Vec::new(),
    }
}
/// The type of an element of a value of type `t` read by an index (`Vec<X>`, `[X; N]`, `&[X]`,
/// `VecDeque<X>`: `X`).
pub(super) fn elem_type(t: &str) -> Option<String> {
    let t = deref_type(t);
    if let Some(inner) = t.strip_prefix('[').and_then(|x| x.strip_suffix(']')) {
        return split_top(inner.split(';').next().unwrap_or(inner))
            .first()
            .map(|x| x.trim().to_string());
    }
    let base = type_name(&t);
    matches!(base.as_str(), "Vec" | "VecDeque" | "SmallVec" | "ArrayVec")
        .then(|| type_args(&t).into_iter().next())
        .flatten()
}
pub(super) fn fn_sig(src: &Source, f: &Item) -> FnSig {
    let s = &src.code;
    let (a, b) = src.span(f);
    let mut out = FnSig {
        generics: Vec::new(),
        params: Vec::new(),
        ret: None,
    };
    let name_at = skip_blank(s, a + 2);
    let mut i = skip_blank(s, name_at + word_of(s, name_at).len());
    if s.get(i) == Some(&'<') {
        let cls = vec![Class::Code; s.len() - i];
        let Some(e) = skip_angle(&s[i..], &cls, 0) else {
            return out;
        };
        out.generics = split_top(&src.text(i + 1, i + e - 1))
            .iter()
            .filter_map(|g| {
                let g = g.trim().trim_start_matches("const ").trim();
                let n: String = g.chars().take_while(|c| is_ident(*c)).collect();
                (!n.is_empty() && !g.starts_with('\'')).then_some(n)
            })
            .collect();
        i = skip_blank(s, i + e);
    }
    let Some(close) = (s.get(i) == Some(&'('))
        .then(|| close_of_at(s, i))
        .flatten()
    else {
        return out;
    };
    for p in split_top(&src.text(i + 1, close)) {
        let p = p.trim();
        if p.is_empty() {
            continue;
        }
        let pc: Vec<char> = p.chars().collect();
        let colon = (0..pc.len())
            .find(|&k| pc[k] == ':' && pc.get(k + 1) != Some(&':') && (k == 0 || pc[k - 1] != ':'));
        match colon {
            Some(k) => {
                let pat: String = pc[..k].iter().collect();
                let ty: String = pc[k + 1..].iter().collect();
                if re!(r"\bself\b").is_match(&pat) {
                    out.params.push(("self".into(), ty.trim().to_string()));
                } else {
                    out.params
                        .push((pat.trim().to_string(), ty.trim().to_string()));
                }
            }
            None if re!(r"\bself\b").is_match(p) => out.params.push(("self".into(), "Self".into())),
            None => out.params.push((p.to_string(), String::new())),
        }
    }
    let open = scan_to(s, close + 1, b, |k| s[k] == '{' || s[k] == ';');
    let tail = src.text(close + 1, open);
    if let Some(r) = tail.trim_start().strip_prefix("->") {
        let r = r.split(" where ").next().unwrap_or(r);
        let r = re!(r"\bwhere\b").split(r).next().unwrap_or(r);
        out.ret = Some(r.trim().to_string());
    }
    out
}
/// The impl block (or trait) a function of the file is a method of.
pub(super) fn impl_of<'a>(src: &'a Source, f: &Item) -> Option<&'a Item> {
    src.items
        .iter()
        .filter(|b| {
            matches!(b.kind, ItemKind::Impl | ItemKind::Trait)
                && b.contains(f.start)
                && b.start != f.start
        })
        .max_by_key(|b| b.start)
}
/// The brackets around the fields of the file's struct `ty` (`{ .. }` or `( .. )`).
pub(super) fn struct_fields(src: &Source, ty: &str) -> Option<(usize, usize)> {
    let s = &src.code;
    let def = src.items.iter().find(|it| {
        it.kind == ItemKind::TypeDef && it.name == ty && kw(s, src.idx(it.start), "struct")
    })?;
    let at = src.idx(def.start);
    let mut i = skip_blank(s, at + 6);
    i = skip_blank(s, i + word_of(s, i).len());
    if s.get(i) == Some(&'<') {
        let cls = vec![Class::Code; s.len() - i];
        i = skip_blank(s, i + skip_angle(&s[i..], &cls, 0)?);
    }
    let open = scan_to(s, i, s.len(), |k| matches!(s[k], '{' | '(' | ';'));
    Some((open, close_of_at(s, open)?))
}
/// The declared type of field `field` (a name, or a tuple index) of the file's struct `ty`.
pub(super) fn field_type(src: &Source, ty: &str, field: &str) -> Option<String> {
    let s = &src.code;
    let (open, close) = struct_fields(src, ty)?;
    let fields = split_top(&src.text(open + 1, close));
    if s[open] == '(' {
        let k: usize = field.parse().ok()?;
        let f = fields.get(k)?.trim();
        return Some(f.trim_start_matches("pub").trim().to_string());
    }
    fields.iter().find_map(|f| {
        let f = f.trim();
        let f = re!(r"^(?:#\[[^\]]*\]\s*)*(?:pub(?:\s*\([^)]*\))?\s+)?").replace(f, "");
        let (n, t) = f.split_once(':')?;
        (n.trim() == field).then(|| t.trim().to_string())
    })
}
/// The return type of the file's method or associated function `name` of type `ty` (its impl's,
/// or the default body of a trait it implements), `Self` read as `ty`.
pub(super) fn method_ret(src: &Source, ty: &str, name: &str) -> Option<String> {
    let fns: Vec<&Item> = src
        .items
        .iter()
        .filter(|f| f.kind == ItemKind::Fn && f.name == name)
        .collect();
    let own = fns
        .iter()
        .find(|f| impl_of(src, f).is_some_and(|b| b.kind == ItemKind::Impl && b.name == ty));
    let f = own.or_else(|| {
        fns.iter().find(|f| {
            impl_of(src, f).is_some_and(|t| {
                t.kind == ItemKind::Trait
                    && src.items.iter().any(|b| {
                        b.kind == ItemKind::Impl
                            && (b.name == ty || b.name.is_empty())
                            && b.trait_name.as_deref().map(type_name) == Some(t.name.clone())
                    })
            })
        })
    })?;
    let ret = fn_sig(src, f).ret?;
    Some(re!(r"\bSelf\b").replace_all(&ret, ty).to_string())
}
/// The type the file's static or const `name`, read at `at`, is declared with.
fn item_type(src: &Source, at: usize, name: &str) -> Option<String> {
    let Some(Found::Item(k)) = lookup(src, at, name) else {
        return None;
    };
    let s = &src.code;
    let (x, y) = src.span(&src.items[k]);
    let colon = scan_to(s, x, y, |k| s[k] == ':');
    // (to its `=`, outside the type's brackets: `Box<dyn Iterator<Item = u8>>`)
    let mut depth = 0i32;
    let eq = (colon..y).find(|&k| {
        match s[k] {
            '<' | '(' | '[' => depth += 1,
            '>' if s[k - 1] != '-' => depth -= 1,
            ')' | ']' => depth -= 1,
            _ => {}
        }
        s[k] == '=' && depth == 0
    })?;
    Some(src.text(colon + 1, eq).trim().to_string())
}
/// The type of the expression at `a..b` of `code` (a variable, a path to a value or a function
/// of the file called, a struct literal, `vec![..]`, then fields, tuple fields, indexes, `?` and
/// the file's methods called), as far as the code says: `None` where it does not.
pub(super) fn expr_type(src: &Source, a: usize, b: usize, depth: usize) -> Option<String> {
    if depth == 0 {
        return None;
    }
    let s = &src.code;
    let b = b.min(s.len());
    let mut i = skip_blank(s, a);
    // references and derefs: a method or field is looked up on what they point to
    loop {
        if s.get(i) == Some(&'&') || s.get(i) == Some(&'*') {
            i = skip_blank(s, i + 1);
            if kw(s, i, "mut") {
                i = skip_blank(s, i + 3);
            }
            continue;
        }
        break;
    }
    if i >= b {
        return None;
    }
    let mut ty: String;
    if s[i] == '(' {
        let c = close_of_at(s, i)?;
        if scan_to(s, i + 1, c, |k| s[k] == ',') < c {
            return None;
        }
        ty = expr_type(src, i + 1, c, depth - 1)?;
        i = c + 1;
    } else if s[i] == '[' {
        // an array literal (`[E1, E1]`): of its first element's type
        let c = close_of_at(s, i)?;
        let e = scan_to(s, i + 1, c, |k| s[k] == ',' || s[k] == ';');
        ty = format!("[{}]", expr_type(src, i + 1, e, depth - 1)?);
        i = c + 1;
    } else if word_start(s, i) {
        let start = i;
        let mut segs: Vec<String> = Vec::new();
        loop {
            let w = word_of(s, i);
            i += w.chars().count();
            segs.push(w);
            let j = skip_blank(s, i);
            if s.get(j) == Some(&':') && s.get(j + 1) == Some(&':') {
                let mut k = skip_blank(s, j + 2);
                if s.get(k) == Some(&'<') {
                    let cls = vec![Class::Code; s.len() - k];
                    k = skip_blank(s, k + skip_angle(&s[k..], &cls, 0)?);
                    i = k;
                    if s.get(k) == Some(&':') && s.get(k + 1) == Some(&':') {
                        k = skip_blank(s, k + 2);
                    } else {
                        break;
                    }
                }
                if word_start(s, k) {
                    i = k;
                    continue;
                }
            }
            break;
        }
        let last = segs.last()?.clone();
        let n = skip_blank(s, i);
        let upper = last.starts_with(char::is_uppercase);
        let is_type = |t: &str| {
            src.items
                .iter()
                .any(|it| it.kind == ItemKind::TypeDef && it.name == t)
        };
        let around = |k: usize| -> Option<String> {
            src.enclosing(src.pos(k), &[ItemKind::Impl])
                .map(|b| b.name.clone())
                .filter(|n| !n.is_empty())
        };
        if upper
            && segs.len() == 1
            && matches!(last.as_str(), "Some" | "Ok")
            && s.get(n) == Some(&'(')
        {
            // `Some(E1)`: an `Option` of what it holds
            let c = close_of_at(s, n)?;
            ty = format!("Option<{}>", expr_type(src, n + 1, c, depth - 1)?);
            i = c + 1;
        } else if upper {
            // a struct literal, a tuple struct's or variant's constructor, a unit struct
            if matches!(s.get(n), Some('{' | '(')) {
                i = close_of_at(s, n)? + 1;
            }
            ty = if is_type(&last) {
                last
            } else if segs.len() >= 2 && is_type(&segs[segs.len() - 2]) {
                segs[segs.len() - 2].clone()
            } else if last == "Self" {
                around(start)?
            } else if segs.len() == 1 && !matches!(s.get(n), Some('{' | '(')) {
                // (a static or const, named in capitals as they are)
                item_type(src, start, &last)?
            } else {
                return None;
            };
        } else if s.get(n) == Some(&'!') {
            // `vec![X, ..]`: a `Vec` of the first element's type
            let o = skip_blank(s, n + 1);
            let c = close_of_at(s, o)?;
            if last != "vec" {
                return None;
            }
            let e = scan_to(s, o + 1, c, |k| s[k] == ',' || s[k] == ';');
            ty = format!("Vec<{}>", expr_type(src, o + 1, e, depth - 1)?);
            i = c + 1;
        } else if s.get(n) == Some(&'(') {
            let c = close_of_at(s, n)?;
            i = c + 1;
            if segs.len() >= 2 && segs[segs.len() - 2].starts_with(char::is_uppercase) {
                let q = &segs[segs.len() - 2];
                let q = if q == "Self" {
                    around(start)?
                } else {
                    q.clone()
                };
                // (`E1::default()` of a derived `Default`: an `E1`)
                ty = match method_ret(src, &q, &last) {
                    Some(t) => t,
                    None if last == "default" && is_type(&q) => q,
                    None => return None,
                };
            } else {
                if segs.len() == 1 && matches!(binding(src, start, &last), Some(Bound::Let { .. }))
                {
                    // a closure or pointer held by a variable
                    return None;
                }
                let f = free_fn_called(src, start, &last, &segs[..segs.len() - 1])?;
                let sig = fn_sig(src, f);
                let r = sig.ret?;
                if sig
                    .generics
                    .iter()
                    .any(|g| re!(r"\w+").find_iter(&r).any(|m| m.as_str() == g))
                {
                    return None;
                }
                ty = r;
            }
        } else if segs.len() == 1 && last == "self" {
            ty = around(start)?;
        } else if segs.len() == 1 {
            ty = match binding(src, start, &last)? {
                Bound::Let { .. } => {
                    let Some(Found::Bind(bd)) = lookup(src, start, &last) else {
                        return None;
                    };
                    // the annotation (`let x: T = ..`), else the initializer's type, for a
                    // binding of the whole value (not a pattern's part)
                    let pat = src.text(bd.pat.0, bd.pat.1);
                    let (p, annot) = match pat.split_once(':') {
                        Some((p, t)) if !t.starts_with(':') => (p.trim().to_string(), Some(t)),
                        _ => (pat.trim().to_string(), None),
                    };
                    let p = p.trim_start_matches("mut ").trim();
                    // the payload of an enum's variant a `match` arm or an `if let` binds
                    // (`Self::Aes128(i) => i.fill_buf()`): the type the enum declares for it
                    if matches!(bd.kind, BindKind::Arm | BindKind::Cond)
                        && let Some(m) =
                            re!(r"^&?\s*((?:\w+\s*::\s*)+)(\w+)\s*\(([^()]*)\)$").captures(p)
                        && let Some(k) = split_top(&m[3]).iter().position(|x| {
                            let x = x.trim();
                            let x = x.strip_prefix("ref ").unwrap_or(x).trim();
                            x.strip_prefix("mut ").unwrap_or(x).trim() == last
                        })
                    {
                        let owner = m[1].trim().trim_end_matches(':').trim();
                        let owner = owner.rsplit("::").next().unwrap_or(owner).trim();
                        let owner = if owner == "Self" {
                            around(start)?
                        } else {
                            owner.to_string()
                        };
                        return variant_field(src, &owner, &m[2], k);
                    }
                    if p != last || !matches!(bd.kind, BindKind::Let) {
                        return None;
                    }
                    match annot {
                        Some(t) => t.trim().to_string(),
                        None => {
                            let (x, y) = bd.init?;
                            expr_type(src, x, y, depth - 1)?
                        }
                    }
                }
                Bound::Param { .. } => {
                    let f = src.enclosing(src.pos(start), &[ItemKind::Fn])?;
                    let sig = fn_sig(src, f);
                    let t = sig
                        .params
                        .iter()
                        .find(|(p, _)| p.trim_start_matches("mut ").trim() == last)?;
                    let base = type_name(&deref_type(&t.1));
                    if sig.generics.contains(&base) {
                        return None;
                    }
                    t.1.clone()
                }
                // a static or const of the file: the type it is declared with
                Bound::Item { .. } => item_type(src, start, &last)?,
                _ => return None,
            };
        } else {
            return None;
        }
    } else {
        return None;
    }
    // fields, tuple fields, indexes, `?`, method calls
    loop {
        let j = skip_blank(s, i);
        if j >= b {
            break;
        }
        match s[j] {
            '.' => {
                let k = skip_blank(s, j + 1);
                let w = word_of(s, k);
                if w.is_empty() {
                    return None;
                }
                let mut n = skip_blank(s, k + w.chars().count());
                if s.get(n) == Some(&':') && s.get(n + 1) == Some(&':') {
                    let o = skip_blank(s, n + 2);
                    let cls = vec![Class::Code; s.len() - o];
                    n = skip_blank(s, o + skip_angle(&s[o..], &cls, 0)?);
                }
                let base = type_name(&deref_type(&ty));
                if s.get(n) == Some(&'(') {
                    i = close_of_at(s, n)? + 1;
                    ty = match w.as_str() {
                        // what these return is the value itself, as far as a method sees
                        "clone" | "as_ref" | "as_mut" | "borrow" | "borrow_mut" | "to_owned"
                        | "deref" | "deref_mut" | "by_ref" => ty,
                        "unwrap" | "expect" | "unwrap_or_default" => {
                            type_args(&deref_type(&ty)).into_iter().next()?
                        }
                        _ => method_ret(src, &base, &w)?,
                    };
                } else {
                    // a field, or a tuple field (`.0`), of a struct or of a tuple
                    i = k + w.chars().count();
                    let d = deref_type(&ty);
                    ty = match (d.trim().strip_prefix('('), w.parse::<usize>()) {
                        (Some(inner), Ok(k)) => split_top(inner.strip_suffix(')')?)
                            .get(k)?
                            .trim()
                            .to_string(),
                        _ => field_type(src, &base, &w)?,
                    };
                }
            }
            '[' => {
                i = close_of_at(s, j)? + 1;
                ty = elem_type(&ty)?;
            }
            '?' => {
                i = j + 1;
                ty = type_args(&deref_type(&ty)).into_iter().next()?;
            }
            _ => break,
        }
    }
    Some(ty)
}
/// The traits of the `dyn` types a type names (`Box<dyn Pick>`: `Pick`; `&(dyn Konst + Sync)`:
/// `Konst`, `Sync`), by their last segment.
pub(super) fn dyn_traits(t: &str) -> Vec<String> {
    let mut out = Vec::new();
    for m in re!(
        r"\bdyn\s+([\w:]+(?:<[^<>]*(?:<[^<>]*>[^<>]*)*>)?(?:\s*\+\s*(?:[\w:]+(?:<[^<>]*>)?|'\w+))*)"
    )
    .captures_iter(t)
    {
        for b in m[1].split('+') {
            let b = b.trim();
            if !b.is_empty() && !b.starts_with('\'') {
                out.push(type_name(b));
            }
        }
    }
    out
}
/// `dyn_traits`, through the file's type aliases (`type BoxPick = Box<dyn Pick>;`) and the
/// traits it imports under another name (`use m::Pick as Chooser;`: `Pick`).
pub(super) fn dyn_traits_src(src: &Source, t: &str) -> Vec<String> {
    let mut v = dyn_traits(t);
    if v.is_empty() {
        let name = type_name(
            t.trim()
                .trim_start_matches('&')
                .trim_start_matches("mut ")
                .trim(),
        );
        if !name.is_empty()
            && name.chars().all(is_ident)
            && let Ok(re) = super::compiled(&format!(
                r"\btype\s+{}\b[^=;]*=\s*([^;]+);",
                regex::escape(&name)
            ))
        {
            let code: String = src.code.iter().collect();
            if let Some(m) = re.captures(&code) {
                v = dyn_traits(&m[1]);
            }
        }
    }
    v.into_iter().map(|t| trait_alias(src, &t)).collect()
}
/// The trait a name the file imports under another name stands for (`use m::Pick as Chooser;`:
/// `Chooser` is `Pick`, and so it is after `use Pick as Chooser;` beside the trait); the name
/// itself otherwise.
pub(super) fn trait_alias(src: &Source, t: &str) -> String {
    src.binds
        .iter()
        .find(|b| b.name == t)
        .and_then(|b| b.path.last().cloned())
        .unwrap_or_else(|| t.to_string())
}
/// The type the file's enum `owner` declares for field `idx` of its tuple variant `variant`
/// (`enum D<R> { Aes128(Inner<Aes128, R>), .. }`: `Inner<Aes128, R>`).
pub(super) fn variant_field(
    src: &Source,
    owner: &str,
    variant: &str,
    idx: usize,
) -> Option<String> {
    let it = src.items.iter().find(|it| {
        it.kind == ItemKind::TypeDef && it.name == owner && kw(&src.code, src.idx(it.start), "enum")
    })?;
    let a = src.idx(it.start);
    let open = scan_to(&src.code, a, src.code.len(), |k| {
        matches!(src.code[k], '{' | ';')
    });
    let close = close_of_at(&src.code, open)?;
    let text = src.text(open, close);
    let var = super::compiled(&format!(r"[{{,]\s*{}\s*\(", regex::escape(variant))).ok()?;
    let m = var.find(&text)?;
    let paren = open + text[..m.end()].chars().count() - 1;
    let end = close_of_at(&src.code, paren)?;
    split_top(&src.text(paren + 1, end))
        .get(idx)
        .map(|f| f.trim().trim_start_matches("pub").trim().to_string())
}
/// The parentheses of the call written from `p` (`<dyn Tr>::f(..)`, `a::b::<T>(..)`, a method's
/// name and its arguments): the indexes of its `(` and `)`.
fn written_call(s: &[char], p: usize) -> Option<(usize, usize)> {
    let mut j = p;
    loop {
        j = skip_blank(s, j);
        if word_start(s, j) {
            j += word_of(s, j).chars().count();
        } else if s.get(j) == Some(&':') && s.get(j + 1) == Some(&':') {
            j += 2;
        } else if s.get(j) == Some(&'<') {
            let cls = vec![Class::Code; s.len() - j];
            j += skip_angle(&s[j..], &cls, 0)?;
        } else if s.get(j) == Some(&'(') {
            return Some((j, close_of_at(s, j)?));
        } else {
            return None;
        }
    }
}
/// Whether the call at `p` is a path called with no argument (`<dyn MessageEncrypter>::
/// invalid()`): it has no receiver, and no value a trait object could be. Not a method's call
/// (`x.f()`, whose receiver is before it), nor what is not written as a path and its arguments.
pub(super) fn call_of_no_value(src: &Source, p: usize) -> bool {
    let s = &src.code;
    !before_blank(s, p).is_some_and(|d| s[d] == '.')
        && written_call(s, p)
            .is_some_and(|(open, close)| open > p && skip_blank(s, open + 1) == close)
}
/// The traits of the trait objects the call at `p` calls methods on (`digest(g.alg(), d)` with
/// `g: Box<dyn Gen>`: `Gen`), in its arguments and receiver: None where it calls none, or one on
/// a value whose type the code does not say (a type parameter's, a call's not followed).
pub(super) fn call_dyn_receivers(src: &Source, p: usize) -> Option<Vec<String>> {
    let s = &src.code;
    let (_, end) = written_call(s, p)?;
    let start = before_blank(s, p)
        .filter(|&d| s[d] == '.')
        .and_then(|dot| receiver_at(s, dot).map(|(r, _, _)| r))
        .unwrap_or(p);
    let (mut out, mut any) = (Vec::new(), false);
    for k in start..end {
        if s[k] != '.' {
            continue;
        }
        let m = skip_blank(s, k + 1);
        let w = word_of(s, m);
        if w.is_empty() || s.get(skip_blank(s, m + w.chars().count())) != Some(&'(') {
            continue;
        }
        let (r, _, _) = receiver_at(s, k)?;
        let t = expr_type(src, r, k, 5)?;
        any = true;
        out.extend(dyn_traits_src(src, &t));
    }
    any.then_some(out)
}

/// Whether an impl block's self type, as written (`impl Put for &mut A`), is the type a context
/// names in full (`<&mut &'static ring::digest::Algorithm as Put>`): its references and type
/// arguments kept, the aliases it names replaced (the one in scope at the block first, else the
/// package's): `None` where that is not to be compared so (a type of the impl's own parameters,
/// no full type in the context, a bare name naming no alias of the file), left to `same_type`.
pub(super) fn written_self(
    src: &Source,
    block: &Item,
    full: Option<&str>,
    aliases: &mut dyn FnMut(&str) -> Vec<String>,
) -> Option<bool> {
    // (a context that elides the type's arguments, `Builder::<..>`, says no more than its name)
    let full = full.filter(|f| !f.contains(".."))?;
    let (ty, own) = impl_self(src, block)?;
    let ty = ty.as_str();
    let names: Vec<&str> = re!(r"\b[A-Za-z_]\w*\b")
        .find_iter(ty)
        .map(|m| m.as_str())
        .collect();
    if names.iter().any(|n| own.iter().any(|o| o == n)) {
        return None;
    }
    let at = src.idx(block.start);
    // the file's aliases in scope at the block, by their paths whole (`m::K`)
    let local = std::cell::Cell::new(false);
    let resolved =
        re!(r"\b[A-Za-z_]\w*(?:\s*::\s*[A-Za-z_]\w*)*").replace_all(ty, |m: &regex::Captures| {
            match src.alias_at(at, &m[0]) {
                Some(d) => {
                    local.set(true);
                    d
                }
                None => imported_as(src, &m[0]),
            }
        });
    let shaped = ty.contains(['&', '<', '(', '[', '*']);
    if !local.get() && !shaped {
        return None;
    }
    // (then the package's, by name)
    let candidates = expansions(&resolved, aliases);
    let expanded = candidates.last().cloned().unwrap_or_default();
    let (written, named) = (
        fold_typenum(&norm_path(&expanded)),
        fold_typenum(&norm_path(full)),
    );
    // a context that gives the type no arguments where the header writes some: arguments equal
    // to the type's defaults are not printed (`NamedTempFile::new_in` is a method of `impl
    // NamedTempFile<File>`, with `struct NamedTempFile<F = File>`). Where the file defines the
    // type, the written arguments are its defaults; elsewhere the context says no more than the
    // type's name.
    if !named.contains('<')
        && written
            .strip_prefix(named.as_str())
            .is_some_and(|r| r.starts_with('<'))
    {
        let defaults = type_defaults(src, &type_name(ty))?;
        let args = type_args(&expanded);
        return Some(
            args.len() == defaults.len()
                && args.iter().zip(&defaults).all(|(a, d)| {
                    d.as_deref()
                        .is_some_and(|d| fold_typenum(&norm_path(d)) == fold_typenum(&norm_path(a)))
                }),
        );
    }
    // or one that gives the first of them and leaves out the rest, each equal to its default:
    // `AcmeConfig::<!>` for `impl AcmeConfig<Infallible, Infallible>`, with `struct
    // AcmeConfig<EC, EA = EC>`, a default naming another parameter, the written argument for it
    if !candidates
        .iter()
        .any(|e| fold_typenum(&norm_path(e)) == named)
        && let Some(params) = type_params(src, &type_name(ty))
    {
        let (want, have) = (type_args(&named), type_args(&written));
        if type_name(&named) == type_name(&written)
            && !want.is_empty()
            && want.len() < have.len()
            && have.len() == params.len()
            && want.iter().zip(&have).all(|(a, b)| a == b)
        {
            let by_name: HashMap<&str, &str> = params
                .iter()
                .map(|(n, _)| n.as_str())
                .zip(have.iter().map(String::as_str))
                .collect();
            let rest = (want.len()..have.len()).all(|k| {
                params[k].1.as_deref().is_some_and(|d| {
                    let d = re!(r"\b[A-Za-z_]\w*\b").replace_all(d, |m: &regex::Captures| {
                        by_name
                            .get(&m[0])
                            .map_or(m[0].to_string(), |a| a.to_string())
                    });
                    fold_typenum(&norm_path(&d)) == have[k]
                })
            });
            return Some(rest);
        }
    }
    Some(
        candidates
            .iter()
            .any(|e| fold_typenum(&norm_path(e)) == named),
    )
}

/// The defaults of the type and const parameters of the file's struct, enum or union `ty`, in
/// order (`struct NamedTempFile<F = File>`: `[Some("File")]`), lifetimes left out.
pub(super) fn type_defaults(src: &Source, ty: &str) -> Option<Vec<Option<String>>> {
    Some(type_params(src, ty)?.into_iter().map(|(_, d)| d).collect())
}
/// The type and const parameters of the file's struct, enum or union `ty`, in order, each with
/// its default (`struct AcmeConfig<EC: Debug, EA: Debug = EC>`: `[("EC", None), ("EA",
/// Some("EC"))]`), lifetimes left out.
pub(super) fn type_params(src: &Source, ty: &str) -> Option<Vec<(String, Option<String>)>> {
    let s = &src.code;
    let def = src.items.iter().find(|it| {
        it.kind == ItemKind::TypeDef
            && it.name == ty
            && ["struct", "enum", "union"]
                .iter()
                .any(|w| kw(s, src.idx(it.start), w))
    })?;
    let at = src.idx(def.start);
    let mut i = skip_blank(s, at + word_of(s, at).chars().count());
    i = skip_blank(s, i + word_of(s, i).chars().count());
    if s.get(i) != Some(&'<') {
        return Some(Vec::new());
    }
    let cls = vec![Class::Code; s.len() - i];
    let e = i + skip_angle(&s[i..], &cls, 0)?;
    let inner: String = s[i + 1..e - 1].iter().collect();
    Some(
        split_top(&inner)
            .into_iter()
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty() && !p.starts_with('\''))
            .map(|p| {
                // the `=` outside the bounds' brackets (`T: Iterator<Item = u8> = Bytes`)
                let mut depth = 0i32;
                let default = p
                    .char_indices()
                    .find(|&(k, c)| {
                        match c {
                            '<' | '(' | '[' => depth += 1,
                            '>' if p[..k].ends_with('-') => {}
                            '>' | ')' | ']' => depth -= 1,
                            _ => {}
                        }
                        c == '=' && depth == 0
                    })
                    .map(|(k, _)| p[k + 1..].trim().to_string());
                let name = word_of(
                    &p.trim_start_matches("const ").chars().collect::<Vec<_>>(),
                    0,
                );
                (name, default)
            })
            .collect(),
    )
}

/// An impl block's self type as written (`m::K`, `&mut A`, the `where` clause left out), and
/// the impl's own type and const parameters.
pub(super) fn impl_self(src: &Source, block: &Item) -> Option<(String, Vec<String>)> {
    let s = &src.code;
    let (a, b) = src.span(block);
    let open = scan_to(s, a, b, |k| s[k] == '{');
    let header = src.text(a, open);
    let header = header.trim().strip_prefix("impl")?.trim_start();
    let (params, rest) = if header.starts_with('<') {
        let hc: Vec<char> = header.chars().collect();
        let cls = vec![Class::Code; hc.len()];
        let e = skip_angle(&hc, &cls, 0)?;
        (
            hc[1..e - 1].iter().collect::<String>(),
            hc[e..].iter().collect::<String>(),
        )
    } else {
        (String::new(), header.to_string())
    };
    let ty = rest.split_once(" for ").map_or(rest.as_str(), |(_, y)| y);
    let ty = ty.split(" where ").next().unwrap_or(ty).trim().to_string();
    let own = re!(r"(?:^|,)\s*(?:const\s+)?([A-Za-z_]\w*)")
        .captures_iter(&params)
        .filter_map(|m| m.get(1).map(|g| g.as_str().to_string()))
        .collect();
    Some((ty, own))
}

/// A name as the file's `use` items import it under another name (`use ring::digest::Algorithm
/// as Digest`: `Digest` is `Algorithm`); any other name as it is.
pub(super) fn imported_as(src: &Source, name: &str) -> String {
    src.binds
        .iter()
        .find(|b| b.name == name)
        .and_then(|b| b.path.last())
        .filter(|l| *l != "self")
        .cloned()
        .unwrap_or_else(|| name.to_string())
}
