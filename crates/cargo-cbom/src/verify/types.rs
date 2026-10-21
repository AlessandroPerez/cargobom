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
/// Two traits are one: the same path, or the same name where either has no arguments.
pub(super) fn same_trait(a: &str, b: &str) -> bool {
    let name = |t: &str| t.split('<').next().unwrap_or(t).to_string();
    a == b || (name(a) == name(b) && (!a.contains('<') || !b.contains('<')))
}
/// A type as written in an impl header is the type a context names: the same name, or an
/// alias that stands for the whole type (`Sha256` for sha2's `CoreWrapper<CtVariableCoreWrapper<
/// Sha256VarCore, U32, OidSha256>>`, which `Sha512` is not).
pub(super) fn same_type(
    written: &str,
    ty: &str,
    full: Option<&str>,
    aliases: &mut dyn FnMut(&str) -> Vec<String>,
) -> bool {
    if written == ty {
        return true;
    }
    // `[u8;?]` (`impl<const N: usize> X for [u8; N]`) is `[u8;32]`
    if written.contains('?') {
        let pat = regex::escape(written).replace(r"\?", r"[^,;\[\]()]+");
        return Regex::new(&format!("^{pat}$")).is_ok_and(|r| r.is_match(ty));
    }
    // (an alias of a type of that name: `impl Put for &mut A` with `type A = &'static
    // Algorithm`, its block named `A`)
    if aliases(written)
        .iter()
        .any(|t| type_name(&expand_aliases(t, aliases, 3)) == type_name(ty))
    {
        return true;
    }
    let Some(full) = full else {
        return false;
    };
    let full = fold_typenum(full);
    aliases(written)
        .iter()
        .any(|t| fold_typenum(&expand_aliases(t, aliases, 3)) == full)
}
/// A trait as written in an impl header is the trait a context names (`same_trait`), also once
/// the aliases among its arguments are replaced (`RandomizedSigner<Signature>` with p521's
/// `type Signature = ecdsa_core::Signature<NistP521>`).
pub(super) fn trait_of(
    written: &str,
    want: &str,
    aliases: &mut dyn FnMut(&str) -> Vec<String>,
) -> bool {
    if same_trait(written, want) {
        return true;
    }
    let (head, args) = written.split_at(written.find('<').unwrap_or(written.len()));
    // (a trait imported under another name: `impl Chooser for B` with `use m::Pick as Chooser`)
    if let Some(e) = aliases(head.trim()).first()
        && e != head.trim()
        && same_trait(&format!("{e}{args}"), want)
    {
        return true;
    }
    let expanded = format!("{head}{}", expand_aliases(args, aliases, 3));
    expanded != written && same_trait(&fold_typenum(&expanded), &fold_typenum(want))
}
/// A type with the aliases it names replaced by what they stand for, `depth` levels deep (the
/// names followed by arguments are types, not aliases without parameters).
pub(super) fn expand_aliases(
    t: &str,
    aliases: &mut dyn FnMut(&str) -> Vec<String>,
    depth: usize,
) -> String {
    let mut out = String::new();
    let mut last = 0;
    for m in re!(r"\b[A-Za-z_]\w*\b").find_iter(t) {
        if t[m.end()..].starts_with('<') {
            continue;
        }
        if let Some(e) = aliases(m.as_str()).first()
            && e != m.as_str()
        {
            out.push_str(&t[last..m.start()]);
            if depth > 1 {
                out.push_str(&expand_aliases(e, aliases, depth - 1));
            } else {
                out.push_str(e);
            }
            last = m.end();
        }
    }
    out.push_str(&t[last..]);
    out
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
    if let Some(f) = f {
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
/// The type of the value a method called at `i` (`E1.ext()`, `W(S1).alg()`, `g.alg()` with `let
/// g = &W(S2);`, `p.b.ext()` with `p` a `Pair` whose `b` is an `E2`, `mk1().ext()`, `e.ext()` with
/// `let e = E1.upgrade();`) is called on, when the code says which type of the file it is: `None`
/// when it does not (a parameter of a type parameter, a trait object, a value of another crate's
/// type).
pub(super) fn receiver_type(src: &Source, i: usize) -> Option<String> {
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
    let mut ty = type_name(&deref_type(&expr_type(src, r, dot, 5)?));
    // (a type alias of the file: `type A2 = E2;`)
    for _ in 0..4 {
        let Ok(re) = Regex::new(&format!(r"\btype\s+{}\s*=\s*([^;<]+)", regex::escape(&ty))) else {
            break;
        };
        let code: String = src.code.iter().collect();
        match re.captures(&code) {
            Some(m) => ty = type_name(m[1].trim()),
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
/// The type arguments the call of the file's generic function `name` at `ci` gives it, by its
/// type parameters: written (`pass::<Last>(..)`), or the type of the argument passed for a
/// parameter of that type (`pass(&B, ..)` for `fn pass<T>(t: &T, ..)`: `B`, a type of the file);
/// `None` for one not known. `None` when no such call is there (a method, a macro).
pub(super) fn call_type_args(src: &Source, ci: usize, name: &str) -> Option<Vec<Option<String>>> {
    let s = &src.code;
    if before_blank(s, ci).is_some_and(|p| s[p] == '.') {
        return None;
    }
    // the path at `ci` up to `name`
    let mut i = ci;
    let mut prefix = Vec::new();
    loop {
        if !word_start(s, i) {
            return None;
        }
        let w = word_of(s, i);
        i += w.chars().count();
        if w == name {
            break;
        }
        prefix.push(w);
        let j = skip_blank(s, i);
        if !(s.get(j) == Some(&':') && s.get(j + 1) == Some(&':')) {
            return None;
        }
        i = skip_blank(s, j + 2);
    }
    let j = skip_blank(s, i);
    if s.get(j) == Some(&':') && s.get(j + 1) == Some(&':') {
        let o = skip_blank(s, j + 2);
        if s.get(o) != Some(&'<') {
            return None;
        }
        let cls = vec![Class::Code; s.len() - o];
        let e = skip_angle(&s[o..], &cls, 0)?;
        // (a type parameter of the caller, `labeled_extract::<Kdf>` in a generic function, is
        // whatever its own instance gives: not compared)
        let mut params: Vec<String> = Vec::new();
        if let Some(f) = src.enclosing(src.pos(ci), &[ItemKind::Fn]) {
            params.extend(fn_sig(src, f).generics);
            if let Some(b) = impl_of(src, f) {
                let (ba, bb) = src.span(b);
                let h = src.text(ba, scan_to(s, ba, bb, |k| s[k] == '{'));
                if let Some(r) = h
                    .trim_start()
                    .strip_prefix("impl")
                    .filter(|r| r.trim_start().starts_with('<'))
                {
                    params.extend(
                        re!(r"[<,]\s*(\w+)\s*[:,>]")
                            .captures_iter(r)
                            .map(|x| x[1].to_string()),
                    );
                }
            }
        }
        return Some(
            split_top(&src.text(o + 1, o + e - 1))
                .into_iter()
                .map(|a| {
                    Some(a.trim().to_string())
                        .filter(|a| a != "_" && !params.contains(&type_name(a)))
                })
                .collect(),
        );
    }
    if s.get(j) != Some(&'(') {
        return None;
    }
    let close = close_of_at(s, j)?;
    let f = free_fn_called(src, ci, name, &prefix)?;
    let sig = fn_sig(src, f);
    if sig.generics.is_empty() {
        return None;
    }
    // the arguments' extents
    let mut args = Vec::new();
    let mut a = j + 1;
    while a < close {
        let e = scan_to(s, a, close, |k| s[k] == ',');
        args.push((a, e));
        a = e + 1;
    }
    Some(
        sig.generics
            .iter()
            .map(|g| {
                let p = sig
                    .params
                    .iter()
                    .position(|(_, t)| type_name(&deref_type(t)) == *g && deref_type(t) == *g)?;
                let &(x, y) = args.get(p)?;
                // (`expr_type` reads through the argument's borrows, `&mut a`: put back; a
                // dereference, `*r`, leaves which references are left unknown)
                let mut borrows = String::new();
                let mut k = skip_blank(s, x);
                while s.get(k) == Some(&'&') {
                    borrows.push('&');
                    k = skip_blank(s, k + 1);
                    if kw(s, k, "mut") {
                        borrows.push_str("mut ");
                        k = skip_blank(s, k + 3);
                    }
                }
                if s.get(k) == Some(&'*') {
                    return None;
                }
                let raw = format!("{borrows}{}", expr_type(src, x, y, 4)?);
                let t = type_name(&deref_type(&raw));
                // (with its path, `m::K`, which says which alias of the name it is, and the
                // references the parameter's type does not take: `t: T` given `&mut a` is a
                // `&mut A`, `t: &T` given `&a` an `A`)
                let refs = |t: &str| {
                    re!(r"^(?:&\s*(?:'\w+\s+)?(?:mut\s+)?)*")
                        .find(t.trim())
                        .map_or(0, |m| m.as_str().matches('&').count())
                };
                let mut inner = raw.trim().to_string();
                for _ in 0..refs(&sig.params[p].1) {
                    inner = re!(r"^&\s*(?:'\w+\s+)?(?:mut\s+)?")
                        .replace(&inner, "")
                        .trim()
                        .to_string();
                }
                src.items
                    .iter()
                    .any(|it| it.kind == ItemKind::TypeDef && it.name == t)
                    .then_some(inner)
            })
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
/// Is a method of item `n` (an instantiation chain's) called on a `t`: `<T as Tr>::m` on a `T`, a
/// trait's method (`app::Tr::m`) on a type implementing the trait (directly or by a blanket
/// impl), an inherent method on its type?
pub(super) fn receiver_fits(src: &Source, n: &InItem, t: &str) -> bool {
    let Some(st) = n.self_ty.as_deref() else {
        return true;
    };
    if n.trait_name.is_some()
        || !src
            .items
            .iter()
            .any(|i| i.kind == ItemKind::Trait && i.name == st)
    {
        return st == t;
    }
    let text = src.lines.join("\n");
    Regex::new(&format!(
        r"\bimpl\b[^{{;]*\b{}\b[^{{;]*\bfor\s+(?:&\s*)?(?:{}\b|[A-Z]\s*(?:\{{|where\b))",
        regex::escape(st),
        regex::escape(t)
    ))
    .is_ok_and(|r| r.is_match(&text))
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
            && let Ok(re) = Regex::new(&format!(
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
/// `Chooser` is `Pick`); the name itself otherwise.
pub(super) fn trait_alias(src: &Source, t: &str) -> String {
    src.binds
        .iter()
        .find(|b| b.name == t && b.path.len() > 1)
        .and_then(|b| b.path.last().cloned())
        .unwrap_or_else(|| t.to_string())
}
/// The type of field `idx` of the tuple struct or enum variant a constructor `w` makes (`W2(..)`,
/// `E3::A(..)`), as the file declares it.
pub(super) fn ctor_field_type(src: &Source, w: &str, idx: usize) -> Option<String> {
    let code: String = src.code.iter().collect();
    let char_at = |b: usize| code[..b].chars().count();
    let field = |open: usize| -> Option<String> {
        let close = close_of_at(&src.code, open)?;
        let fields = split_top(&src.text(open + 1, close));
        fields
            .get(idx)
            .map(|f| f.trim().trim_start_matches("pub").trim().to_string())
    };
    let st = Regex::new(&format!(
        r"\bstruct\s+{}\b\s*(?:<[^>]*>)?\s*\(",
        regex::escape(w)
    ))
    .ok()?;
    if let Some(m) = st.find(&code) {
        return field(char_at(m.end()) - 1);
    }
    // a variant of one of the file's enums
    let var = Regex::new(&format!(r"[{{,]\s*{}\s*\(", regex::escape(w))).ok()?;
    for it in src
        .items
        .iter()
        .filter(|it| it.kind == ItemKind::TypeDef && kw(&src.code, src.idx(it.start), "enum"))
    {
        // (the item is its keyword: its body is the braces after it)
        let a = src.idx(it.start);
        let open = scan_to(&src.code, a, src.code.len(), |k| {
            matches!(src.code[k], '{' | ';')
        });
        let Some(b) = close_of_at(&src.code, open) else {
            continue;
        };
        let text = src.text(open, b);
        if let Some(m) = var.find(&text) {
            return field(open + text[..m.end()].chars().count() - 1);
        }
    }
    None
}
/// The traits of objects a field named `field` of the file's structs holds (`p: Box<dyn Pick>`).
pub(super) fn field_dyn(src: &Source, field: &str) -> Vec<String> {
    let Ok(re) = Regex::new(&format!(
        r"\b{}\s*:\s*([^,;=]*\bdyn\b[^,;=]*)",
        regex::escape(field)
    )) else {
        return Vec::new();
    };
    src.lines
        .iter()
        .filter_map(|l| re.captures(l).map(|m| dyn_traits_src(src, &m[1])))
        .flatten()
        .collect()
}
/// The type an annotation gives the part of a value a projection names (`(&Fast, &dyn Tr)` and
/// `[1]`: `&dyn Tr`; `[&dyn Tr; 2]` and an element: `&dyn Tr`), innermost projection last; the
/// whole type where it says no more.
pub(super) fn project_type(t: &str, proj: &[Option<usize>]) -> String {
    let mut t = t.trim().to_string();
    for p in proj.iter().rev() {
        let inner = t.trim_start_matches('&').trim();
        let inner = inner.strip_prefix("mut ").unwrap_or(inner).trim();
        t = match p {
            Some(k) if inner.starts_with('(') && inner.ends_with(')') => {
                match split_top(&inner[1..inner.len() - 1]).get(*k) {
                    Some(e) => e.trim().to_string(),
                    None => return t,
                }
            }
            None => match elem_type(inner) {
                Some(e) => e,
                None => return t,
            },
            _ => return t,
        };
    }
    t
}
/// The traits the value at `i` (`Fast`, `x`, `W::<A>(..)`, `3u8`), made a pointer there (`&x`,
/// `&mut x`, `Box::new(x)`), becomes a trait object of: the `dyn` type of the context the
/// pointer is in, from the inside out: an `as` cast after it, the parameter of the function or
/// method it is passed to (`foreign` reads another crate's: path written, name, argument index ->
/// the parameter's type), the field of the struct literal it initializes, the variable whose
/// method stores it (`m.insert(k, b)` with `m` declared with `dyn`), the annotation of the `let`,
/// `static` or `const` whose value it is (the tuple element or array element it is), the return
/// type of the function whose result it is (its tail or `return`). Through tuples, arrays,
/// blocks, `if`s, `match`es, `Some`/`Ok`/`Err` and `Box::new`/`Rc::new`/`Arc::new`. None when
/// it becomes none there (`let probe = &Fast;`, `label(&Fast)` taking another trait's object
/// returns that trait).
pub(super) fn coercion_traits(
    src: &Source,
    i: usize,
    foreign: &mut ForeignParam<'_>,
) -> Option<Vec<String>> {
    let s = &src.code;
    let some = |v: Vec<String>| (!v.is_empty()).then_some(v);
    // the value: a path (with turbofish), a struct literal or constructor's arguments
    let mut e = i;
    loop {
        e += word_of(s, e).chars().count();
        let j = skip_blank(s, e);
        if s.get(j) == Some(&':') && s.get(j + 1) == Some(&':') {
            let k = skip_blank(s, j + 2);
            if s.get(k) == Some(&'<') {
                let cls = vec![Class::Code; s.len() - k];
                e = k + skip_angle(&s[k..], &cls, 0)?;
                let j2 = skip_blank(s, e);
                if s.get(j2) == Some(&':')
                    && s.get(j2 + 1) == Some(&':')
                    && word_start(s, skip_blank(s, j2 + 2))
                {
                    e = skip_blank(s, j2 + 2);
                    continue;
                }
                break;
            }
            if word_start(s, k) {
                e = k;
                continue;
            }
        }
        break;
    }
    let j = skip_blank(s, e);
    if matches!(s.get(j), Some('{' | '(')) && s[i].is_uppercase() {
        e = close_of_at(s, j)? + 1;
    }
    let (mut ps, mut pe) = (i, e);
    // the pointer made of it
    if let Some(p) = before_blank(s, ps) {
        if s[p] == '&' {
            ps = p;
        } else if word_before_at(s, ps) == "mut"
            && let Some(a) = before_blank(s, p + 1 - 3).filter(|&a| s[a] == '&')
        {
            ps = a;
        } else if s[p] == '('
            && let Some((wb, w)) = callee_before(s, p)
            && matches!(w.as_str(), "new" | "pin")
        {
            let path = path_before(s, wb);
            if path
                .last()
                .is_some_and(|q| matches!(q.as_str(), "Box" | "Rc" | "Arc" | "Pin"))
            {
                let st = path_start(s, wb);
                ps = st;
                pe = close_of_at(s, p)? + 1;
            }
        }
    }
    // the item: a function's body or a static's value, not past it
    let item = src.enclosing(src.pos(i), &[ItemKind::Fn, ItemKind::Static])?;
    let (fa, fb) = src.span(item);
    let floor = if item.kind == ItemKind::Fn {
        scan_to(s, fa, fb, |k| s[k] == '{')
    } else {
        fa
    };
    // the first index of its body or value
    let lo = if item.kind == ItemKind::Fn {
        floor + 1
    } else {
        fa
    };
    let mut proj: Vec<Option<usize>> = Vec::new();
    for _ in 0..24 {
        // `as T`
        let n = skip_blank(s, pe);
        if kw(s, n, "as") {
            let t_end = scan_to(s, n + 2, fb, |k| matches!(s[k], ',' | ';' | '=' | '{'));
            return some(dyn_traits_src(src, &src.text(n + 2, t_end)));
        }
        // back to the bracket around it, the statement's start, a `=` of its statement
        let mut depth = 0i32;
        let mut k = ps;
        let mut eq = None;
        // (where the statement starts when no bracket is around it)
        let mut st = lo;
        let stop = loop {
            if k <= lo {
                break None;
            }
            k -= 1;
            if s[k] == ';' && depth == 0 {
                st = k + 1;
                break None;
            }
            match s[k] {
                ')' | ']' | '}' => depth += 1,
                '(' | '[' | '{' => {
                    if depth == 0 {
                        break Some(k);
                    }
                    depth -= 1;
                }
                '=' if depth == 0
                    && eq.is_none()
                    && !matches!(s.get(k + 1), Some('=' | '>'))
                    && !matches!(
                        k.checked_sub(1).map(|q| s[q]),
                        Some('=' | '!' | '<' | '>' | '+' | '-' | '*' | '/' | '%' | '^' | '&' | '|')
                    ) =>
                {
                    eq = Some(k)
                }
                _ => {}
            }
        };
        if let Some(eq) = eq {
            // the value of a `let`, `static` or `const`: its annotation
            let st = stop.map_or(st, |b| b + 1);
            let head = src.text(st, eq);
            let head = head.trim();
            let head = re!(r"^(?:pub(?:\s*\([^)]*\))?\s+)?").replace(head, "");
            // an assignment to a field (`v1.p = Box::new(T1);`): the field's declared type
            if let Some(m) = re!(r"^\*?\s*[\w.\[\]]+\.(\w+)$").captures(&head) {
                return some(field_dyn(src, &m[1]));
            }
            if !re!(r"^(?:let|static|const)\b").is_match(&head) {
                return None;
            }
            let hc: Vec<char> = head.chars().collect();
            let colon = (0..hc.len()).find(|&c| {
                hc[c] == ':' && hc.get(c + 1) != Some(&':') && (c == 0 || hc[c - 1] != ':')
            })?;
            let t: String = hc[colon + 1..].iter().collect();
            return some(dyn_traits_src(src, &project_type(&t, &proj)));
        }
        let Some(ob) = stop else {
            // a statement's start inside a block (`{ let t = T10; Box::new(t) }`): the value is
            // the block's when it is its tail
            if st > lo {
                let mut depth = 0i32;
                let mut k = st - 1;
                let open = loop {
                    if k <= lo {
                        break None;
                    }
                    k -= 1;
                    match s[k] {
                        ')' | ']' | '}' => depth += 1,
                        '(' | '[' => {
                            if depth == 0 {
                                break None;
                            }
                            depth -= 1;
                        }
                        '{' => {
                            if depth == 0 {
                                break Some(k);
                            }
                            depth -= 1;
                        }
                        _ => {}
                    }
                };
                if let Some(ob2) = open
                    && let Some(cb2) = close_of_at(s, ob2)
                    && scan_to(s, pe, cb2, |m| s[m] == ';') >= cb2
                {
                    ps = ob2;
                    pe = cb2 + 1;
                    continue;
                }
            }
            // a statement's start: its function's result (a tail expression, `return`)
            let st = skip_blank(s, st);
            if item.kind != ItemKind::Fn {
                return None;
            }
            let body_end = close_of_at(s, floor)?;
            let tail = kw(s, st, "return") || scan_to(s, st, body_end, |m| s[m] == ';') >= body_end;
            if !tail {
                return None;
            }
            let ret = fn_sig(src, item).ret?;
            return some(dyn_traits_src(src, &ret));
        };
        let cb = close_of_at(s, ob)?;
        // its element index
        let idx = (ob + 1..ps)
            .filter(|&m| s[m] == ',' && scan_to(s, ob + 1, m + 1, |q| q == m) == m)
            .count();
        match s[ob] {
            '(' => match callee_before(s, ob)
                .filter(|(_, w)| !is_keyword(w) && w != "match" && w != "if")
            {
                None => {
                    // a tuple (or parentheses)
                    if scan_to(s, ob + 1, cb, |m| s[m] == ',') < cb {
                        proj.push(Some(idx));
                    }
                }
                Some((wb, w)) => {
                    let path = path_before(s, wb);
                    let method = before_blank(s, wb).is_some_and(|d| s[d] == '.');
                    let wrapper = matches!(w.as_str(), "Some" | "Ok" | "Err")
                        || (matches!(w.as_str(), "new" | "pin" | "from")
                            && path.last().is_some_and(|q| {
                                matches!(q.as_str(), "Box" | "Rc" | "Arc" | "Pin")
                            }));
                    if wrapper {
                        let st = path_start(s, wb);
                        ps = st;
                        pe = cb + 1;
                        continue;
                    }
                    if w.starts_with(char::is_uppercase) {
                        // a constructor of a tuple struct or enum variant of the file: the
                        // field's declared type; else what is coerced is the value it makes
                        return some(dyn_traits_src(src, &ctor_field_type(src, &w, idx)?));
                    }
                    if method {
                        let d = before_blank(s, wb)?;
                        // a store into a variable declared with a trait object (`m.insert(k, b)`)
                        if let Some((r, recv, _)) = receiver_at(s, d)
                            && recv.chars().all(is_ident)
                            && let Some(Bound::Let { first, last, .. }) = binding(src, r, &recv)
                        {
                            let decl: String = (first..=last)
                                .map(|l| src.lines[l - 1].as_str())
                                .collect::<Vec<_>>()
                                .join("\n");
                            let t = dyn_traits_src(src, &decl);
                            if !t.is_empty() {
                                return Some(t);
                            }
                        }
                        // the file's method of that name: its parameter after `self`
                        let ts: Vec<String> = src
                            .items
                            .iter()
                            .filter(|f| f.kind == ItemKind::Fn && f.name == w)
                            .filter_map(|f| {
                                let sig = fn_sig(src, f);
                                let k = idx
                                    + usize::from(
                                        sig.params.first().is_some_and(|p| p.0 == "self"),
                                    );
                                sig.params.get(k).map(|p| dyn_traits_src(src, &p.1))
                            })
                            .flatten()
                            .collect();
                        return some(ts);
                    }
                    let ty = match free_fn_called(src, wb, &w, &path) {
                        Some(f) => fn_sig(src, f).params.get(idx).map(|p| p.1.clone()),
                        None => foreign(&path, &w, idx),
                    };
                    return some(dyn_traits_src(src, &ty?));
                }
            },
            '[' => {
                // an array literal (`[&A, &B]`, `vec![..]`), not an index
                let p = before_blank(s, ob);
                if p.is_some_and(|p| is_ident(s[p]) || matches!(s[p], ')' | ']')) {
                    return None;
                }
                proj.push(None);
                if let Some(pb) = p.filter(|&pb| s[pb] == '!') {
                    let we = before_blank(s, pb)?;
                    let mut wb = we + 1;
                    while wb > 0 && is_ident(s[wb - 1]) {
                        wb -= 1;
                    }
                    ps = path_start(s, wb);
                    pe = cb + 1;
                    continue;
                }
            }
            '{' => {
                // a field of a struct literal (`S { inner: Box::new(X) }`)
                let head = word_before_at(s, ob);
                let colon =
                    before_blank(s, ps).filter(|&c| s[c] == ':' && (c == 0 || s[c - 1] != ':'));
                if head.starts_with(char::is_uppercase)
                    && let Some(c) = colon
                {
                    let field = word_before_at(s, c);
                    if let Some(t) = field_type(src, &head, &field) {
                        return some(dyn_traits_src(src, &t));
                    }
                    let ts: Vec<String> = src
                        .lines
                        .iter()
                        .filter_map(|l| {
                            Regex::new(&format!(
                                r"\b{}\s*:\s*([^,;=]*\bdyn\b[^,;=]*)",
                                regex::escape(&field)
                            ))
                            .ok()?
                            .captures(l)
                            .map(|m| dyn_traits_src(src, &m[1]))
                        })
                        .flatten()
                        .collect();
                    return some(ts);
                }
                // a closure's body with a return annotation (`|| -> Box<dyn P9> { .. }`)
                let back = src.text(ob.saturating_sub(200).max(lo), ob);
                if let Some(m) = re!(r"\|[^|{};]*\|\s*->\s*([^{};]+?)\s*$").captures(&back) {
                    return some(dyn_traits_src(src, &m[1]));
                }
                // a block, an `if`'s or a `match`'s: the value of the expression around it
            }
            _ => return None,
        }
        ps = ob;
        pe = cb + 1;
    }
    None
}
/// The traits of the trait objects the call at `p` calls methods on (`digest(g.alg(), d)` with
/// `g: Box<dyn Gen>`: `Gen`), in its arguments and receiver: None where it calls none, or one on
/// a value whose type the code does not say (a type parameter's, a call's not followed).
pub(super) fn call_dyn_receivers(src: &Source, p: usize) -> Option<Vec<String>> {
    let s = &src.code;
    let mut j = p;
    let end = loop {
        j = skip_blank(s, j);
        if word_start(s, j) {
            j += word_of(s, j).chars().count();
        } else if s.get(j) == Some(&':') && s.get(j + 1) == Some(&':') {
            j += 2;
        } else if s.get(j) == Some(&'<') {
            let cls = vec![Class::Code; s.len() - j];
            j += skip_angle(&s[j..], &cls, 0)?;
        } else if s.get(j) == Some(&'(') {
            break close_of_at(s, j)?;
        } else {
            return None;
        }
    };
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
    let expanded = expand_aliases(&resolved, aliases, 3);
    Some(fold_typenum(&norm_path(&expanded)) == fold_typenum(&norm_path(full)))
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
