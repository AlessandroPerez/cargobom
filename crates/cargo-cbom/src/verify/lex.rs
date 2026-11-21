//! Lexing a source file: tokens, words, paths and their generic arguments, blanks, literals and comments.

use super::*;

/// A path or type without its generic arguments: every `<..>` whose brackets match is removed
/// (an unmatched `<` or `>` stays, as a comparison's). The `>` of a function type's `->` closes
/// nothing (`MapErr<S, fn(E) -> F {into_service_error}, F>` is `MapErr`).
pub(super) fn strip_generics(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut keep = vec![true; chars.len()];
    let mut open = Vec::new();
    for (i, &c) in chars.iter().enumerate() {
        match c {
            '<' => open.push(i),
            '>' if i > 0 && chars[i - 1] == '-' => {}
            '>' => {
                if let Some(a) = open.pop() {
                    keep[a..=i].iter_mut().for_each(|k| *k = false);
                }
            }
            _ => {}
        }
    }
    chars
        .iter()
        .zip(keep)
        .filter_map(|(c, k)| k.then_some(*c))
        .collect()
}
/// The trait of a qualified path, read from after its `<`: `aead::Buffer` of `alloc::vec::
/// Vec<u8> as aead::Buffer>::extend_from_slice`. None for one that names no trait (`<T>::f`).
pub(super) fn qualified_trait(q: &str) -> Option<&str> {
    let b = q.as_bytes();
    let (mut depth, mut from) = (0usize, None);
    for i in 0..b.len() {
        match b[i] {
            b'<' => depth += 1,
            b'>' if i > 0 && b[i - 1] == b'-' => {}
            b'>' if depth == 0 => return from.map(|a: usize| q[a..i].trim()),
            b'>' => depth -= 1,
            b' ' if depth == 0 && from.is_none() && q[i..].starts_with(" as ") => {
                from = Some(i + " as ".len());
            }
            _ => {}
        }
    }
    None
}
pub(super) fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}
/// Classifies each char of a Rust source: in a `//` or `/* */` comment (nested), in a string
/// literal (`"..."`, `b".."`, `c".."`, raw `r#".."#`) or a char literal, or code.
pub(super) fn classify(text: &str) -> Vec<Class> {
    let chars: Vec<char> = text.chars().collect();
    let mut class = vec![Class::Code; chars.len()];
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        let prev_ident = i > 0 && is_ident(chars[i - 1]);
        if c == '/' && next == Some('/') {
            while i < chars.len() && chars[i] != '\n' {
                class[i] = Class::Comment;
                i += 1;
            }
        } else if c == '/' && next == Some('*') {
            let mut depth = 0;
            while i < chars.len() {
                if chars[i] == '/' && chars.get(i + 1) == Some(&'*') {
                    depth += 1;
                    class[i] = Class::Comment;
                    class[i + 1] = Class::Comment;
                    i += 2;
                } else if chars[i] == '*' && chars.get(i + 1) == Some(&'/') {
                    depth -= 1;
                    class[i] = Class::Comment;
                    class[i + 1] = Class::Comment;
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    class[i] = Class::Comment;
                    i += 1;
                }
            }
        } else if !prev_ident && (c == 'r' || ((c == 'b' || c == 'c') && next == Some('r'))) && {
            // raw string: r#*"
            let mut j = i + if c == 'r' { 1 } else { 2 };
            while chars.get(j) == Some(&'#') {
                j += 1;
            }
            chars.get(j) == Some(&'"')
        } {
            let mut j = i + if c == 'r' { 1 } else { 2 };
            let mut hashes = 0;
            while chars[j] == '#' {
                hashes += 1;
                j += 1;
            }
            j += 1; // opening quote
            loop {
                if j >= chars.len() {
                    break;
                }
                if chars[j] == '"' && (0..hashes).all(|k| chars.get(j + 1 + k) == Some(&'#')) {
                    j += 1 + hashes;
                    break;
                }
                j += 1;
            }
            for k in class.iter_mut().take(j.min(chars.len())).skip(i) {
                *k = Class::Literal;
            }
            i = j;
        } else if c == '"' {
            let mut j = i + 1;
            while j < chars.len() && chars[j] != '"' {
                if chars[j] == '\\' {
                    j += 1;
                }
                j += 1;
            }
            let end = (j + 1).min(chars.len());
            for k in class.iter_mut().take(end).skip(i) {
                *k = Class::Literal;
            }
            i = end;
        } else if c == '\'' {
            // char literal, or a lifetime / label (code)
            let end = if next == Some('\\') {
                // skip the backslash and the escaped char (`'\''`), then find the closing quote
                let mut j = i + 3;
                while j < chars.len() && chars[j] != '\'' && chars[j] != '\n' {
                    j += 1;
                }
                Some(j + 1)
            } else if next.is_some() && next != Some('\n') && chars.get(i + 2) == Some(&'\'') {
                Some(i + 3)
            } else {
                None
            };
            match end {
                Some(e) => {
                    let e = e.min(chars.len());
                    for k in class.iter_mut().take(e).skip(i) {
                        *k = Class::Literal;
                    }
                    i = e;
                }
                None => i += 1,
            }
        } else {
            i += 1;
        }
    }
    class
}
/// Per line, per char: the class of each char of a Rust source; and the file with comments and
/// literals blanked, for finding `use` items.
pub(super) fn lex(text: &str) -> (Vec<Vec<Class>>, String) {
    let class = classify(text);
    let mut per_line = vec![Vec::new()];
    let mut blank = String::with_capacity(text.len());
    for (c, k) in text.chars().zip(class) {
        if c == '\n' {
            per_line.push(Vec::new());
            blank.push('\n');
        } else {
            per_line.last_mut().unwrap().push(k);
            blank.push(if k == Class::Code { c } else { ' ' });
        }
    }
    (per_line, blank)
}
/// Skips a balanced `<...>` starting at `i` (which must be `<`); `->` does not close, and
/// brackets in comments and literals do not count.
pub(super) fn skip_angle(s: &[char], cls: &[Class], mut i: usize) -> Option<usize> {
    let mut depth = 0;
    while i < s.len() {
        if cls[i] == Class::Code {
            match s[i] {
                '<' => depth += 1,
                '>' if i > 0 && s[i - 1] == '-' => {}
                '>' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(i + 1);
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }
    None
}
/// Skips whitespace, line breaks and comments.
pub(super) fn ws(s: &[char], cls: &[Class], mut i: usize) -> usize {
    while i < s.len() && (s[i].is_whitespace() || cls[i] == Class::Comment) {
        i += 1;
    }
    i
}
/// The path at the start of `at`: `(<T as Tr>::)? ::? (seg (::<..>)? ::)* last`, as its idents
/// (qualifiers first) and the final segment; raw identifiers (`r#digest`) without their `r#`.
/// Whitespace, line breaks and comments between tokens are allowed (rustfmt breaks long
/// turbofishes and qualified paths). None if `at` does not start with a path.
#[cfg(test)]
pub(super) fn path_at(at: &str) -> Option<(Vec<String>, String)> {
    let s: Vec<char> = at.chars().collect();
    path_and_generics(&s, &classify(at)).map(|(q, l, _)| (q, l))
}
/// Like `path_at`, on chars and their classes, plus the first segment of every path written
/// inside the generic arguments (`Hmac::<sha2::Sha256>::new` gives `sha2`).
pub(super) fn path_and_generics(
    s: &[char],
    cls: &[Class],
) -> Option<(Vec<String>, String, Vec<String>)> {
    let mut generics: Vec<String> = Vec::new();
    let mut heads = |from: usize, to: usize| {
        let mut k = from;
        while k < to {
            if cls[k] != Class::Code || !is_ident(s[k]) || s[k].is_ascii_digit() {
                k += 1;
                continue;
            }
            let mut st = k;
            while k < to && cls[k] == Class::Code && is_ident(s[k]) {
                k += 1;
            }
            // `r#Type`
            if k - st == 1 && s[st] == 'r' && s.get(k) == Some(&'#') {
                st = k + 1;
                k = st;
                while k < to && cls[k] == Class::Code && is_ident(s[k]) {
                    k += 1;
                }
                if k == st {
                    continue;
                }
            }
            // the code chars before: not after `::` (a later segment) or `'` (a lifetime)
            let mut before = Vec::new();
            let mut b = st;
            while b > from && before.len() < 2 {
                b -= 1;
                if cls[b] == Class::Code && !s[b].is_whitespace() {
                    before.push(s[b]);
                } else if cls[b] == Class::Literal {
                    break;
                }
            }
            if before != [':', ':'] && before.first() != Some(&'\'') {
                generics.push(s[st..k].iter().collect());
            }
        }
    };
    let colons = |i: usize| {
        s.get(i) == Some(&':')
            && s.get(i + 1) == Some(&':')
            && cls[i] == Class::Code
            && cls[i + 1] == Class::Code
    };
    let ident_at = |i: usize| s.get(i).is_some_and(|&c| is_ident(c)) && cls[i] == Class::Code;
    // a segment: an identifier, or a raw identifier; its name and end
    let segment = |i: usize| -> Option<(String, usize)> {
        let start = if s.get(i) == Some(&'r') && s.get(i + 1) == Some(&'#') && ident_at(i + 2) {
            i + 2
        } else {
            i
        };
        let mut e = start;
        while ident_at(e) {
            e += 1;
        }
        (e > start).then(|| (s[start..e].iter().collect(), e))
    };
    let mut i = 0;
    if s.first() == Some(&'<') {
        let close = skip_angle(s, cls, 0)?;
        heads(1, close - 1);
        i = ws(s, cls, close);
        if !colons(i) {
            return None;
        }
        i = ws(s, cls, i + 2);
    } else if colons(0) {
        // `::sha2::Sha256`: a crate named from the root
        i = ws(s, cls, 2);
    }
    let mut segs = Vec::new();
    loop {
        let (seg, end) = segment(i)?;
        segs.push(seg);
        // `::<..>` turbofish
        let mut j = ws(s, cls, end);
        if colons(j) && s.get(ws(s, cls, j + 2)) == Some(&'<') {
            let open = ws(s, cls, j + 2);
            let close = skip_angle(s, cls, open)?;
            heads(open + 1, close - 1);
            j = ws(s, cls, close);
        }
        if colons(j) && segment(ws(s, cls, j + 2)).is_some() {
            i = ws(s, cls, j + 2);
            continue;
        }
        let last = segs.pop().unwrap();
        return Some((segs, last, generics));
    }
}
/// Whether a token starts at `col` of `line` (1-based): not inside an identifier (nor after the
/// `r#` of a raw identifier), and not after `::`, with whitespace and comments in between: a
/// path is cited at its first segment. A single `:` (`W { n:Sha256::digest(d) }`) does not
/// continue a path.
pub(super) fn token_start(src: &Source, line: usize, col: usize) -> bool {
    let Some(text) = src.lines.get(line.wrapping_sub(1)) else {
        return false;
    };
    let chars: Vec<char> = text.chars().collect();
    let before = |k: usize| col.checked_sub(k).and_then(|i| chars.get(i)).copied();
    if before(1).is_some_and(is_ident) {
        return false;
    }
    if before(1) == Some('#') && before(2) == Some('r') && !before(3).is_some_and(is_ident) {
        return false;
    }
    // the two code (or literal) chars before, whitespace and comments skipped, over a few lines
    let mut prev = Vec::new();
    let (mut l, mut c) = (line - 1, col.min(chars.len()));
    loop {
        let lc: Vec<char> = src.lines[l].chars().collect();
        while c > 0 && prev.len() < 2 {
            c -= 1;
            let comment = src.class[l].get(c) == Some(&Class::Comment);
            if !comment && !lc[c].is_whitespace() {
                prev.push(lc[c]);
            }
        }
        if prev.len() == 2 || l == 0 || line - 1 - l >= 8 {
            break;
        }
        l -= 1;
        c = src.lines[l].chars().count();
    }
    prev != [':', ':']
}
/// A context's parts, split at the `; ` outside brackets (`in <[u8; 32] as From>::from; ..`).
pub(super) fn parts(details: &str) -> Vec<&str> {
    let b = details.as_bytes();
    let (mut out, mut depth, mut start) = (Vec::new(), 0i32, 0);
    for (i, &c) in b.iter().enumerate() {
        match c {
            b'<' | b'[' | b'(' => depth += 1,
            b'>' if i == 0 || b[i - 1] != b'-' => depth -= 1,
            b']' | b')' => depth -= 1,
            b';' if depth <= 0 && b.get(i + 1) == Some(&b' ') => {
                out.push(&details[start..i]);
                start = i + 2;
            }
            _ => {}
        }
    }
    out.push(&details[start..]);
    out
}
/// The identifier just before a position (whitespace and comments skipped, over a few lines),
/// when the token before it is one: `fn` in `fn seal<..>`, `macro_rules` in `macro_rules! m`.
pub(super) fn word_before(src: &Source, line: usize, offset: usize) -> Option<String> {
    let mut code = String::new();
    for l in line.saturating_sub(4).max(1)..=line {
        let chars: Vec<char> = src.lines[l - 1].chars().collect();
        let end = if l == line {
            offset.min(chars.len())
        } else {
            chars.len()
        };
        code.extend(
            chars[..end]
                .iter()
                .zip(&src.class[l - 1])
                .map(|(&c, k)| if *k == Class::Comment { ' ' } else { c }),
        );
        code.push(' ');
    }
    let code = code.trim_end();
    let code = code.strip_suffix('!').unwrap_or(code);
    let word: String = code
        .chars()
        .rev()
        .take_while(|&c| is_ident(c))
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    (!word.is_empty()).then_some(word)
}
/// The source from a position on, over the next 63 lines: chars and their classes. A path is
/// read from it with its generic arguments balanced, so the extent only bounds a path rustfmt
/// spread over many lines.
pub(super) fn rest(src: &Source, line: usize, offset: usize) -> (Vec<char>, Vec<Class>) {
    let mut s = Vec::new();
    let mut k = Vec::new();
    for (n, l) in src.lines.iter().enumerate().skip(line - 1).take(64) {
        if n + 1 != line {
            s.push('\n');
            k.push(Class::Code);
        }
        let from = if n + 1 == line { offset } else { 0 };
        for (c, ch) in l.chars().enumerate().skip(from) {
            s.push(ch);
            k.push(src.class[n].get(c).copied().unwrap_or(Class::Code));
        }
    }
    (s, k)
}
pub(super) fn word_of(s: &[char], i: usize) -> String {
    s.get(i..)
        .unwrap_or_default()
        .iter()
        .take_while(|c| is_ident(**c))
        .collect()
}
/// Whether an identifier (not a number) starts at `i`.
pub(super) fn word_start(s: &[char], i: usize) -> bool {
    i < s.len() && is_ident(s[i]) && !s[i].is_ascii_digit() && (i == 0 || !is_ident(s[i - 1]))
}
/// Whether the keyword `k` is at `i`.
pub(super) fn kw(s: &[char], i: usize, k: &str) -> bool {
    word_start(s, i)
        && s[i..].iter().take(k.len()).copied().eq(k.chars())
        && !s.get(i + k.len()).is_some_and(|c| is_ident(*c))
}
pub(super) fn skip_blank(s: &[char], mut i: usize) -> usize {
    while i < s.len() && s[i].is_whitespace() {
        i += 1;
    }
    i
}
/// The last non-blank char before `i`.
pub(super) fn before_blank(s: &[char], i: usize) -> Option<usize> {
    (0..i.min(s.len())).rev().find(|&k| !s[k].is_whitespace())
}
/// The parentheses of the call whose path starts at `k` (`Algorithm::hash(..)`, `f::<T>(..)`):
/// the indexes of its `(` and `)`.
pub(super) fn call_args_span(s: &[char], k: usize) -> Option<(usize, usize)> {
    let mut i = k;
    loop {
        if !word_start(s, i) {
            return None;
        }
        i = skip_blank(s, i + word_of(s, i).chars().count());
        if !(s.get(i) == Some(&':') && s.get(i + 1) == Some(&':')) {
            break;
        }
        i = skip_blank(s, i + 2);
        if s.get(i) == Some(&'<') {
            let cls = vec![Class::Code; s.len() - i];
            i = skip_blank(s, i + skip_angle(&s[i..], &cls, 0)?);
            break;
        }
    }
    Some((i, close_of_at(s, i).filter(|_| s.get(i) == Some(&'('))?))
}
/// The word that ends before `i`, blanks skipped (empty when a symbol does).
pub(super) fn word_before_at(s: &[char], i: usize) -> String {
    let Some(e) = before_blank(s, i).filter(|&e| is_ident(s[e])) else {
        return String::new();
    };
    let mut b = e + 1;
    while b > 0 && is_ident(s[b - 1]) {
        b -= 1;
    }
    s[b..=e].iter().collect()
}
/// The matching close of the bracket at `open` (`(`, `[`, `{`).
pub(super) fn close_of_at(s: &[char], open: usize) -> Option<usize> {
    if !matches!(s.get(open), Some('(' | '[' | '{')) {
        return None;
    }
    let mut depth = 0i32;
    for (j, &c) in s.iter().enumerate().skip(open) {
        match c {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(j);
                }
            }
            _ => {}
        }
    }
    None
}
/// The matching open of the bracket at `close` (`)`, `]`, `}`).
pub(super) fn open_of_at(s: &[char], close: usize) -> Option<usize> {
    if !matches!(s.get(close), Some(')' | ']' | '}')) {
        return None;
    }
    let mut depth = 0i32;
    for j in (0..=close).rev() {
        match s[j] {
            ')' | ']' | '}' => depth += 1,
            '(' | '[' | '{' => {
                depth -= 1;
                if depth == 0 {
                    return Some(j);
                }
            }
            _ => {}
        }
    }
    None
}
/// From `from`, the first index outside the brackets opened after `from` where `stop` holds,
/// or where a bracket opened before `from` closes; `to` when none does before it.
pub(super) fn scan_to(s: &[char], from: usize, to: usize, stop: impl Fn(usize) -> bool) -> usize {
    let to = to.min(s.len());
    let mut depth = 0i32;
    let mut i = from;
    while i < to {
        if depth == 0 && stop(i) {
            return i;
        }
        match s[i] {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => {
                depth -= 1;
                if depth < 0 {
                    return i;
                }
            }
            _ => {}
        }
        i += 1;
    }
    to
}
/// The `=` of a `let` whose pattern starts at `from`: the first outside brackets that is no
/// `==`, `=>`, `<=`, `>=`, `!=` or compound assignment; None at a `;` first (`let x;`).
pub(super) fn let_eq_at(s: &[char], from: usize, to: usize) -> Option<usize> {
    let i = scan_to(s, from, to, |i| {
        s[i] == ';'
            || (s[i] == '='
                && !matches!(s.get(i + 1), Some('=' | '>'))
                && !matches!(
                    i.checked_sub(1).map(|p| s[p]),
                    Some('=' | '!' | '<' | '>' | '+' | '-' | '*' | '/' | '%' | '^' | '&' | '|')
                ))
    });
    (s.get(i) == Some(&'=')).then_some(i)
}
pub(super) fn is_keyword(w: &str) -> bool {
    matches!(
        w,
        "let"
            | "mut"
            | "ref"
            | "if"
            | "else"
            | "match"
            | "for"
            | "in"
            | "while"
            | "loop"
            | "return"
            | "as"
            | "move"
            | "async"
            | "await"
            | "unsafe"
            | "true"
            | "false"
            | "break"
            | "continue"
            | "where"
            | "fn"
            | "const"
            | "static"
            | "dyn"
            | "impl"
            | "crate"
            | "super"
            | "box"
    )
}
/// The call whose arguments the bracket at `ob` opens: the start of its callee's last segment
/// and that name (`f`, `m::f::<T>`, `.m`), skipping a turbofish.
pub(super) fn callee_before(s: &[char], ob: usize) -> Option<(usize, String)> {
    let mut e = before_blank(s, ob)?;
    if s[e] == '>' {
        // `::<..>`: back to its `<`, then past the `::`
        let mut depth = 0;
        let mut k = e + 1;
        loop {
            k = k.checked_sub(1)?;
            match s[k] {
                '>' => depth += 1,
                '<' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
        }
        let c = before_blank(s, k)?;
        if s[c] != ':' || c == 0 || s[c - 1] != ':' {
            return None;
        }
        e = before_blank(s, c - 1)?;
    }
    if !is_ident(s[e]) {
        return None;
    }
    let mut b = e + 1;
    while b > 0 && is_ident(s[b - 1]) {
        b -= 1;
    }
    Some((b, s[b..=e].iter().collect()))
}
/// The parameters of a parameter list, split at its top-level commas.
pub(super) fn split_top(t: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut cur = String::new();
    for c in t.chars() {
        match c {
            '(' | '[' | '{' | '<' => depth += 1,
            ')' | ']' | '}' | '>' => depth -= 1,
            ',' if depth == 0 => {
                out.push(std::mem::take(&mut cur));
                continue;
            }
            _ => {}
        }
        cur.push(c);
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    out
}
/// The path written before the word at `start` (`dep::inner::` before `X`: `[dep, inner]`).
pub(super) fn path_before(s: &[char], start: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut at = start;
    while let Some(p) = before_blank(s, at)
        && s[p] == ':'
        && p > 0
        && s[p - 1] == ':'
    {
        let Some(e) = before_blank(s, p - 1) else {
            break;
        };
        if !is_ident(s[e]) {
            break;
        }
        let mut b = e;
        while b > 0 && is_ident(s[b - 1]) {
            b -= 1;
        }
        out.push(s[b..=e].iter().collect::<String>());
        at = b;
    }
    out.reverse();
    out
}
/// Is the statement at `at` under a `#[cfg(..)]` attribute?
pub(super) fn cfg_before(s: &[char], at: usize) -> bool {
    let Some(p) = before_blank(s, at).filter(|&p| s[p] == ']') else {
        return false;
    };
    let mut depth = 0;
    let mut k = p + 1;
    while k > 0 {
        k -= 1;
        match s[k] {
            ']' => depth += 1,
            '[' => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            _ => {}
        }
    }
    k > 0 && s[k - 1] == '#' && kw(s, skip_blank(s, k + 1), "cfg")
}
/// Whether the code at `a..b` is `t`, blanks aside.
pub(super) fn src_text_is(s: &[char], a: usize, b: usize, t: &str) -> bool {
    s[a..b.min(s.len())]
        .iter()
        .filter(|c| !c.is_whitespace())
        .copied()
        .eq(t.chars())
}
impl Tok {
    pub(super) fn text(&self) -> String {
        match self {
            Tok::Word(w) | Tok::Lit(w) => w.clone(),
            Tok::Punct(c) => c.to_string(),
            Tok::Group(d, inner) => {
                let close = match d {
                    '(' => ')',
                    '[' => ']',
                    _ => '}',
                };
                format!("{d}{}{close}", toks_text(inner))
            }
        }
    }
}
pub(super) fn toks_text(t: &[Tok]) -> String {
    t.iter().map(Tok::text).collect::<Vec<_>>().join(" ")
}
/// The tokens of `text`: comments skipped, literals whole, brackets as groups.
pub(super) fn tokens(text: &str) -> Vec<Tok> {
    fn go(chars: &[char], cls: &[Class], i: &mut usize, close: Option<char>) -> Vec<Tok> {
        let mut out = Vec::new();
        while *i < chars.len() {
            let c = chars[*i];
            match cls[*i] {
                Class::Comment => {
                    *i += 1;
                    continue;
                }
                Class::Literal => {
                    let s = *i;
                    while *i < chars.len() && cls[*i] == Class::Literal {
                        *i += 1;
                    }
                    out.push(Tok::Lit(chars[s..*i].iter().collect()));
                    continue;
                }
                Class::Code => {}
            }
            if c.is_whitespace() {
                *i += 1;
                continue;
            }
            if Some(c) == close {
                *i += 1;
                return out;
            }
            let s = *i;
            match c {
                '(' | '[' | '{' => {
                    let cl = match c {
                        '(' => ')',
                        '[' => ']',
                        _ => '}',
                    };
                    *i += 1;
                    let inner = go(chars, cls, i, Some(cl));
                    out.push(Tok::Group(c, inner));
                }
                _ if is_ident(c) => {
                    while *i < chars.len() && is_ident(chars[*i]) && cls[*i] == Class::Code {
                        *i += 1;
                    }
                    let w: String = chars[s..*i].iter().collect();
                    out.push(if c.is_ascii_digit() {
                        Tok::Lit(w)
                    } else {
                        Tok::Word(w)
                    });
                }
                _ => {
                    out.push(Tok::Punct(c));
                    *i += 1;
                }
            }
        }
        out
    }
    let chars: Vec<char> = text.chars().collect();
    let cls = classify(text);
    let mut i = 0;
    go(&chars, &cls, &mut i, None)
}

/// The callee of a call through a pointer, as `pointer_callee` reads it.
pub(super) struct Callee {
    /// The name the pointer is read by: the first name of a parenthesised expression, the
    /// last segment of a path.
    pub(super) root: String,
    /// Where it is, in the text read.
    pub(super) root_at: usize,
    /// Where the path alone ends (none for a parenthesised expression).
    pub(super) path_end: Option<usize>,
    /// Where the callee may end: before each bracketed group of arguments that follows (`f` of
    /// `f(a)`; `get` and `get()` of `get()(a)`).
    pub(super) ends: Vec<usize>,
}

/// The callee of a call through a pointer at the start of `s` (the code from the position on,
/// over the lines after, with its classes): a parenthesised expression (`(h.f)`), or a path
/// (`h`, `Self::F`, `algs::HASH`, `pick::<u8>`) with fields, indexes, calls and `?` after it
/// (`fs[ix[0]]`, `get()`), before the arguments. None when the text is no such expression
/// followed by arguments.
pub(super) fn pointer_callee(s: &[char], cls: &[Class]) -> Option<Callee> {
    let code = |i: usize| cls.get(i) == Some(&Class::Code);
    // past blanks and comments
    let skip = |mut i: usize| {
        while i < s.len()
            && (!code(i) && cls.get(i) != Some(&Class::Literal) || s[i].is_whitespace())
        {
            i += 1;
        }
        i
    };
    // past the bracket at `i` and what it holds
    let group = |i: usize| -> Option<usize> {
        let mut depth = 0usize;
        for (k, &c) in s.iter().enumerate().skip(i) {
            if !code(k) {
                continue;
            }
            match c {
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' => {
                    depth = depth.checked_sub(1)?;
                    if depth == 0 {
                        return Some(k + 1);
                    }
                }
                _ => {}
            }
        }
        None
    };
    let ident = |i: usize| -> usize {
        let mut k = i;
        if s.get(k) == Some(&'r') && s.get(k + 1) == Some(&'#') {
            k += 2;
        }
        let st = k;
        while k < s.len() && code(k) && is_ident(s[k]) {
            k += 1;
        }
        if k == st || s[st].is_ascii_digit() {
            i
        } else {
            k
        }
    };
    let (mut i, mut root, mut root_at, mut path_end) = (0, String::new(), 0, None);
    if s.first() == Some(&'(') {
        i = group(0)?;
        let inner = skip(1);
        let mut k = inner;
        while k < i && (matches!(s[k], '*' | '&') || s[k].is_whitespace()) {
            k += 1;
        }
        let e = ident(k);
        if e > k {
            root = s[k..e]
                .iter()
                .collect::<String>()
                .trim_start_matches("r#")
                .to_string();
            root_at = k;
        }
    } else {
        loop {
            let e = ident(i);
            if e == i {
                return None;
            }
            root = s[i..e]
                .iter()
                .collect::<String>()
                .trim_start_matches("r#")
                .to_string();
            root_at = i;
            i = e;
            // `::segment`, `::<arguments>`
            let mut j = skip(i);
            let mut more = false;
            while s.get(j) == Some(&':') && s.get(j + 1) == Some(&':') {
                j = skip(j + 2);
                if s.get(j) == Some(&'<') {
                    let mut depth = 0usize;
                    let mut k = j;
                    while k < s.len() {
                        if code(k) {
                            match s[k] {
                                '<' => depth += 1,
                                '>' if k > 0 && s[k - 1] == '-' => {}
                                '>' => {
                                    depth -= 1;
                                    if depth == 0 {
                                        break;
                                    }
                                }
                                ';' | '{' | '}' => return None,
                                _ => {}
                            }
                        }
                        k += 1;
                    }
                    if k >= s.len() {
                        return None;
                    }
                    i = k + 1;
                    j = skip(i);
                } else {
                    i = j;
                    more = true;
                    break;
                }
            }
            if !more {
                break;
            }
        }
        path_end = Some(i);
    }
    let mut ends = Vec::new();
    loop {
        let j = skip(i);
        match s.get(j) {
            Some('.') => {
                let k = skip(j + 1);
                let mut e = ident(k);
                if e == k {
                    // (a tuple's element)
                    while e < s.len() && s[e].is_ascii_digit() {
                        e += 1;
                    }
                }
                if e == k {
                    break;
                }
                i = e;
            }
            Some('[') => i = group(j)?,
            Some('(') => {
                ends.push(i);
                i = group(j)?;
            }
            Some('?') => i = j + 1,
            _ => break,
        }
    }
    (!ends.is_empty()).then_some(Callee {
        root,
        root_at,
        path_end,
        ends,
    })
}

/// The code from a position on, over the lines after: comments and literals blanked.
pub(super) fn code_from(src: &Source, line: usize, offset: usize) -> String {
    let (s, k) = rest(src, line, offset);
    s.iter()
        .zip(&k)
        .map(|(&c, k)| if *k == Class::Code { c } else { ' ' })
        .collect()
}

/// A pattern for the path `name` as the grammar lets it be written where the text starts:
/// from the root (`::pm::Sum`) or `$crate`, under any qualifiers, with blanks and line ends
/// around its `::`, each segment a raw identifier or not (`mac::r#free_fn`); then `suffix`.
pub(super) fn written_path(name: &str, suffix: &str) -> Regex {
    let segments: Vec<String> = name
        .split("::")
        .filter(|g| !g.is_empty())
        .map(|g| format!("(?:r#)?{}", regex::escape(g.trim_start_matches("r#"))))
        .collect();
    Regex::new(&format!(
        r"^(?:\$crate\s*::\s*|::\s*)?(?:(?:r#)?\w+\s*::\s*)*{}{suffix}",
        segments.join(r"\s*::\s*")
    ))
    .unwrap()
}
