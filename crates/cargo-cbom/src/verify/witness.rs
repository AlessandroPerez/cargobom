//! What the compiler records of where code is written, as the generator gives it in an
//! occurrence's details, checked against the source's bytes.
//!
//! The details name spans (`file:line:column-line:column`, columns from 0, the end exclusive)
//! and, for code a macro writes, the expansions it is in, innermost first (`by macro m! at
//! <span> line #.. defined file:line-line`, `by derive D at <span> line #..`, `by attribute a
//! at <span> line #..`, `by rewrite await at <span> line #..`, `by compiler`). Nothing here
//! looks for code: each span is read where the detail says it is, and held to what the detail
//! says of it.
//! - A span starts and ends at a token's edge, in code; the text a detail records of it is its
//!   text, and the fingerprint (`line #..`) is that of its start in its line: another line, or
//!   another column of the line, has another.
//! - An expansion's invocation is its macro's: `name!`, the name in a `#[derive(..)]`, an
//!   attribute; a rewrite's code is what the compiler rewrites (`await`, `?`, `for`, `while`,
//!   `async`), unless a procedural macro writes that syntax: its tokens are at a span of its
//!   choosing (its invocation, a token of the item it is on). A definition is a
//!   `macro_rules!`, a `macro`, or a procedural macro's function. The last invocation is at
//!   the position cited.
//! - Code in an expansion is written in that macro's definition, in an invocation around it, or
//!   in the item an attribute or a derive around it is on.
//! - Code no procedural macro, no macro built into the compiler and no rewrite writes names
//!   what it uses, or takes the name from an invocation around it by a metavariable. An
//!   `include!`'s code is in the file its invocation names.
//! - An item is named at its identifier, after `fn`, `static` or `const`, and holds the
//!   positions of its code; a closure or an `async` block, which has no identifier, starts
//!   with the text and has the fingerprint its record gives, and holds them from where it
//!   starts to where it ends. In the standard library, compiled with functions put into their
//!   callers, a position need not be in the item that runs it.

use super::*;

/// `file:line:column-line:column`: lines from 1, columns from 0, the end exclusive.
#[derive(Clone, Debug)]
pub(super) struct Span {
    pub(super) file: String,
    pub(super) start: (usize, usize),
    pub(super) end: (usize, usize),
}

#[derive(Clone, Debug, PartialEq)]
pub(super) enum StepKind {
    Macro,
    Derive,
    Attribute,
    Rewrite(Rewrite),
    Compiler,
}

/// The compiler's rewrites of syntax, as the generator names them.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) enum Rewrite {
    QuestionMark,
    Try,
    Yeet,
    Impl,
    Async,
    Await,
    For,
    While,
    Bound,
    Contract,
    Pattern,
    Format,
    Range,
}

#[derive(Clone, Debug)]
pub(super) struct Step {
    pub(super) kind: StepKind,
    pub(super) name: String,
    pub(super) call: Option<Span>,
    /// The fingerprint of the invocation's line.
    pub(super) line: Option<String>,
    /// The definition: its file and lines.
    pub(super) def: Option<(String, usize, usize)>,
}

/// Where code is written, how its text starts, its line's fingerprint, and the expansions it is
/// in.
#[derive(Clone, Debug)]
pub(super) struct Written {
    pub(super) at: Span,
    pub(super) text: Option<String>,
    pub(super) line: Option<String>,
    pub(super) steps: Vec<Step>,
    /// An item whole, in the file it is named in: from, to.
    pub(super) within: Option<((usize, usize), (usize, usize))>,
}

/// What the compiler records of a step of an instantiation chain.
#[derive(Clone, Debug)]
pub(super) struct Via {
    /// For a call of a function under another name than the one instantiated (`Future::poll`
    /// for an `async` block), that function.
    pub(super) named: Option<String>,
    pub(super) to: (usize, usize),
    /// How the step's code starts, and its line's fingerprint.
    pub(super) text: Option<String>,
    pub(super) line: Option<String>,
    pub(super) from: Option<Written>,
    pub(super) caller: Option<Written>,
}

fn num(s: &str) -> usize {
    s.parse().unwrap_or(0)
}

fn span(s: &str) -> Option<(Span, &str)> {
    let m = re!(r"^([^\s;]+?):(\d+):(\d+)-(\d+):(\d+)").captures(s)?;
    Some((
        Span {
            file: m[1].to_string(),
            start: (num(&m[2]), num(&m[3])),
            end: (num(&m[4]), num(&m[5])),
        },
        &s[m[0].len()..],
    ))
}

fn step(s: &str) -> Option<(Step, &str)> {
    if let Some(rest) = s.strip_prefix("compiler") {
        return Some((
            Step {
                kind: StepKind::Compiler,
                name: String::new(),
                call: None,
                line: None,
                def: None,
            },
            rest,
        ));
    }
    let m = re!(r"^(?:macro ([\w:$]+)!|derive ([\w:$]+)|attribute ([\w:$]+)|rewrite (\S+)) at ")
        .captures(s)?;
    let (kind, name) = if let Some(n) = m.get(1) {
        (StepKind::Macro, n.as_str())
    } else if let Some(n) = m.get(2) {
        (StepKind::Derive, n.as_str())
    } else if let Some(n) = m.get(3) {
        (StepKind::Attribute, n.as_str())
    } else {
        let r = match &m[4] {
            "?" => Rewrite::QuestionMark,
            "try" => Rewrite::Try,
            "yeet" => Rewrite::Yeet,
            "impl" => Rewrite::Impl,
            "async" => Rewrite::Async,
            "await" => Rewrite::Await,
            "for" => Rewrite::For,
            "while" => Rewrite::While,
            "bound" => Rewrite::Bound,
            "contract" => Rewrite::Contract,
            "pattern" => Rewrite::Pattern,
            "format" => Rewrite::Format,
            "range" => Rewrite::Range,
            _ => return None,
        };
        (StepKind::Rewrite(r), "")
    };
    let (call, rest) = span(&s[m[0].len()..])?;
    let (_, line, rest) = reads(rest)?;
    let (def, rest) = match re!(r"^ defined ([^\s;]+?):(\d+)-(\d+)").captures(rest) {
        Some(d) => (
            Some((d[1].to_string(), num(&d[2]), num(&d[3]))),
            &rest[d[0].len()..],
        ),
        None => (None, rest),
    };
    Some((
        Step {
            kind,
            name: name.to_string(),
            call: Some(call),
            line,
            def,
        },
        rest,
    ))
}

/// ` as `text`` and ` line #mark`, and what follows them.
fn reads(mut rest: &str) -> Option<(Option<String>, Option<String>, &str)> {
    let mut text = None;
    if let Some(r) = rest.strip_prefix(" as `") {
        let k = r.find('`')?;
        text = Some(r[..k].to_string());
        rest = &r[k + 1..];
    }
    let mut line = None;
    if let Some(m) = re!(r"^ line #([0-9a-f]{8})").captures(rest) {
        line = Some(m[1].to_string());
        rest = &rest[m[0].len()..];
    }
    Some((text, line, rest))
}

/// The fingerprint of a position in its source line: FNV-1a over the line's bytes with a zero
/// byte where the position is, as 8 hexadecimal digits. The generator records it from the
/// compiler's span; another line, or another column of the line, has another.
pub(super) fn line_mark(line: &str, col: usize) -> String {
    let at = line.char_indices().nth(col).map_or(line.len(), |(i, _)| i);
    let mut h: u32 = 0x811c_9dc5;
    let mut eat = |b: u8| {
        h ^= u32::from(b);
        h = h.wrapping_mul(0x0100_0193);
    };
    line.as_bytes()[..at].iter().for_each(|b| eat(*b));
    eat(0);
    line.as_bytes()[at..].iter().for_each(|b| eat(*b));
    format!("{h:08x}")
}

/// Whether the code of `src`, the file at `path`, from `a` to `b` takes the file `other` in by
/// an `include!`: one whose argument is a path to it from the file's directory
/// (`include!("table.rs")`), or is built of parts and ends as the file's path does
/// (`include!(concat!(env!("OUT_DIR"), "/const.rs"))`).
pub(super) fn includes(
    src: &Source,
    path: &Path,
    a: (usize, usize),
    b: (usize, usize),
    other: &Path,
) -> bool {
    let (from, to) = (src.idx(a), src.idx(b));
    let code = src.text(from, to);
    re!(r"\binclude\s*!\s*\(").find_iter(&code).any(|m| {
        let open = from + code[..m.end()].chars().count() - 1;
        let Some(close) = close_of_at(&src.code, open) else {
            return false;
        };
        let arg = text_of(src, src.pos(open + 1), src.pos(close));
        let arg = arg.trim().trim_end_matches(',').trim_end();
        let parts: Vec<&str> = re!(r#""((?:[^"\\]|\\.)*)""#)
            .captures_iter(arg)
            .filter_map(|c| c.get(1))
            .map(|g| g.as_str())
            .collect();
        let Some(last) = parts.last().filter(|l| !l.is_empty()) else {
            return false;
        };
        if parts.len() == 1 && arg.starts_with('"') && arg.ends_with('"') {
            let named = path
                .parent()
                .map(|d| rcbom_manifest::normalize(&d.join(last)));
            return named.is_some_and(|n| n == rcbom_manifest::normalize(other));
        }
        other
            .to_string_lossy()
            .strip_suffix(last)
            .is_some_and(|rest| last.starts_with('/') || rest.ends_with('/'))
    })
}

/// `<span> as `text` line #mark (by .., by ..)`, and what follows it.
fn written(s: &str) -> Option<(Written, &str)> {
    let (at, rest) = span(s)?;
    let (text, line, mut rest) = reads(rest)?;
    let mut steps = Vec::new();
    if let Some(mut r) = rest.strip_prefix(" (by ") {
        loop {
            let (st, after) = step(r)?;
            steps.push(st);
            match after.strip_prefix(", by ") {
                Some(a) => r = a,
                None => {
                    rest = after.strip_prefix(')')?;
                    break;
                }
            }
        }
    }
    let mut within = None;
    if let Some(m) = re!(r"^ within (\d+):(\d+)-(\d+):(\d+)").captures(rest) {
        within = Some(((num(&m[1]), num(&m[2])), (num(&m[3]), num(&m[4]))));
        rest = &rest[m[0].len()..];
    }
    Some((
        Written {
            at,
            text,
            line,
            steps,
            within,
        },
        rest,
    ))
}

/// A detail of where an item is named (`owner at <written>`, or with the item where it is not
/// the occurrence's own, ``owner `item` at <written>``): the item named, and where.
pub(super) fn owner_detail(part: &str) -> Option<(Option<&str>, &str)> {
    let rest = part.strip_prefix("owner ")?;
    match rest.strip_prefix('`') {
        Some(r) => r.split_once("` at ").map(|(item, at)| (Some(item), at)),
        None => rest.strip_prefix("at ").map(|at| (None, at)),
    }
}

/// A detail that is all of one written position (`owner at ..`, `expanded from ..`, after
/// those words).
pub(super) fn written_whole(s: &str) -> Option<Written> {
    written(s)
        .filter(|(_, rest)| rest.is_empty())
        .map(|(w, _)| w)
}

/// A step of an instantiation chain with what the compiler records of it: the step as it is
/// without that, and the record.
pub(super) fn split_via(part: &str) -> Result<(&str, Option<Via>), String> {
    let Some(m) = re!(
        r" at [^\s;]+?:\d+:\d+(?: as `[^`]*`)?( \((?:call|closure pointer|constant|drop|built|pointer|object)\b)"
    )
    .captures(part) else {
        return Ok((part, None));
    };
    if !part.contains("instantiated by ") {
        return Ok((part, None));
    }
    let open = m.get(1).map_or(0, |g| g.start());
    let bad = || format!("`{part}`: what is recorded of the step cannot be read");
    let inside = part[open..]
        .strip_prefix(" (")
        .and_then(|x| x.strip_suffix(')'))
        .ok_or_else(bad)?;
    // how the code there reaches the function: a call (of a function named), a value dropped,
    // a closure built, a function or a closure made a pointer, a value made a trait object, a
    // constant holding pointers
    let (named, rest) = if let Some(r) = inside.strip_prefix("call of `") {
        let k = r.find('`').ok_or_else(bad)?;
        (Some(r[..k].to_string()), &r[k + 1..])
    } else {
        let kind = [
            "call",
            "closure pointer",
            "constant",
            "drop",
            "built",
            "pointer",
            "object",
        ]
        .into_iter()
        .find(|k| inside.starts_with(k))
        .ok_or_else(bad)?;
        (None, &inside[kind.len()..])
    };
    let t = re!(r"^, to (\d+):(\d+)").captures(rest).ok_or_else(bad)?;
    let to = (num(&t[1]), num(&t[2]));
    let (text, line, mut rest) = reads(&rest[t[0].len()..]).ok_or_else(bad)?;
    let mut from = None;
    if let Some(r) = rest.strip_prefix(", from ") {
        let (w, after) = written(r).ok_or_else(bad)?;
        from = Some(w);
        rest = after;
    }
    let mut caller = None;
    if let Some(r) = rest.strip_prefix(", caller at ") {
        let (w, after) = written(r).ok_or_else(bad)?;
        caller = Some(w);
        rest = after;
    }
    if !rest.is_empty() {
        return Err(bad());
    }
    Ok((
        &part[..open],
        Some(Via {
            named,
            to,
            text,
            line,
            from,
            caller,
        }),
    ))
}

/// The last name of a path as a macro's code writes it, metavariables and all
/// (`$mode::$mode2::<aes::Aes128>::new`: `new`; `ring::digest::$alg`: `$alg`): what follows the
/// last `::` outside brackets. `None` where the text is no path: each segment is a name, with
/// generic arguments or not, or bracketed whole.
pub(super) fn last_segment(text: &str) -> Option<String> {
    let cs: Vec<char> = text.trim().chars().collect();
    let mut segments: Vec<String> = Vec::new();
    let (mut depth, mut start, mut i) = (0usize, 0usize, 0usize);
    while i < cs.len() {
        match cs[i] {
            '<' | '(' | '[' | '{' => depth += 1,
            '>' if i > 0 && cs[i - 1] == '-' => {}
            '>' | ')' | ']' | '}' => depth = depth.checked_sub(1)?,
            ':' if depth == 0 && cs.get(i + 1) == Some(&':') => {
                segments.push(cs[start..i].iter().collect());
                start = i + 2;
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }
    if depth != 0 {
        return None;
    }
    segments.push(cs[start..].iter().collect());
    let mut last = None;
    for seg in &segments {
        let seg = seg.trim();
        // (`<T as Trait>`, a turbofish's `<u8>`)
        if seg.starts_with('<') && seg.ends_with('>') {
            continue;
        }
        let m = re!(r"^(\$?(?:r#)?[A-Za-z_]\w*)\s*(?:<.*>)?$").captures(seg)?;
        last = Some(m[1].to_string());
    }
    last
}

/// The last name of an item's path, without generic arguments (`<a::S as T>::f::<u8>`: `f`); a
/// closure's is `{closure#0}`.
fn last_name(item: &str) -> String {
    let mut depth = 0i32;
    let mut out = String::new();
    let b: Vec<char> = item.chars().collect();
    for (i, &c) in b.iter().enumerate() {
        match c {
            '<' => depth += 1,
            '>' if i > 0 && b[i - 1] == '-' => {}
            '>' => depth -= 1,
            _ if depth == 0 => out.push(c),
            _ => {}
        }
    }
    out.rsplit("::")
        .map(str::trim)
        .find(|s| !s.is_empty())
        .unwrap_or_default()
        .trim_start_matches("r#")
        .to_string()
}

/// Whether an item's path names a closure, an `async` block or another body with no name of
/// its own.
fn unnamed(item: &str) -> bool {
    let n = last_name(item);
    n.starts_with('{') && n.ends_with('}')
}

/// The source text from one position to another (comments and literals kept).
fn text_of(src: &Source, a: (usize, usize), b: (usize, usize)) -> String {
    let mut out = String::new();
    for l in a.0.max(1)..=b.0.min(src.lines.len()) {
        let chars: Vec<char> = src.lines[l - 1].chars().collect();
        let from = if l == a.0 { a.1.min(chars.len()) } else { 0 };
        let to = if l == b.0 {
            b.1.min(chars.len())
        } else {
            chars.len()
        };
        out.extend(&chars[from.min(to)..to]);
        if l != b.0 {
            out.push('\n');
        }
    }
    out
}

/// The source at a position starts as a detail says, on a line of the fingerprint it gives.
fn reads_as(
    src: &Source,
    span: &Span,
    start: (usize, usize),
    text: Option<&str>,
    line: Option<&str>,
) -> Result<(), String> {
    reads_at(src, &span.file, start, text, line)
}

/// `reads_as` for a position a detail gives alone (where a function pointer was named).
pub(super) fn reads_at(
    src: &Source,
    file: &str,
    start: (usize, usize),
    text: Option<&str>,
    line: Option<&str>,
) -> Result<(), String> {
    let at = format!("{file}:{}:{}", start.0, start.1);
    if let Some(t) = text {
        let got = text_of(src, start, (start.0, usize::MAX));
        if !got.starts_with(t) {
            let got: String = got.chars().take(t.chars().count()).collect();
            return Err(format!("{at} reads `{got}`, not `{t}`"));
        }
    }
    if let Some(mark) = line
        && src
            .lines
            .get(start.0.wrapping_sub(1))
            .is_none_or(|l| line_mark(l, start.1) != mark)
    {
        return Err(format!("{at}: the line is not the one recorded (#{mark})"));
    }
    Ok(())
}

/// The code of a line (comments and literals blank).
fn code_line(src: &Source, line: usize) -> String {
    src.lines
        .get(line.wrapping_sub(1))
        .zip(src.class.get(line.wrapping_sub(1)))
        .map(|(t, cls)| {
            t.chars()
                .zip(cls)
                .map(|(c, k)| if *k == Class::Code { c } else { ' ' })
                .collect()
        })
        .unwrap_or_default()
}

/// The item an attribute is on, from the attribute's end: to the end of its body, or its `;`.
/// Indexes in `code`.
fn item_after(src: &Source, from: usize) -> Option<usize> {
    let code = &src.code;
    // the attribute's own `]`: from its `#`, or from inside it (a derive's name in its list)
    let close = if code.get(from) == Some(&'#') {
        let open = (from..code.len()).find(|&k| code[k] == '[')?;
        close_of_at(code, open)
    } else {
        let mut depth = 0i32;
        let mut i = from;
        let mut close = None;
        while i < code.len() {
            match code[i] {
                '[' => depth += 1,
                ']' if depth == 0 => {
                    close = Some(i);
                    break;
                }
                ']' => depth -= 1,
                _ => {}
            }
            i += 1;
        }
        close
    };
    let mut i = skip_blank(code, close? + 1);
    // the attributes after it
    while code.get(i) == Some(&'#') {
        let open = (i..code.len()).find(|&k| code[k] == '[')?;
        i = skip_blank(code, close_of_at(code, open)? + 1);
    }
    let mut depth = 0i32;
    while i < code.len() {
        match code[i] {
            '(' | '[' => depth += 1,
            ')' | ']' => depth -= 1,
            '{' if depth <= 0 => return close_of_at(code, i),
            ';' if depth <= 0 => return Some(i),
            _ => {}
        }
        i += 1;
    }
    None
}

/// The last line of the macro defined on `line` (`macro_rules! m { .. }`, `macro m(..) { .. }`,
/// or the invocation that writes it, `define! { .. }`): where its brackets close.
fn macro_end(src: &Source, line: usize, written: bool) -> Option<usize> {
    let code = &src.code;
    let from = src.idx((line, 0));
    let text: String = code[from..src.idx((line + 1, 0))].iter().collect();
    let declared = re!(r"\bmacro_rules\s*!\s*\w+|\bmacro\s+\w+").find(&text);
    let m = declared.or_else(|| invocation().find(&text).filter(|_| written))?;
    // (`macro m(..) { .. }`: its parameters, then its body)
    let two = declared.is_some() && !m.as_str().starts_with("macro_rules");
    let mut i = from + text[..m.end()].chars().count();
    let mut end = None;
    for _ in 0..2 {
        i = skip_blank(code, i);
        if !matches!(code.get(i), Some('(' | '[' | '{')) {
            break;
        }
        let round = code[i] == '(';
        let close = close_of_at(code, i)?;
        end = Some(close);
        i = close + 1;
        if !two || !round {
            break;
        }
    }
    end.map(|e| src.pos(e).0)
}

/// A macro invoked: its path and `!`, before the bracket its input opens with.
fn invocation() -> &'static Regex {
    re!(r"(?:\$crate\s*::\s*|::\s*)?\b\w+(?:\s*::\s*\w+)*\s*!")
}

/// What a step of an expansion holds of the source: its definition's lines, its invocation, the
/// item its attribute is on.
struct Holder {
    def: Option<(PathBuf, usize, usize)>,
    call: Option<Extent>,
    item: Option<Extent>,
    /// An `include!`'s invocation, as it reads: its code is the file it names.
    included: Option<String>,
}

/// A stretch of a file: from a position to another.
type Extent = (PathBuf, (usize, usize), (usize, usize));

impl Holder {
    fn holds(&self, path: &Path, a: (usize, usize), b: (usize, usize)) -> bool {
        let within = |h: &Option<Extent>| {
            h.as_ref()
                .is_some_and(|(p, x, y)| p == path && *x <= a && b <= *y)
        };
        self.def
            .as_ref()
            .is_some_and(|(p, l0, l1)| p == path && *l0 <= a.0 && b.0 <= *l1)
            || within(&self.call)
            || within(&self.item)
            || self.included.as_ref().is_some_and(|text| {
                path.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| text.contains(n))
            })
    }
}

impl Files<'_> {
    /// A place the compiler records and no name in the text holds (`<span> as `text` line
    /// #mark`, a coercion's): the span runs from a token's edge to a token's edge, starts with
    /// that text, and is on a line of that fingerprint.
    pub(super) fn check_place(&mut self, record: &str) -> Result<(), String> {
        let w = written_whole(record).ok_or_else(|| format!("`{record}` cannot be read"))?;
        let Some(mark) = &w.line else {
            return Err(format!(
                "no fingerprint of the line of {}:{}:{}",
                w.at.file, w.at.start.0, w.at.start.1
            ));
        };
        let (_, src) = self.span_at(&w.at, true)?;
        reads_as(&src, &w.at, w.at.start, w.text.as_deref(), Some(mark))
    }

    /// The detail of a position in what a procedural function-like macro was handed (`in the
    /// input of macro m! at <span> line #.. defined F:L-L`): the invocation is that macro's,
    /// as the compiler records the expansion; the macro is none the source declares, whose
    /// input would read as the code it is; and the invocation holds the position, past its
    /// first token.
    pub(super) fn check_input_of(
        &mut self,
        record: &str,
        at: (&Path, usize, usize),
    ) -> Result<(), String> {
        let (st, rest) = step(record)
            .filter(|(s, _)| s.kind == StepKind::Macro)
            .ok_or("the invocation cannot be read")?;
        let Some(call) = st.call.clone().filter(|_| rest.is_empty()) else {
            return Err("the invocation cannot be read".into());
        };
        let w = Written {
            at: call.clone(),
            text: None,
            line: st.line.clone(),
            steps: vec![st],
            within: None,
        };
        if self.check_written(&w, None, false)? {
            return Err(format!(
                "the macro invoked at {}:{}:{} is declared: what it is handed reads as the \
                 code it is",
                call.file, call.start.0, call.start.1
            ));
        }
        if self.resolve(&call.file)? != at.0
            || !(call.start < (at.1, at.2) && (at.1, at.2) < call.end)
        {
            return Err(format!(
                "the invocation at {}:{}:{} does not hold the position",
                call.file, call.start.0, call.start.1
            ));
        }
        Ok(())
    }

    /// A span's file read, the span in it: from a token's edge to a token's edge, in code
    /// (`literal`: or in a literal, a format string's part). A documentation comment is a
    /// token too, an attribute of the item it is on: a span may start at one, and what holds
    /// the span says whether code can be there (only code a procedural macro writes).
    fn span_at(&mut self, s: &Span, literal: bool) -> Result<(PathBuf, Rc<Source>), String> {
        let path = self.resolve(&s.file)?;
        let src = self
            .source(&path)
            .ok_or_else(|| format!("cannot read {}", s.file))?;
        let at = format!("{}:{}:{}", s.file, s.start.0, s.start.1);
        let line = |l: usize| -> Option<Vec<char>> {
            src.lines
                .get(l.wrapping_sub(1))
                .map(|t| t.chars().collect())
        };
        let (Some(first), Some(last)) = (line(s.start.0), line(s.end.0)) else {
            return Err(format!("{at}: no such line"));
        };
        if s.end < s.start || s.start.1 > first.len() || s.end.1 > last.len() {
            return Err(format!("{at}: no such span"));
        }
        let class = |l: usize, c: usize| src.class.get(l - 1).and_then(|k| k.get(c)).copied();
        if s.start.1 < first.len() {
            let k = class(s.start.0, s.start.1);
            if !(k == Some(Class::Code)
                || literal && k.is_some()
                || doc_comment_at(&src, s.start.0, s.start.1))
            {
                return Err(format!("{at}: not in code"));
            }
            if first[s.start.1].is_whitespace()
                || is_ident(first[s.start.1]) && s.start.1 > 0 && is_ident(first[s.start.1 - 1])
            {
                return Err(format!("{at}: no token starts there"));
            }
        }
        if s.end.1 > 0
            && s.end.1 < last.len()
            && is_ident(last[s.end.1 - 1])
            && is_ident(last[s.end.1])
            && class(s.end.0, s.end.1) == Some(Class::Code)
        {
            return Err(format!(
                "{}:{}:{}: no token ends there",
                s.file, s.end.0, s.end.1
            ));
        }
        Ok((path, src))
    }

    /// Where code is written and the expansions it is in, each as the detail says: the spans,
    /// the text, each invocation and definition, and each span inside what holds it. `cited`
    /// is the position the last expansion's invocation is cited at, where an occurrence or a
    /// step cites it. `lent`: the code is in an item a procedural macro writes, which may have
    /// put it at any token it was handed. Whether no procedural or built-in macro is among the
    /// expansions: the code is then written as it reads.
    pub(super) fn check_written(
        &mut self,
        w: &Written,
        cited: Option<(&Path, usize, usize)>,
        lent: bool,
    ) -> Result<bool, String> {
        let format = w
            .steps
            .iter()
            .any(|s| s.kind == StepKind::Rewrite(Rewrite::Format));
        let (raw_path, raw_src) = self.span_at(&w.at, format)?;
        reads_as(
            &raw_src,
            &w.at,
            w.at.start,
            w.text.as_deref(),
            w.line.as_deref(),
        )?;
        let mut plain = true;
        let mut holders: Vec<Holder> = Vec::new();
        // (which expansions are of a procedural or built-in macro, and the rewrites whose code
        // does not read as what they rewrite)
        let mut procedural: Vec<bool> = Vec::new();
        let mut unread: Vec<(usize, String)> = Vec::new();
        let n = w.steps.len();
        for (i, st) in w.steps.iter().enumerate() {
            let mut holder = Holder {
                def: None,
                call: None,
                item: None,
                included: None,
            };
            let Some(call) = &st.call else {
                // code the compiler adds: no source
                plain = false;
                holders.push(holder);
                procedural.push(false);
                continue;
            };
            let (cpath, csrc) =
                self.span_at(call, st.kind == StepKind::Rewrite(Rewrite::Format))?;
            let Some(mark) = &st.line else {
                return Err(format!(
                    "{}:{}:{}: no fingerprint of the invocation's line",
                    call.file, call.start.0, call.start.1
                ));
            };
            reads_as(&csrc, call, call.start, None, Some(mark))?;
            // the last invocation is where the occurrence or the step is cited
            if let Some((p, l, c)) = cited.filter(|_| i + 1 == n)
                && (p != cpath || (l, c) != call.start)
            {
                return Err(format!(
                    "the last expansion is invoked at {}:{}:{}, not at the position cited",
                    call.file, call.start.0, call.start.1
                ));
            }
            let start = call.start;
            let here = format!("{}:{}:{}", call.file, start.0, start.1);
            let (rs, _) = rest(&csrc, start.0, start.1);
            let head: String = rs.iter().take(400).collect();
            let name = st.name.rsplit("::").next().unwrap_or_default();
            let named = |prefix: &str, suffix: &str| {
                super::compiled(&format!("^{prefix}"))
                    .ok()
                    .and_then(|r| r.find(&head))
                    .is_some_and(|open| written_path(name, suffix).is_match(&head[open.end()..]))
            };
            match &st.kind {
                StepKind::Macro => {
                    // (a macro another one is handed by name and invokes through its
                    // metavariable, kryptering's `$callback!(sha2::Sha256)` in `dispatch_hash!`
                    // invoked as `dispatch_hash!(hash, do_sign)`: an invocation around this
                    // one names it)
                    let handed = re!(r"^\$[A-Za-z_]\w*\s*!").is_match(&head)
                        && w.steps[i + 1..].iter().any(|outer| {
                            outer.call.as_ref().is_some_and(|c| {
                                self.span_at(c, false).is_ok_and(|(_, s)| {
                                    super::compiled(&format!(r"\b{}\b", regex::escape(name)))
                                        .is_ok_and(|r| r.is_match(&text_of(&s, c.start, c.end)))
                                })
                            })
                        });
                    if !named("", r"\s*!") && !handed {
                        // (cited inside an attribute: what reads the attribute, a procedural
                        // macro, writes the invocation at the span of what the attribute
                        // holds. derive-deftly's `Deftly` invokes the template named in
                        // `#[derive_deftly(Name)]` at that name, and where a `macro_rules!`
                        // writes the attribute the compiler has no expansion of `Deftly`
                        // between the two. The text there is the attribute's.)
                        if attribute_before(&csrc, start.0, start.1).is_some() {
                            plain = false;
                        } else {
                            unread.push((i, format!("{here}: no invocation of `{}!`", st.name)));
                        }
                    }
                }
                StepKind::Derive => {
                    let listed = attribute_before(&csrc, start.0, start.1).is_some_and(|a| {
                        re!(r"^(?:derive|cfg_attr)\s*\(").is_match(&a) && open_in(&a, "derive")
                    });
                    if !(named("", r"\b") && listed) {
                        unread.push((
                            i,
                            format!(
                                "{here}: `{}` is not named in a `#[derive(..)]` there",
                                st.name
                            ),
                        ));
                    }
                }
                StepKind::Attribute => {
                    let direct = named(r"#\s*!?\s*\[\s*", r"\b");
                    let inside =
                        named("", r"\b") && attribute_before(&csrc, start.0, start.1).is_some();
                    if !(direct || inside) {
                        unread.push((i, format!("{here}: no attribute `{}`", st.name)));
                    }
                }
                StepKind::Rewrite(r) => {
                    let text = text_of(&csrc, start, call.end);
                    let t = text.trim();
                    let ok = match r {
                        Rewrite::Await => t.ends_with("await"),
                        Rewrite::QuestionMark => t.ends_with('?'),
                        Rewrite::For => t.starts_with("for") || head_before(&csrc, start, "in"),
                        Rewrite::While => t.starts_with("while") || t.starts_with('\''),
                        Rewrite::Async => true,
                        Rewrite::Try => t.starts_with("try") || t.starts_with('{'),
                        Rewrite::Yeet
                        | Rewrite::Impl
                        | Rewrite::Bound
                        | Rewrite::Contract
                        | Rewrite::Pattern
                        | Rewrite::Format
                        | Rewrite::Range => true,
                    };
                    if !ok {
                        unread.push((i, format!("{here}: `{t}` is not what `{r:?}` rewrites")));
                    }
                }
                StepKind::Compiler => {}
            }
            holder.call = Some((cpath.clone(), start, call.end));
            // (`include!("gen.rs")`, `include!(concat!(env!("OUT_DIR"), "/gen.rs"))`: the one
            // macro whose code is another file's, the file its invocation names)
            if st.kind == StepKind::Macro && name == "include" {
                holder.included = Some(text_of(&csrc, start, call.end));
            }
            // (the item an attribute or a derive is on)
            if matches!(st.kind, StepKind::Derive | StepKind::Attribute)
                && let Some(end) = item_after(&csrc, csrc.idx(call.start))
            {
                // (from the attribute's line: the attributes beside it are the item's too)
                holder.item = Some((cpath.clone(), (call.start.0, 0), csrc.pos(end + 1)));
            }
            match &st.def {
                Some((file, l0, l1)) => {
                    let dpath = self.resolve(file)?;
                    let dsrc = self
                        .source(&dpath)
                        .ok_or_else(|| format!("cannot read {file}"))?;
                    if *l0 == 0 || *l1 < *l0 || *l1 > dsrc.lines.len() {
                        return Err(format!("{file}:{l0}-{l1}: no such lines"));
                    }
                    let code = code_line(&dsrc, *l0);
                    let declared = re!(r"\bmacro_rules\s*!|\bmacro\s+\w").is_match(&code);
                    // (a macro the compiler implements: its definition's text is not its code)
                    let built_in = (l0.saturating_sub(4).max(1)..=*l0)
                        .any(|l| code_line(&dsrc, l).contains("rustc_builtin_macro"));
                    // a procedural macro is a function of a procedural-macro crate. The
                    // line reads `fn`, or it is whatever a macro that writes the function
                    // gave it (`#[proc_macro_error]` over the function puts it at its own
                    // line): then the package's manifest says what the crate is
                    let function = re!(r"\bfn\b").is_match(&code)
                        || super::manifest::in_proc_macro_package(&dpath);
                    // a macro another macro writes is defined, for the compiler, where that
                    // one is invoked (derive-deftly's `define_derive_deftly! { Name: .. }`
                    // writes the `macro_rules!` of its template), or at the derive or the
                    // attribute that writes it: the line invokes a macro or is in an
                    // attribute, and what is there is not read as the macro's code
                    let written = !declared
                        && (invocation().find(&code).is_some_and(|m| {
                            matches!(
                                code[m.end()..].trim_start().chars().next(),
                                Some('(' | '[' | '{')
                            )
                        }) || code
                            .chars()
                            .position(|c| !c.is_whitespace())
                            .is_some_and(|c| attribute_before(&dsrc, *l0, c + 2).is_some()));
                    if !(declared || function || written) {
                        return Err(format!("{file}:{l0}: no macro is defined there"));
                    }
                    if !declared || built_in {
                        plain = false;
                    }
                    procedural.push(!declared || built_in);
                    self.by_macro |= !declared || built_in;
                    // (the compiler records where a macro of another crate starts: it runs
                    // to its closing bracket)
                    let end =
                        macro_end(&dsrc, *l0, written && !function).map_or(*l1, |e| e.max(*l1));
                    holder.def = Some((dpath, *l0, end));
                }
                // (a rewrite's calls are the compiler's: `next` of a `for`, `poll` of an
                // `await`; a macro without a definition is built in)
                None => {
                    plain = false;
                    procedural.push(!matches!(st.kind, StepKind::Rewrite(_)));
                    self.by_macro |= !matches!(st.kind, StepKind::Rewrite(_));
                }
            }
            holders.push(holder);
        }
        // an invocation reads as its macro's, and a rewrite's code as what it rewrites, where
        // it is written as it reads: a procedural macro puts what it writes at a span of its
        // choosing (its own invocation, a token of the item it is on), whose text is not that
        // syntax (rust-s3's `#[maybe_async::maybe_async]` writes `#[async_trait::async_trait]`
        // over the trait it is on, at its own span). So in an item a procedural macro
        // writes, with no expansion of that macro around the code: the span is a token the
        // macro was handed (rocket's `#[launch]` awaits what the function returns, and gives
        // the `.await` the span of the function's return type)
        if !lent
            && let Some((_, e)) = unread
                .into_iter()
                .find(|(i, _)| !procedural.get(i + 1).copied().unwrap_or(false))
        {
            return Err(e);
        }
        // each span inside what holds it: the code in the expansions around it, an invocation
        // in the expansions around its own
        for i in 0..n {
            let (path, a, b, file) = if i == 0 {
                (raw_path.clone(), w.at.start, w.at.end, &w.at.file)
            } else {
                let Some(c) = &w.steps[i - 1].call else {
                    continue;
                };
                let Some((p, _, _)) = &holders[i - 1].call else {
                    continue;
                };
                (p.clone(), c.start, c.end, &c.file)
            };
            // (code the compiler adds holds whatever it writes)
            let free = w.steps[i..].iter().any(|s| s.kind == StepKind::Compiler);
            if !free && !holders[i..].iter().any(|h| h.holds(&path, a, b)) {
                return Err(format!(
                    "{file}:{}:{} is in neither the definition nor the invocation of an \
                     expansion around it",
                    a.0, a.1
                ));
            }
        }
        // (macros that are declared write their tokens where they read: none of their code
        // is at a documentation comment)
        if plain && doc_comment_at(&raw_src, w.at.start.0, w.at.start.1) {
            return Err(format!(
                "{}:{}:{}: not in code",
                w.at.file, w.at.start.0, w.at.start.1
            ));
        }
        Ok(plain)
    }

    /// The code written at a position names `symbol`: a path whose last name is its last name,
    /// or one the file imports it as; or the operator the symbol's method is written as.
    pub(super) fn names_symbol(&mut self, w: &Written, symbol: &str) -> Result<bool, String> {
        let path = self.resolve(&w.at.file)?;
        let Some(src) = self.source(&path) else {
            return Ok(false);
        };
        let ident = last_name(symbol);
        // (a macro's `$crate::path`, `$name`: read from after the `$`)
        let dollar = src
            .lines
            .get(w.at.start.0.wrapping_sub(1))
            .and_then(|l| l.chars().nth(w.at.start.1))
            == Some('$');
        let (rs, rc) = rest(&src, w.at.start.0, w.at.start.1 + usize::from(dollar));
        let last = path_and_generics(&rs, &rc).map(|(_, last, _)| last);
        if last.as_deref().map(|l| l.trim_start_matches("r#")) == Some(ident.as_str()) {
            return Ok(true);
        }
        if let Some(l) = &last
            && src
                .binds
                .iter()
                .any(|b| b.name == *l && b.path.last() == Some(&ident))
        {
            return Ok(true);
        }
        // (a `macro_rules!` body's path is resolved where the macro is invoked: a name the
        // invoking file imports the symbol as; and `$crate::name`, one the macro's package
        // re-exports it as)
        if let Some(l) = &last {
            let mut binds: Vec<Rc<Vec<Binding>>> = Vec::new();
            for st in &w.steps {
                let Some(call) = &st.call else { continue };
                let cpath = self.resolve(&call.file)?;
                if let Some(csrc) = self.source(&cpath) {
                    binds.push(Rc::new(csrc.binds.clone()));
                }
            }
            if dollar && let Some(dir) = self.man.owner_of(&path).map(|p| p.manifest_dir.clone()) {
                binds.push(self.package_binds(&dir));
            }
            if binds
                .iter()
                .flat_map(|b| b.iter())
                .any(|b| b.name == *l && b.path.last() == Some(&ident))
            {
                return Ok(true);
            }
        }
        // (an operator is somewhere in its expression's span)
        let text = text_of(&src, w.at.start, w.at.end);
        if super::check::operator_of(symbol).is_some_and(|op| text.contains(op)) {
            return Ok(true);
        }
        if !re!(r"\$[A-Za-z_]\w*").is_match(&text) {
            return Ok(false);
        }
        // a path with a metavariable before its last name (`$mode::$mode2::<aes::Aes128>::new`):
        // the name is what follows the path's last `::`
        if let Some(l) = last_segment(&text) {
            let l = l.trim_start_matches("r#");
            if l == ident
                || src
                    .binds
                    .iter()
                    .any(|b| b.name == l && b.path.last() == Some(&ident))
            {
                return Ok(true);
            }
        }
        // a name the macro takes from its invocation (`ring::digest::$alg`, `$f(..)`): the
        // code is written with a metavariable, and an invocation around it names the symbol,
        // by its name or by one its file imports it as
        for st in &w.steps {
            let Some(call) = &st.call else { continue };
            let cpath = self.resolve(&call.file)?;
            let Some(csrc) = self.source(&cpath) else {
                continue;
            };
            let code = csrc.text(csrc.idx(call.start), csrc.idx(call.end));
            let mut names = vec![regex::escape(&ident)];
            names.extend(
                csrc.binds
                    .iter()
                    .filter(|b| b.path.last() == Some(&ident) && b.name != "*")
                    .map(|b| regex::escape(&b.name)),
            );
            if super::compiled(&format!(r"\b(?:{})\b", names.join("|")))
                .is_ok_and(|r| r.is_match(&code))
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// An item is named where the detail says, and holds the position `held`: the occurrence's,
    /// or a step's (`on`: or is the item the attribute cited there is on). Whether no
    /// procedural or built-in macro writes the item: its code is then written as it reads.
    pub(super) fn check_item_at(
        &mut self,
        w: &Written,
        item: &str,
        held: (&Path, usize, Option<usize>),
        on: Option<((usize, usize), (usize, usize))>,
    ) -> Result<bool, String> {
        let name = last_name(item);
        let at = format!("{}:{}:{}", w.at.file, w.at.start.0, w.at.start.1);
        let inside = |a: (usize, usize), b: (usize, usize)| match held.2 {
            Some(c) => a <= (held.1, c) && (held.1, c) <= b,
            None => a.0 <= held.1 && held.1 <= b.0,
        };
        // (the item the attribute cited at the position is on: it is where it is named)
        let attributed = on.is_some_and(|(a, b)| a <= w.at.start && w.at.end <= b);
        if !w.steps.is_empty() {
            // an item a macro writes: named where the detail says, in that macro's code or its
            // invocation; the position is in the invocation, or in the item its attribute is on
            let plain = self.check_written(w, None, false)?;
            if plain
                && !unnamed(item)
                && let Some(t) = &w.text
                && t.chars().all(|c| is_ident(c) || c == '#')
                && t.trim_start_matches("r#") != name
            {
                return Err(format!("{at} names `{t}`, not `{name}`"));
            }
            let Some(last) = w.steps.iter().rev().find_map(|s| s.call.as_ref()) else {
                return Ok(plain);
            };
            let (cpath, csrc) = self.span_at(last, false)?;
            if cpath != held.0 || last.file.starts_with("/rustc/") {
                return Ok(plain);
            }
            let item = item_after(&csrc, csrc.idx(last.start)).map(|e| csrc.pos(e + 1));
            if inside(last.start, last.end) || item.is_some_and(|e| inside((last.start.0, 0), e)) {
                return Ok(plain);
            }
            return Err(format!(
                "the invocation at {}:{}:{} that makes `{name}` does not hold {}:{}",
                last.file,
                last.start.0,
                last.start.1,
                held.1,
                held.2.unwrap_or(0)
            ));
        }
        let (path, src) = self.span_at(&w.at, false)?;
        // (an item no macro writes is where it reads)
        if doc_comment_at(&src, w.at.start.0, w.at.start.1) {
            return Err(format!("{at}: not in code"));
        }
        let library = w.at.file.starts_with("/rustc/");
        // (the item whole, where the compiler has it: it holds where it is named)
        if let Some((a, b)) = w.within
            && !(a <= w.at.start && w.at.end <= b && b.0 <= src.lines.len())
        {
            return Err(format!(
                "{at}: `{name}` is not within {}:{}-{}:{}",
                a.0, a.1, b.0, b.1
            ));
        }
        if unnamed(item) {
            // a closure, an `async` block, a constant's block: where it is written, as the
            // detail says it starts. Where the compiler has only where it starts (one of
            // another crate, seen from a static's value), it starts before the position.
            let Some(mark) = &w.line else {
                return Err(format!("{at}: no fingerprint of the line of `{name}`"));
            };
            reads_as(&src, &w.at, w.at.start, w.text.as_deref(), Some(mark))?;
            let (a, b) = w.within.unwrap_or((w.at.start, (usize::MAX, 0)));
            if path != held.0 {
                // (code another file holds for it: an `include!` inside it)
                if includes(&src, &path, a, b, held.0) {
                    return Ok(true);
                }
                return Err(format!("{at}: `{name}` is not in the file of the position"));
            }
            if !library && !attributed && !inside(a, b) {
                return Err(format!(
                    "{at} (to {}:{}) does not hold {}:{}",
                    b.0,
                    b.1,
                    held.1,
                    held.2.unwrap_or(0)
                ));
            }
            return Ok(true);
        }
        let text = text_of(&src, w.at.start, w.at.end);
        if text.trim_start_matches("r#") != name {
            return Err(format!("{at} names `{text}`, not `{name}`"));
        }
        let word = word_before(&src, w.at.start.0, w.at.start.1);
        if !matches!(word.as_deref(), Some("fn" | "static" | "const" | "mut")) {
            return Err(format!("{at}: `{name}` is not defined there"));
        }
        if library {
            return Ok(true);
        }
        if path != held.0 {
            // (code another file holds for the item: `fn table() { include!("table.rs") }`)
            if let Some((a, b)) = w.within
                && includes(&src, &path, a, b, held.0)
            {
                return Ok(true);
            }
            return Err(format!("{at}: `{name}` is not in the file of the position"));
        }
        if attributed {
            return Ok(true);
        }
        if let Some((a, b)) = w.within {
            if !inside(a, b) {
                return Err(format!(
                    "`{name}` at {at} (to {}:{}) does not hold {}:{}",
                    b.0,
                    b.1,
                    held.1,
                    held.2.unwrap_or(0)
                ));
            }
            return Ok(true);
        }
        // its extent, where the compiler's is not at hand (an item of another crate, seen
        // from the program's): to the end of its body, or of its value
        let code = &src.code;
        let mut i = src.idx(w.at.end);
        let mut depth = 0i32;
        let mut end = None;
        while i < code.len() {
            match code[i] {
                '(' | '[' => depth += 1,
                ')' | ']' => depth -= 1,
                '{' if depth <= 0 => {
                    end = close_of_at(code, i);
                    // (a value's block: `static T: X = { .. };`, to its `;`)
                    if word.as_deref() != Some("fn")
                        && let Some(e) = end
                    {
                        i = e;
                        end = None;
                    } else {
                        break;
                    }
                }
                ';' if depth <= 0 => {
                    end = (word.as_deref() != Some("fn")).then_some(i);
                    break;
                }
                _ => {}
            }
            i += 1;
        }
        let Some(end) = end else {
            return Err(format!("{at}: `{name}` has no body there"));
        };
        if !inside(w.at.start, src.pos(end)) {
            let (el, ec) = src.pos(end);
            return Err(format!(
                "`{name}` at {at} (to {el}:{ec}) does not hold {}:{}",
                held.1,
                held.2.unwrap_or(0)
            ));
        }
        Ok(true)
    }

    /// A step of an instantiation chain as the compiler records it: at `at`, in `caller`,
    /// reaching the code held at `inner`. Whether the caller is written as it reads: no
    /// procedural or built-in macro writes it.
    pub(super) fn check_via(
        &mut self,
        part: &str,
        via: &Via,
        caller: &str,
        at: (&str, &Path, usize, usize),
        inner: (&Path, usize, Option<usize>),
    ) -> Result<bool, String> {
        let (file, path, line, col) = at;
        let err = |e: String| format!("`{part}`: {e}");
        let here = Span {
            file: file.to_string(),
            start: (line, col),
            end: via.to,
        };
        let (_, src) = self.span_at(&here, false).map_err(err)?;
        reads_as(
            &src,
            &here,
            here.start,
            via.text.as_deref(),
            via.line.as_deref(),
        )
        .map_err(err)?;
        // a function the step names (the call is of it, the instance another's: `Future::poll`
        // for an `async` block) is of a crate of the build, or of the standard library
        if let Some(n) = &via.named {
            let first = n
                .trim_start_matches('<')
                .split(" as ")
                .last()
                .unwrap_or(n)
                .split("::")
                .next()
                .unwrap_or_default();
            if !self.crate_known(first) {
                return Err(err(format!("`{n}` is of no crate of the build")));
            }
        }
        // (a closure or an `async` block built there is not held to the span of the code that
        // builds it: a procedural macro gives that code the span of whatever it was made from,
        // `async` of an `async fn` for the block it wraps the body in. The closure is held to
        // its own extent, as the item of the step before.)
        let _ = inner;
        // (a step cited at an attribute or a derive: the caller is the item it is on)
        let on = via.from.as_ref().and_then(|w| {
            let last = w.steps.iter().rev().find(|s| s.call.is_some())?;
            if !matches!(last.kind, StepKind::Derive | StepKind::Attribute) {
                return None;
            }
            let end = item_after(&src, src.idx((line, col)))?;
            Some(((line, 0), src.pos(end + 1)))
        });
        self.by_macro = false;
        let as_read = match &via.caller {
            Some(w) => self
                .check_item_at(w, caller, (path, line, Some(col)), on)
                .map_err(err)?,
            None => true,
        };
        // where a macro writes its code: in the expansions the step is cited at (read as the
        // caller is written: by a procedural macro, at whatever token that macro chose)
        let lent = self.by_macro;
        if let Some(w) = &via.from {
            self.check_written(w, Some((path, line, col)), lent)
                .map_err(err)?;
        }
        Ok(as_read)
    }
}

/// Whether the word before a position (whitespace skipped) is `word`: a `for` loop's iterator
/// is after its `in`.
fn head_before(src: &Source, at: (usize, usize), word: &str) -> bool {
    let i = src.idx(at);
    before_blank(&src.code, i).is_some_and(|k| {
        k + 1 >= word.len()
            && src.code[k + 1 - word.len()..=k]
                .iter()
                .copied()
                .eq(word.chars())
    })
}
