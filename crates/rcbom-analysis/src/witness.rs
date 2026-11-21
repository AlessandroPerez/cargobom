//! Where code is written, as the compiler records it and an occurrence's details give it: the
//! verifier checks these against the source's bytes instead of looking for the code itself.
//!
//! A span is `file:line:column-line:column` (columns from 0, the end exclusive), followed by
//! the start of its text (`as `..``) and a fingerprint of its line (`line #..`). A chain lists
//! the expansions code is in, innermost first: `by macro m! at <span> line #.. defined
//! file:line-line` (the invocation, its line's fingerprint, the definition's lines),
//! `by derive D at <span>`, `by attribute a at <span>`, `by rewrite await at <span>` (the
//! compiler's rewrites of syntax), `by compiler` (code the compiler adds).

use rcbom_facts::{Edge, Expansion, ExpansionStep, ItemAt, Loc, Rewrite, StepKind, ViaStep};

/// How a file of the facts is named in the CBOM.
pub(crate) type Named<'a> = &'a dyn Fn(&str) -> String;

/// `file:line:column-line:column`.
pub(crate) fn span(l: &Loc, named: Named) -> String {
    format!(
        "{}:{}:{}-{}:{}",
        named(&l.file),
        l.line,
        l.col.saturating_sub(1),
        l.end_line,
        l.end_col.saturating_sub(1)
    )
}

/// The start of a source text that a detail can hold between backquotes: up to a character the
/// details are split at, with its brackets closed.
pub(crate) fn quotable(t: &str) -> &str {
    let mut depth = 0i32;
    let mut end = 0;
    let b = t.as_bytes();
    for (i, &c) in b.iter().enumerate() {
        match c {
            b'`' | b';' => break,
            b'<' | b'[' | b'(' => depth += 1,
            b'>' if i == 0 || b[i - 1] != b'-' => depth -= 1,
            b']' | b')' => depth -= 1,
            _ => {}
        }
        if depth < 0 {
            break;
        }
        if depth == 0 && t.is_char_boundary(i + 1) {
            end = i + 1;
        }
    }
    t[..end].trim_end()
}

/// ` as `text`` and ` line #mark`: the start of the text at a position, and the fingerprint of
/// the position in its line (`rcbom_facts::line_mark`).
pub(crate) fn reads(text: Option<&String>, mark: Option<&String>) -> String {
    let mut out = String::new();
    if let Some(t) = text.map(|t| quotable(t)).filter(|t| !t.is_empty()) {
        out.push_str(&format!(" as `{t}`"));
    }
    if let Some(m) = mark {
        out.push_str(&format!(" line #{m}"));
    }
    out
}

pub(crate) fn rewrite(r: Rewrite) -> &'static str {
    match r {
        Rewrite::QuestionMark => "?",
        Rewrite::TryBlock => "try",
        Rewrite::Yeet => "yeet",
        Rewrite::OpaqueTy => "impl",
        Rewrite::Async => "async",
        Rewrite::Await => "await",
        Rewrite::ForLoop => "for",
        Rewrite::WhileLoop => "while",
        Rewrite::BoundModifier => "bound",
        Rewrite::Contract => "contract",
        Rewrite::PatTyRange => "pattern",
        Rewrite::FormatLiteral => "format",
        Rewrite::RangeExpr => "range",
    }
}

fn step(s: &ExpansionStep, named: Named) -> String {
    let what = match s.kind {
        StepKind::Bang => format!("macro {}!", s.name),
        StepKind::Derive => format!("derive {}", s.name),
        StepKind::Attr => format!("attribute {}", s.name),
        StepKind::Rewrite(r) => format!("rewrite {}", rewrite(r)),
        StepKind::Pass => return "by compiler".to_string(),
    };
    let mut out = format!("by {what} at {}", span(&s.call, named));
    out.push_str(&reads(None, s.mark.as_ref()));
    if s.def.line != 0 {
        out.push_str(&format!(
            " defined {}:{}-{}",
            named(&s.def.file),
            s.def.line,
            s.def.end_line
        ));
    }
    out
}

/// `<span> as `text` (<chain>)`: where the code of an expansion is written, and the expansions
/// it is in.
fn written(e: &Expansion, named: Named) -> String {
    let mut out = span(&e.def_site, named);
    out.push_str(&reads(e.text.as_ref(), e.mark.as_ref()));
    if !e.steps.is_empty() {
        let steps: Vec<String> = e.steps.iter().map(|s| step(s, named)).collect();
        out.push_str(&format!(" ({})", steps.join(", ")));
    }
    out
}

/// The detail of a position in a macro's code: `expanded from <span> as `text` (<chain>)`.
pub(crate) fn expanded(e: &Expansion, named: Named) -> String {
    format!("expanded from {}", written(e, named))
}

/// Where an item is named: its span, or for one a macro writes, where its name is written and
/// the expansions it is in.
fn item(at: &ItemAt, named: Named) -> String {
    match &at.expansion {
        Some(e) => written(e, named),
        // (` within line:column-line:column`: the item whole, in the file it is named in)
        // (an item with no identifier: with how it starts and its line's fingerprint)
        None => {
            let at_name = format!(
                "{}{}",
                span(&at.name, named),
                reads(at.text.as_ref(), at.mark.as_ref())
            );
            match at.body.as_ref().filter(|b| b.file == at.name.file) {
                Some(b) => format!(
                    "{at_name} within {}:{}-{}:{}",
                    b.line,
                    b.col.saturating_sub(1),
                    b.end_line,
                    b.end_col.saturating_sub(1)
                ),
                None => at_name,
            }
        }
    }
}

/// The detail of where the item a site is in is named: ``owner `item` at ..``. `cbom::context`
/// leaves the name out where it is the occurrence's own: an occurrence several items share (a
/// macro's invocation writing each) gives each one's.
pub(crate) fn owner(at: &ItemAt, name: &str, named: Named) -> String {
    format!("owner `{name}` at {}", item(at, named))
}

/// An `owner` detail as the analysis keeps it: the item's name, and where it is named.
pub(crate) fn owner_parts(d: &str) -> Option<(&str, &str)> {
    d.strip_prefix("owner `")?.split_once("` at ")
}

/// What the compiler records of a step of an instantiation chain, after the step: ` (call of
/// `f`, to line:column as `text` line #mark, from <written>, caller at <item>)`: how the code
/// reaches the function, where its span ends, how it starts and its line's fingerprint, where
/// a macro writes it, and where the caller is named. `callee` is the function the step
/// instantiates.
pub(crate) fn via(
    v: &ViaStep,
    callee: &str,
    short: &dyn Fn(&str) -> String,
    named: Named,
) -> String {
    let Some(edge) = &v.edge else {
        return String::new();
    };
    // (the last name of a path, without generic arguments)
    let last = |p: &str| {
        let mut depth = 0i32;
        let mut out = String::new();
        for c in p.chars() {
            match c {
                '<' => depth += 1,
                '>' => depth -= 1,
                _ if depth == 0 => out.push(c),
                _ => {}
            }
        }
        out.rsplit("::")
            .find(|s| !s.is_empty())
            .unwrap_or_default()
            .to_string()
    };
    let mut parts = vec![match edge {
        Edge::Call { named: n } if n.is_empty() || last(n) == last(callee) => "call".to_string(),
        Edge::Call { named: n } => format!("call of `{}`", short(n)),
        Edge::Drop => "drop".to_string(),
        Edge::Built => "built".to_string(),
        Edge::Pointer => "pointer".to_string(),
        Edge::ClosurePointer => "closure pointer".to_string(),
        Edge::Object => "object".to_string(),
        Edge::Constant => "constant".to_string(),
    }];
    parts.push(format!(
        "to {}:{}{}",
        v.span.end_line,
        v.span.end_col.saturating_sub(1),
        reads(v.head.as_ref(), v.mark.as_ref())
    ));
    if let Some(e) = &v.expansion {
        parts.push(format!("from {}", written(e, named)));
    }
    if let Some(at) = &v.caller_at {
        parts.push(format!("caller at {}", item(at, named)));
    }
    format!(" ({})", parts.join(", "))
}
