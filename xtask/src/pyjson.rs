//! JSON and text written as the earlier Python tools wrote them (`json.dumps`, `str`, a list's
//! `repr`), so that golden files and committed scores stay byte for byte what they were.

use serde_json::Value;

/// A JSON value whose objects keep the order they are built in (`Obj`), for documents written
/// in insertion order; a `serde_json::Value` converts with its keys sorted.
#[derive(Clone, Debug, PartialEq)]
pub enum Val {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    List(Vec<Val>),
    Obj(Vec<(String, Val)>),
}

impl From<&Value> for Val {
    fn from(v: &Value) -> Val {
        match v {
            Value::Null => Val::Null,
            Value::Bool(b) => Val::Bool(*b),
            Value::Number(n) => match n.as_i64() {
                Some(i) => Val::Int(i),
                None => Val::Float(n.as_f64().unwrap_or(f64::NAN)),
            },
            Value::String(s) => Val::Str(s.clone()),
            Value::Array(a) => Val::List(a.iter().map(Val::from).collect()),
            Value::Object(o) => Val::Obj(o.iter().map(|(k, v)| (k.clone(), v.into())).collect()),
        }
    }
}

impl From<&str> for Val {
    fn from(s: &str) -> Val {
        Val::Str(s.to_string())
    }
}

impl From<String> for Val {
    fn from(s: String) -> Val {
        Val::Str(s)
    }
}

impl From<usize> for Val {
    fn from(n: usize) -> Val {
        Val::Int(n as i64)
    }
}

impl From<i64> for Val {
    fn from(n: i64) -> Val {
        Val::Int(n)
    }
}

impl From<Vec<String>> for Val {
    fn from(v: Vec<String>) -> Val {
        Val::List(v.into_iter().map(Val::Str).collect())
    }
}

/// `json.dumps(v)`, with `sort_keys` and `indent` as Python takes them (ASCII only).
pub fn dumps(v: &Val, sort_keys: bool, indent: Option<usize>) -> String {
    let mut out = String::new();
    write(v, sort_keys, indent, 0, &mut out);
    out
}

/// `json.dumps(v, sort_keys=True)` of a parsed value.
pub fn js(v: &Value) -> String {
    dumps(&v.into(), true, None)
}

fn write(v: &Val, sort_keys: bool, indent: Option<usize>, level: usize, out: &mut String) {
    let newline = |out: &mut String, level: usize| {
        if let Some(n) = indent {
            out.push('\n');
            out.push_str(&" ".repeat(n * level));
        }
    };
    let sep = if indent.is_some() { "," } else { ", " };
    match v {
        Val::Null => out.push_str("null"),
        Val::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Val::Int(i) => out.push_str(&i.to_string()),
        Val::Float(f) => out.push_str(&float(*f)),
        Val::Str(s) => string(s, out),
        Val::List(items) if items.is_empty() => out.push_str("[]"),
        Val::List(items) => {
            out.push('[');
            for (i, x) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(sep);
                }
                newline(out, level + 1);
                write(x, sort_keys, indent, level + 1, out);
            }
            newline(out, level);
            out.push(']');
        }
        Val::Obj(fields) if fields.is_empty() => out.push_str("{}"),
        Val::Obj(fields) => {
            let mut fields: Vec<&(String, Val)> = fields.iter().collect();
            if sort_keys {
                fields.sort_by(|a, b| a.0.cmp(&b.0));
            }
            out.push('{');
            for (i, (k, x)) in fields.into_iter().enumerate() {
                if i > 0 {
                    out.push_str(sep);
                }
                newline(out, level + 1);
                string(k, out);
                out.push_str(": ");
                write(x, sort_keys, indent, level + 1, out);
            }
            newline(out, level);
            out.push('}');
        }
    }
}

/// A float as Python's `repr` writes it: the shortest form that reads back, with `.0` on a
/// whole number.
pub fn float(f: f64) -> String {
    if f.is_finite() && f.fract() == 0.0 && f.abs() < 1e16 {
        format!("{f:.1}")
    } else {
        format!("{f}")
    }
}

/// A string as `json.dumps` writes it, with `ensure_ascii`.
fn string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || (c as u32) > 0x7f => {
                let mut buf = [0u16; 2];
                for u in c.encode_utf16(&mut buf) {
                    out.push_str(&format!("\\u{u:04x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// A parsed value as Python's `str` writes it in an f-string (`None`, `True`, a string as it
/// is); a list or an object as JSON.
pub fn pystr(v: Option<&Value>) -> String {
    match v {
        None | Some(Value::Null) => "None".into(),
        Some(Value::Bool(b)) => if *b { "True" } else { "False" }.into(),
        Some(Value::Number(n)) => match n.as_i64() {
            Some(i) => i.to_string(),
            None => float(n.as_f64().unwrap_or(f64::NAN)),
        },
        Some(Value::String(s)) => s.clone(),
        Some(other) => js(other),
    }
}

/// A list of strings as Python's `repr` writes it (`['SHA-256', 'SHA-384']`).
pub fn repr_list<S: AsRef<str>>(items: &[S]) -> String {
    let inner: Vec<String> = items
        .iter()
        .map(|s| {
            format!(
                "'{}'",
                s.as_ref().replace('\\', "\\\\").replace('\'', "\\'")
            )
        })
        .collect();
    format!("[{}]", inner.join(", "))
}
