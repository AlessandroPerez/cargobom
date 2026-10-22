//! The check of one occurrence: its position, its code, its details.

use super::*;

impl Files<'_> {
    pub(super) fn check(&mut self, oi: usize, line: usize, offset: usize) -> Result<(), String> {
        self.check_with(oi, line, offset, None)
    }

    /// `check`, with the occurrence's context replaced by `context` when given (the self-test
    /// shifts the lines its details cite).
    pub(super) fn check_with(
        &mut self,
        oi: usize,
        line: usize,
        offset: usize,
        context: Option<&str>,
    ) -> Result<(), String> {
        let occs = self.occs;
        let man = self.man;
        let mut o = occs[oi].clone();
        if let Some(c) = context {
            o.context = c.to_string();
        }
        let o = &o;
        let path = self.resolve(&o.location)?;
        let src = self
            .source(&path)
            .ok_or_else(|| format!("cannot read {}", path.display()))?;
        let text = src
            .lines
            .get(line.wrapping_sub(1))
            .ok_or("line out of range")?
            .clone();
        let chars: Vec<char> = text.chars().collect();
        if offset > chars.len() {
            return Err("offset past end of line".into());
        }
        let at: String = chars[offset..].iter().collect();

        // one occurrence per asset, position and symbol (the generator deduplicates by it): a
        // shifted position that lands on another occurrence of the same name is caught here
        if self
            .at_pos
            .get(&(o.location.clone(), line, offset))
            .into_iter()
            .flatten()
            .any(|&j| {
                j != oi && occs[j].component_ref == o.component_ref && occs[j].symbol == o.symbol
            })
        {
            return Err(
                "another occurrence of the same asset and symbol is at this position".into(),
            );
        }

        if o.context.starts_with("[manifest]") {
            let file = o.location.rsplit('/').next().unwrap_or("");
            return match file {
                "Cargo.lock" => check_lock(
                    &src.lines,
                    line,
                    offset,
                    &o.symbol,
                    &o.context,
                    &o.component_ref,
                ),
                "Cargo.toml" => check_toml(
                    &src.toml,
                    &text,
                    line,
                    offset,
                    &o.symbol,
                    &o.context,
                    &o.component_ref,
                ),
                _ => Err("a manifest occurrence outside Cargo.toml and Cargo.lock".into()),
            };
        }
        // evidence in code is one of the kinds the generator writes, after its tier
        let ctx = split_context(&o.context);
        let kind =
            re!(r"^\[(?:reachable|present)\] \[(call|static|via-static|instantiation|component)\]")
                .captures(ctx.tags)
                .map(|m| m[1].to_string())
                .ok_or("no tier and evidence kind among the tags")?;
        // an unknown algorithm is an operation's: the call is one the knowledge base lists (an
        // operation, a boundary model), or a use of a crypto package's API it does not model or
        // name (`p256::SecretKey::random`, age's `Identity::generate`)
        if o.component_ref.starts_with("crypto:algorithm:unknown:")
            && kind == "call"
            && !self.is_operation(&o.symbol)
        {
            return Err(format!(
                "`{}` is no operation the knowledge base lists, nor a crypto package's use",
                o.symbol
            ));
        }
        let starts_token = token_start(&src, line, offset);
        // the instance of a generic function the occurrence is in (`in tlib::hash_c::<ilib::
        // CFast>`, or a closure in it): its function's type parameters' arguments
        self.alg_arg = alg_arg(self.kb, &o.symbol);
        self.inst = ctx
            .details
            .strip_prefix(ctx.tags)
            .unwrap_or(ctx.details)
            .trim_start()
            .strip_prefix("in ")
            .and_then(|d| parts(d).into_iter().next())
            .and_then(|item| {
                let item = re!(r"(?:::\{closure#\d+\})+\s*$").replace(item.trim(), "");
                let args = instance_args(&item)?;
                let f = src.enclosing((line, offset), &[ItemKind::Fn])?;
                let g = fn_sig(&src, f).generics;
                (g.len() == args.len()).then(|| g.into_iter().zip(args).collect())
            })
            .unwrap_or_default();
        // code positions are in code, not in a comment or a literal
        if src.class[line - 1].get(offset) != Some(&Class::Code) {
            return Err(format!("position inside a comment or literal in {text:?}"));
        }
        // the generator records the source line and, when it is on one line outside a macro,
        // the exact text at the position, last in the context, in that order; the line may hold
        // backquotes, the text does not
        let Some(l) = ctx.line else {
            return Err("no source line recorded".into());
        };
        if text.trim() != l {
            return Err(format!("expected the line `{l}`, found {text:?}"));
        }
        if let Some(code) = ctx.code
            && !at.starts_with(code)
        {
            return Err(format!("expected `{code}` in {text:?}"));
        }
        // an import names an item, it does not use it
        if src
            .use_spans
            .iter()
            .any(|&(a, b)| a <= (line, offset) && (line, offset) < b)
        {
            return Err(format!("position inside a `use` item in {text:?}"));
        }
        // the positions the details name: where a generic instance was instantiated, where a
        // macro's code was written
        self.check_details(
            ctx.details,
            ctx.tags,
            &o.symbol,
            ctx.line,
            (&path, line, offset),
            &o.component_ref,
        )?;
        // where a type was made a trait object
        self.check_coercions(ctx.details)?;
        // the macro tags are among the leading tags, never in the recorded source text; a tagged
        // position is the macro's, derive's or attribute's name, not the symbol's
        let mut tagged = false;
        let mut macro_tagged = false;
        if let Some(m) = re!(r"\[macro ([\w:]+!)\]").captures(ctx.tags) {
            let name = &m[1];
            let ok = Regex::new(&format!(r"^(?:\w+::)*{}", regex::escape(name)))
                .unwrap()
                .is_match(&at);
            if !(ok && starts_token) {
                return Err(format!("expected `{name}` in {text:?}"));
            }
            tagged = true;
            macro_tagged = true;
        }
        // derive: the position is the derive's name inside `#[derive(..)]` (or a `cfg_attr`'s
        // `derive(..)`)
        if !tagged && let Some(m) = re!(r"\[derive ([\w:]+)\]").captures(ctx.tags) {
            let name = m[1].rsplit("::").next().unwrap_or(&m[1]).to_string();
            let ok = Regex::new(&format!(r"^(?:\w+::)*{}\b", regex::escape(&name)))
                .unwrap()
                .is_match(&at);
            let in_derive = attribute_before(&src, line, offset).is_some_and(|a| {
                re!(r"^(?:derive|cfg_attr)\s*\(").is_match(&a) && open_in(&a, "derive")
            });
            if !(ok && starts_token && in_derive) {
                return Err(format!(
                    "expected derive `{name}` inside `#[derive(..)]` in {text:?}"
                ));
            }
            tagged = true;
        }
        // attribute macro: the position is the attribute, or its name inside a `cfg_attr`
        if !tagged && let Some(m) = re!(r"\[attribute ([\w:]+)\]").captures(ctx.tags) {
            let name = m[1].rsplit("::").next().unwrap_or(&m[1]).to_string();
            let direct = Regex::new(&format!(r"^#!?\[\s*(?:\w+::)*{}\b", regex::escape(&name)))
                .unwrap()
                .is_match(&at)
                && at.starts_with('#');
            let in_cfg_attr = Regex::new(&format!(r"^(?:\w+::)*{}\b", regex::escape(&name)))
                .unwrap()
                .is_match(&at)
                && attribute_before(&src, line, offset)
                    .is_some_and(|a| re!(r"^cfg_attr\s*\(").is_match(&a));
            if !((direct || in_cfg_attr) && starts_token) {
                return Err(format!("expected an attribute in {text:?}"));
            }
            tagged = true;
        }
        // the symbol's crate is a package of the CBOM (or the standard library): a made-up one
        // would switch the checks below off
        let sym = strip_generics(&o.symbol);
        let sym_crate = sym.split("::").next().unwrap_or("").to_string();
        // (a qualified path's, `<t14::S384 as t14::Scheme>::ALG`, is its type's)
        let first = o
            .symbol
            .trim_start_matches('<')
            .split("::")
            .next()
            .unwrap_or("");
        let known = matches!(first, "core" | "std" | "alloc")
            || self.libs.as_ref().is_some_and(|l| l.contains_key(first))
            || self
                .man
                .packages
                .iter()
                .any(|p| p.name.replace('-', "_") == first);
        if !known {
            return Err(format!("`{}`: no crate `{first}` in the build", o.symbol));
        }
        // a standard-library path names a type or trait and a function of it that exist
        // (`core::convert::From::from`), in the module it names or one inside it
        if matches!(first, "core" | "std" | "alloc") && !self.std_item(&sym) {
            return Err(format!(
                "`{}`: no such item in the standard library",
                o.symbol
            ));
        }
        let mut parsed = None;
        let owner = man.owner_of(&path);
        let owner_id = owner.map(|p| p.id.repr.clone());
        // a macro's invocation is in the item the context names, as any position
        if macro_tagged {
            let chains = self.module_chains(&path, 0);
            let mut aliases = |n: &str| self.alias_targets(&src, owner, n);
            // (a static's own descriptor tells invocations apart too: `#[cfg(unix)] g!(run,
            // SHA384)` beside `#[cfg(not(unix))] g!(run, SHA512)`)
            let own = sym.rsplit("::").next().unwrap_or("");
            let own = (kind == "static"
                && own
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'))
            .then_some(own);
            check_item(
                &src,
                ctx.details.strip_prefix(ctx.tags).unwrap_or(ctx.details),
                (line, offset),
                &mut aliases,
                chains.as_deref(),
                own,
            )?;
        }
        if !tagged {
            // the enclosing item the context names (an identical statement in another
            // function, or in another type's method of that name, is another occurrence), and
            // no macro's body (a macro's code is cited where it is called)
            let chains = self.module_chains(&path, 0);
            let mut aliases = |n: &str| self.alias_targets(&src, owner, n);
            check_item(
                &src,
                ctx.details.strip_prefix(ctx.tags).unwrap_or(ctx.details),
                (line, offset),
                &mut aliases,
                chains.as_deref(),
                None,
            )?;
            // a definition names a new item, it does not use one (`fn seal<..>`, `pub fn digest`)
            if let Some(w) = word_before(&src, line, offset)
                && matches!(
                    w.as_str(),
                    "fn" | "struct"
                        | "enum"
                        | "union"
                        | "trait"
                        | "type"
                        | "mod"
                        | "static"
                        | "const"
                        | "let"
                        | "macro_rules"
                )
            {
                return Err(format!("position after `{w}`: a definition, in {text:?}"));
            }
            // code: the callee or static, by name or by an import alias of it (a raw
            // identifier's name without `r#`: `rand::Rng::r#gen` is written `.r#gen()`)
            let ident = sym
                .trim_end_matches(':')
                .rsplit("::")
                .next()
                .unwrap_or("")
                .trim_start_matches("r#")
                .to_string();
            if ident.is_empty() {
                return Err("no identifier in symbol".into());
            }
            // a call through a function pointer (`h(&SHA256, d)`): the position is the call's
            // callee expression, a name, a field or a parenthesised expression followed by its
            // arguments; the position the detail gives for where the function was made the
            // pointer names it (or an import alias of it)
            // (each function the pointer may hold: `FNS[i](..)` over `[digest, my_hash]`)
            let pointers: Vec<(String, usize, usize)> = re!(
                r"called through a function pointer to `[^`]+` named at ([^\s;]+?):(\d+):(\d+)(?:;|$)"
            )
            .captures_iter(ctx.details)
            .map(|m| {
                (
                    m[1].to_string(),
                    m[2].parse::<usize>().unwrap_or(0),
                    m[3].parse::<usize>().unwrap_or(0),
                )
            })
            .collect();
            let pointer = pointers.first().cloned();
            for (file, l2, c2) in &pointers {
                let (l2, c2) = (*l2, *c2);
                // the callee expression: a parenthesised expression (`(h.f)`), or a name with
                // fields, indexes and calls after it (`h`, `fs[0]`, `get()`), then the
                // arguments
                let callee = re!(
                    r"^(?:\(([^()]*(?:\([^()]*\)[^()]*)*)\)|([A-Za-z_]\w*)(?:\s*\.\s*\w+|\s*\[[^\[\]]*\]|\s*\([^()]*\))*)\s*\("
                )
                .captures(&at);
                // not a method (`.next(`) or a path (`ring::digest::digest(`): those name a
                // function, not a pointer
                let before = chars[..offset].iter().rev().find(|c| !c.is_whitespace());
                let method = matches!(before, Some('.' | ':'));
                let Some(callee) = callee.filter(|_| starts_token && !method) else {
                    return Err(format!(
                        "expected a call through a function pointer in {text:?}"
                    ));
                };
                // the root of the callee: a variable, not a function of the file (`run(`)
                let root = callee
                    .get(2)
                    .map(|m| m.as_str().to_string())
                    .or_else(|| {
                        callee.get(1).and_then(|m| {
                            re!(r"^\s*([A-Za-z_]\w*)")
                                .captures(m.as_str())
                                .map(|r| r[1].to_string())
                        })
                    })
                    .unwrap_or_default();
                let plain = callee.get(2).is_some_and(|m| {
                    callee[0][m.end()..].trim_start().starts_with('(')
                        && callee[0][m.end()..].trim() == "("
                });
                if plain
                    && src
                        .items
                        .iter()
                        .any(|i| i.kind == ItemKind::Fn && i.name == root)
                {
                    return Err(format!(
                        "`{root}` is a function of the file, not a pointer, in {text:?}"
                    ));
                }
                // the variable holds the function named where the function binds it: in the
                // statement when it calls nothing (`let p: HashFn = digest::digest;`), in the
                // binding of the variable it copies (`if let Some(f) = o`: `o`'s), in the body
                // of the file's function it calls (`let g = get();`: `get`'s)
                if !root.is_empty() && self.resolve(file).ok().as_deref() == Some(path.as_path()) {
                    // (the root as read at the call: `self` in `(self.f)(..)`)
                    let rest: String = chars[offset..].iter().collect();
                    let k = Regex::new(&format!(r"\b{}\b", regex::escape(&root)))
                        .ok()
                        .and_then(|r| r.find(&rest))
                        .map_or(0, |m| rest[..m.start()].chars().count());
                    let root_at = src.idx((line, offset + k));
                    pointer_bound(&src, root_at, &root, l2).map_err(|e| {
                        format!("{e}, not where the function is named ({file}:{l2}:{c2})")
                    })?;
                }
                let p2 = self.resolve(file)?;
                let src2 = self
                    .source(&p2)
                    .ok_or_else(|| format!("cannot read {file}, named in the context"))?;
                let named = src2.lines.get(l2.wrapping_sub(1)).and_then(|t| {
                    let chars: Vec<char> = t.chars().collect();
                    let (rs, rc) = rest(&src2, l2, c2);
                    (c2 < chars.len() && token_start(&src2, l2, c2))
                        .then(|| path_and_generics(&rs, &rc))
                        .flatten()
                });
                let names = named.is_some_and(|(_, last, _)| {
                    last == ident
                        || src2.binds.iter().any(|b| {
                            b.name == last
                                && self.alias_of(
                                    b,
                                    &ident,
                                    &sym_crate,
                                    owner_id.as_deref(),
                                    &src2.binds,
                                )
                        })
                });
                // or a macro of the file whose expansion binds it is invoked there (`bind!(m)`
                // with `let $n: HashFn = digest::digest;`): its body names it
                let by_macro = !names
                    && macro_call_at(&src2, (l2, c2))
                    && invocation_text(&src2, (l2, c2)).is_some_and(|(m, _)| {
                        src2.items
                            .iter()
                            .filter(|i| i.kind == ItemKind::Macro && i.name == m)
                            .any(|i| {
                                let (a, b) = src2.span(i);
                                Regex::new(&format!(r"\b{}\b", regex::escape(&ident)))
                                    .is_ok_and(|r| r.is_match(&src2.text(a, b)))
                            })
                    });
                if !names && !by_macro {
                    return Err(format!(
                        "the function pointer's position {file}:{l2}:{c2} does not name `{ident}`"
                    ));
                }
            }
            // the path, from the position on over the next lines (rustfmt breaks long paths);
            // generic arguments balanced, so it cannot run on into the next expression
            let (rs, rc) = rest(&src, line, offset);
            parsed = path_and_generics(&rs, &rc);
            let mut ok = parsed.as_ref().is_some_and(|(_, last, _)| {
                *last == ident
                    || src.binds.iter().any(|b| {
                        b.name == *last
                            && self.alias_of(b, &ident, &sym_crate, owner_id.as_deref(), &src.binds)
                    })
            });
            // an alias another file defines: of this package, or of the crate the path goes
            // through (`mylib::hash_it` for `pub use ring::digest::digest as hash_it;` in mylib)
            if !ok
                && starts_token
                && let Some((quals, last, _)) = &parsed
            {
                let mut dirs: Vec<PathBuf> =
                    owner.map(|p| p.manifest_dir.clone()).into_iter().collect();
                for root in import_roots(&src.binds, quals.first().unwrap_or(last))
                    .into_iter()
                    .flatten()
                {
                    for r in self.crate_refs(owner_id.as_deref(), &root) {
                        let pkg = r
                            .strip_prefix("pkg:cargo/")
                            .and_then(|nv| nv.split_once('@'))
                            .and_then(|(n, v)| man.by_name_version(n, v));
                        if let Some(p) = pkg
                            && !dirs.contains(&p.manifest_dir)
                        {
                            dirs.push(p.manifest_dir.clone());
                        }
                    }
                }
                for d in dirs {
                    let binds = self.package_binds(&d);
                    // (a re-export inside the symbol's own crate, relative to it: `pub use
                    // inner::DEEP as SHALLOW;` in picklib for `picklib::inner::DEEP`)
                    let own_crate = self
                        .man
                        .packages
                        .iter()
                        .find(|p| p.manifest_dir == d)
                        .is_some_and(|p| {
                            p.lib_name.as_deref() == Some(sym_crate.as_str())
                                || p.name.replace('-', "_") == sym_crate
                        });
                    if binds.iter().any(|b| {
                        b.name == *last
                            && (self.alias_of(b, &ident, &sym_crate, owner_id.as_deref(), &binds)
                                || (own_crate && b.path.last() == Some(&ident) && {
                                    let rel: Vec<&str> = b
                                        .path
                                        .iter()
                                        .map(String::as_str)
                                        .skip_while(|g| matches!(*g, "crate" | "self"))
                                        .collect();
                                    sym.ends_with(&format!("::{}", rel.join("::")))
                                }))
                    }) {
                        ok = true;
                        break;
                    }
                }
            }
            if pointer.is_none() && !(ok && starts_token) {
                return Err(format!("expected `{ident}` in {text:?}"));
            }
        }
        // an instantiation's position that details cite (`instantiated by X at F:L:C`) is cited
        // by one of this asset's
        if kind == "instantiation"
            && let Some(by) = self.cited.get(&(o.location.clone(), line, offset))
            && !by.contains(&o.component_ref)
        {
            return Err(format!(
                "the instantiation here is cited by {} occurrences of other assets only",
                by.len()
            ));
        }
        // a component is used where the asset it is part of is used
        if kind == "component" {
            let Some(m) = re!(r"; part of ([^\s;(]+)").captures(ctx.details) else {
                return Err("a component that names no asset it is part of".into());
            };
            let parent = &m[1];
            let here = self
                .at_pos
                .get(&(o.location.clone(), line, offset))
                .into_iter()
                .flatten()
                .any(|&j| j != oi && occs[j].component == parent);
            // a parent merged into a more specific name on the same line (Argon2 ->
            // Argon2id-19456-2-1) keeps the line, not necessarily the column
            let merged = self
                .at_line
                .get(&(o.location.clone(), line))
                .into_iter()
                .flatten()
                .any(|&j| {
                    j != oi
                        && extends(
                            &occs[j].component,
                            parent,
                            self.graph
                                .family
                                .get(&occs[j].component_ref)
                                .map(String::as_str),
                        )
                });
            if !(here || merged) {
                return Err(format!("`{parent}`, which this is part of, is not here"));
            }
        }
        // what a call does is one of the asset's functions (those of its reachable occurrences,
        // observed or the knowledge base's, when it has any): an encryption is no use of SHA-512
        if let Some(f) = parts(ctx.details)
            .into_iter()
            .find_map(|p| p.strip_prefix("use: "))
            && let Some((fs, reachable)) = self.graph.functions.get(&o.component_ref)
            && (ctx.tags.starts_with("[reachable]") || !reachable)
            && !f.split(" or ").all(|f| fs.iter().any(|x| x == f))
        {
            return Err(format!(
                "use `{f}` is not among {}'s functions ({})",
                o.component,
                fs.join(", ")
            ));
        }
        // a descriptor is evidence of the asset the knowledge base names it (`ring::digest::
        // SHA512` is SHA-512, not SHA-384): the static itself, or the one a table leads to
        let descriptor = match kind.as_str() {
            "static" => Some(sym.clone()),
            "via-static" => re!(r" -> ([\w:]+)(?:;|$)")
                .captures(ctx.details)
                .map(|m| m[1].to_string()),
            _ => None,
        };
        // the descriptor a call's algorithm comes from names the asset too
        let mut descriptors: Vec<String> = Vec::new();
        // the call a table member is read at (not a macro's: its code is the macro's)
        let call_at = (kind == "call" && !ctx.tags.contains("[macro ")).then_some((line, offset));
        for p in parts(ctx.details) {
            // a member of a boundary model (jsonwebtoken's `Header.alg`)
            if let Some(m) = re!(
                r"^algorithm (?:from|one of \d+ (?:chosen at run time \(selector: \w+\) |that may reach the call )?from) `(\w+)\.(\w+)`(?:: possible)?(?: \((object: from|caller: passed by|container: a value|container: in the list|type-join: a value|table: stored by) `(?:static |const )?([^`]+)`[^)]*\))?$"
            )
            .captures(p)
            {
                let witness = m.get(3).zip(m.get(4)).map(|(k, w)| (k.as_str(), w.as_str()));
                let families = re!(r"(?:^|; )the key's family \(([^)]*)\) allows these")
                    .captures(ctx.details)
                    .map(|f| f[1].split(", ").map(str::to_string).collect::<Vec<_>>());
                let beside = ctx.details.contains("beside others not followed")
                    || p.contains(": possible");
                self.check_model(
                    &src,
                    &path,
                    o,
                    (&m[1], &m[2]),
                    witness,
                    families.as_deref(),
                    (call_at, beside),
                )?;
                continue;
            }
            // a static a member is stored by holds it (`member: table, stored by `static T``);
            // one a member is a value of exists (`member: static, possible (a value `static T`
            // holds ..)`)
            if let Some(m) =
                re!(r"^member: table, stored by `(?:static|const) ([^`]+)`").captures(p)
            {
                for d in &descriptors {
                    self.check_table(&src, &path, &m[1], d, call_at)?;
                }
                continue;
            }
            if let Some(m) = re!(
                r"^member: static, possible \((?:(?:a|the) value `static ([^`]+)` holds|the value `static ([^`]+)` starts with|a value `[^`]+` puts in `static ([^`]+)`)"
            )
            .captures(p)
            {
                let st = m.get(1).or(m.get(2)).or(m.get(3)).map_or("", |g| g.as_str());
                self.check_table(&src, &path, st, "", call_at)?;
                continue;
            }
            // (a static member in a form this check does not read: not passed unread)
            if p.starts_with("member: static") {
                return Err(format!("`{p}`: a static member in a form not checked"));
            }
            // a member through a trait object (`member: dyn, possible (dyn: `T` is coerced to
            // `dyn Tr` ..)`): the call calls a method on an object of `Tr` (or of a trait whose
            // supertraits include it), wherever the receivers' types are known
            if let Some(m) = re!(r"^member: dyn, possible \(dyn: `[^`]+`(?:, the only type)? (?:is )?coerced to `([^`]+)`")
                .captures(p)
                && let Some(at) = call_at
            {
                let want = type_name(m[1].trim().trim_start_matches("dyn ").trim());
                let supers = self.supertraits(&path, &m[1]);
                if let Some(ts) = call_dyn_receivers(&src, src.idx(at))
                    && !ts.iter().any(|t| {
                        let mut seen = vec![t.clone()];
                        let mut k = 0;
                        while k < seen.len() {
                            if seen[k] == want {
                                return true;
                            }
                            for s2 in supers.get(&seen[k]).into_iter().flatten() {
                                if !seen.contains(s2) {
                                    seen.push(s2.clone());
                                }
                            }
                            k += 1;
                        }
                        false
                    })
                {
                    return Err(format!(
                        "the call calls no method on a `dyn {want}` (its trait objects: {})",
                        if ts.is_empty() { "none".to_string() } else { ts.join(", ") }
                    ));
                }
                continue;
            }
            // the function a member comes from (returned or written by it, passed by it, stored
            // by it in the field) is one of the build's that can give it
            if let Some(m) = re!(
                r"^member: (object, from|caller, passed by|impl, possible \(what|type-join, possible \(a value) `([^`]+)`"
            )
            .captures(p)
            {
                // (a member beside others not followed may be the value a write the analysis
                // does not follow replaces: kept by a writer that replaces it; so may one the
                // flow-insensitive points-to analysis says only possibly reaches the call)
                let beside = ctx.details.contains("beside others not followed")
                    || ctx.details.contains("may possibly reach the call");
                for d in &descriptors {
                    self.check_witness(&path, &m[1], &m[2], d, &o.component_ref, beside)?;
                }
                continue;
            }
            let named: Vec<&str> = if let Some(m) = re!(
                r"^algorithm (?:possibly )?from ([\w:]+)(?: in the arguments|, reaching .*|, the only one found reaching .*)?$"
            )
            .captures(p)
            {
                vec![m.get(1).map_or("", |g| g.as_str())]
            } else if let Some(m) = re!(
                r"^algorithm (?:from ([\w:]+), stored in `(?:static|const) ([^`]+)`|one of the \d+ in `(?:static |const )?([^`]+)`(?:,| that) .*?: ([\w:]+))$"
            )
            .captures(p)
            {
                // a member of a static (a table): it holds it
                let d = m.get(1).or(m.get(4)).map_or("", |g| g.as_str());
                let table = m.get(2).or(m.get(3)).map_or("", |g| g.as_str());
                self.check_table(&src, &path, table, d, call_at)?;
                vec![d]
            } else if let Some(m) = re!(r"^algorithm one of \d+ that .*?: (.+)$").captures(p) {
                m.get(1)
                    .map_or("", |g| g.as_str())
                    .split(", ")
                    .map(|d| d.trim_end_matches(" in the arguments"))
                    .collect()
            } else {
                continue;
            };
            let family = self.graph.family.get(&o.component_ref).cloned();
            let family = family.as_deref();
            // the values the label says are all that reach the call (no unknown beside them):
            // a store through a pointer that replaces one on every way to the call excludes it
            let exact = !p.contains("beside others not followed") && !p.contains(" possibly ");
            // (a container's elements, possible: any of them, whatever an element store replaced;
            // said of several, `one of N`, never of one value the claim says is all)
            let smashed = re!(r"; member: container, possible\b").is_match(ctx.details)
                && p.starts_with("algorithm one of ");
            // the code the call reads names it (`Salt::new(hkdf::HKDF_SHA256, ..)` is no
            // `HKDF_SHA384`; `prk.expand(.., HKDF_SHA256)` with `prk` from `Salt::new(HKDF_SHA384,
            // ..)` may be either)
            if p.ends_with(" in the arguments") {
                let members = named.clone();
                let expanded: Vec<usize> = re!(r"expanded from ([^\s;]+?):(\d+)(?:;|$)")
                    .captures_iter(ctx.details)
                    .filter(|m| self.resolve(&m[1]).ok().as_deref() == Some(path.as_path()))
                    .filter_map(|m| m[2].parse().ok())
                    .collect();
                self.check_args(
                    &src,
                    &path,
                    (line, offset),
                    &members,
                    &o.component_ref,
                    ctx.tags.contains("[macro ").then_some(expanded.as_slice()),
                    (exact, smashed),
                )?;
            }
            // a member reaching the call from another function, labelled as one that does
            // (`object`, `caller`, `fixed`), or with no label (checked as an `object` one): the
            // code the call reads does not name another descriptor of its primitive instead,
            // where it reads no value from elsewhere
            if !p.ends_with(" in the arguments")
                && kind == "call"
                && !ctx.tags.contains("[macro ")
                && re!(r"reaching the call from another function|from other functions").is_match(p)
                && (re!(r"; member: (?:object|caller|fixed|dyn|container|type-join|impl)\b")
                    .is_match(ctx.details)
                    || !ctx.details.contains("; member: "))
            {
                // (a `type-join` or `impl` member is any value stored in a field of that type,
                // or that a function writes: only a call that reads no field is checked)
                let join = re!(r"; member: (?:type-join|impl)\b").is_match(ctx.details);
                self.check_elsewhere(
                    &src,
                    &path,
                    (line, offset),
                    &named,
                    &o.component_ref,
                    (exact, smashed),
                    join,
                )?;
            }
            descriptors.extend(named.iter().map(|d| d.to_string()));
            for d in named {
                let names =
                    rcbom_analysis::static_names(self.kb, d.split("::").next().unwrap_or(""), d);
                if !names.is_empty()
                    && !names
                        .iter()
                        .any(|n| *n == o.component || extends(&o.component, n, family))
                {
                    return Err(format!(
                        "the algorithm `{d}` is {}, not {}",
                        names.join(" or "),
                        o.component
                    ));
                }
            }
        }
        if kind == "via-static" && descriptor.is_none() {
            return Err("a `[via-static]` occurrence without its chain to a descriptor".into());
        }
        if let Some(d) = descriptor {
            let k = d.split("::").next().unwrap_or("");
            let names = rcbom_analysis::static_names(self.kb, k, &d);
            let family = self.graph.family.get(&o.component_ref).map(String::as_str);
            if names.is_empty() {
                return Err(format!("`{d}` is no knowledge-base descriptor"));
            }
            if !names
                .iter()
                .any(|n| *n == o.component || extends(&o.component, n, family))
            {
                return Err(format!(
                    "`{d}` is {}, not {}",
                    names.join(" or "),
                    o.component
                ));
            }
        }
        // what the path names must provide the asset: the callee's crate, a self type written
        // as a qualifier (`Hmac::<Sha256>::new_from_slice` for `crypto_common::KeyInit::
        // new_from_slice`), or a type in the generic arguments (`<Hmac<Sha256> as Mac>::m`,
        // `seal::<Aes256Gcm>`). Each is a package of the CBOM the file can name it from; the
        // standard library, an interface crate and the program's own code provide nothing and
        // decide nothing. A type parameter or a local type could carry any asset: no check.
        if matches!(
            kind.as_str(),
            "call" | "static" | "via-static" | "instantiation"
        ) && let Some((quals, _, generics)) = &parsed
            && let Some(provs) = self.graph.providers.get(&o.component_ref)
        {
            let sym_segs: Vec<String> = sym
                .split("::")
                .map(|s| s.trim_start_matches('<').to_string())
                .collect();
            const NEUTRAL: &[&str] = &[
                "u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32", "i64", "i128",
                "isize", "f32", "f64", "bool", "char", "str", "String", "Vec", "Option", "Box",
                "Result", "as", "dyn", "impl", "mut", "const", "fn", "static", "_",
            ];
            let owner_id = owner_id.as_deref();
            let mut roots: Vec<String> = Vec::new();
            let mut unknown = false;
            // the callee's crate
            roots.extend(
                self.lib_refs(&sym_crate)
                    .into_iter()
                    .filter(|r| !self.neutral(r)),
            );
            // a written qualifier: a self type, unless the path is the trait's own path
            // (`aes_gcm::aead::KeyInit::new_from_slice`: the qualifiers lead to the trait)
            let trait_path = quals.last().is_some_and(|q| sym_segs.contains(q));
            if let Some(q0) = quals.first()
                && !matches!(q0.as_str(), "crate" | "self" | "super" | "Self")
                && !sym_segs.contains(q0)
                && !trait_path
            {
                match self.origins(&src, owner_id, q0) {
                    Some(r) => roots.extend(r.into_iter().filter(|r| !self.neutral(r))),
                    None => unknown = true,
                }
            }
            for g in generics.iter().filter(|g| !NEUTRAL.contains(&g.as_str())) {
                match self.origins(&src, owner_id, g) {
                    Some(r) => roots.extend(r.into_iter().filter(|r| !self.neutral(r))),
                    None => unknown = true,
                }
            }
            let provided = roots.iter().any(|r| {
                let cl = self.graph.closure(r);
                provs.iter().any(|p| cl.contains(p))
            });
            if !unknown && !roots.is_empty() && !provided {
                roots.sort();
                roots.dedup();
                return Err(format!(
                    "the path names {}, which does not provide {}",
                    roots.join(", "),
                    o.component
                ));
            }
        }
        Ok(())
    }

    /// "algorithm from X in the arguments" (or one of several such `members`) at the call at
    /// `at`: X is named in the code the call reads (`call_reads`: the argument carrying the
    /// algorithm, the variables it reads and what the function stores in them, the statics,
    /// consts and `const fn`s those name), and the call reads no other descriptor of the asset's
    /// primitive instead. `exact`: the label says the values found are all (`Reads::strict`).
    /// Where that code reads values from elsewhere (a parameter), X is named in the function.
    /// A macro's call (`expanded` gives the lines of its body cited) reads the invocation and
    /// those lines.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn check_args(
        &mut self,
        src: &Source,
        path: &Path,
        at: (usize, usize),
        members: &[&str],
        component_ref: &str,
        expanded: Option<&[usize]>,
        (exact, smashed): (bool, bool),
    ) -> Result<(), String> {
        let s = &src.code;
        let lasts: Vec<String> = members
            .iter()
            .map(|d| d.rsplit("::").next().unwrap_or(d).to_string())
            .collect();
        let has = |r: &Reads| lasts.iter().any(|l| r.names.contains(l));
        let p = src.idx(at);
        if let Some(lines) = expanded {
            let mut seen = HashSet::new();
            let mut call = Reads::default();
            // the invocation's arguments and the macro's lines
            let open = scan_to(s, p, s.len(), |i| matches!(s[i], '(' | '[' | '{' | ';'));
            if let Some(close) = close_of_at(s, open) {
                names_read(src, self.kb, open + 1, close, 3, &mut seen, &mut call, true);
            }
            for &l in lines {
                let (a, b) = (src.idx((l, 0)), src.idx((l + 1, 0)));
                names_read(src, self.kb, a, b, 1, &mut seen, &mut call, false);
            }
            if has(&call) || call.open || lines.is_empty() {
                return Ok(());
            }
            return Err(format!(
                "neither the invocation nor the macro's line names {}",
                lasts.join(", ")
            ));
        }
        let Some(mut call) =
            call_reads(src, self.kb, p, (exact, smashed), &self.inst, self.alg_arg)
        else {
            return Ok(());
        };
        self.resolve_foreign(path, &mut call);
        self.resolve_assoc(path, &mut call);
        if has(&call) {
            return Ok(());
        }
        // other descriptors of its primitive, or a type of the build's crates that the knowledge
        // base gives one (`kp.sign(..)` with `kp` an `Ed25519KeyPair`)
        let prim = self.graph.primitive.get(component_ref);
        let others: Vec<&String> = call
            .names
            .iter()
            .filter(|w| {
                self.kb
                    .statics
                    .iter()
                    .any(|e| e.pattern.is_match(w) && Some(&e.algo.primitive) == prim)
            })
            .chain(call.types.iter().filter(|w| {
                self.kb.types.iter().any(|e| {
                    e.name == **w
                        && Some(&e.algo.primitive) == prim
                        && self.libs.as_ref().is_some_and(|l| l.contains_key(&e.krate))
                })
            }))
            .collect();
        if !(call.open || call.foreign) || (!others.is_empty() && !call.replaced) {
            let read = if others.is_empty() {
                "no descriptor of its kind".to_string()
            } else {
                others
                    .iter()
                    .map(|w| w.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            return Err(format!(
                "the code the call reads names {read}, not {}",
                lasts.join(", ")
            ));
        }
        // a value from elsewhere (a parameter, a variable a call of the file's lends as `&mut`,
        // a field a method sets) is no value named in the arguments: the claim is not that one
        if call.open && !call.foreign {
            return Err(format!(
                "the code the call reads names no {} (it reads values from elsewhere)",
                lasts.join(", ")
            ));
        }
        // a constant of a crate whose sources are not at hand: X named in the function at least
        if let Some(f) = src.enclosing(at, &[ItemKind::Fn]) {
            let (a, b) = src.span(f);
            let mut whole = Reads {
                inst: self.inst.clone(),
                ..Reads::default()
            };
            names_read(src, self.kb, a, b, 2, &mut HashSet::new(), &mut whole, true);
            self.resolve_foreign(path, &mut whole);
            self.resolve_assoc(path, &mut whole);
            if !has(&whole) && !whole.foreign {
                return Err(format!(
                    "the function names no {} (the call reads values from elsewhere)",
                    lasts.join(", ")
                ));
            }
        }
        Ok(())
    }

    /// The positions a context's details name: `instantiated by <caller> at <file>:<line>`
    /// (where a generic instance was instantiated) and `expanded from <file>:<line>` (where a
    /// macro's code is written) must be lines of code of files that exist; a standard-library
    /// file is read from the pinned toolchain, whose commit it must name. Outside the standard
    /// library, an instantiation's line is in the caller and names what it instantiates (the
    /// occurrence's item, then each caller in turn; a closure is instantiated where it is
    /// written), and a macro's line is in the body of the `macro_rules!` of its tag.
    pub(super) fn check_details(
        &mut self,
        details: &str,
        tags: &str,
        symbol: &str,
        call_line: Option<&str>,
        at: (&Path, usize, usize),
        component_ref: &str,
    ) -> Result<(), String> {
        let mut callee = details
            .strip_prefix(tags)
            .unwrap_or(details)
            .strip_prefix("in ")
            .and_then(|d| parts(d).into_iter().next())
            .map(str::to_string);
        // the names of the occurrence's item and of the callers so far
        let mut earlier: Vec<String> = callee
            .as_deref()
            .and_then(in_item)
            .map(|n| n.name)
            .into_iter()
            .collect();
        // the position the next detail's code holds: the occurrence's, then each cited
        // caller's (line, and column where the detail gives one)
        let mut inner: (PathBuf, usize, Option<usize>) = (at.0.to_path_buf(), at.1, Some(at.2));
        for part in parts(details) {
            let Some(m) =
                re!(r"^(instantiated by (.*) at|expanded from) ([^\s;]+?):(\d+)(?::(\d+))?(?: as `([^`]*)`)?$")
                    .captures(part)
            else {
                continue;
            };
            let (file, line) = (m[3].to_string(), m[4].parse::<usize>().unwrap_or(0));
            let col: Option<usize> = m.get(5).and_then(|c| c.as_str().parse().ok());
            // the call's text, where the detail gives it, is what the line holds at the column
            // (`aes_ctr::<Aes128Ctr>`, not its neighbour's `aes_ctr::<Aes192Ctr>`)
            let call_text = m.get(6).map(|t| t.as_str().to_string());
            let caller = m.get(2).map(|c| c.as_str().to_string());
            let path = self.resolve(&file)?;
            let src = self
                .source(&path)
                .ok_or_else(|| format!("cannot read {file}, named in `{part}`"))?;
            let cols: Vec<usize> = src
                .class
                .get(line.wrapping_sub(1))
                .zip(src.lines.get(line.wrapping_sub(1)))
                .map(|(cls, l)| {
                    l.chars()
                        .zip(cls)
                        .enumerate()
                        .filter(|(_, (c, k))| **k == Class::Code && !c.is_whitespace())
                        .map(|(j, _)| j)
                        .collect()
                })
                .unwrap_or_default();
            if cols.is_empty() {
                return Err(format!("`{part}`: no code at line {line} of {file}"));
            }
            if let (Some(t), Some(c0)) = (&call_text, col) {
                let at: String = src.lines[line - 1].chars().skip(c0).collect();
                if !at.starts_with(t.as_str()) {
                    return Err(format!("`{part}`: line {line} has no `{t}` at column {c0}"));
                }
            }
            // where the CBOM records what an instantiation chooses there (`[instantiation]`
            // occurrences: `h::<sha2::Sha384>` is SHA-384's), this asset is among it
            if let (Some(_), Some(c0)) = (&caller, col) {
                let here: Vec<usize> = self
                    .at_pos
                    .get(&(file.clone(), line, c0))
                    .cloned()
                    .unwrap_or_default();
                let chosen: Vec<&str> = here
                    .iter()
                    .filter(|&&j| self.occs[j].context.contains("] [instantiation]"))
                    .map(|&j| self.occs[j].component.as_str())
                    .collect();
                if !chosen.is_empty()
                    && !here
                        .iter()
                        .any(|&j| self.occs[j].component_ref == component_ref)
                {
                    return Err(format!(
                        "`{part}`: the instantiation at {file}:{line}:{c0} chooses {}",
                        chosen.join(", ")
                    ));
                }
            }
            // in the standard library, the line names the caller: a closure's `call_once` shim
            // is cited at the trait's declaration of it
            if file.starts_with("/rustc/") {
                if let Some(n) = caller.as_deref().and_then(in_item) {
                    // in code (not `#[lang = "drop_glue"]` above the function)
                    let text = &src.lines[line - 1];
                    let in_code = Regex::new(&format!(r"\b{}\b", regex::escape(&n.name)))
                        .unwrap()
                        .find_iter(text)
                        .any(|m| cols.contains(&text[..m.start()].chars().count()));
                    if !in_code {
                        return Err(format!("`{part}`: line {line} does not name `{}`", n.name));
                    }
                    // at the start of a token
                    if let Some(c0) = col {
                        let chars: Vec<char> = src.lines[line - 1].chars().collect();
                        let start = cols.contains(&c0)
                            && (!is_ident(chars[c0]) || c0 == 0 || !is_ident(chars[c0 - 1]));
                        if !start {
                            return Err(format!("`{part}`: no token starts at column {c0}"));
                        }
                    }
                    if !earlier.contains(&n.name) {
                        earlier.push(n.name);
                    }
                } else if caller.is_none() {
                    // a standard-library macro's line (`thread_local!`'s, read from the
                    // toolchain's sources): it names the symbol (`= __RUST_STD_INTERNAL_INIT;`),
                    // or uses a metavariable the invocation's line, which names it, fills
                    let sym = strip_generics(symbol);
                    let ident = sym.rsplit("::").next().unwrap_or(&sym);
                    let word = Regex::new(&format!(r"\b{}\b", regex::escape(ident))).unwrap();
                    let text: String = src.lines[line - 1]
                        .chars()
                        .zip(&src.class[line - 1])
                        .map(|(c, k)| if *k == Class::Code { c } else { ' ' })
                        .collect();
                    let metavar = re!(r"\$(\w+)")
                        .captures_iter(&text)
                        .any(|m| &m[1] != "crate");
                    if !word.is_match(&text)
                        && !(metavar && call_line.is_some_and(|l| word.is_match(l)))
                    {
                        return Err(format!("`{part}`: line {line} does not name `{ident}`"));
                    }
                }
                callee = caller;
                inner = (path.clone(), line, col);
                continue;
            }
            match &caller {
                // an instantiation in the items a macro invocation outside any item makes,
                // cited at the invocation (hpke's `impl_dhkem!(..)` makes `encap`)
                Some(c)
                    if {
                        let c0 = col.unwrap_or(cols[0]);
                        src.enclosing((line, c0), &[ItemKind::Fn, ItemKind::Static])
                            .is_none()
                            && macro_call_at(&src, (line, c0))
                            && match invocation_names(&src, (line, c0), c, &[]) {
                                Pick::Exact => true,
                                Pick::Range => {
                                    RANGED.with(|r| r.set(true));
                                    true
                                }
                                Pick::No => false,
                            }
                    } =>
                {
                    if let Some(n) = in_item(c)
                        && !earlier.contains(&n.name)
                    {
                        earlier.push(n.name);
                    }
                    callee = Some(c.clone());
                    inner = (path.clone(), line, col);
                }
                Some(c) => {
                    let want = in_item(c).ok_or_else(|| format!("`{part}`: no item"))?;
                    // where the line names what it instantiates, as a use (not `fn seal(..)`
                    // defining the caller): the item or a caller before it (an occurrence
                    // instantiated along two chains lists both last callers, each naming the
                    // item before them). A closure is called through a variable, and what
                    // syntax calls (`.await` polls, a scope's end drops, `?`, operators,
                    // `for`) is not named: any code of the line then.
                    let text = &src.lines[line - 1];
                    // a closure (or `async` body) the caller itself writes is cited where it
                    // does: `|..|`, `async`, `move`
                    let own_closure = callee
                        .as_deref()
                        .and_then(closure_parent)
                        .is_some_and(|p| strip_generics(p) == strip_generics(c));
                    // a closure's caller that is its parent but for the closures' indexes
                    // (`main::{closure#7}` for `main::{closure#0}::{closure#0}`) names another
                    // closure than the one holding it
                    if let Some(p) = callee.as_deref().and_then(closure_parent) {
                        let idx = |x: &str| {
                            re!(r"\{closure#\d+\}")
                                .replace_all(x, "{closure}")
                                .to_string()
                        };
                        let (p, c2) = (strip_generics(p), strip_generics(c));
                        if p.trim() != c2.trim() && idx(&p).trim() == idx(&c2).trim() {
                            return Err(format!(
                                "`{part}`: the closure is in `{}`, not in `{}`",
                                p.trim(),
                                c2.trim()
                            ));
                        }
                    }
                    let unnamed = callee.as_deref().is_none_or(|p| {
                        p.trim_end().ends_with('}') || in_item(p).is_some_and(|n| by_syntax(&n))
                    });
                    let chars: Vec<char> = text.chars().collect();
                    // an `async` closure's body is made where it starts (`async move |d| expr`:
                    // at `expr`)
                    let closure_caller = c.trim_end().ends_with('}');
                    let named: Vec<usize> = if own_closure {
                        // and an `async fn`'s body at its `{`
                        let starts = re!(r"\|\|?|\basync\b|\bmove\b|\bstatic\b|\{")
                            .find_iter(text)
                            .map(|m| text[..m.start()].chars().count())
                            .filter(|col| cols.contains(col));
                        let body = col.filter(|&c0| {
                            closure_caller
                                && cols.contains(&c0)
                                && async_body_at(&src.code, src.idx((line, c0))).is_some()
                        });
                        starts.chain(body).collect()
                    } else if unnamed
                        && !part.contains(" as `")
                        && let Some(f) = callee.as_deref().and_then(|p| {
                            // an `async fn`'s body (`m::hash_with::{closure#0}`): made where the
                            // line calls that function
                            let base = p.trim().strip_suffix("::{closure#0}")?;
                            let name = strip_generics(base).rsplit("::").next()?.to_string();
                            src.items
                                .iter()
                                .any(|it| {
                                    it.kind == ItemKind::Fn
                                        && it.name == name
                                        && src.lines.get(it.start.0.wrapping_sub(1)).is_some_and(
                                            |l| {
                                                Regex::new(&format!(
                                                    r"\basync\s+(?:unsafe\s+)?fn\s+{}\b",
                                                    regex::escape(&name)
                                                ))
                                                .is_ok_and(|r| r.is_match(l))
                                            },
                                        )
                                })
                                .then_some(name)
                        })
                    {
                        let word = Regex::new(&format!(r"\b{}\b", regex::escape(&f))).unwrap();
                        if word.is_match(text) {
                            // (at a token: a name, `?`, a bracket, as below)
                            cols.iter()
                                .copied()
                                .filter(|&j| {
                                    col.is_none()
                                        || (is_ident(chars[j])
                                            && (j == 0 || !is_ident(chars[j - 1])))
                                        || "?{}()[]|".contains(chars[j])
                                })
                                .collect()
                        } else {
                            Vec::new()
                        }
                    } else if unnamed {
                        // a token the language calls through: a name (`poll`, a closure's
                        // variable), `?`, a bracket
                        cols.iter()
                            .copied()
                            .filter(|&j| {
                                col.is_none()
                                    || (is_ident(chars[j]) && (j == 0 || !is_ident(chars[j - 1])))
                                    || "?{}()[]|".contains(chars[j])
                            })
                            .collect()
                    } else {
                        // a method is also instantiated where a value of its type is made a
                        // trait object (`let b: Box<dyn H> = Box::new(A)` makes `<A as H>::h`'s
                        // vtable): the line names the type or the trait
                        let owners: Vec<String> = callee
                            .as_deref()
                            .and_then(in_item)
                            .map(|n| {
                                n.self_ty
                                    .into_iter()
                                    .chain(n.owner.map(|(t, _)| t))
                                    .chain(
                                        n.trait_name
                                            .map(|t| t.split('<').next().unwrap_or(&t).to_string()),
                                    )
                                    .filter(|t| t.chars().all(is_ident) && !t.is_empty())
                                    .collect()
                            })
                            .unwrap_or_default();
                        // (a value of a generic type, `Box::new(conn)` in reqwest: a coercion to a
                        // trait object, for a method of a trait)
                        let coerces = callee
                            .as_deref()
                            .and_then(in_item)
                            .is_some_and(|n| n.trait_name.is_some() || n.owner.is_some())
                            && re!(r"\b(Box|Arc|Rc)::(new|pin)\(|\bas\s+(?:[&*]|dyn\b|Box\b|Arc\b|Rc\b|Pin\b)|\bdyn\s")
                                .is_match(text);
                        // (or the value at the column becomes an object of the method's trait
                        // there: `up_dyn(&mut a1)` with `fn up_dyn(u: &mut dyn Up)` makes the
                        // vtable of `a1`'s type, whose `up` is the trait's default body unless the
                        // type's impl writes its own)
                        let vtable = match (col, callee.as_deref().and_then(in_item)) {
                            (Some(c0), Some(n)) if c0 < chars.len() => {
                                let s = &src.code;
                                let is_trait = |t: &str| {
                                    src.items
                                        .iter()
                                        .any(|x| x.kind == ItemKind::Trait && x.name == t)
                                };
                                let (ty, tr) = match (n.self_ty.clone(), n.trait_name.clone()) {
                                    (Some(st), Some(tr)) => (Some(st), Some(type_name(&tr))),
                                    (Some(st), None) if is_trait(&st) => (None, Some(st)),
                                    _ => (None, None),
                                };
                                let mut v = src.idx((line, c0));
                                if s.get(v) == Some(&'&') {
                                    v = skip_blank(s, v + 1);
                                    if kw(s, v, "mut") {
                                        v = skip_blank(s, v + 3);
                                    }
                                }
                                let vty = expr_type(&src, v, src.idx((line + 1, 0)), 4)
                                    .map(|t| type_name(&deref_type(&t)));
                                let overrides = |vt: &str, tr: &str| {
                                    src.items.iter().any(|b| {
                                        b.kind == ItemKind::Impl
                                            && b.name == vt
                                            && b.trait_name.as_deref().map(type_name).as_deref()
                                                == Some(tr)
                                            && src.items.iter().any(|f| {
                                                f.kind == ItemKind::Fn
                                                    && f.name == n.name
                                                    && b.contains(f.start)
                                                    && b.start != f.start
                                            })
                                    })
                                };
                                match tr {
                                    Some(tr)
                                        if word_start(s, v)
                                            && match (&ty, &vty) {
                                                (Some(st), Some(vt)) => type_name(st) == *vt,
                                                (Some(_), None) => false,
                                                (None, Some(vt)) => !overrides(vt, &tr),
                                                (None, None) => true,
                                            } =>
                                    {
                                        let supers = self.supertraits(&path, "");
                                        let man = self.man;
                                        let owner = man.owner_of(&path);
                                        let mut foreign = |p: &[String], f: &str, k: usize| {
                                            self.foreign_param(&src, owner, p, f, k)
                                        };
                                        coercion_traits(&src, v, &mut foreign).is_some_and(|ts| {
                                            ts.iter().any(|t| {
                                                *t == tr
                                                    || supers
                                                        .get(t)
                                                        .is_some_and(|x| x.contains(&tr))
                                            })
                                        })
                                    }
                                    _ => false,
                                }
                            }
                            _ => false,
                        };
                        let names_owner =
                            coerces || vtable || owners.iter().any(|o| path_names(text, o));
                        earlier
                            .iter()
                            .flat_map(|n| {
                                Regex::new(&format!(r"\b{}\b", regex::escape(n)))
                                    .unwrap()
                                    .find_iter(text)
                                    .map(|m| text[..m.start()].chars().count())
                                    .collect::<Vec<_>>()
                            })
                            // the coercion's expression, from its first token
                            .chain(col.filter(|_| names_owner))
                            .chain(
                                cols.first()
                                    .copied()
                                    .filter(|_| col.is_none() && names_owner),
                            )
                            .filter(|&j| {
                                cols.contains(&j) && {
                                    let before: String = chars[..j].iter().collect();
                                    !re!(r"\bfn\s+$").is_match(&before)
                                }
                            })
                            // with a column: the path written there names it (`hash::<S384>`,
                            // `crate::m::seal`, a method's name)
                            .filter_map(|j| match col {
                                None => Some(j),
                                // (a column past the line's end, as a shifted position may be)
                                Some(c0) if c0 > chars.len() => None,
                                Some(c0) => {
                                    let start =
                                        chars.get(c0).is_some_and(|ch| is_ident(*ch) || *ch == '<')
                                            && (c0 == 0 || !is_ident(chars[c0 - 1]));
                                    // (a coercion's expression may start with `&` or `(`:
                                    // `&Legacy` made a `&dyn Pick`)
                                    let coercion = j == c0
                                        && names_owner
                                        && chars.get(c0).is_some_and(|ch| matches!(ch, '&' | '('));
                                    // (the coercion's expression from its first token: not a
                                    // token inside `&W(S2)` or `Box::new(X)`)
                                    let prev: String = chars[..c0].iter().collect();
                                    let inside = re!(r"(?:&\s*(?:mut\s+)?|\b(?:new|pin)\s*\(\s*)$")
                                        .is_match(&prev);
                                    // (a token naming none of the chain's items is the
                                    // coercion's, which starts there)
                                    let names_item = earlier.iter().any(|n| {
                                        word_of(&chars, j) == *n
                                            || chars
                                                [c0..(c0 + path_len(&chars, c0)).min(chars.len())]
                                                .iter()
                                                .collect::<String>()
                                                .split("::")
                                                .any(|g| g.trim() == n)
                                    });
                                    ((start
                                        && (names_item || !inside)
                                        && ((j >= c0 && j < c0 + path_len(&chars, c0))
                                            || (j == c0 && names_owner)))
                                        || coercion)
                                        .then_some(c0)
                                }
                            })
                            .collect()
                    };
                    // with a column, that token; not a function item a `let` binds to a variable
                    // (`let h = Local::alg;`): that is instantiated where the variable is called
                    let item_bound = col.is_some_and(|c0| {
                        re!(r"^(\s*let\s+(?:mut\s+)?\w+\s*=\s*)([\w:<>, ]+?)\s*;\s*$")
                            .captures(text)
                            .is_some_and(|m| {
                                let a = m[1].chars().count();
                                (a..a + m[2].chars().count()).contains(&c0)
                            })
                    });
                    let mut named: Vec<usize> = match col {
                        Some(_) if item_bound => Vec::new(),
                        Some(c0) => named.into_iter().filter(|&j| j == c0).collect(),
                        None => named,
                    };
                    // a call a macro invoked in the function makes (`calls!(T0 T1)` expanding to
                    // `outer::<T0>()`), or one through a variable bound to the function item
                    // (`let h = Local::alg; h(&d)`)
                    if named.is_empty()
                        && !own_closure
                        && let Some(c0) = col
                        && let Some(want_name) = callee.as_deref().and_then(in_item).map(|n| n.name)
                    {
                        let word = Regex::new(&format!(r"\b{}\b", regex::escape(&want_name))).ok();
                        let names_it = |t: &str| word.as_ref().is_some_and(|r| r.is_match(t));
                        let ci = src.idx((line, c0));
                        let by_macro = macro_call_at(&src, (line, c0))
                            && expansion(&src, (line, c0)).is_some_and(|e| names_it(&e));
                        let w = word_of(&src.code, ci);
                        let by_variable = !w.is_empty()
                            && w.starts_with(|c: char| c.is_lowercase() || c == '_')
                            && skip_blank(&src.code, ci + w.chars().count()) < src.code.len()
                            && src.code[skip_blank(&src.code, ci + w.chars().count())] == '('
                            && matches!(binding(&src, ci, &w),
                                Some(Bound::Let { init, .. }) if names_it(&init)
                                    && !init.contains('(')
                                    && fn_item_runs(&src, callee.as_deref().unwrap_or(""), init.trim()));
                        if by_macro || by_variable {
                            named.push(c0);
                        }
                    }
                    if named.is_empty() && own_closure {
                        return Err(format!(
                            "`{part}`: line {line} writes no closure or `async` body"
                        ));
                    }
                    // the closure cited holds the code instantiated in it (not the closure
                    // beside it)
                    if own_closure
                        && let Some(c0) = col
                        && inner.0 == path
                    {
                        let ci = src.idx((line, c0));
                        let Some((a, b)) =
                            closure_span(&src.code, ci).or_else(|| async_body_at(&src.code, ci))
                        else {
                            return Err(format!(
                                "`{part}`: no closure or `async` body starts at column {c0}"
                            ));
                        };
                        // strictly inside it, and in no closure nested in it
                        // (`run1(|x| run1(|y| digest(..), x), d)`: the code is `|y|`'s)
                        let bar = src.code.get(a) == Some(&'|')
                            || ["move", "async", "static"]
                                .iter()
                                .any(|w| kw(&src.code, a, w));
                        let holds = match inner.2 {
                            Some(ic) => {
                                let ii = src.idx((inner.1, ic));
                                (a < ii || (a == ii && !bar))
                                    && ii < b
                                    && !(a + 1..ii).any(|k| {
                                        closure_at(&src.code, k)
                                            && closure_span(&src.code, k)
                                                .is_some_and(|(x, y)| x < ii && ii < y && y < b)
                                    })
                            }
                            None => a <= src.idx((inner.1 + 1, 0)) && src.idx((inner.1, 0)) < b,
                        };
                        if !holds {
                            let (el, ec) = src.pos(b);
                            return Err(format!(
                                "`{part}`: the closure at {line}:{c0} (to {el}:{ec}) does not hold \
                                 {}:{}",
                                inner.1,
                                inner.2.unwrap_or(0)
                            ));
                        }
                    }
                    if named.is_empty() {
                        return Err(format!(
                            "`{part}`: line {line} does not name `{}`",
                            callee
                                .as_deref()
                                .and_then(in_item)
                                .map(|n| n.name)
                                .unwrap_or_default()
                        ));
                    }
                    // a method called on a value of a type of the file: of the chain's type
                    // (`E2.ext()` instantiates `<E2 as Ext>::ext`, not `E1.ext()`), or one
                    // implementing the chain's trait
                    if let Some(c0) = col
                        && !own_closure
                        && let Some(n) = callee.as_deref().and_then(in_item)
                        && let Some(t) = receiver_type(&src, src.idx((line, c0)))
                    {
                        if !receiver_fits(&src, &n, &t) {
                            return Err(format!(
                                "`{part}`: the method at {line}:{c0} is called on a `{t}`, not on \
                                 what `{}` is of",
                                n.path
                            ));
                        }
                        // (the instance's own type, not one implementing its trait: a call of
                        // that instance this caller makes, on whatever line; the self-test reads
                        // it)
                        if n.self_ty.as_deref() == Some(t.as_str()) {
                            TYPED.with(|t| t.borrow_mut().push(part.to_string()));
                        }
                    }
                    // a generic function's instance (`pass::<A>`): the call's type arguments,
                    // written (`pass::<Last>(..)`) or given by its arguments (`pass(&B, ..)` for
                    // `fn pass<T: Pick>(t: &T, ..)`), are the instance's
                    if let Some(c0) = col
                        && !own_closure
                        && let Some(want_args) = callee.as_deref().and_then(instance_args)
                        && let Some(n) = callee.as_deref().and_then(in_item)
                        && let Some(found) = call_type_args(&src, src.idx((line, c0)), &n.name)
                    {
                        let man = self.man;
                        let owner = man.owner_of(&path);
                        for (k, t) in found.iter().enumerate() {
                            // (through the file's type aliases: `apply(&mut a)` with `a: A`,
                            // `type A = &'static Algorithm`; the one in scope at the call, else
                            // the package's)
                            let at = src.idx((line, c0));
                            let Some(t) = t else { continue };
                            let Some(w) = want_args.get(k) else { continue };
                            // the type written, its aliases replaced: the file's in scope at
                            // the call by their paths whole (`m::K`), then the package's
                            let resolved = re!(r"\b[A-Za-z_]\w*(?:\s*::\s*[A-Za-z_]\w*)*")
                                .replace_all(t, |m: &regex::Captures| {
                                    src.alias_at(at, &m[0])
                                        .unwrap_or_else(|| imported_as(&src, &m[0]))
                                })
                                .to_string();
                            let full = expand_aliases(
                                &resolved,
                                &mut |a| self.alias_targets(&src, owner, a),
                                3,
                            );
                            // (by name; whole where either has references, or the code writes
                            // the type's arguments)
                            let name = |x: &str| type_name(&deref_type(x));
                            let named = name(w) == name(t) || name(w) == name(&full);
                            let refs = !(w.contains('&') || full.contains(['&', '<']))
                                || fold_typenum(&norm_path(&full)) == fold_typenum(&norm_path(w));
                            if !(named && refs) {
                                return Err(format!(
                                    "`{part}`: the call at {line}:{c0} instantiates `{}` with `{}`, \
                                     not `{}`",
                                    n.name,
                                    norm_path(t),
                                    norm_path(w)
                                ));
                            }
                        }
                    }
                    // the caller is around it, as for an occurrence: its item, the impl block
                    // or trait, the module; or the attribute on it (`#[tokio::main]` makes
                    // `main`'s body)
                    let chains = self.module_chains(&path, 0);
                    let man = self.man;
                    let owner = man.owner_of(&path);
                    let mut aliases = |n: &str| self.alias_targets(&src, owner, n);
                    let mut first_err = None;
                    let mut inside = false;
                    for &col in &named {
                        match check_item(
                            &src,
                            &format!("in {c}"),
                            (line, col),
                            &mut aliases,
                            chains.as_deref(),
                            None,
                        ) {
                            Ok(()) => {
                                inside = true;
                                break;
                            }
                            Err(e) => {
                                first_err.get_or_insert(e);
                            }
                        }
                    }
                    if !inside && attribute_of(&src, line).is_some_and(|i| i.name == want.name) {
                        inside = true;
                    }
                    if !inside {
                        return Err(format!(
                            "`{part}`: line {line} is not in `{}` ({})",
                            want.name,
                            first_err.unwrap_or_default()
                        ));
                    }
                    if !earlier.contains(&want.name) {
                        earlier.push(want.name);
                    }
                    callee = Some(c.clone());
                    inner = (path.clone(), line, col);
                }
                None => {
                    // a procedural macro's code (a derive's, an attribute's, a function-like
                    // one's) is cited at its use: the attribute or invocation the position is
                    // in, from its first line
                    let bang = re!(r"\[macro (?:[\w]+::)*(\w+)!\]").captures(tags);
                    let rules = bang.as_ref().is_some_and(|t| {
                        src.items
                            .iter()
                            .any(|i| i.kind == ItemKind::Macro && i.name == t[1])
                    });
                    let Some(t) = bang.filter(|_| rules) else {
                        let first = attribute_start(self, at.0, at.1);
                        if path != at.0 || first != Some(line) {
                            return Err(format!(
                                "`{part}`: not the first line of the attribute or macro call at line {}",
                                at.1
                            ));
                        }
                        continue;
                    };
                    // the tagged macro's body, or that of a macro of the same file it invokes
                    // (primeorder's `impl_mont_field_element!` writes its arithmetic through
                    // `impl_mont_field_element_arithmetic!`)
                    let invoked = macros_invoked(&src, &t[1]);
                    let inside = cols.iter().any(|&col| {
                        src.enclosing((line, col), &[ItemKind::Macro])
                            .is_some_and(|m| invoked.contains(&m.name))
                    });
                    if !inside {
                        return Err(format!(
                            "`{part}`: line {line} is not in the body of `macro_rules! {}`",
                            &t[1]
                        ));
                    }
                    // the macro's line names the symbol, or the call passes it in
                    // (`hash_with!(SHA384)` for a body calling `digest(&$alg, ..)`): the line
                    // then uses a metavariable, which a matcher's `$alg:expr` only declares
                    let sym = strip_generics(symbol);
                    let ident = sym.rsplit("::").next().unwrap_or(&sym);
                    // (or a name the invocation's file imports it as: `use ..SHA1_FOR_LEGACY_USE_ONLY
                    // as SHA1;` with `ty!(T4, SHA1)`)
                    let mut names = vec![regex::escape(ident)];
                    let occ_src = self.source(at.0);
                    for b in src
                        .binds
                        .iter()
                        .chain(occ_src.iter().flat_map(|o| o.binds.iter()))
                    {
                        if b.path.last().map(String::as_str) == Some(ident)
                            && b.name != ident
                            && b.name != "*"
                        {
                            names.push(regex::escape(&b.name));
                        }
                    }
                    let word = Regex::new(&format!(r"\b(?:{})\b", names.join("|"))).unwrap();
                    let text = &src.lines[line - 1];
                    // the metavariables the line uses (not declares); where the macro's rule and
                    // the invocation say which one the call's token binds (`mk!(m256, hash_a,
                    // SHA256)` with `($m:ident, $f:ident, $alg:ident)`: `$alg`), that one
                    let used: Vec<&str> = re!(r"\$(\w+)")
                        .captures_iter(text)
                        .filter(|m| {
                            !text[m.get(0).map_or(0, |g| g.end())..]
                                .trim_start()
                                .starts_with(':')
                        })
                        .filter_map(|m| m.get(1).map(|g| g.as_str()))
                        .collect();
                    // the rule the occurrence's invocation matches (rustc's first), where it can
                    // be read: the line is in its transcriber, and its metavariables are bound
                    let occ = self.source(at.0);
                    let rule = src
                        .items
                        .iter()
                        .find(|i| {
                            i.kind == ItemKind::Macro
                                && i.name == t[1]
                                && (i.start.0..=i.end.0).contains(&line)
                        })
                        .and_then(|m| {
                            let (_, args) = invocation_args(occ.as_deref()?, (at.1, at.2))?;
                            rule_for(&src, m, &args)
                        });
                    if let Some((r, _)) = &rule {
                        let (l0, l1) = (src.pos(r.body.0).0, src.pos(r.body.1).0);
                        if !(l0..=l1).contains(&line) {
                            return Err(format!(
                                "`{part}`: line {line} is not in the rule of `macro_rules! {}` the \
                                 invocation matches (lines {l0}-{l1})",
                                &t[1]
                            ));
                        }
                    }
                    let binding = match &rule {
                        Some((_, binds)) => Some(
                            binds
                                .iter()
                                .filter(|(_, toks)| word.is_match(&toks_text(toks)))
                                .map(|(n, _)| n.clone())
                                .collect::<Vec<_>>(),
                        ),
                        None => cols
                            .iter()
                            .find_map(|&col| src.enclosing((line, col), &[ItemKind::Macro]))
                            .and_then(|m| {
                                let body: String = (m.start.0..=m.end.0.min(src.lines.len()))
                                    .map(|l| src.lines[l - 1].as_str())
                                    .collect::<Vec<_>>()
                                    .join("\n");
                                call_line.and_then(|l| metavars_of(&body, l, &word))
                            }),
                    };
                    let uses_metavar = match &binding {
                        Some(vars) => used.iter().any(|u| vars.iter().any(|v| v == u)),
                        None => !used.is_empty(),
                    };
                    if !word.is_match(text)
                        && !(uses_metavar && call_line.is_some_and(|l| word.is_match(l)))
                    {
                        return Err(format!(
                            "`{part}`: line {line} of the macro does not name `{ident}`"
                        ));
                    }
                }
            }
        }
        Ok(())
    }
}
/// A code position is inside the item its context names (`in <item>; ..`): the innermost
/// function, static or const around it has the item's name, and, for a method whose path names
/// its type, the impl block (or the trait, for a default method) around that names it too. Not
/// inside a `macro_rules!` body. The source may name a type through an alias (`impl Writer for
/// Sha256`, where the context names `CoreWrapper<..>`): `aliases` gives what a name stands for.
pub(super) fn check_item(
    src: &Source,
    details: &str,
    at: (usize, usize),
    aliases: &mut dyn FnMut(&str) -> Vec<String>,
    chains: Option<&[Vec<String>]>,
    descriptor: Option<&str>,
) -> Result<(), String> {
    if let Some(m) = src.enclosing(at, &[ItemKind::Macro]) {
        return Err(format!(
            "position inside the body of `macro_rules! {}`",
            m.name
        ));
    }
    let Some(want) = details
        .strip_prefix("in ")
        .and_then(|d| parts(d).into_iter().next())
        .and_then(in_item)
    else {
        return Err("no enclosing item in the context".into());
    };
    let Some(item) = src.enclosing(at, &[ItemKind::Fn, ItemKind::Static]) else {
        // an item a macro invocation outside any item makes (`hash_fn!(..)` at module level),
        // cited inside the invocation or at its start (hpke's `nistp_dhkex!(..)`)
        if src.enclosing(at, &[ItemKind::MacroCall]).is_some() || macro_call_at(src, at) {
            let path = details
                .strip_prefix("in ")
                .and_then(|d| parts(d).into_iter().next())
                .unwrap_or_default();
            // the descriptor the occurrence's algorithm comes from, which the item's code names
            let extra: Vec<String> = re!(r"algorithm (?:possibly )?from (?:\w+::)*(\w+)")
                .captures_iter(details)
                .map(|m| m[1].to_string())
                .chain(descriptor.map(str::to_string))
                .collect();
            match invocation_names(src, at, path, &extra) {
                Pick::Exact => return Ok(()),
                Pick::Range => {
                    RANGED.with(|r| r.set(true));
                    return Ok(());
                }
                Pick::No => {}
            }
            return Err(format!(
                "the macro invocation does not make `{}`: another invocation of the same \
                 macro in the file does",
                want.name
            ));
        }
        return Err(format!("position outside any item, not in `{}`", want.name));
    };
    // code a macro's invocation wraps (`thread_local! { static TL: .. = digest(..) }`) is in
    // the items the macro makes inside the item around it, which the context's path names
    // (`t7::TL::__rust_std_internal_init_fn`); `format!(..)` makes none
    // (also an invocation inside a function, `fn local_key() { thread_local! { .. } }`)
    let in_call = src.enclosing(at, &[ItemKind::MacroCall]).is_some() || macro_call_at(src, at);
    if item.name != want.name {
        if in_call && path_names(&want.path, &item.name) {
            return Ok(());
        }
        return Err(format!(
            "position in `{}`, not in `{}`",
            item.name, want.name
        ));
    }
    // the module: the file's and those of the inline modules (and functions) around the
    // position are those the context names; for a method, around its type's or trait's
    // definition when the file has it. An identical statement in another module or file is
    // another item (rustls's `crypto::ring::tls12` repeats `crypto::aws_lc_rs::tls12`).
    if let Some(chains) = chains {
        let around = |p: (usize, usize)| -> Vec<String> {
            let mut v: Vec<&Item> = src
                .items
                .iter()
                .filter(|i| matches!(i.kind, ItemKind::Mod | ItemKind::Fn) && i.contains(p))
                .collect();
            v.sort_by_key(|i| i.start);
            v.iter().map(|i| i.name.clone()).collect()
        };
        let in_chain = |inner: &[String], want: &[String]| {
            chains.iter().any(|c| {
                c.len() + inner.len() == want.len()
                    && c.iter().chain(inner).zip(want).all(|(a, b)| a == b)
            })
        };
        if let Some(mods) = &want.mods {
            let mut inner = around(at);
            if item.kind == ItemKind::Fn {
                inner.pop();
            }
            if !in_chain(&inner, mods) {
                return Err(format!(
                    "position in module `{}`, not in `{}`",
                    chains
                        .first()
                        .map(|c| c
                            .iter()
                            .chain(&inner)
                            .cloned()
                            .collect::<Vec<_>>()
                            .join("::"))
                        .unwrap_or_default(),
                    mods.join("::")
                ));
            }
        } else if let Some((ty, mods)) = &want.owner {
            let defs: Vec<&Item> = src
                .items
                .iter()
                .filter(|i| matches!(i.kind, ItemKind::TypeDef | ItemKind::Trait) && i.name == *ty)
                .collect();
            if !defs.is_empty() && !defs.iter().any(|d| in_chain(&around(d.start), mods)) {
                return Err(format!(
                    "`{ty}` of this file is not the one in `{}`",
                    mods.join("::")
                ));
            }
        }
    }
    // the block the function is written in (not the function itself)
    let container = src
        .items
        .iter()
        .filter(|i| {
            matches!(i.kind, ItemKind::Impl | ItemKind::Trait | ItemKind::Fn)
                && i.start < item.start
                && i.contains(item.start)
        })
        .max_by_key(|i| i.start);
    if let Some(ty) = &want.self_ty
        && let Some(block) = container
    {
        let ok = match block.kind {
            // a blanket impl's type is any type: its trait is named
            ItemKind::Impl if block.name.is_empty() => {
                matches!((&block.trait_name, &want.trait_name), (Some(a), Some(b))
                    if trait_of(a, b, aliases) || trait_of(&trait_alias(src, a), b, aliases))
            }
            // its type, and the trait it implements: `impl TryFrom<&PrivateKeyDer<'_>> for
            // KeyPair` is not `impl TryFrom<&[u8]> for KeyPair`
            ItemKind::Impl => {
                written_self(src, block, want.self_full.as_deref(), aliases).unwrap_or_else(|| {
                    same_type(&block.name, ty, want.self_full.as_deref(), aliases)
                }) && match (&block.trait_name, &want.trait_name) {
                    // (a trait imported under another name: `use m::Pick as Chooser`)
                    (Some(a), Some(b)) => {
                        trait_of(a, b, aliases) || trait_of(&trait_alias(src, a), b, aliases)
                    }
                    _ => true,
                }
            }
            ItemKind::Trait => {
                block.name == *ty
                    || want
                        .trait_name
                        .as_deref()
                        .is_some_and(|t| same_trait(&block.name, t))
            }
            // a function inside a function: no impl block of its own
            _ => true,
        };
        if !ok {
            let of = |t: &Option<String>, ty: &str| match t {
                Some(t) => format!("`impl {t} for {ty}`"),
                None => format!("`{ty}`"),
            };
            return Err(format!(
                "position in a method of {}, not of {}",
                of(&block.trait_name, &block.name),
                of(&want.trait_name, ty)
            ));
        }
    }
    Ok(())
}
