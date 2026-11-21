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
            // the package's component says what its bom-ref does (which the position's lock or
            // manifest entry is checked against)
            if let Some([name, version, purl]) = self.graph.libraries.get(&o.component_ref)
                && (package_of(&o.component_ref) != Some((name.as_str(), version.as_str()))
                    || *purl != o.component_ref)
            {
                return Err(format!(
                    "the component says {name} {version} ({purl}), its bom-ref {}",
                    o.component_ref
                ));
            }
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
        // (or one the boundary check cites itself: a call into a crypto package the knowledge
        // base gives no meaning)
        if o.component_ref.starts_with("crypto:algorithm:unknown:")
            && kind == "call"
            && !self.is_operation(&o.symbol, &o.component_ref)
            && !(ctx
                .details
                .contains("algorithm unresolved: the boundary check: ")
                && self.crypto_package(&o.component_ref))
        {
            return Err(format!(
                "`{}` is no operation the knowledge base lists, nor a crypto package's use",
                o.symbol
            ));
        }
        // a call the boundary check cites by name: one the standard library or a wrapper
        // package (`[semantics] wrappers`) makes for the program, which the knowledge base
        // names as this asset's function (``run for this call by `uuid::..::new_v4`:
        // `rand::random` of rand 0.10.3``); the function called here is the occurrence's symbol
        for run in ctx.details.split("run for this call by ").skip(1) {
            let mut quoted = run.split('`');
            let (entry, callee) = (quoted.nth(1).unwrap_or(""), quoted.nth(1).unwrap_or(""));
            let entry_crate = entry.split("::").next().unwrap_or("");
            let for_caller = matches!(entry_crate, "core" | "std" | "alloc")
                || self
                    .kb
                    .wrappers
                    .iter()
                    .any(|w| w.replace('-', "_") == entry_crate);
            if !for_caller {
                return Err(format!(
                    "`{entry}` is neither the standard library's nor a wrapper package's: its \
                     calls are not the caller's"
                ));
            }
            let last = |p: &str| p.rsplit("::").next().unwrap_or("").to_string();
            if last(entry) != last(&o.symbol) {
                return Err(format!(
                    "the occurrence is at `{}`, not at `{entry}`",
                    o.symbol
                ));
            }
            // (by a `[[fn]]` entry for the function, or by the `[[type]]` entry of the type it
            // is a function of, whose name may have parameters the type's arguments fill:
            // `HMAC-{hash}`)
            let of = run
                .split("; ")
                .next()
                .and_then(|clause| clause.split(", a function of `").nth(1))
                .and_then(|t| t.split('`').next());
            let names = rcbom_analysis::floor_names(self.kb, callee, of);
            let asset = o
                .component_ref
                .strip_prefix("crypto:algorithm:")
                .unwrap_or(&o.component_ref);
            if !names.iter().any(|n| n == asset || fits_template(n, asset)) {
                return Err(format!(
                    "the knowledge base does not name `{callee}` as {asset}"
                ));
            }
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
        // the occurrence's item, where the compiler records it: named there, and holding the
        // position (or made by the macro invoked there). An occurrence several items share
        // (a macro's invocation making each) gives each one's, the others' by name (``owner
        // `item` at ..``).
        let mut owner_plain = true;
        let head = ctx
            .details
            .strip_prefix(ctx.tags)
            .unwrap_or(ctx.details)
            .trim_start()
            .strip_prefix("in ")
            .and_then(|d| parts(d).into_iter().next())
            .unwrap_or_default();
        for p in parts(ctx.details) {
            let Some((item, at)) = witness::owner_detail(p) else {
                continue;
            };
            let w = witness::written_whole(at).ok_or_else(|| format!("`{p}` cannot be read"))?;
            let item = item.unwrap_or(head);
            owner_plain &= self.check_item_at(&w, item, (&path, line, Some(offset)), None)?;
        }
        // the positions the details name: where a generic instance was instantiated, where a
        // macro's code was written
        self.check_details(
            ctx.details,
            ctx.tags,
            &o.symbol,
            (&path, line, offset),
            &o.component_ref,
            owner_plain,
        )?;
        // where a type was made a trait object
        self.check_coercions(ctx.details)?;
        // the macro tags are among the leading tags, never in the recorded source text; a tagged
        // position is the macro's, derive's or attribute's name, not the symbol's
        let mut tagged = false;
        if let Some(m) = re!(r"\[macro ([\w:]+!)\]").captures(ctx.tags) {
            let name = &m[1];
            let ok = Regex::new(&format!(r"^(?:\w+::)*{}", regex::escape(name)))
                .unwrap()
                .is_match(&at);
            if !(ok && starts_token) {
                return Err(format!("expected `{name}` in {text:?}"));
            }
            tagged = true;
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
            .trim_start_matches('&')
            .trim_start_matches("mut ")
            .split("::")
            .next()
            .unwrap_or("");
        // (of a type parameter's, `<D as digest::digest::Digest>::update`, its trait's)
        let first = first.split(" as ").last().unwrap_or(first);
        // (and of a standard-library type's implementation of another crate's trait, `<alloc::
        // vec::Vec<u8> as aead::Buffer>::extend_from_slice`, its trait's: only the trait's
        // crate can implement it for that type)
        let of_trait = o
            .symbol
            .strip_prefix('<')
            .and_then(|q| qualified_trait(q))
            .and_then(|t| t.split("::").next())
            .filter(|t| !matches!(*t, "core" | "std" | "alloc"));
        let first = match of_trait {
            Some(t) if matches!(first, "core" | "std" | "alloc") => t,
            _ => first,
        };
        if !self.crate_known(first) {
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
        // a function held as a value by an item of another crate (``held as a value in
        // `md5::TABLE` named here``): the position names that item, in whose value the compiler
        // finds the function; the text is checked for the item as it is for a static
        let held_in = re!(r"held as a value in `([^`]+)` named here")
            .captures(ctx.details)
            .map(|m| strip_generics(&m[1]));
        let (sym, sym_crate) = match &held_in {
            Some(h) => {
                let krate = h.split("::").next().unwrap_or("").to_string();
                if !self.crate_known(&krate) {
                    return Err(format!("`{h}`: no crate `{krate}` in the build"));
                }
                (h.clone(), krate)
            }
            None => (sym, sym_crate),
        };
        let mut parsed = None;
        // a method call (`cipher.encrypt_padded_vec_mut::<Pkcs7>(..)`): its receiver, whose type
        // the text does not give, may carry the asset, not the method's own type arguments
        let mut method_call = false;
        let owner = man.owner_of(&path);
        let owner_id = owner.map(|p| p.id.repr.clone());
        if !tagged {
            // the enclosing item the context names (an identical statement in another
            // function, or in another type's method of that name, is another occurrence), and
            // no macro's body (a macro's code is cited where it is called)
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
            // an operator trait's method is called by its operator (`point * scalar`): the
            // position is the operator, unless the code names the method itself
            // (`Pin::new(&mut fut).poll(cx)`, `a.add(b)`)
            let by_name = at.starts_with(ident.as_str())
                && !at[ident.len()..].starts_with(is_ident)
                && starts_token;
            let op = operator_of(&o.symbol).filter(|_| !by_name && held_in.is_none());
            if let Some(op) = op
                && !(at.starts_with(op)
                    && !at[op.len()..].starts_with('=')
                    && !(op == "await" && at[op.len()..].starts_with(is_ident)))
            {
                return Err(format!("expected the operator `{op}` in {text:?}"));
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
                    pointer_bound(&src, root_at, &root, l2, src.idx((l2, c2))).map_err(|e| {
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
            method_call = before_blank(&src.code, src.idx((line, offset)))
                .is_some_and(|k| src.code[k] == '.');
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
            // (a `for` loop calls its iterator's `next`, and `into_iter` first: at the `for`)
            let looped = re!(
                r"core::iter::traits::(?:iterator::Iterator\b.*::next|collect::IntoIterator\b.*::into_iter)$"
            )
            .is_match(&o.symbol)
                && held_in.is_none()
                && at.starts_with("for")
                && !at["for".len()..].starts_with(is_ident);
            if pointer.is_none() && op.is_none() && !looped && !(ok && starts_token) {
                return Err(format!("expected `{ident}` in {text:?}"));
            }
            // a method called on the result of a call of the same name, or whose result one is
            // called on (`.get_ref()` three times down a chain, each another type's): where the
            // CBOM does not cite the neighbour as this function too, the text cannot say which
            // of them is the symbol's, and the position is one of that range
            if pointer.is_none() && op.is_none() {
                for (l, c) in chain_neighbours(&src, src.idx((line, offset)), &ident) {
                    // (another occurrence: not this one's own position, beside the one a
                    // shift moved it to)
                    let same = self
                        .at_pos
                        .get(&(o.location.clone(), l, c))
                        .is_some_and(|v| {
                            v.iter()
                                .any(|&j| j != oi && self.occs[j].symbol == o.symbol)
                        });
                    if !same {
                        RANGED.with(|r| r.set(true));
                    }
                }
            }
        }
        // an instantiation's position that details cite (`instantiated by X at F:L:C`) is cited
        // by one of this asset's, where an asset of its kind cites it at all: the function
        // instantiated may use, beside the algorithm its type argument chooses, one of its own
        // (pgp's `StreamDecryptor::<Aes128>::new`: the cipher chosen, and the SHA-1 of its
        // integrity check, whose occurrences cite the instantiation)
        // (or by one of this asset's name less its parameters, or more: the instance runs
        // `RSA-PKCS1-1.5` with whatever hash its callers' values name, and this call's is
        // `Pkcs1v15Sign::new::<Sha256>()`, RSA-PKCS1-1.5-SHA-256)
        if kind == "instantiation"
            && let Some(by) = self.cited.get(&(o.location.clone(), line, offset))
            && !by.contains(&o.component_ref)
            && !by.iter().any(|b| self.refines(b, &o.component_ref))
            && by
                .iter()
                .any(|b| self.graph.primitive.get(b) == self.graph.primitive.get(&o.component_ref))
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
            // (a member that reaches the call from other functions comes through a method
            // such an object runs there, not at the call: rustls 0.21's `self.dec_key
            // .open_within(..)`, the key made by `<AesGcm as Tls12AeadAlgorithm>::decrypter`;
            // the coercion is checked as any, `check_coercions`)
            if let Some(m) = re!(r"^member: dyn(?:, possible)? \(dyn: `([^`]+)`(?:, the only type)? (?:is )?coerced to `([^`]+)`")
                .captures(p)
                && let Some(at) = call_at
                && !ctx.details.contains("that may reach the call from other functions")
            {
                // (a member no descriptor names is the type made the object: the knowledge
                // base names that type as this asset, `receiver: one of 2 types the build makes
                // a `dyn DynDigest` of` with a `Sha256`)
                if ctx.details.contains("; receiver: ") {
                    let asset = o
                        .component_ref
                        .strip_prefix("crypto:algorithm:")
                        .unwrap_or(&o.component_ref);
                    let names = rcbom_analysis::floor_names(self.kb, "", Some(&m[1]));
                    if !names.iter().any(|n| n == asset || fits_template(n, asset)) {
                        return Err(format!(
                            "the knowledge base does not name `{}` as {asset}",
                            &m[1]
                        ));
                    }
                }
                let m = [&m[0], &m[2]];
                let want = type_name(m[1].trim().trim_start_matches("dyn ").trim());
                let supers = self.supertraits(&path, m[1]);
                // (a trait the package imports under another name, in whatever file:
                // hqckem-ref's `pub(crate) use sha3::digest::XofReader as Xof;`, its functions
                // taking a `&mut dyn Xof`)
                let renames = match self.man.owner_of(&path).map(|p| p.manifest_dir.clone()) {
                    Some(d) => self.package_binds(&d),
                    None => Rc::new(Vec::new()),
                };
                if let Some(ts) = call_dyn_receivers(&src, src.idx(at))
                    && !ts.iter().any(|t| {
                        let mut seen = vec![t.clone()];
                        let mut k = 0;
                        while k < seen.len() {
                            if seen[k] == want {
                                return true;
                            }
                            let here = seen[k].clone();
                            let named = renames
                                .iter()
                                .filter(|b| b.name == here)
                                .filter_map(|b| b.path.last());
                            for s2 in supers.get(&here).into_iter().flatten().chain(named) {
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
                let expanded: Vec<usize> =
                    re!(r"expanded (?:`[^`]*` )?from ([^\s;]+?):(\d+)(?::\d+-|;|$)")
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
                // (a descriptor the knowledge base does not know is none: also where no witness
                // or argument is checked, a member reaching the call from another function; a
                // member's label, `passed by `F``, is no path)
                if names.is_empty() && re!(r"^[A-Za-z_]\w*(::[A-Za-z_]\w*)+$").is_match(d) {
                    return Err(format!("`{d}` is no knowledge-base descriptor"));
                }
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
            && let Some(provs) = self.graph.providers.get(&o.component_ref).cloned()
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
            // the callee's crate (not of an instantiation: the function instantiated is of any
            // crate, the asset is its type argument's, written or not: `Scalar::from_hash(
            // Sha512::default()..)` chooses SHA-512 for curve25519-dalek's function)
            // (a function that runs for a type its caller gives, a trait's method or one with
            // a type parameter, may provide the asset, `Oaep::new::<Sha1>()` of rsa; where it
            // does not, the asset may be that type's and the crate says nothing:
            // `rand::make_rng()` making a `rand_chacha::ChaCha20Rng`, `rng.random()` on one)
            let chosen = kind == "instantiation";
            let mut open: Vec<String> = Vec::new();
            if !chosen {
                let refs: Vec<String> = self
                    .lib_refs(&sym_crate)
                    .into_iter()
                    .filter(|r| !self.neutral(r))
                    .collect();
                if self.runs_for_a_type(&refs, &sym_segs) {
                    open = refs;
                } else {
                    roots.extend(refs);
                }
            }
            // a written qualifier: a self type, unless the path is the trait's own path
            // (`aes_gcm::aead::KeyInit::new_from_slice`: the qualifiers lead to the trait)
            let trait_path = quals.last().is_some_and(|q| sym_segs.contains(q));
            if let Some(q0) = quals.first()
                && !matches!(q0.as_str(), "crate" | "self" | "super" | "Self")
                && !sym_segs.contains(q0)
                && !trait_path
                && !chosen
            {
                match self.origins(&src, owner_id, q0) {
                    Some(r) => roots.extend(r.into_iter().filter(|r| !self.neutral(r))),
                    None => unknown = true,
                }
            }
            let provides = |r: &String| {
                let cl = self.graph.closure(r);
                provs.iter().any(|p| cl.contains(p))
            };
            let mut by_generics = Vec::new();
            for g in generics.iter().filter(|g| !NEUTRAL.contains(&g.as_str())) {
                match self.origins(&src, owner_id, g) {
                    Some(r) => by_generics.extend(r.into_iter().filter(|r| !self.neutral(r))),
                    None => unknown = true,
                }
            }
            if !method_call || by_generics.iter().any(provides) {
                roots.extend(by_generics);
            }
            let provided = roots.iter().chain(&open).any(provides);
            if !unknown && !roots.is_empty() && !provided {
                roots.extend(open);
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
            .chain(call.foreign_types.iter().filter(|w| {
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

    /// Whether one of two assets is the other with more of its parameters named
    /// (`RSA-PKCS1-1.5-SHA-256` and `RSA-PKCS1-1.5`): by their names, as `extends` reads them.
    fn refines(&self, a: &str, b: &str) -> bool {
        let name = |r: &str| r.strip_prefix("crypto:algorithm:").map(str::to_string);
        let family = |r: &str| self.graph.family.get(r).map(String::as_str);
        match (name(a), name(b)) {
            (Some(x), Some(y)) => extends(&x, &y, family(a)) || extends(&y, &x, family(b)),
            _ => false,
        }
    }

    pub(super) fn check_details(
        &mut self,
        details: &str,
        tags: &str,
        symbol: &str,
        at: (&Path, usize, usize),
        component_ref: &str,
        owner_plain: bool,
    ) -> Result<(), String> {
        let mut callee = details
            .strip_prefix(tags)
            .unwrap_or(details)
            .strip_prefix("in ")
            .and_then(|d| parts(d).into_iter().next())
            .map(str::to_string);
        // the position the next detail's code holds: the occurrence's, then each cited
        // caller's (line, and column where the detail gives one)
        /// A position a detail's code holds: file, line, and the column where one is given.
        type Held = (PathBuf, usize, Option<usize>);
        let mut inner: Held = (at.0.to_path_buf(), at.1, Some(at.2));
        // the chain so far: each item instantiated, with the position its code holds. An
        // occurrence instantiated along two chains that part at a closure (a generic function's
        // closure, made once per instance of the function) lists the second chain from that
        // closure on: a detail naming the closure's parent continues from the closure.
        let mut chain: Vec<(String, Held)> =
            callee.iter().map(|c| (c.clone(), inner.clone())).collect();
        // whether the code at the occurrence names a type parameter of the function or the
        // impl it is in: its asset is then what an instance's arguments choose. Not where it
        // also names a type that is this asset by itself (`run_oaep_primitive::<D, Sha1>` is
        // SHA-1's whatever `D` is, xml-sec)
        let asset = component_ref
            .strip_prefix("crypto:algorithm:")
            .unwrap_or(component_ref);
        let kb = self.kb;
        let by_param = self.source(at.0).is_some_and(|occ| {
            let (rs, rc) = rest(&occ, at.1, at.2);
            let Some((quals, last, generics)) = path_and_generics(&rs, &rc) else {
                return false;
            };
            let Some(f) = occ.enclosing((at.1, at.2), &[ItemKind::Fn]) else {
                return false;
            };
            let mut params = fn_sig(&occ, f).generics;
            if let Some(b) = impl_of(&occ, f) {
                let (ba, bb) = occ.span(b);
                let head = occ.text(ba, scan_to(&occ.code, ba, bb, |k| occ.code[k] == '{'));
                // (the parameters the impl declares: the first `<..>` after `impl`)
                if let Some(h) = head
                    .trim_start()
                    .strip_prefix("impl")
                    .map(str::trim_start)
                    .filter(|r| r.starts_with('<'))
                {
                    let hs: Vec<char> = h.chars().collect();
                    let cls = vec![Class::Code; hs.len()];
                    if let Some(e) = skip_angle(&hs, &cls, 0) {
                        let inner: String = hs[1..e - 1].iter().collect();
                        params.extend(split_top(&inner).iter().filter_map(|g| {
                            let g = g.trim().trim_start_matches("const ").trim();
                            let n: String = g.chars().take_while(|c| is_ident(*c)).collect();
                            (!n.is_empty() && !g.starts_with('\'')).then_some(n)
                        }));
                    }
                }
            }
            // (every name in the path's generic arguments: `sha2::Sha224` is `Sha224`'s)
            let mut inside: Vec<String> = Vec::new();
            let mut i = 0;
            while i < rs.len() && rc[i] == Class::Code {
                if rs[i] == '<' {
                    let Some(close) = skip_angle(&rs, &rc, i) else {
                        break;
                    };
                    let text: String = rs[i + 1..close - 1].iter().collect();
                    inside.extend(
                        re!(r"[A-Za-z_]\w*")
                            .find_iter(&text)
                            .map(|m| m.as_str().to_string()),
                    );
                    i = close;
                } else if is_ident(rs[i]) || rs[i] == ':' || rs[i].is_whitespace() {
                    i += 1;
                } else {
                    break;
                }
            }
            let own = quals.iter().chain(&inside).any(|w| {
                !params.contains(w)
                    && kb
                        .types
                        .iter()
                        .any(|e| e.name == *w && e.algo.asset == asset)
            });
            !own && quals
                .iter()
                .chain(&generics)
                .chain(std::iter::once(&last))
                .any(|w| params.contains(w))
        });
        // what the instantiations of the chains choose: one that chooses others of this
        // asset's kind and not it, and whether one chooses it
        let mut unchosen: Option<String> = None;
        let mut chosen_by_one = false;
        // the items the occurrence is in beside the one it names, each with the compiler's
        // record of where it is
        let owners: Vec<&str> = parts(details)
            .into_iter()
            .filter_map(witness::owner_detail)
            .filter_map(|(item, _)| item)
            .collect();
        for part in parts(details) {
            if let Some(c) = &callee
                && chain.last().is_none_or(|(k, _)| k != c)
            {
                chain.push((c.clone(), inner.clone()));
            }
            // a step that names the item it instantiates, where that is not the caller of the
            // step before (an occurrence several instances of its item reach joins their
            // chains): the occurrence's item or a caller before, with the position its code
            // holds; or another instance of the occurrence's item
            let (named_item, part) = match re!(r"^`([^`]*)` (instantiated by .*)$").captures(part) {
                Some(m) => (
                    m.get(1).map(|k| k.as_str()),
                    m.get(2).map_or(part, |p| p.as_str()),
                ),
                None => (None, part),
            };
            if let Some(k) = named_item {
                match chain.iter().rev().find(|(n, _)| n == k) {
                    Some((n, at)) => {
                        callee = Some(n.clone());
                        inner = at.clone();
                    }
                    None => match chain.first() {
                        // (a closure's body is one text whichever instance runs it: named as
                        // the occurrence names it, without the kind an `async` closure's body
                        // is printed with, `{closure#0}::<i32>`)
                        Some((first, at)) if same_item(first, k) => {
                            let closure = strip_generics(k).trim_end_matches("::").ends_with('}');
                            callee = Some(if closure {
                                first.clone()
                            } else {
                                k.to_string()
                            });
                            inner = at.clone();
                        }
                        // (or another item the occurrence is in: the instances of a generic
                        // function share its code, and so do the functions one macro
                        // invocation writes from one line, picky's `define_oid! { A => a =>
                        // "..", B => b => ".." }` or cosmian_cover_crypt's `enc` and `dec` of
                        // `make_mlkem!`. The compiler's record of that item is among the
                        // details, `owner `k` at ..`, and is read with the position)
                        Some((_, held)) if owners.contains(&k) => {
                            callee = Some(k.to_string());
                            inner = held.clone();
                        }
                        _ => {
                            return Err(format!(
                                "`{part}`: `{k}` is neither the occurrence's item nor a caller \
                                 before this one"
                            ));
                        }
                    },
                }
            }
            // where the compiler records the occurrence's item: read with the position
            if witness::owner_detail(part).is_some() {
                continue;
            }
            // a macro's code, as the compiler records where it is written: in the expansions
            // the occurrence is cited at; written as it reads, it names the symbol
            // (the code of another call cited here with the occurrence's, one of a less
            // specific asset the same invocation writes, says which: ``expanded `f` from ..``,
            // cms's `$alg::key_size()` beside the `generate_key_iv` of its CBC encryptor)
            let expanded = part
                .strip_prefix("expanded from ")
                .map(|p| (symbol, p))
                .or_else(|| {
                    part.strip_prefix("expanded `")
                        .and_then(|r| r.split_once("` from "))
                });
            if let Some((symbol, p)) = expanded {
                let w = witness::written_whole(p)
                    .filter(|w| !w.steps.is_empty())
                    .ok_or_else(|| format!("`{part}`: where the code is written cannot be read"))?;
                let plain = self
                    .check_written(&w, Some(at))
                    .map_err(|e| format!("`{part}`: {e}"))?;
                // (in an item a procedural macro writes, a span says where that macro took its
                // code's span from, not what the code is: a derive's call at a field's type)
                if plain && owner_plain && !self.names_symbol(&w, symbol)? {
                    return Err(format!(
                        "`{part}`: the macro's code there does not name `{symbol}`"
                    ));
                }
                continue;
            }
            // a step with what the compiler records of it
            let whole = part;
            let (part, via) = witness::split_via(part)?;
            let Some(m) =
                re!(r"^(instantiated by (.*) at|expanded from) ([^\s;]+?):(\d+)(?::(\d+))?(?: as `([^`]*)`)?$")
                    .captures(part)
            else {
                // (a step without a position, a call in the standard library's optimised
                // code: the next step instantiates its caller)
                if let Some(c) = part.strip_prefix("instantiated by ") {
                    callee = Some(c.to_string());
                }
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
            // occurrences: `h::<sha2::Sha384>` is SHA-384's), this asset is among it, or has it
            // as a component (`tag::<Sha256>` building an `Hmac<D>`: HMAC-SHA-256's SHA-256).
            // What is chosen there of another kind than this asset and its components says
            // nothing of it: the function instantiated may use an algorithm of its own beside
            // the one its type argument chooses (the SHA-1 of pgp's integrity check, in a
            // decryptor instantiated with its cipher); nor of an operation of unknown algorithm
            // (cfb-mode's, run over the cipher chosen there). And it is held so only where the
            // occurrence's own code is written with a type parameter of its function or impl
            // (`D::new()`, `Hmac::<D>::new_from_slice(k)`): code that names a type of its own
            // runs it whatever the instance (cotp's `Sha256::new()` in a function generic
            // over the hash of its HMAC, instantiated with SHA-1)
            if let (Some(_), Some(c0)) = (&caller, col)
                && !component_ref.starts_with("crypto:algorithm:unknown")
                && by_param
            {
                let here: Vec<usize> = self
                    .at_pos
                    .get(&(file.clone(), line, c0))
                    .cloned()
                    .unwrap_or_default();
                let parts = self.graph.depends_on.get(component_ref);
                let kinds: Vec<&String> = std::iter::once(component_ref)
                    .chain(parts.into_iter().flatten().map(String::as_str))
                    .filter_map(|r| self.graph.primitive.get(r))
                    .collect();
                // (what this caller's instance chooses: the position may be in generic code,
                // where another instance of the caller chooses otherwise, `new::<C>(..)` in an
                // `impl<C> Cipher for Block<C>` instantiated for CTR and for CBC ciphers)
                let chooser = |j: usize| {
                    let c = &self.occs[j].context;
                    c.find("] in ")
                        .and_then(|k| {
                            super::lex::parts(&c[k + "] in ".len()..])
                                .into_iter()
                                .next()
                        })
                        .map(str::trim)
                };
                let chosen: Vec<&str> = here
                    .iter()
                    .filter(|&&j| {
                        self.occs[j].context.contains("] [instantiation]")
                            && chooser(j)
                                .is_none_or(|i| caller.as_deref().map(str::trim) == Some(i))
                            && self
                                .graph
                                .primitive
                                .get(&self.occs[j].component_ref)
                                .is_some_and(|p| kinds.contains(&p))
                    })
                    .map(|&j| self.occs[j].component.as_str())
                    .collect();
                // (held of the chains together: a function of two type parameters is given
                // one by one caller and the other by the next, `run_oaep_primitive::<D, Sha1>`
                // in `run_oaep_mgf::<Sha512>`: SHA-1 is chosen at the first, and the second
                // chooses another hash for another parameter)
                if !chosen.is_empty() {
                    if here.iter().any(|&j| {
                        self.occs[j].component_ref == component_ref
                            || parts.is_some_and(|p| p.contains(&self.occs[j].component_ref))
                            || self.refines(&self.occs[j].component_ref, component_ref)
                    }) {
                        chosen_by_one = true;
                    } else {
                        unchosen.get_or_insert(format!(
                            "`{part}`: the instantiation at {file}:{line}:{c0} chooses {}",
                            chosen.join(", ")
                        ));
                    }
                }
            }
            // an instance its arguments choose, its `<..>` not written (`Algorithm::hash(
            // HmacSha256::new_from_slice(k).unwrap(), d)`): where they set up assets of this
            // asset's primitive (constructors, and the components cited with them), this asset
            // is among them (not the next line's `HmacSha512`)
            if let (Some(_), Some(c0)) = (&caller, col)
                && callee
                    .as_deref()
                    .is_some_and(|p| p.trim_end().ends_with("::<..>"))
                && let Some((a, b)) = call_args_span(&src.code, src.idx((line, c0)))
                && let Some(prim) = self.graph.primitive.get(component_ref)
            {
                let (from, to) = (src.pos(a), src.pos(b));
                let set_up: Vec<&Occ> = self
                    .occs
                    .iter()
                    .filter(|o| {
                        o.location == file
                            && (o.line, o.offset) > from
                            && (o.line, o.offset) < to
                            && (o.context.contains(": setup, not a use")
                                || o.context.contains("] [component]"))
                            && self.graph.primitive.get(&o.component_ref) == Some(prim)
                    })
                    .collect();
                if !set_up.is_empty()
                    && !set_up.iter().any(|o| {
                        o.component_ref == component_ref
                            || self.refines(&o.component_ref, component_ref)
                    })
                {
                    let mut names: Vec<&str> =
                        set_up.iter().map(|o| o.component.as_str()).collect();
                    names.sort();
                    names.dedup();
                    return Err(format!(
                        "`{part}`: the call at {file}:{line}:{c0} sets up {}",
                        names.join(", ")
                    ));
                }
            }
            // as the compiler records the step: its code at the position, in the caller
            if let (Some(via), Some(c), Some(c0)) = (&via, &caller, col) {
                self.check_via(
                    whole,
                    via,
                    c,
                    (&file, &path, line, c0),
                    (&inner.0, inner.1, inner.2),
                )?;
                callee = Some(c.clone());
                inner = (path.clone(), line, col);
                continue;
            }
            // (a step with a position says what the compiler records there)
            return Err(format!(
                "`{whole}`: the step does not say what the compiler records at its position"
            ));
        }
        match unchosen {
            Some(e) if !chosen_by_one => Err(e),
            _ => Ok(()),
        }
    }
}
/// Whether two instance names are of one item of the source: one path once their generic
/// arguments are dropped. The by-move body the compiler makes of an `async` closure's body
/// (`f::{closure#0}::{synthetic#0}`) is that body (`f::{closure#0}::{closure#0}`).
fn same_item(a: &str, b: &str) -> bool {
    let bare = |x: &str| {
        re!(r"\{synthetic#\d+\}")
            .replace_all(&strip_generics(x).replace("::::", "::"), "{closure#0}")
            .trim()
            .trim_end_matches("::")
            .to_string()
    };
    // (a trait's default method run for a type, `<A as Pick>::alg`, is the trait's `Pick::alg`;
    // and so are the closures and `async` bodies written in it, `..::alg::{closure#0}`, by the
    // same indexes)
    let closures = |x: &str| {
        let x = bare(x);
        let k = re!(r"(?:::\{closure#\d+\})+$")
            .find(&x)
            .map_or(x.len(), |m| m.start());
        x[k..].to_string()
    };
    let default_of = |x: &str, y: &str| {
        let (cx, cy) = (closures(x), closures(y));
        let y = bare(y);
        let head = &y[..y.len() - cy.len()];
        let mut segs = head.rsplit("::");
        let (name, owner) = (segs.next(), segs.next());
        cx == cy
            && in_item(x).is_some_and(|n| {
                Some(n.name.as_str()) == name
                    && n.trait_name.as_deref().map(type_name).as_deref() == owner
            })
    };
    bare(a) == bare(b) || default_of(a, b) || default_of(b, a)
}

/// Whether an asset's name is one a knowledge-base entry's name gives: its parameters (`{hash}`)
/// stand for any text, its optional parts (`[..]`) may be absent (`HMAC-{hash}`: `HMAC-SHA-256`).
fn fits_template(template: &str, asset: &str) -> bool {
    let mut re = String::from("^");
    let mut chars = template.chars();
    while let Some(ch) = chars.next() {
        match ch {
            '{' => {
                chars.by_ref().take_while(|x| *x != '}').for_each(drop);
                re.push_str(".+?");
            }
            '[' => re.push_str("(?:"),
            ']' => re.push_str(")?"),
            _ => re.push_str(&regex::escape(&ch.to_string())),
        }
    }
    re.push('$');
    Regex::new(&re).is_ok_and(|r| r.is_match(asset))
}

/// The calls of a method `name` next to the one at `i` in its chain: the one its receiver ends
/// with, the one made on its result (`a.name()\n.name()\n.name()`), as (line, column) of their
/// names.
fn chain_neighbours(src: &Source, i: usize, name: &str) -> Vec<(usize, usize)> {
    let s = &src.code;
    let mut out = Vec::new();
    if word_of(s, i) != name || before_blank(s, i).is_none_or(|d| s[d] != '.') {
        return out;
    }
    // after: `name(..)` then `.name(`
    let open = skip_blank(s, i + name.chars().count());
    if s.get(open) == Some(&'(')
        && let Some(close) = close_of_at(s, open)
    {
        let dot = skip_blank(s, close + 1);
        let k = skip_blank(s, dot + 1);
        if s.get(dot) == Some(&'.')
            && word_of(s, k) == name
            && s.get(skip_blank(s, k + name.chars().count())) == Some(&'(')
        {
            out.push(src.pos(k));
        }
    }
    // before: `.name(..)` ending the receiver
    if let Some(dot) = before_blank(s, i)
        && let Some(close) = before_blank(s, dot).filter(|&p| s[p] == ')')
        && let Some(open) = open_of_at(s, close)
        && let Some((wb, w)) = callee_before(s, open)
        && w == name
        && before_blank(s, wb).is_some_and(|d| s[d] == '.')
    {
        out.push(src.pos(wb));
    }
    out
}

/// The operator a method of an operator trait is written as (`<P as core::ops::arith::Mul<S>>::
/// mul`: `*`; `core::ops::try_trait::FromResidual::from_residual`: `?`), for a symbol naming one.
pub(super) fn operator_of(symbol: &str) -> Option<&'static str> {
    // (`.await` polls its operand, made a future first: `Future::poll`,
    // `IntoFuture::into_future`)
    if re!(r"core::future::(?:future::Future\b.*::poll|into_future::IntoFuture\b.*::into_future)$")
        .is_match(symbol)
    {
        return Some("await");
    }
    // (`x[i]` indexes: `Index::index`, `IndexMut::index_mut`, at the bracket)
    if re!(r"core::ops::index::(?:Index\b.*::index|IndexMut\b.*::index_mut)$").is_match(symbol) {
        return Some("[");
    }
    // (`?` branches on its operand and converts the error it returns: `Try::branch`,
    // `FromResidual::from_residual`)
    if re!(r"core::ops::try_trait::(?:Try\b.*::branch|FromResidual\b.*::from_residual)$")
        .is_match(symbol)
    {
        return Some("?");
    }
    let m = re!(
        r"core::ops::(?:arith::|bit::)?(Add|Sub|Mul|Div|Rem|BitAnd|BitOr|BitXor|Shl|Shr|Neg|Not)(Assign)?\b"
    )
    .captures(symbol)?;
    let method = symbol.rsplit("::").next().unwrap_or("");
    let want = format!(
        "{}{}",
        m[1].to_ascii_lowercase(),
        if m.get(2).is_some() { "_assign" } else { "" }
    );
    if method != want {
        return None;
    }
    let op = match &m[1] {
        "Add" => "+",
        "Sub" | "Neg" => "-",
        "Mul" => "*",
        "Div" => "/",
        "Rem" => "%",
        "BitAnd" => "&",
        "BitOr" => "|",
        "BitXor" => "^",
        "Shl" => "<<",
        "Shr" => ">>",
        _ => "!",
    };
    Some(match (op, m.get(2).is_some()) {
        (o, false) => o,
        ("+", true) => "+=",
        ("-", true) => "-=",
        ("*", true) => "*=",
        ("/", true) => "/=",
        ("%", true) => "%=",
        ("&", true) => "&=",
        ("|", true) => "|=",
        ("^", true) => "^=",
        ("<<", true) => "<<=",
        (_, true) => ">>=",
    })
}
