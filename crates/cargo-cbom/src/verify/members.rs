//! Members reaching a call from another function: witnesses, foreign parameters, coercions, static tables.

use super::*;

impl Files<'_> {
    /// The constants of other files and packages of the build `r` reads (`algs::CHOSEN`, `use
    /// picklib::CALG as X`, `picklib::SHALLOW` re-exporting `inner::DEEP`): found by the module
    /// path the code writes (from the module of the file `path`, or another package's root), what
    /// their initializers name (the field read, where one is) is read into `r`, and what those
    /// name in turn, from their own module. One not found in a package of the build makes the
    /// code name nothing there; `r.foreign` stays only for one of a crate whose sources are not
    /// at hand. Where the modules are not known (no `cargo metadata`), by name in the package.
    pub(super) fn resolve_foreign(&mut self, path: &Path, r: &mut Reads) {
        let items = std::mem::take(&mut r.foreign_items);
        let own = self.man.owner_of(path).map(|p| p.manifest_dir.clone());
        let here = self
            .module_chains(path, 0)
            .and_then(|c| c.into_iter().next());
        // (package dir, module where it is written, prefix, item, field)
        let mut pending: Vec<Pending> = Vec::new();
        let mut unresolved = false;
        for (prefix, item, field) in items {
            match &own {
                Some(d) => pending.push((d.clone(), here.clone(), prefix, item, field)),
                None => unresolved = true,
            }
        }
        let mut done = Vec::new();
        while let Some(key) = pending.pop() {
            if done.contains(&key) || done.len() > 32 {
                continue;
            }
            done.push(key.clone());
            let (dir, here, prefix, item, field) = key;
            // where it is: by module path, else (modules not known) by name in the package
            let mut spots: Vec<Spot> = Vec::new();
            let mut local = true;
            let by_module = here.as_ref().and_then(|h| {
                let (d2, m2) = self.module_of(&dir, h, &prefix)?;
                local = self
                    .man
                    .packages
                    .iter()
                    .find(|p| p.manifest_dir == d2)
                    .is_some_and(|p| p.local);
                let mut found = self.find_item(&d2, &m2, &item, 4)?;
                // (`a::X` with no child module `a`: a path from the root, 2015 style)
                if found.is_empty()
                    && prefix
                        .first()
                        .is_some_and(|f| !matches!(f.as_str(), "crate" | "self" | "super"))
                {
                    found = self.find_item(&d2, &prefix, &item, 4).unwrap_or_default();
                }
                Some(found)
            });
            match by_module {
                Some(found) => spots.extend(found.into_iter().map(|(f, sp, m)| (f, sp, Some(m)))),
                None => {
                    // the package the path names, else the file's own
                    let named = prefix.first().and_then(|first| {
                        let first = renamed_dep(&dir, first).unwrap_or_else(|| first.clone());
                        self.man
                            .packages
                            .iter()
                            .find(|p| {
                                p.lib_name.as_deref() == Some(first.as_str())
                                    || p.name.replace('-', "_") == first
                            })
                            .map(|p| (p.manifest_dir.clone(), p.local))
                    });
                    let (d2, l2) = named.unwrap_or((dir.clone(), true));
                    local = l2;
                    for f in package_files(&d2) {
                        let Some(src) = self.source(&f) else { continue };
                        for it in src
                            .items
                            .iter()
                            .filter(|it| it.kind == ItemKind::Static && it.name == item)
                        {
                            spots.push((f.clone(), src.span(it), None));
                        }
                    }
                }
            }
            if spots.is_empty() {
                // a package of the build whose sources are at hand: nothing of that name there
                unresolved |= !local;
                continue;
            }
            for (f, sp, m) in spots {
                let Some(src) = self.source(&f) else { continue };
                let mut sub = Reads::default();
                let parts = field
                    .as_deref()
                    .map(|fd| {
                        project(
                            &src,
                            sp.0,
                            sp.1,
                            &fd.split('.').collect::<Vec<_>>(),
                            8,
                            &mut sub.names,
                        )
                    })
                    .unwrap_or(vec![sp]);
                for (x, y) in parts {
                    names_read(&src, self.kb, x, y, 3, &mut HashSet::new(), &mut sub, false);
                }
                r.names.extend(sub.names);
                r.types.extend(sub.types);
                r.replaced |= sub.replaced;
                // what that initializer names in turn, from its own module
                let d3 = self
                    .man
                    .owner_of(&f)
                    .map(|p| p.manifest_dir.clone())
                    .unwrap_or_else(|| dir.clone());
                for (pre, it, fd) in sub.foreign_items {
                    pending.push((d3.clone(), m.clone(), pre, it, fd));
                }
            }
        }
        // (`names_read` marks every such constant; what is left is what was not found)
        r.foreign = unresolved;
    }

    /// The associated items `r` reads of an instance's types (`Reads::assoc`, `T::ALG` in
    /// `hash_c::<CFast>`): what the type's impl gives them (`impl HasConst for CFast { const ALG:
    /// .. = &SHA512; }`), in the package its path names or the file's, else the trait's default
    /// (a const of that name in a trait); neither found: a value from elsewhere (`foreign`).
    pub(super) fn resolve_assoc(&mut self, path: &Path, r: &mut Reads) {
        let items = std::mem::take(&mut r.assoc);
        for (ty, name) in items {
            let krate = ty
                .trim_start_matches(['&', '<'])
                .split("::")
                .next()
                .unwrap_or("")
                .trim()
                .to_string();
            let tname = type_name(&ty);
            let mut dirs: Vec<PathBuf> = Vec::new();
            if let Some(p) = self.man.packages.iter().find(|p| {
                p.lib_name.as_deref() == Some(krate.as_str()) || p.name.replace('-', "_") == krate
            }) {
                dirs.push(p.manifest_dir.clone());
            }
            if let Some(p) = self.man.owner_of(path)
                && !dirs.contains(&p.manifest_dir)
            {
                dirs.push(p.manifest_dir.clone());
            }
            let files: Vec<PathBuf> = dirs.iter().flat_map(|d| package_files(d)).collect();
            let mut found = false;
            for in_trait in [false, true] {
                for f in &files {
                    let Some(src2) = self.source(f) else { continue };
                    for it in src2.items.iter().filter(|it| {
                        it.kind == ItemKind::Static
                            && it.name == name
                            && src2.items.iter().any(|b| {
                                b.contains(it.start)
                                    && b.start != it.start
                                    && if in_trait {
                                        b.kind == ItemKind::Trait
                                    } else {
                                        b.kind == ItemKind::Impl && b.name == tname
                                    }
                            })
                    }) {
                        found = true;
                        let (a, b) = src2.span(it);
                        let mut sub = Reads::default();
                        names_read(
                            &src2,
                            self.kb,
                            a,
                            b,
                            3,
                            &mut HashSet::new(),
                            &mut sub,
                            false,
                        );
                        r.names.extend(sub.names);
                        r.types.extend(sub.types);
                    }
                }
                if found {
                    break;
                }
            }
            r.foreign |= !found;
        }
    }

    /// A member said to reach the call at `at` from another function (any label but a table's
    /// or a static's, which `check_table` reads): when the argument carrying the algorithm holds
    /// no value from elsewhere (a parameter, a constant of a crate not at hand, a variable a swap
    /// may change, a static the program may change), it does not name only other descriptors of
    /// the asset's primitive, or a type the knowledge base gives one (`digest(b2.alg)` with `b2 =
    /// B { alg: &SHA256 }` and nothing storing into it is no SHA-384). `join`: a `type-join` or
    /// `impl` member, any value of a field's type, is not checked at a call reading a field.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn check_elsewhere(
        &mut self,
        src: &Source,
        path: &Path,
        at: (usize, usize),
        members: &[&str],
        component_ref: &str,
        (exact, smashed): (bool, bool),
        join: bool,
    ) -> Result<(), String> {
        let Some(mut r) = call_reads(
            src,
            self.kb,
            src.idx(at),
            (exact, smashed),
            &self.inst,
            self.alg_arg,
        ) else {
            return Ok(());
        };
        if join && r.fields {
            return Ok(());
        }
        self.resolve_foreign(path, &mut r);
        self.resolve_assoc(path, &mut r);
        let lasts: Vec<&str> = members
            .iter()
            .map(|d| d.rsplit("::").next().unwrap_or(d))
            .collect();
        if r.open || r.foreign || r.replaced || r.lent || lasts.iter().any(|l| r.names.contains(*l))
        {
            return Ok(());
        }
        // a static the program may change at run time (`static mut`, a lock, a cell): a value
        // from elsewhere
        let changed = src.items.iter().any(|it| {
            it.kind == ItemKind::Static && r.names.contains(&it.name) && {
                let (a, b) = src.span(it);
                let head = src.text(a, scan_to(&src.code, a, b, |k| src.code[k] == '='));
                re!(r"^static\s+mut\b|\b(?:RwLock|Mutex|OnceLock|OnceCell|Cell|RefCell|UnsafeCell|ArcSwap\w*|Atomic\w*)\b")
                    .is_match(head.trim_start())
            }
        });
        if changed {
            return Ok(());
        }
        let prim = self.graph.primitive.get(component_ref);
        // other descriptors of its primitive, or a type of the build's crates the knowledge
        // base gives one (`kp.sign(..)` with `kp` an `Ed25519KeyPair` is no ECDSA)
        let others: Vec<&String> = r
            .names
            .iter()
            .filter(|w| {
                self.kb
                    .statics
                    .iter()
                    .any(|e| e.pattern.is_match(w) && Some(&e.algo.primitive) == prim)
            })
            .chain(r.types.iter().filter(|w| {
                self.kb.types.iter().any(|e| {
                    e.name == **w
                        && Some(&e.algo.primitive) == prim
                        && self.libs.as_ref().is_some_and(|l| l.contains_key(&e.krate))
                })
            }))
            .collect();
        if others.is_empty() {
            return Ok(());
        }
        Err(format!(
            "the code the call reads names {}, not {}",
            others
                .iter()
                .map(|w| w.as_str())
                .collect::<Vec<_>>()
                .join(", "),
            lasts.join(", ")
        ))
    }

    /// The witness `w` of a member `d` (`member: object, from `w``, `caller, passed by `w``,
    /// `impl, possible (what `w` writes)`, `type-join, possible (a value `w` stores ..)`) is a
    /// function of the build's sources (of the package its path names) that can give it: its
    /// body names `d`, or reads its parameters (a value it passes on or keeps), and, for one
    /// returning or writing it, does not replace on every way what it writes with other
    /// descriptors only. Witnesses that are no function (a static's initializer, a constant
    /// expression, an element write, `vec![..]`, the standard library's) are not checked here.
    /// A member of a boundary model (`algorithm one of 12 .. from `Header.alg` (object: from
    /// `F`)`; the key's family (Hmac) allows these`): the call is one the knowledge base models,
    /// whose algorithm is the field cited; the asset is a variant of the model's enum, of a key
    /// family the detail lists; and where the code says it comes from (the function the label
    /// cites, the static of a table, or else the code the call reads) can give that variant:
    /// names it, or passes on a value from elsewhere, and names no other variant only.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn check_model(
        &mut self,
        src: &Source,
        path: &Path,
        o: &Occ,
        (adt, field): (&str, &str),
        witness: Option<(&str, &str)>,
        families: Option<&[String]>,
        (call_at, beside): (Option<(usize, usize)>, bool),
    ) -> Result<(), String> {
        let kb = self.kb;
        let sym = strip_generics(&o.symbol);
        let (krate, rest) = sym.split_once("::").unwrap_or((&sym, ""));
        let Some(b) = kb
            .boundaries
            .iter()
            .find(|b| b.krate == krate && b.pattern.is_match(rest))
        else {
            return Err(format!(
                "`{}` is no call the knowledge base models",
                o.symbol
            ));
        };
        if b.algorithm.adt.as_deref().is_some_and(|a| a != adt)
            || b.algorithm.field.as_deref().is_some_and(|f| f != field)
        {
            return Err(format!(
                "`{}` takes its algorithm from {}, not `{adt}.{field}`",
                o.symbol,
                match (&b.algorithm.adt, &b.algorithm.field) {
                    (Some(a), Some(f)) => format!("`{a}.{f}`"),
                    _ => format!("argument {}", b.algorithm.arg),
                }
            ));
        }
        let Some(e) = kb
            .enums
            .iter()
            .find(|e| e.krate == b.krate && e.name == b.enumeration)
        else {
            return Err(format!("no enum `{}` in the knowledge base", b.enumeration));
        };
        let variants: Vec<&String> = e
            .variants
            .iter()
            .filter(|(_, v)| v.algo.asset == o.component)
            .filter(|(_, v)| {
                families.is_none_or(|fs| v.key.as_ref().is_none_or(|k| fs.contains(k)))
            })
            .map(|(n, _)| n)
            .collect();
        let Some(v) = variants.first() else {
            return Err(format!(
                "{} is no variant of `{}`{}",
                o.component,
                e.name,
                families.map_or(String::new(), |fs| format!(
                    " for a key of family {}",
                    fs.join(", ")
                ))
            ));
        };
        let d = format!("{}::{}::{v}", e.krate, e.name);
        let rivals: Vec<String> = e
            .variants
            .keys()
            .filter(|n| !variants.contains(n))
            .cloned()
            .collect();
        match witness {
            Some(("table: stored by", t)) => self.check_table(src, path, t, &d, call_at),
            Some((kind, w)) => {
                let kind = match kind {
                    "object: from" => "object, from",
                    "type-join: a value" => "type-join, possible (a value",
                    // a value a function passes, or puts in the list
                    _ => "caller, passed by",
                };
                self.check_witness_of(path, kind, w, &d, &o.component_ref, beside, &rivals)
            }
            // (named in the code the call reads)
            None => match call_at {
                Some(at) => {
                    self.check_args(src, path, at, &[&d], &o.component_ref, None, (false, false))
                }
                None => Ok(()),
            },
        }
    }

    /// A call that is an operation, whose algorithm may be unknown: one the knowledge base
    /// lists (`[[operation]]`, `[[boundary]]`), any call but a setup (`new`, `from_der`: its
    /// `[unmodelled]` names) into a crypto package it does not model, or a use (a method of
    /// `[[use]]`) of an algorithm crate's API it does not name, or of an algorithm or trait crate
    /// at a version it does not cover (password-hash 0.6).
    pub(super) fn is_operation(&self, symbol: &str) -> bool {
        let sym = strip_generics(symbol);
        let Some((krate, rest)) = sym.split_once("::") else {
            return false;
        };
        let kb = self.kb;
        if kb.operation(krate, rest).is_some()
            || kb
                .boundaries
                .iter()
                .any(|b| b.krate == krate && b.pattern.is_match(rest))
        {
            return true;
        }
        let method = rest.rsplit("::").next().unwrap_or(rest);
        let named_use = kb
            .uses
            .iter()
            .any(|u| u.methods.iter().any(|m| m == method));
        let pkgs: Vec<_> = self
            .man
            .packages
            .iter()
            .filter(|p| p.lib_name.as_deref() == Some(krate) && !p.local)
            .collect();
        let open = pkgs
            .iter()
            .any(|p| p.unmodelled == Some(rcbom_kb::Unmodelled::Crypto));
        let modelled = pkgs.iter().any(|p| {
            matches!(
                p.role,
                Some(rcbom_kb::Role::Algorithm | rcbom_kb::Role::Trait)
            )
        });
        (open && (named_use || !kb.unmodelled_setup(method))) || (modelled && named_use)
    }

    pub(super) fn check_witness(
        &mut self,
        path: &Path,
        kind: &str,
        w: &str,
        d: &str,
        component_ref: &str,
        beside: bool,
    ) -> Result<(), String> {
        self.check_witness_of(path, kind, w, d, component_ref, beside, &[])
    }

    /// `check_witness`, where the names in `rivals` (the other variants of a model's enum) are
    /// other values of the primitive too.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn check_witness_of(
        &mut self,
        path: &Path,
        kind: &str,
        w: &str,
        d: &str,
        component_ref: &str,
        beside: bool,
        rivals: &[String],
    ) -> Result<(), String> {
        // (an instance's name printed with an empty turbofish, `m1::gen_set::`: its function;
        // a trait's method of a type printed as `a::Tr::m for a::T`: `<a::T as a::Tr>::m`)
        let w = w.trim_end_matches("::");
        let w = match re!(r"^(.+)::(\w+) for (.+)$").captures(w) {
            Some(m) => format!("<{} as {}>::{}", &m[3], &m[1], &m[2]),
            None => w.to_string(),
        };
        let w = w.as_str();
        // (what the compiler or a macro makes, `t::TA::__rust_std_internal_init_fn`, is not
        // written in the source)
        if !w.contains("::")
            || w.contains('{')
            || w.split("::").any(|g| g.starts_with("__"))
            || re!(r"^(?:static |const |core::|std::|alloc::|<core::|<std::|<alloc::)").is_match(w)
        {
            return Ok(());
        }
        let Some(n) = in_item(w) else {
            return Ok(());
        };
        // the packages its path names: its own, and the trait's for a default body
        // (`<app::Legacy as lib::Pick>::alg` runs `lib`'s)
        let mut krates = vec![
            w.trim_start_matches('<')
                .split("::")
                .next()
                .unwrap_or("")
                .to_string(),
        ];
        if let Some(m) = re!(r" as ([A-Za-z_]\w*)::").captures(w) {
            krates.push(m[1].to_string());
        }
        let dirs: Vec<PathBuf> = krates
            .iter()
            .filter_map(|k| {
                self.man
                    .packages
                    .iter()
                    .find(|p| {
                        p.lib_name.as_deref() == Some(k.as_str()) || p.name.replace('-', "_") == *k
                    })
                    .filter(|p| p.local)
                    .map(|p| p.manifest_dir.clone())
            })
            .collect();
        if dirs.is_empty() {
            return Ok(());
        }
        let _ = path;
        let last = d.rsplit("::").next().unwrap_or(d).to_string();
        let prim = self.graph.primitive.get(component_ref).cloned();
        let files: Vec<PathBuf> = dirs.iter().flat_map(|d| package_files(d)).collect();
        // `<T as Tr>::m` runs the trait's default body only where T's impl of Tr writes no `m`
        let overrides = match (n.self_ty.as_deref(), n.trait_name.as_deref()) {
            (Some(t), Some(tr)) => files.iter().any(|f| {
                self.source(f).is_some_and(|src| {
                    src.items.iter().any(|b| {
                        b.kind == ItemKind::Impl
                            && b.name == t
                            && b.trait_name
                                .as_deref()
                                .is_some_and(|bt| type_name(bt) == type_name(tr))
                            && src.items.iter().any(|g| {
                                g.kind == ItemKind::Fn
                                    && g.name == n.name
                                    && b.contains(g.start)
                                    && b.start != g.start
                            })
                    })
                })
            }),
            _ => false,
        };
        // (an impl's self type through the package's type aliases: `impl Put for &mut A` with
        // `type A = &'static Algorithm` is `<&mut &'static Algorithm as Put>`'s)
        let aliases: Vec<Rc<HashMap<String, Vec<String>>>> =
            dirs.iter().map(|d| self.package_aliases(d)).collect();
        let dealias = |t: &str| {
            let lookup = &mut |a: &str| {
                aliases
                    .iter()
                    .find_map(|m| m.get(a).cloned())
                    .unwrap_or_default()
            };
            type_name(&expand_aliases(&type_name(t), lookup, 3))
        };
        let mut found = false;
        for f in files {
            let Some(src) = self.source(&f) else { continue };
            let is_trait = |t: &str| {
                src.items
                    .iter()
                    .any(|i| i.kind == ItemKind::Trait && i.name == t)
            };
            let in_block = |kind: ItemKind, name: &str, tr: Option<&str>, f: &Item| {
                src.items.iter().any(|b| {
                    b.kind == kind
                        // (the impl's type written in full, with its references and type
                        // arguments, where it says more than its name: `impl Put for &mut A`
                        // is no `<&'static Algorithm as Put>`'s)
                        && (kind != ItemKind::Impl
                            || written_self(&src, b, n.self_full.as_deref(), &mut |a| {
                                aliases
                                    .iter()
                                    .find_map(|m| m.get(a).cloned())
                                    .unwrap_or_default()
                            })
                            .unwrap_or(true))
                        && (b.name == name
                            || impl_self(&src, b)
                                .and_then(|(t, _)| src.alias_at(src.idx(b.start), &t))
                                .map_or_else(|| dealias(&b.name), |d| type_name(&d))
                                == dealias(name))
                        && b.contains(f.start)
                        && b.start != f.start
                        && tr.is_none_or(|t| {
                            b.trait_name
                                .as_deref()
                                .is_some_and(|bt| type_name(bt) == type_name(t))
                        })
                })
            };
            let candidates: Vec<&Item> = src
                .items
                .iter()
                .filter(|f| f.kind == ItemKind::Fn && f.name == n.name)
                .filter(|f| match (n.self_ty.as_deref(), n.trait_name.as_deref()) {
                    // `<T as Tr>::m`: T's impl of Tr, else the trait's default body
                    (Some(t), Some(tr)) => {
                        in_block(ItemKind::Impl, t, Some(tr), f)
                            || (!overrides && in_block(ItemKind::Trait, &type_name(tr), None, f))
                    }
                    // a trait's method, or an inherent one
                    (Some(t), None) if is_trait(t) => in_block(ItemKind::Trait, t, None, f),
                    (Some(t), None) => in_block(ItemKind::Impl, t, None, f),
                    // a free function
                    (None, _) => !src.items.iter().any(|o| {
                        matches!(o.kind, ItemKind::Impl | ItemKind::Trait) && o.contains(f.start)
                    }),
                })
                .collect();
            for f in candidates {
                found = true;
                // (its body: not its own name, read as a call)
                let (a, b) = src.span(f);
                let a = scan_to(&src.code, a, b, |k| src.code[k] == '{');
                let mut r = Reads::default();
                names_read(&src, self.kb, a, b, 3, &mut HashSet::new(), &mut r, true);
                // (a model enum's variants are its values, not constants not read)
                let foreign = r.foreign
                    && (rivals.is_empty()
                        || r.foreign_items
                            .iter()
                            .any(|k| k.1 != last && !rivals.contains(&k.1)));
                if r.names.contains(&last) || foreign {
                    return Ok(());
                }
                let others = r.names.iter().any(|x| {
                    rivals.contains(x)
                        || self.kb.statics.iter().any(|e| {
                            e.pattern.is_match(x) && Some(&e.algo.primitive) == prim.as_ref()
                        })
                });
                // a parameter it reads that can hold the algorithm (not an integer, a string,
                // bytes): a value from its caller it passes on or keeps
                let sig = fn_sig(&src, f);
                let body = src.text(a, b);
                let carrying = r.open
                    && sig.params.iter().any(|(p, ty)| {
                        !neutral_type(ty)
                            && Regex::new(&format!(
                                r"\b{}\b",
                                regex::escape(p.trim_start_matches("mut ").trim())
                            ))
                            .is_ok_and(|x| x.is_match(&body))
                    });
                if !others {
                    // one that returns or writes the object: of a type that can hold it (not a
                    // `String` made of the arguments)
                    let gives = sig.ret.as_deref().is_some_and(|t| !neutral_type(t))
                        || sig.params.iter().any(|(p, ty)| {
                            (p == "self" || ty.contains("&mut")) && !neutral_type(ty)
                        });
                    if carrying
                        || r.lent
                        || ((kind == "object, from" || kind.starts_with("impl")) && gives)
                    {
                        return Ok(());
                    }
                    continue;
                }
                // it names other descriptors only: a writer keeping the value before on some way
                // (or, for a member beside others not followed, one writing the object at all)
                if kind == "object, from" || kind.starts_with("impl") {
                    let sc = src.fn_scope(f);
                    let replaced = sc
                        .params
                        .iter()
                        .any(|p| !body_assigns(&src, f, p, 3).is_empty());
                    // (or a value of the file's type holding a `&mut`: `fn wset(w: W)` with `W {
                    // slot: &mut D }`, writing the caller's variable through it)
                    let holder = |ty: &str| {
                        struct_fields(&src, &type_name(ty)).is_some_and(|(a, b)| {
                            re!(r"&\s*(?:'\w+\s+)?mut\b").is_match(&src.text(a, b))
                        })
                    };
                    let writes = sig.params.iter().any(|(p, ty)| {
                        (p == "self" || ty.contains("&mut") || holder(ty)) && !neutral_type(ty)
                    });
                    if (!replaced && carrying) || (beside && writes) {
                        return Ok(());
                    }
                }
            }
        }
        Err(if found {
            format!("`{w}` gives no `{last}`")
        } else {
            format!("no function `{w}` in its package")
        })
    }

    /// The type of parameter `idx` of the function `name` that a call in `src` names with the
    /// path `prefix` (`tlib::by_dyn`, or `by_dyn` imported from `tlib`), read from the sources
    /// of the package the path or the import leads to (the file's own for a `crate::` path).
    pub(super) fn foreign_param(
        &mut self,
        src: &Source,
        owner: Option<&rcbom_manifest::Pkg>,
        prefix: &[String],
        name: &str,
        idx: usize,
    ) -> Option<String> {
        let owner_id = owner.map(|p| p.id.repr.clone());
        let roots: Vec<String> = match prefix.first() {
            Some(f) if matches!(f.as_str(), "crate" | "self" | "super") => Vec::new(),
            Some(f) => import_roots(&src.binds, f)
                .map(|r| r.into_iter().collect())
                .unwrap_or_else(|| vec![f.clone()]),
            None => import_roots(&src.binds, name)?.into_iter().collect(),
        };
        let mut dirs: Vec<PathBuf> = Vec::new();
        for r in &roots {
            for p in self.crate_refs(owner_id.as_deref(), r) {
                if let Some(pkg) = self
                    .man
                    .packages
                    .iter()
                    .find(|k| pkg_ref(&k.name, &k.version.to_string()) == p)
                    && !dirs.contains(&pkg.manifest_dir)
                {
                    dirs.push(pkg.manifest_dir.clone());
                }
            }
        }
        if dirs.is_empty() {
            dirs.extend(owner.map(|p| p.manifest_dir.clone()));
        }
        for d in dirs {
            for f in package_files(&d) {
                let Some(s2) = self.source(&f) else { continue };
                for it in s2.items.iter().filter(|it| {
                    it.kind == ItemKind::Fn
                        && it.name == name
                        && !s2.items.iter().any(|o| {
                            matches!(o.kind, ItemKind::Impl | ItemKind::Trait)
                                && o.contains(it.start)
                        })
                }) {
                    if let Some(p) = fn_sig(&s2, it).params.get(idx) {
                        return Some(p.1.clone());
                    }
                }
            }
        }
        None
    }

    /// "dyn: `T` is coerced to `dyn Tr` at F:L" (or "in a static at F:L"): line L of F makes a
    /// `T` a pointer there that becomes a `dyn Tr` (or a trait object of a trait whose
    /// supertraits include `Tr`; `coercion_traits`): it names the type (`Box::new(Fast)`,
    /// `&Legacy`, `W::<A>(..)` with its type arguments, `3u8`), or a variable or parameter whose
    /// binding does (`&mut c4` with `let mut c4 = Ctx { .. }`, a parameter declared of the type or
    /// of a type parameter of its function).
    pub(super) fn check_coercions(&mut self, details: &str) -> Result<(), String> {
        for m in re!(
            r"dyn: `([^`]+)`(?:, the only type)? (?:is )?coerced to `([^`]+)` (in a static )?at ([^\s;)]+?):(\d+)\)"
        )
        .captures_iter(details)
        {
            let (ty, file, line) = (&m[1], &m[4], m[5].parse::<usize>().unwrap_or(0));
            let what = m[0].trim_end_matches(')');
            let want = type_name(m[2].trim().trim_start_matches("dyn ").trim());
            let path = self.resolve(file)?;
            let src = self
                .source(&path)
                .ok_or_else(|| format!("cannot read {file}, named in `{what}`"))?;
            // the traits whose objects are objects of `want` too (their supertraits include it)
            let supers = self.supertraits(&path, &m[2]);
            let fits = |ts: &[String]| {
                ts.iter().any(|t| {
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
            };
            let Some(text) = src.lines.get(line.wrapping_sub(1)) else {
                return Err(format!("`{what}`: no line {line} in {file}"));
            };
            // a static's value is "in a static", a function's or a const's not
            let in_static = src
                .enclosing((line, text.chars().count()), &[ItemKind::Static])
                .or_else(|| src.enclosing((line, 0), &[ItemKind::Static]))
                .is_some_and(|i| kw(&src.code, src.span(i).0, "static"));
            if in_static != m.get(3).is_some() {
                return Err(format!(
                    "`{what}`: line {line} of {file} is {}in a static",
                    if in_static { "" } else { "not " }
                ));
            }
            let code: String = text
                .chars()
                .zip(&src.class[line - 1])
                .map(|(c, k)| if *k == Class::Code { c } else { ' ' })
                .collect();
            let base = type_name(ty);
            // the type's arguments (`d3::W<d3::A>`: `A`)
            let args: Vec<String> = ty
                .find('<')
                .map(|i| {
                    let inner = &ty[i + 1..ty.len().saturating_sub(1)];
                    inner
                        .split(',')
                        .map(type_name)
                        .filter(|a| !a.is_empty() && a.chars().all(is_ident))
                        .collect()
                })
                .unwrap_or_default();
            let word = |w: &str| {
                Regex::new(&format!(r"\b{}\b", regex::escape(w))).is_ok_and(|r| r.is_match(&code))
            };
            const PRIMS: &[&str] = &[
                "u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32", "i64", "i128",
                "isize", "f32", "f64",
            ];
            let s = &src.code;
            let (l0, l1) = (src.idx((line, 0)), src.idx((line + 1, 0)));
            let dyn_here = word("dyn");
            // a value made a pointer at `i`: `&x`, `&mut x`, `Box::new(x`, `Rc::new(x`, or the
            // value of a statement with a `dyn` type (`let d: Box<dyn Tr> = b;`)
            let made_pointer = |i: usize| -> bool {
                let Some(p) = before_blank(s, i) else {
                    return false;
                };
                match s[p] {
                    '&' => true,
                    // `&*b`: what the box holds
                    '*' => before_blank(s, p).is_some_and(|q| s[q] == '&'),
                    '=' => dyn_here,
                    '(' => {
                        let w = word_before_at(s, p);
                        let start = before_blank(s, p).map_or(p, |e| e + 1 - w.len().min(e + 1));
                        let head = src.text(l0.min(start), start);
                        matches!(w.as_str(), "new" | "pin")
                            && re!(r"\b(?:Box|Rc|Arc)\s*::\s*$").is_match(head.trim_end())
                    }
                    c if is_ident(c) => {
                        word_before_at(s, i) == "mut"
                            && p >= 2
                            && before_blank(s, p - 2).is_some_and(|q| s[q] == '&')
                    }
                    _ => false,
                }
            };
            // where it is made a pointer, it becomes an object of the trait (`coercion_traits`;
            // another crate's function's parameter read from its sources)
            let man = self.man;
            let owner = man.owner_of(&path);
            let mut foreign = |prefix: &[String], name: &str, idx: usize| {
                self.foreign_param(&src, owner, prefix, name, idx)
            };
            let mut coerced =
                |i: usize| coercion_traits(&src, i, &mut foreign).is_some_and(|ts| fits(&ts));
            // its arguments are written on the line, or the line is in a generic function whose
            // instance gives them (`Box::new(W(t))` in `fn boxed<T: Pick>(t: T) -> Box<dyn Gen>`)
            let generic_at = |i: usize| {
                src.enclosing(src.pos(i), &[ItemKind::Fn]).is_some_and(|f| {
                    let (fa, fb) = src.span(f);
                    let open = scan_to(s, fa, fb, |k| s[k] == '(');
                    src.text(fa, open).contains('<')
                })
            };
            let args_written = args.iter().all(|a| word(a));
            // the type, with its arguments, made a pointer
            let names_type = ((l0..l1).any(|i| {
                kw(s, i, &base)
                    && (args_written || generic_at(i))
                    && made_pointer(i)
                    && coerced(i)
            }))
                || (PRIMS.contains(&base.as_str())
                    && (l0..l1).any(|i| {
                        s[i].is_ascii_digit()
                            && (i == 0 || !is_ident(s[i - 1]))
                            && word_of(s, i).ends_with(base.as_str())
                            && made_pointer(i)
                            && coerced(i)
                    }));
            if names_type {
                continue;
            }
            // a variable or parameter of the type, made a pointer there
            let ty_word = Regex::new(&format!(r"\b{}\b", regex::escape(&base))).ok();
            let via_var = (l0..l1).any(|i| {
                    if !word_start(s, i)
                        || before_blank(s, i).is_some_and(|p| s[p] == '.' || s[p] == ':')
                        || !made_pointer(i)
                        || !coerced(i)
                    {
                        return false;
                    }
                    let w = word_of(s, i);
                    if !w.chars().next().is_some_and(|c| c.is_lowercase() || c == '_')
                        || (is_keyword(&w) && w != "self")
                    {
                        return false;
                    }
                    // a field of `self` (`&self.t` in a method of `impl Own8`): its declared type
                    let after = skip_blank(s, i + w.chars().count());
                    if s.get(after) == Some(&'.') {
                        let fb = skip_blank(s, after + 1);
                        let field = word_of(s, fb);
                        let next = skip_blank(s, fb + field.chars().count());
                        if w != "self" || field.is_empty() || s.get(next) == Some(&'(') {
                            return false;
                        }
                        return src
                            .enclosing(src.pos(i), &[ItemKind::Fn])
                            .and_then(|f| impl_of(&src, f))
                            .and_then(|b| field_type(&src, &b.name, &field))
                            .is_some_and(|t| type_name(&deref_type(&t)) == base);
                    }
                    if w == "self" {
                        return false;
                    }
                    match binding(&src, i, &w) {
                        // (not one that is a trait object already: `let up: &dyn Super = s;`
                        // with `let s: &dyn Sub = &S1;` coerces no `S1`: its own annotation)
                        Some(Bound::Let {
                            init, first, last, at,
                        }) => {
                            let stmt: Vec<&str> =
                                (first..=last).map(|l| src.lines[l - 1].as_str()).collect();
                            let head = src.text(src.idx((first, 0)), at);
                            let own_dyn = Regex::new(&format!(
                                r"\blet\s+(?:mut\s+)?{}\b([^=]*)=\s*$",
                                regex::escape(&w)
                            ))
                            .ok()
                            .and_then(|r| r.captures(&head).map(|m| m[1].contains("dyn")))
                            .unwrap_or_else(|| stmt.iter().any(|l| re!(r"\bdyn\b").is_match(l)));
                            ty_word.as_ref().is_some_and(|r| {
                                r.is_match(&init) || stmt.iter().any(|l| r.is_match(l))
                            }) && !own_dyn
                        }
                        // a closure's parameter (`vec![T4].into_iter().map(|x| Box::new(x) as
                        // ..)`): the type named on the line before the closure
                        Some(Bound::ClosureParam) => ty_word
                            .as_ref()
                            .is_some_and(|r| r.is_match(&src.text(l0, i))),
                        // a parameter declared of the type, or of a type parameter of its
                        // function or impl block
                        Some(Bound::Param { .. }) => {
                            src.enclosing(src.pos(i), &[ItemKind::Fn]).is_some_and(|f| {
                                let sig = fn_sig(&src, f);
                                let impl_params = impl_of(&src, f)
                                    .map(|b| {
                                        let (ba, bb) = src.span(b);
                                        let h = src.text(
                                            ba,
                                            scan_to(&src.code, ba, bb, |k| src.code[k] == '{'),
                                        );
                                        h.trim_start()
                                            .strip_prefix("impl")
                                            .filter(|r| r.trim_start().starts_with('<'))
                                            .map(|r| r.to_string())
                                            .unwrap_or_default()
                                    })
                                    .unwrap_or_default();
                                sig.params.iter().any(|(p, t)| {
                                    p.trim_start_matches("mut ").trim() == w && {
                                        let tn = type_name(&deref_type(t));
                                        tn == base
                                            || sig.generics.contains(&tn)
                                            || t.trim_start_matches('&').trim().starts_with("impl ")
                                            || re!(r"[<,]\s*(\w+)\s*[:,>]")
                                                .captures_iter(&impl_params)
                                                .any(|x| x[1] == tn)
                                    }
                                })
                            })
                        }
                        _ => false,
                    }
                });
            if !via_var {
                return Err(format!(
                    "`{what}`: line {line} of {file} makes no `{ty}` a pointer to a trait object"
                ));
            }
        }
        Ok(())
    }

    /// "one of the N in `TABLE`, ..: X": a static or const `TABLE` of the package holds X (in
    /// its initializer, or in a static or const it names). At a call (`at`) whose code reads no
    /// value from elsewhere, that code reads `TABLE` and, through the field it reads of it
    /// (`TABLE[i].legacy`), X.
    pub(super) fn check_table(
        &mut self,
        src: &Source,
        path: &Path,
        table: &str,
        d: &str,
        at: Option<(usize, usize)>,
    ) -> Result<(), String> {
        let name = table.rsplit("::").next().unwrap_or(table);
        let last = d.rsplit("::").next().unwrap_or(d).to_string();
        // (at a call whose code reads no value from elsewhere, that code reads the static and,
        // through the field it reads of it, the descriptor)
        let tie = |this: &mut Self| -> Result<(), String> {
            if let Some(at) = at
                && let Some(mut r) = call_reads(
                    src,
                    this.kb,
                    src.idx(at),
                    (false, false),
                    &this.inst,
                    this.alg_arg,
                )
            {
                this.resolve_foreign(path, &mut r);
                this.resolve_assoc(path, &mut r);
                if !r.open && !r.foreign {
                    if !r.names.contains(name) {
                        return Err(format!("the call reads no `{table}`"));
                    }
                    if !last.is_empty() && !r.names.contains(&last) {
                        return Err(format!(
                            "what the call reads of `{table}` names no `{last}`"
                        ));
                    }
                }
            }
            Ok(())
        };
        let mut files: Vec<PathBuf> = vec![path.to_path_buf()];
        let own = self.man.owner_of(path);
        if let Some(p) = own {
            files.extend(package_files(&p.manifest_dir));
        }
        // a static of another package of the build (`dep::N1`): that package's files; of a
        // crate whose sources are not at hand, not checked
        let krate = table.split("::").next().unwrap_or("");
        if table.contains("::") && own.is_none_or(|p| p.name.replace('-', "_") != krate) {
            match self
                .man
                .packages
                .iter()
                .find(|p| p.name.replace('-', "_") == krate)
            {
                Some(p) => files.extend(package_files(&p.manifest_dir)),
                None => return Ok(()),
            }
        }
        let mut found = false;
        files.dedup();
        for f in files {
            let owned;
            let src2: &Source = if f == path {
                src
            } else {
                match self.source(&f) {
                    Some(s) => {
                        owned = s;
                        &owned
                    }
                    None => continue,
                }
            };
            for it in src2
                .items
                .iter()
                .filter(|i| i.kind == ItemKind::Static && i.name == name)
            {
                found = true;
                let (a, b) = src2.span(it);
                let mut r = Reads::default();
                names_read(src2, self.kb, a, b, 3, &mut HashSet::new(), &mut r, false);
                if last.is_empty() || r.names.contains(&last) {
                    return tie(self);
                }
            }
        }
        Err(if found {
            format!("`{table}` holds no `{last}`")
        } else {
            format!("no static or const `{name}` in the package")
        })
    }
}
