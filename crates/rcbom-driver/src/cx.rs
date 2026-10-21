//! The crate sets the CLI passes, and the shared state of one crate's analysis (`Cx`).

use super::*;

impl CrateSet {
    pub(super) fn from_env(name: &str) -> CrateSet {
        let mut m: HashMap<String, Vec<std::path::PathBuf>> = HashMap::new();
        for e in std::env::var(name).unwrap_or_default().split('\n') {
            if e.is_empty() {
                continue;
            }
            let (n, dir) = match e.split_once('=') {
                Some((n, d)) => (n, Some(std::path::PathBuf::from(d))),
                None => (e, None),
            };
            let dirs = m.entry(n.replace('-', "_")).or_default();
            dirs.extend(dir);
        }
        CrateSet(m)
    }

    /// Does crate `name`, whose root source file is `root`, belong to the set? Under
    /// `--remap-path-prefix` a dependency's root is its remapped name (`/registry/md-5-0.10.6/
    /// src/lib.rs`): the package directory's own name (`md-5-0.10.6`) still tells it apart.
    pub(super) fn contains(
        &self,
        name: &str,
        root: impl FnOnce() -> Option<std::path::PathBuf>,
    ) -> bool {
        match self.0.get(name) {
            None => false,
            Some(dirs) if dirs.is_empty() => true,
            Some(dirs) => root().is_some_and(|r| {
                dirs.iter().any(|d| {
                    r.starts_with(d)
                        || d.file_name()
                            .is_some_and(|n| r.components().any(|c| c.as_os_str() == n))
                })
            }),
        }
    }
}
/// The crates of the program's own packages: those whose root file belongs to a workspace
/// member or path dependency (`RCBOM_LOCAL_DIRS`, their directories, one per line).
pub(super) fn local_crates(
    tcx: TyCtxt<'_>,
) -> (HashSet<rustc_span::def_id::CrateNum>, HashSet<String>) {
    let dirs: Vec<PathBuf> = std::env::var("RCBOM_LOCAL_DIRS")
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.is_empty())
        .map(PathBuf::from)
        .collect();
    let cwd = std::env::current_dir().unwrap_or_default();
    let sm = tcx.sess.source_map();
    let mut nums = HashSet::new();
    let mut ids = HashSet::new();
    for c in tcx
        .crates(())
        .iter()
        .copied()
        .chain([rustc_span::def_id::LOCAL_CRATE])
    {
        let root = sm
            .span_to_filename(tcx.def_span(c.as_def_id()))
            .prefer_local_unconditionally()
            .to_string();
        let root = cwd.join(root);
        // the package the root file belongs to: the nearest directory above it with a
        // `Cargo.toml` (a crate vendored under the project, or a `CARGO_HOME` inside it, has its
        // own)
        let pkg = root
            .ancestors()
            .skip(1)
            .find(|d| d.join("Cargo.toml").is_file());
        if pkg.is_some_and(|p| dirs.iter().any(|d| d == p)) {
            nums.insert(c);
            ids.insert(format!("{:016x}", tcx.stable_crate_id(c).as_u64()));
        }
    }
    (nums, ids)
}
impl Cx<'_> {
    /// The root source file of a crate (`…/md-5-0.10.6/src/lib.rs`), or its remapped name.
    pub(super) fn crate_root(&self, c: rustc_span::def_id::CrateNum) -> Option<std::path::PathBuf> {
        self.crate_roots
            .borrow_mut()
            .entry(c)
            .or_insert_with(|| {
                let span = self.tcx.def_span(c.as_def_id());
                let name = self.tcx.sess.source_map().span_to_filename(span);
                matches!(name, rustc_span::FileName::Real(_)).then(|| {
                    let cwd = std::env::current_dir().unwrap_or_default();
                    cwd.join(name.prefer_local_unconditionally().to_string())
                })
            })
            .clone()
    }

    pub(super) fn in_set(&self, set: &CrateSet, c: rustc_span::def_id::CrateNum) -> bool {
        !self.local.contains(&c)
            && set.contains(self.tcx.crate_name(c).as_str(), || self.crate_root(c))
    }

    /// Is this crate one the knowledge base describes?
    pub(crate) fn kb_crate(&self, c: rustc_span::def_id::CrateNum) -> bool {
        self.in_set(&self.kb_crates, c)
    }

    /// The same for a crate as the facts name it.
    pub(super) fn kb_ref(&self, k: &rcbom_facts::CrateRef) -> bool {
        if self.local_ids.contains(&k.stable_id) {
            return false;
        }
        let by_id = self.by_stable_id.get_or_init(|| {
            self.tcx
                .crates(())
                .iter()
                .chain(std::iter::once(&rustc_span::def_id::LOCAL_CRATE))
                .map(|&c| (format!("{:016x}", self.tcx.stable_crate_id(c).as_u64()), c))
                .collect()
        });
        match by_id.get(&k.stable_id) {
            Some(&c) => self.kb_crate(c),
            None => self.kb_crates.contains(&k.name, || None),
        }
    }

    /// Is this crate one of the program's own (a workspace member, a path dependency)?
    pub(crate) fn is_program(&self, c: rustc_span::def_id::CrateNum) -> bool {
        self.local.contains(&c)
    }

    /// Is this crate one whose code the walk does not enter (an algorithm implementation)?
    pub(crate) fn stop_crate(&self, c: rustc_span::def_id::CrateNum) -> bool {
        self.in_set(&self.stop_crates, c)
    }

    /// Is this crate a dependency of a stop crate (`RCBOM_IMPL_CRATES`): part of how an
    /// algorithm is implemented, when a stop crate calls into it?
    pub(super) fn impl_crate(&self, c: rustc_span::def_id::CrateNum) -> bool {
        self.in_set(&self.impl_crates, c)
    }

    /// A static is worth recording if it belongs to a KB crate, or its value points (through
    /// any depth of allocations) at a static that is.
    pub(crate) fn static_interesting(&mut self, did: rustc_span::def_id::DefId) -> bool {
        let key = def_hash(self.tcx, did);
        if let Some(v) = self.interesting_statics.get(&key) {
            return *v;
        }
        // A search through the statics the initializers point at. Only complete answers are
        // remembered: an answer computed while another static of the same cycle was still being
        // searched could miss what that one leads to.
        let tcx = self.tcx;
        let mut stack = vec![did];
        let mut seen = HashSet::from([did]);
        let mut found = false;
        while let Some(s) = stack.pop() {
            match self.interesting_statics.get(&def_hash(tcx, s)) {
                Some(true) => {
                    found = true;
                    break;
                }
                Some(false) => continue,
                None => {}
            }
            if self.kb_crate(s.krate) {
                found = true;
                break;
            }
            // an extern static (FFI) has no initializer to evaluate
            if tcx.is_foreign_item(s) {
                continue;
            }
            let next = catch_unwind(AssertUnwindSafe(|| {
                tcx.eval_static_initializer(s).ok().map(|a| {
                    let mut found = Vec::new();
                    for (_, prov) in a.inner().provenance().ptrs().iter() {
                        statics::statics_in(
                            tcx,
                            prov.alloc_id(),
                            &mut found,
                            &mut HashSet::new(),
                            0,
                        );
                    }
                    found
                })
            }))
            .ok()
            .flatten()
            .unwrap_or_default();
            for t in next {
                if seen.insert(t) {
                    stack.push(t);
                }
            }
        }
        self.interesting_statics.insert(key, found);
        found
    }

    pub(super) fn is_std(&self, krate: &str) -> bool {
        matches!(krate, "core" | "std" | "alloc")
    }
}
