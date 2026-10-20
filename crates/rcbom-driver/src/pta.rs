//! A points-to analysis over the walked instances' MIR: inclusion constraints (Andersen),
//! context-insensitive, field-sensitive by byte offset within each object, solved with the
//! `ascent` Datalog engine (docs: pta-design.md, local).
//!
//! - Objects are the locals of each walked instance, temporaries the translation makes,
//!   statics, constant memory, heap allocations (by call site), function items (for indirect
//!   calls) and `UNKNOWN`. A location is an object and a byte offset in it; pointers point to
//!   locations. Offsets come from the types' layouts, so a cast (a `Cell` to its value, a `Box`
//!   to its pointer) keeps the location. Elements of arrays, slices and heap buffers share the
//!   first element's offsets (one location per element field).
//! - A call to a walked instance binds the arguments to its parameters and its return value to
//!   the destination; a call through a pointer binds every function the pointer may point to;
//!   a `dyn` call binds the method of every type coerced to that trait in the walked code.
//! - A call into code that is not translated (no MIR, an extern, a stop crate, a body that did
//!   not translate) may write anything into every location reachable from its arguments: those
//!   objects are havocked (they may hold `UNKNOWN` anywhere), and its result is `UNKNOWN`.
//! - Queries are the arguments of calls into the stop crates (the knowledge base's): the
//!   statics each may point to, and whether it may be `UNKNOWN`.

// (fixed-seed hashing: the same input gives the same objects, merges and answers)
use rustc_data_structures::fx::{FxHashMap as HashMap, FxHashSet as HashSet};

use crate::pta_solve::Solver;
use rustc_middle::ty::TyCtxt;
use rustc_middle::ty::layout::{LayoutCx, LayoutOf};
use rustc_public::CrateDef;
use rustc_public::mir::mono::{Instance, InstanceKind};
use rustc_public::mir::{
    AggregateKind, BinOp, Body, CastKind, ConstOperand, NonDivergingIntrinsic, Operand, Place,
    PointerCoercion, ProjectionElem, Rvalue, StatementKind, TerminatorKind,
};
use rustc_public::rustc_internal;
use rustc_public::ty::RigidTy;

/// The object no analysis follows: what code not translated may have put somewhere.
pub(crate) const UNKNOWN: u32 = 0;

#[derive(Clone, Hash, PartialEq, Eq, Debug)]
enum Obj {
    Unknown,
    Local(u32, usize),
    Temp(u32, u32),
    Static(rustc_span::def_id::DefId),
    Mem(rustc_middle::mir::interpret::AllocId),
    Heap(u32, u32),
    Fn(u32),
    /// A vtable: index into `Pta::vt_list` (its methods by slot).
    VTable(u32),
    /// An instance-specific object (a local, temporary or heap object) in a context's copy of
    /// a library body.
    Ctx(u32, u32),
    /// The pointers exposed as integers (`p as usize`), which integers cast to pointers may
    /// be.
    Exposed,
}

#[derive(Clone)]
/// A call found in a body, bound when the analysis is solved (when it is known which callees
/// were translated and which types are coerced to which traits).
struct Call {
    callee: Callee,
    /// Each argument's location and size (`None`: nothing a pointer can be in).
    args: Vec<Option<(u32, u32, u32)>>,
    /// Where the result goes, and its size.
    dest: Option<(u32, u32, u32)>,
    /// The call's line, for diagnostics.
    line: u32,
}

#[derive(Clone)]
enum Callee {
    Inst(Instance),
    /// Through a function pointer or closure value held at this location.
    Ptr(u32, u32),
    /// A `dyn` method: the receiver's location (its vtable is 8 bytes on) and the slot.
    Virtual(u32, u32, usize),
}

/// A question asked at a call into a stop crate: what each argument may point to.
#[derive(Clone)]
pub(crate) struct Query {
    /// Where the call is, at its callee expression (as the walk's sites are placed).
    pub(crate) at: rcbom_facts::Loc,
    pub(crate) callee: String,
    /// The defining path of the function called (not of the instance it resolves to).
    pub(crate) callee_path: String,
    /// The instance whose body holds the call (its mangled name, as the walk's sites name
    /// their owner) and its item's def-path hash (as the per-item scan's do).
    pub(crate) owner: String,
    pub(crate) owner_def: String,
    pub(crate) args: Vec<Option<(u32, u32, u32)>>,
    /// Whether the copy holding the call is reached from the roots through bound calls (set
    /// when solved): an empty answer in a reached copy is a gap, in another dead code.
    pub(crate) live: bool,
    /// The copy holding the call (instance, context).
    copy: (u32, u32),
    /// The type each argument's first word points to, when it is a struct or enum: a static of
    /// another type is not an answer (merged objects mix what different types held).
    pointees: Vec<Option<rustc_span::def_id::DefId>>,
    /// Whether the argument is itself a pointer to that type (`&Algorithm`), not a value holding
    /// one (ring's `pbkdf2::Algorithm`, passed by value, points to an `hmac::Algorithm`).
    pub(crate) direct: Vec<bool>,
}

impl Query {
    /// The struct or enum argument `k` points to.
    pub(crate) fn pointee(&self, k: usize) -> Option<rustc_span::def_id::DefId> {
        self.pointees.get(k).copied().flatten()
    }
}

/// The constraints of one translated body, instantiated once (program code) or once per
/// calling context (library code) when the analysis is solved.
#[derive(Default)]
struct Template {
    addr: Vec<(u32, u32, u32, u32)>,
    copy: Vec<(u32, u32, u32, u32, u32)>,
    load: Vec<(u32, u32, u32, u32, u32, u32)>,
    store: Vec<(u32, u32, u32, u32, u32, u32)>,
    addr_deref: Vec<(u32, u32, u32, u32, u32)>,
    havoc_arg: Vec<(u32, u32, u32)>,
    havocked: Vec<(u32, u32, u32)>,
    calls: Vec<Call>,
    queries: Vec<Query>,
    slots: Vec<ParamSlot>,
    ret: u32,
    /// The standard library's (`core`, `alloc`, `std`): copied per calling context.
    lib: bool,
}

impl Template {
    fn havoc_call(&mut self, args: &[Option<(u32, u32, u32)>], dest: Option<(u32, u32, u32)>) {
        for (ao, aoff, asize) in args.iter().flatten() {
            self.havoc_arg.push((*ao, *aoff, *asize));
        }
        if let Some((d, doff, dsize)) = dest {
            self.havocked.push((d, doff, dsize));
        }
    }
}

/// What making copies of bodies gives besides constraints: the queries, the call graph between
/// copies (for liveness), the copy and call index of each call through a pointer or vtable (by
/// site), and the copies made.
#[derive(Default)]
struct Copies {
    queries: Vec<Query>,
    edges: HashMap<(u32, u32), Vec<(u32, u32)>>,
    site_copy: HashMap<u32, (u32, u32, u32)>,
    icall_site: u32,
    done: HashSet<(u32, u32)>,
}

impl Copies {
    /// A new site of a call through a pointer or vtable, made in copy `(f, c)` by its call
    /// `k`: its arguments and destination given to the solver.
    fn indirect(
        &mut self,
        prog: &mut Solver,
        (f, c, k): (u32, u32, u32),
        args: &[Option<(u32, u32, u32)>],
        dest: Option<(u32, u32, u32)>,
    ) -> u32 {
        self.icall_site += 1;
        let n = self.icall_site;
        self.site_copy.insert(n, (f, c, k));
        for (k, a) in args.iter().enumerate() {
            if let Some((ao, aoff, asize)) = a {
                prog.icall_arg.push((n, k as u32, *ao, *aoff, *asize));
            }
        }
        if let Some((d, doff, dsize)) = dest {
            prog.icall_dest.push((n, d, doff, dsize));
        }
        n
    }
}

#[derive(Default)]
pub(crate) struct Pta {
    objs: Vec<Obj>,
    obj_ids: HashMap<Obj, u32>,
    insts: Vec<Instance>,
    inst_ids: HashMap<Instance, u32>,
    temps: u32,
    /// The translated bodies.
    templates: HashMap<u32, Template>,
    /// Calling contexts of library copies: the last `k` call sites (caller, call index).
    ctxs: Vec<Vec<(u32, u32)>>,
    ctx_ids: HashMap<Vec<(u32, u32)>, u32>,
    k: usize,
    /// Library copies named by the program's call site that entered the library
    /// (`RCBOM_PTA_CTX=entry`, the default), not by the last `k` call sites.
    entry: bool,
    addr: Vec<(u32, u32, u32, u32)>,
    copy: Vec<(u32, u32, u32, u32, u32)>,
    load: Vec<(u32, u32, u32, u32, u32, u32)>,
    store: Vec<(u32, u32, u32, u32, u32, u32)>,
    addr_deref: Vec<(u32, u32, u32, u32, u32)>,
    havoc_arg: Vec<(u32, u32, u32)>,
    havocked: Vec<(u32, u32, u32)>,
    /// Vtables of types coerced to `dyn` traits: their methods by slot.
    vt_list: Vec<Vec<Option<Instance>>>,
    vt_ids: HashMap<(rustc_span::def_id::DefId, String), u32>,
    statics_read: HashSet<rustc_span::def_id::DefId>,
    /// Constant allocations holding a knowledge-base constant's value: the constants' items.
    mem_names: HashMap<u32, Vec<rustc_span::def_id::DefId>>,
    /// The public constant items of each stop crate (`kb_const_names`).
    kb_const_items: HashMap<rustc_span::def_id::CrateNum, Vec<rustc_span::def_id::DefId>>,
    /// The structs and enums each static's type is made of (`Query::pointees`).
    static_adts: HashMap<rustc_span::def_id::DefId, Vec<rustc_span::def_id::DefId>>,
    mems_read: HashSet<rustc_middle::mir::interpret::AllocId>,
    pub(crate) failed: usize,
    /// The stop crates (the knowledge base's): calls into them are queries, not translated.
    stop: HashSet<rustc_span::def_id::CrateNum>,
    /// Why calls were not followed (callee or reason), for measuring the fallback's reach.
    pub(crate) havoc_why: HashMap<String, usize>,
    /// The entry points (the walk's roots).
    roots: Vec<u32>,
    /// Constraints made by the copies so far.
    constraints: usize,
    /// Drop glue instances (`drop_in_place::<T>`) called at `Drop` terminators.
    drops: HashSet<u32>,
    /// Locals whose type tells which words may hold a vtable or a function (`code_words`).
    typed: HashMap<u32, Vec<(u32, u8)>>,
    /// Leave out the values no query can depend on (`relevant`); `RCBOM_PTA_PRUNE=0` keeps all.
    prune: bool,
}

/// A parameter of a translated body: the caller's argument index, the part of it (the field's
/// offset in a spread `rust-call` tuple), the local and its size.
#[derive(Clone, Copy)]
struct ParamSlot {
    arg: usize,
    part: Option<u32>,
    local: u32,
    size: u32,
}

impl Pta {
    pub(crate) fn new(stop: HashSet<rustc_span::def_id::CrateNum>) -> Self {
        let k = std::env::var("RCBOM_PTA_K")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(2);
        let entry = std::env::var("RCBOM_PTA_CTX").map_or(true, |v| v != "k");
        let prune = std::env::var("RCBOM_PTA_PRUNE").map_or(true, |v| v != "0");
        let mut p = Pta {
            stop,
            k,
            entry,
            prune,
            ..Pta::default()
        };
        p.obj(Obj::Unknown);
        p.ctxs.push(Vec::new());
        p.ctx_ids.insert(Vec::new(), 0);
        p
    }

    pub(crate) fn set_roots(&mut self, roots: &[Instance]) {
        self.roots = roots.iter().map(|i| self.inst(*i)).collect();
    }

    fn obj(&mut self, o: Obj) -> u32 {
        if let Some(&i) = self.obj_ids.get(&o) {
            return i;
        }
        let i = self.objs.len() as u32;
        self.objs.push(o.clone());
        self.obj_ids.insert(o, i);
        i
    }

    fn inst(&mut self, i: Instance) -> u32 {
        if let Some(&n) = self.inst_ids.get(&i) {
            return n;
        }
        let n = self.insts.len() as u32;
        self.insts.push(i);
        self.inst_ids.insert(i, n);
        n
    }

    fn temp(&mut self, f: u32) -> u32 {
        self.temps += 1;
        self.obj(Obj::Temp(f, self.temps))
    }

    /// Translates one walked instance's body into a template. A body that does not translate
    /// (a type the layouts cannot give) is left out: its callers then havoc their arguments.
    pub(crate) fn add_body(&mut self, tcx: TyCtxt<'_>, inst: Instance, body: &Body) {
        let f = self.inst(inst);
        let krate = rustc_internal::internal(tcx, inst.def.def_id()).krate;
        let lib = matches!(tcx.crate_name(krate).as_str(), "core" | "alloc" | "std");
        let ok = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut t = Tr {
                p: self,
                t: Template {
                    lib,
                    ..Template::default()
                },
                tcx,
                f,
                body,
                relevance: HashMap::default(),
                line: 0,
            };
            let (slots, ret) = t.body()?;
            t.t.slots = slots;
            t.t.ret = ret;
            Some(t.t)
        }));
        match ok {
            Ok(Some(t)) => {
                self.templates.insert(f, t);
            }
            _ => self.failed += 1,
        }
    }

    /// The contents of a static's initializer (once), at offsets normalised by its type.
    fn read_static(&mut self, tcx: TyCtxt<'_>, def: rustc_span::def_id::DefId) -> u32 {
        let o = self.obj(Obj::Static(def));
        if self.statics_read.insert(def) {
            let ty = tcx.type_of(def).instantiate_identity().skip_normalization();
            let adts = ty
                .walk()
                .filter_map(|a| match a.as_type()?.kind() {
                    rustc_middle::ty::Adt(d, _) => Some(d.did()),
                    _ => None,
                })
                .collect();
            self.static_adts.insert(def, adts);
            match tcx.eval_static_initializer(def) {
                Ok(alloc) => self.read_alloc(tcx, o, alloc.inner(), ty),
                // an extern static, or one that does not evaluate: anything
                Err(_) => self.havocked.push((o, 0, u32::MAX)),
            }
        }
        o
    }

    /// The pointers in an allocation of type `ty`, written into object `o`.
    fn read_alloc<'tcx>(
        &mut self,
        tcx: TyCtxt<'tcx>,
        o: u32,
        alloc: &rustc_middle::mir::interpret::Allocation,
        ty: rustc_middle::ty::Ty<'tcx>,
    ) {
        for (off, prov) in alloc.provenance().ptrs().iter() {
            let off = norm_offset(tcx, ty, off.bytes()).unwrap_or(off.bytes()) as u32;
            let target_ty = pointee_at(tcx, ty, off as u64);
            if let Some(t) = self.global(tcx, prov.alloc_id(), target_ty) {
                self.addr.push((o, off, t, 0));
            }
        }
    }

    /// The object an allocation id names (its contents read once), or `None` for a vtable.
    fn global<'tcx>(
        &mut self,
        tcx: TyCtxt<'tcx>,
        id: rustc_middle::mir::interpret::AllocId,
        pointee: Option<rustc_middle::ty::Ty<'tcx>>,
    ) -> Option<u32> {
        use rustc_middle::mir::interpret::GlobalAlloc;
        match tcx.try_get_global_alloc(id)? {
            GlobalAlloc::Static(def) => Some(self.read_static(tcx, def)),
            GlobalAlloc::Memory(m) => {
                let o = self.obj(Obj::Mem(id));
                if self.mems_read.insert(id) {
                    // a knowledge-base constant's value (`aws_lc_rs::aead::AES_128_GCM` is a
                    // `const`): named after it, as statics are
                    if let Some(ty) = pointee {
                        let names = self.kb_const_names(tcx, ty, m.inner());
                        if !names.is_empty() {
                            let adts: Vec<rustc_span::def_id::DefId> = ty
                                .walk()
                                .filter_map(|a| match a.as_type()?.kind() {
                                    rustc_middle::ty::Adt(d, _) => Some(d.did()),
                                    _ => None,
                                })
                                .collect();
                            for d in &names {
                                self.static_adts.insert(*d, adts.clone());
                            }
                            self.mem_names.insert(o, names);
                        }
                    }
                    match pointee {
                        Some(ty) => self.read_alloc(tcx, o, m.inner(), ty),
                        None => {
                            // untyped: its pointers anywhere in it
                            for (_, prov) in m.inner().provenance().ptrs().iter() {
                                if let Some(t) = self.global(tcx, prov.alloc_id(), None) {
                                    self.addr.push((o, 0, t, 0));
                                }
                            }
                        }
                    }
                }
                Some(o)
            }
            GlobalAlloc::VTable(concrete, preds) => {
                let dynamic =
                    rustc_middle::ty::Ty::new_dynamic(tcx, preds, tcx.lifetimes.re_erased);
                self.coerced(tcx, concrete, dynamic)
            }
            GlobalAlloc::Function { instance } => {
                let i = self.inst(rustc_internal::stable(instance));
                Some(self.obj(Obj::Fn(i)))
            }
            _ => None,
        }
    }

    /// The knowledge-base constants whose value allocation `m` holds (it has type `ty`, a type
    /// of a stop crate): the crate's public `const` items of that type whose values are equal,
    /// pointers compared by what they point to.
    fn kb_const_names<'tcx>(
        &mut self,
        tcx: TyCtxt<'tcx>,
        ty: rustc_middle::ty::Ty<'tcx>,
        m: &rustc_middle::mir::interpret::Allocation,
    ) -> Vec<rustc_span::def_id::DefId> {
        let rustc_middle::ty::Adt(adt, _) = ty.kind() else {
            return Vec::new();
        };
        let krate = adt.did().krate;
        if !self.stop.contains(&krate) {
            return Vec::new();
        }
        let env = rustc_middle::ty::TypingEnv::fully_monomorphized();
        let Ok(layout) = tcx.layout_of(env.as_query_input(ty)) else {
            return Vec::new();
        };
        let size = layout.size.bytes() as usize;
        if m.size().bytes() as usize != size {
            return Vec::new();
        }
        let items = self
            .kb_const_items
            .entry(krate)
            .or_insert_with(|| crate_consts(tcx, krate))
            .clone();
        items
            .into_iter()
            .filter(|c| {
                tcx.type_of(*c).instantiate_identity().skip_normalization() == ty
                    && const_value_is(tcx, *c, m, size)
            })
            .collect()
    }

    /// The vtable object of a type coerced to a `dyn` trait (its methods by slot); `UNKNOWN`
    /// for a `dyn` type coerced to another (trait upcasting: the slots differ), `None` without
    /// a principal trait (no methods).
    pub(crate) fn coerced<'tcx>(
        &mut self,
        tcx: TyCtxt<'tcx>,
        concrete: rustc_middle::ty::Ty<'tcx>,
        dynamic: rustc_middle::ty::Ty<'tcx>,
    ) -> Option<u32> {
        let rustc_middle::ty::Dynamic(preds, ..) = dynamic.kind() else {
            return None;
        };
        let principal = preds.principal()?;
        if matches!(concrete.kind(), rustc_middle::ty::Dynamic(..)) {
            return Some(UNKNOWN);
        }
        let def = principal.def_id();
        let key = (def, format!("{concrete:?}"));
        if let Some(&n) = self.vt_ids.get(&key) {
            return Some(self.obj(Obj::VTable(n)));
        }
        let trait_ref = principal.with_self_ty(tcx, concrete);
        let trait_ref = tcx.instantiate_bound_regions_with_erased(trait_ref);
        let slots = tcx
            .vtable_entries(trait_ref)
            .iter()
            .map(|e| match e {
                rustc_middle::ty::VtblEntry::Method(i) => Some(rustc_internal::stable(*i)),
                _ => None,
            })
            .collect();
        let n = self.vt_list.len() as u32;
        self.vt_list.push(slots);
        self.vt_ids.insert(key, n);
        Some(self.obj(Obj::VTable(n)))
    }

    /// The context of a call at `site` made from a copy in context `c`: the last `k` sites.
    fn push_ctx(&mut self, c: u32, site: (u32, u32)) -> u32 {
        let mut v = self.ctxs[c as usize].clone();
        v.push(site);
        if v.len() > self.k {
            v.drain(..v.len() - self.k);
        }
        if let Some(&n) = self.ctx_ids.get(&v) {
            return n;
        }
        let n = self.ctxs.len() as u32;
        self.ctxs.push(v.clone());
        self.ctx_ids.insert(v, n);
        n
    }

    /// Object `o` in context `c`'s copy of instance `f`'s body.
    fn in_ctx(&mut self, f: u32, c: u32, o: u32) -> u32 {
        if c == 0 {
            return o;
        }
        match self.objs[o as usize] {
            Obj::Local(g, _) | Obj::Temp(g, _) | Obj::Heap(g, _) if g == f => {
                self.obj(Obj::Ctx(c, o))
            }
            _ => o,
        }
    }

    fn loc_in_ctx(
        &mut self,
        f: u32,
        c: u32,
        l: Option<(u32, u32, u32)>,
    ) -> Option<(u32, u32, u32)> {
        l.map(|(o, off, size)| (self.in_ctx(f, c, o), off, size))
    }

    /// The context of a copy of `g`'s body called at `site` from a copy in context `c`: a
    /// library body in the call's context, any other in its single copy.
    fn callee_ctx(&mut self, c: u32, caller_lib: bool, site: (u32, u32), lib: bool) -> u32 {
        if !lib {
            0
        } else if self.entry {
            // the program's call site that entered the library; inside it the entry stays
            if caller_lib {
                c
            } else {
                self.push_ctx(0, site)
            }
        } else if self.k > 0 {
            self.push_ctx(c, site)
        } else {
            0
        }
    }

    /// Makes the copies in `work` (body, context) and those their direct calls reach, adding
    /// their constraints to `prog`'s inputs.
    fn instantiate(&mut self, prog: &mut Solver, st: &mut Copies, mut work: Vec<(u32, u32)>) {
        while let Some((f, c)) = work.pop() {
            if !st.done.insert((f, c)) {
                continue;
            }
            let t = self.templates.remove(&f).unwrap();
            for &(d, doff, o, ooff) in &t.addr {
                let (d, o) = (self.in_ctx(f, c, d), self.in_ctx(f, c, o));
                self.addr.push((d, doff, o, ooff));
            }
            for &(d, doff, s, soff, size) in &t.copy {
                let (d, s) = (self.in_ctx(f, c, d), self.in_ctx(f, c, s));
                self.copy.push((d, doff, s, soff, size));
            }
            for &(d, doff, pp, poff, off, size) in &t.load {
                let (d, pp) = (self.in_ctx(f, c, d), self.in_ctx(f, c, pp));
                self.load.push((d, doff, pp, poff, off, size));
            }
            for &(pp, poff, off, s, soff, size) in &t.store {
                let (pp, s) = (self.in_ctx(f, c, pp), self.in_ctx(f, c, s));
                self.store.push((pp, poff, off, s, soff, size));
            }
            for &(d, doff, pp, poff, off) in &t.addr_deref {
                let (d, pp) = (self.in_ctx(f, c, d), self.in_ctx(f, c, pp));
                self.addr_deref.push((d, doff, pp, poff, off));
            }
            for &(o, off, size) in &t.havoc_arg {
                let o = self.in_ctx(f, c, o);
                self.havoc_arg.push((o, off, size));
            }
            for &(o, off, size) in &t.havocked {
                let o = self.in_ctx(f, c, o);
                self.havocked.push((o, off, size));
            }
            for q in &t.queries {
                let args: Vec<_> = q.args.iter().map(|a| self.loc_in_ctx(f, c, *a)).collect();
                prog.needed
                    .extend(args.iter().flatten().map(|(o, off, _)| (*o, *off)));
                st.queries.push(Query {
                    at: q.at.clone(),
                    callee: q.callee.clone(),
                    callee_path: q.callee_path.clone(),
                    owner: q.owner.clone(),
                    owner_def: q.owner_def.clone(),
                    args,
                    live: false,
                    copy: (f, c),
                    pointees: q.pointees.clone(),
                    direct: q.direct.clone(),
                });
            }
            for (k, call) in t.calls.iter().enumerate() {
                let site = (f, k as u32);
                let args: Vec<_> = call
                    .args
                    .iter()
                    .map(|a| self.loc_in_ctx(f, c, *a))
                    .collect();
                let dest = self.loc_in_ctx(f, c, call.dest);
                match &call.callee {
                    Callee::Inst(i) => {
                        let g = self.inst(*i);
                        if let Some(to) = self.bind(c, t.lib, site, g, &args, dest, &mut work) {
                            st.edges.entry((f, c)).or_default().push(to);
                        }
                    }
                    Callee::Virtual(ro, roff, slot) => {
                        let ro = self.in_ctx(f, c, *ro);
                        let n = st.indirect(prog, (f, c, k as u32), &args, dest);
                        prog.vcall.push((n, ro, roff + 8, *slot as u32));
                    }
                    Callee::Ptr(o, off) => {
                        let o = self.in_ctx(f, c, *o);
                        let n = st.indirect(prog, (f, c, k as u32), &args, dest);
                        prog.icall.push((n, o, *off));
                    }
                }
            }
            self.templates.insert(f, t);
        }
        self.constraints += self.addr.len()
            + self.copy.len()
            + self.load.len()
            + self.store.len()
            + self.addr_deref.len();
        prog.addr.append(&mut self.addr);
        prog.copy.append(&mut self.copy);
        prog.load.append(&mut self.load);
        prog.store.append(&mut self.store);
        prog.addr_deref.append(&mut self.addr_deref);
        prog.havoc_arg.append(&mut self.havoc_arg);
        prog.havocked.append(&mut self.havocked);
    }

    /// Tells the solver which objects made since `from` are never merged: what answers and
    /// calls name (the knowledge base's statics, functions, vtables) and `UNKNOWN`, `Exposed`.
    fn mark_fixed(&self, prog: &mut Solver, from: &mut usize) {
        for (n, o) in self.objs.iter().enumerate().skip(*from) {
            // (a copy of a typed local is typed alike; vtables are what the filter drops)
            match o {
                Obj::Local(..) | Obj::Temp(..) => {
                    if let Some(w) = self.typed.get(&(n as u32)) {
                        prog.typed.insert(n as u32, w.clone());
                    }
                }
                Obj::Ctx(_, inner) => {
                    if let Some(w) = self.typed.get(inner) {
                        prog.typed.insert(n as u32, w.clone());
                    }
                }
                Obj::VTable(_) => {
                    prog.vtables.insert(n as u32);
                }
                Obj::Fn(_) => {
                    prog.fns.insert(n as u32);
                }
                _ => {}
            }
            let fixed = match o {
                Obj::Mem(..) => self.mem_names.contains_key(&(n as u32)),
                Obj::Local(..) | Obj::Temp(..) | Obj::Heap(..) | Obj::Ctx(..) => false,
                Obj::Static(d) => self.kb_static(*d),
                _ => true,
            };
            if fixed {
                prog.fixed.insert(n as u32);
            }
        }
        *from = self.objs.len();
    }

    /// Whether a static can be an answer: one of a stop crate's, or of a type made of one of
    /// their types.
    fn kb_static(&self, d: rustc_span::def_id::DefId) -> bool {
        self.stop.contains(&d.krate)
            || self
                .static_adts
                .get(&d)
                .is_some_and(|v| v.iter().any(|a| self.stop.contains(&a.krate)))
    }

    /// Solves the constraints; the answer to each query.
    pub(crate) fn solve(mut self) -> (Vec<Query>, Vec<Vec<Option<Answer>>>, Stats) {
        let mut prog = Solver::default();
        let mut st = Copies::default();
        // the program's bodies once (and any root of the library's); the library's per context,
        // as calls reach them
        let mut work: Vec<(u32, u32)> = self
            .templates
            .iter()
            .filter(|(_, t)| !t.lib)
            .map(|(&f, _)| (f, 0))
            .collect();
        work.extend(
            self.roots
                .iter()
                .filter(|r| self.templates.get(r).is_some_and(|t| t.lib))
                .map(|r| (*r, 0)),
        );
        self.instantiate(&mut prog, &mut st, work);
        // the roots are called from outside the program (a library's public functions): what
        // their parameters point to is anything, and what they return is the caller's
        for r in self.roots.clone() {
            let Some((slots, ret)) = self.templates.get(&r).map(|t| (t.slots.clone(), t.ret))
            else {
                continue;
            };
            for sl in slots {
                prog.havocked.push((sl.local, 0, u32::MAX));
            }
            let r0 = self.local_obj(r, 0);
            prog.havoc_arg.push((r0, 0, ret));
        }
        // the methods vtables give, by slot
        for n in 0..self.vt_list.len() {
            let vt = self.obj(Obj::VTable(n as u32));
            for (slot, m) in self.vt_list[n].clone().into_iter().enumerate() {
                if let Some(i) = m {
                    let ii = self.inst(i);
                    let fo = self.obj(Obj::Fn(ii));
                    prog.vt_entry.push((vt, slot as u32, fo));
                }
            }
        }
        // the functions a pointer may name: a program body's single copy is bound in the
        // solver, a library body's copy in the caller's context is made when the solver asks
        let fns: Vec<(u32, u32)> = self
            .objs
            .iter()
            .enumerate()
            .filter_map(|(n, o)| match o {
                Obj::Fn(i) => Some((n as u32, *i)),
                _ => None,
            })
            .collect();
        let fn_inst: HashMap<u32, u32> = fns.iter().copied().collect();
        for (n, i) in fns {
            match self
                .templates
                .get(&i)
                .map(|t| (t.slots.clone(), t.ret, t.lib))
            {
                Some((_, _, true)) => prog.fn_lib.push(n),
                Some((slots, ret, false)) => {
                    for s in slots {
                        prog.fn_param.push((
                            n,
                            s.arg as u32,
                            s.part.unwrap_or(0),
                            s.part.is_some(),
                            s.local,
                            s.size,
                        ));
                    }
                    let r = self.local_obj(i, 0);
                    prog.fn_ret.push((n, r, ret));
                }
                None => prog.fn_untranslated.push((n,)),
            }
        }
        prog.addr.push((UNKNOWN, 0, UNKNOWN, 0));
        // the tier: unification when the copies are too many for the inclusion solver to hold
        // (`RCBOM_PTA_TIER`: `unify`, `include` to force one; `RCBOM_PTA_UNIFY_COPIES`)
        let limit: usize = std::env::var("RCBOM_PTA_UNIFY_COPIES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(400_000);
        let tier = std::env::var("RCBOM_PTA_TIER").unwrap_or_default();
        if tier == "unify" || (tier != "include" && st.done.len() > limit) {
            eprintln!(
                "rcbom-pta: {} copies: unification tier (inclusion up to {limit})",
                st.done.len()
            );
            prog.set_unify();
        }
        let mut marked = 0;
        self.mark_fixed(&mut prog, &mut marked);
        eprintln!(
            "rcbom-pta: {} objects, {} bodies, {} copies; addr {} copy {} load {} store {} \
             addr_deref {} havoc_arg {} havocked {} icalls {} vcalls {}",
            self.objs.len(),
            self.templates.len(),
            st.done.len(),
            prog.addr.len(),
            prog.copy.len(),
            prog.load.len(),
            prog.store.len(),
            prog.addr_deref.len(),
            prog.havoc_arg.len(),
            prog.havocked.len(),
            prog.icall.len(),
            prog.vcall.len()
        );
        loop {
            prog.run();
            let requests = std::mem::take(&mut prog.requests);
            if prog.exhausted || requests.is_empty() {
                break;
            }
            for (site, fo) in requests {
                let (cf, cc, ck) = st.site_copy[&site];
                let g = fn_inst[&fo];
                let caller_lib = self.templates.get(&cf).is_some_and(|t| t.lib);
                // (under memory pressure, and in the unification tier, one shared copy instead of
                // one per calling context)
                let cg = if prog.pressure() >= 2 || prog.unifying() {
                    0
                } else {
                    self.callee_ctx(cc, caller_lib, (cf, ck), true)
                };
                self.instantiate(&mut prog, &mut st, vec![(g, cg)]);
                st.edges.entry((cf, cc)).or_default().push((g, cg));
                let (slots, ret) = {
                    let t = &self.templates[&g];
                    (t.slots.clone(), t.ret)
                };
                let ps: Vec<(u32, u32, u32, u32)> = slots
                    .iter()
                    .map(|s| {
                        (
                            s.arg as u32,
                            s.part.unwrap_or(0),
                            self.in_ctx(g, cg, s.local),
                            s.size,
                        )
                    })
                    .collect();
                let r0 = self.local_obj(g, 0);
                let r = self.in_ctx(g, cg, r0);
                prog.bind_to(site, &ps, Some((r, ret)));
            }
            self.mark_fixed(&mut prog, &mut marked);
        }
        eprintln!("rcbom-pta: solved: {}", prog.summary());
        let mut stats = Stats {
            vcalls_without_vtable: 0,
            vcalls_without_vtable_in: Vec::new(),
            havoc_why: std::mem::take(&mut self.havoc_why),
            objects: self.objs.len(),
            instances: self.templates.len(),
            copies: st.done.len(),
            failed: self.failed,
            constraints: self.constraints,
            static_types: Vec::new(),
        };
        let mut queries = std::mem::take(&mut st.queries);
        let mut edges = std::mem::take(&mut st.edges);
        let site_copy: HashMap<u32, (u32, u32)> = st
            .site_copy
            .iter()
            .map(|(s, (f, c, _))| (*s, (*f, *c)))
            .collect();
        let exhausted = prog.exhausted;
        if std::env::var_os("RCBOM_PTA_DEBUG").is_some() {
            // the largest sets, and the targets most locations hold
            let mut sizes: HashMap<(u32, u32), usize> = HashMap::default();
            let mut freq: HashMap<u32, usize> = HashMap::default();
            for (o, off, t, _) in prog.pts_tuples() {
                *sizes.entry((o, off)).or_default() += 1;
                *freq.entry(t).or_default() += 1;
            }
            let mut big: Vec<_> = sizes.into_iter().collect();
            big.sort_by_key(|x| std::cmp::Reverse(x.1));
            for ((o, off), n) in big.iter().take(25) {
                eprintln!("rcbom-pta: set {n}: {} +{off}", self.describe(*o));
            }
            // entries by the holder's crate and kind (program, library shared, library per
            // entry, heap, global)
            let mut by_kind: HashMap<String, usize> = HashMap::default();
            for ((o, _), n) in big.iter() {
                *by_kind.entry(self.kind_of(*o)).or_default() += n;
            }
            let mut bk: Vec<_> = by_kind.into_iter().collect();
            bk.sort_by_key(|x| std::cmp::Reverse(x.1));
            for (k, n) in bk.iter().take(40) {
                eprintln!("rcbom-pta: entries {n} held in {k}");
            }
            let mut tk: HashMap<String, usize> = HashMap::default();
            for (t, n) in freq.iter() {
                *tk.entry(self.kind_of(*t)).or_default() += n;
            }
            let mut tk: Vec<_> = tk.into_iter().collect();
            tk.sort_by_key(|x| std::cmp::Reverse(x.1));
            for (k, n) in tk.iter().take(40) {
                eprintln!("rcbom-pta: entries {n} targeting {k}");
            }
            if std::env::var("RCBOM_PTA_COLLAPSE").as_deref() == Ok("0") {
                // the largest cycle, and paths through it between two crates' locations
                let cyc = prog.largest_cycle();
                let within: HashSet<u32> = cyc.iter().copied().collect();
                let mut kinds: HashMap<String, usize> = HashMap::default();
                for l in &cyc {
                    *kinds.entry(self.kind_of(prog.loc_of(*l).0)).or_default() += 1;
                }
                let mut kinds: Vec<_> = kinds.into_iter().collect();
                kinds.sort_by_key(|x| std::cmp::Reverse(x.1));
                eprintln!("rcbom-pta: cycle of {} locations", cyc.len());
                for (k, c) in kinds.iter().take(15) {
                    eprintln!("rcbom-pta:   {c} in {k}");
                }
                let krate = |p: &Pta, l: u32| {
                    let k = p.kind_of(prog.loc_of(l).0);
                    k.rsplit(' ').next().unwrap_or("").to_string()
                };
                if let Some(&a) = cyc.first() {
                    let ka = krate(&self, a);
                    for &b in &cyc {
                        if krate(&self, b) == ka {
                            continue;
                        }
                        for (x, y) in [(a, b), (b, a)] {
                            eprintln!("rcbom-pta: path:");
                            for (o, off) in prog.path_within(&within, x, y) {
                                eprintln!("rcbom-pta:   {} +{off}", self.describe(o));
                            }
                        }
                        break;
                    }
                }
            }
            for (n, g) in prog.largest_groups(3).iter().enumerate() {
                let mut kinds: HashMap<String, usize> = HashMap::default();
                for (o, _) in g {
                    *kinds.entry(self.kind_of(*o)).or_default() += 1;
                }
                let mut kinds: Vec<_> = kinds.into_iter().collect();
                kinds.sort_by_key(|x| std::cmp::Reverse(x.1));
                eprintln!("rcbom-pta: group {n}: {} locations", g.len());
                for (k, c) in kinds.iter().take(15) {
                    eprintln!("rcbom-pta:   {c} in {k}");
                }
                for (o, off) in g.iter().step_by((g.len() / 40).max(1)).take(40) {
                    eprintln!("rcbom-pta:   member {} +{off}", self.describe(*o));
                }
            }
            let mut fq: Vec<_> = freq.into_iter().collect();
            fq.sort_by_key(|x| std::cmp::Reverse(x.1));
            for (t, n) in fq.iter().take(25) {
                eprintln!("rcbom-pta: target in {n} sets: {}", self.describe(*t));
            }
        }
        if exhausted {
            eprintln!("rcbom-pta: budget exhausted, every answer is unknown");
        }
        // the unification tier: the class each knowledge-base static is in, and the classes the
        // live queries' arguments point to
        if std::env::var_os("RCBOM_PTA_DEBUG").is_some()
            && let Some((u, _)) = prog.unify_classes(UNKNOWN)
        {
            eprintln!("rcbom-pta: unknown's class {u}");
            for (n, o) in self.objs.iter().enumerate() {
                if let Obj::Static(d) = o
                    && prog.fixed.contains(&(n as u32))
                {
                    let (c, _) = prog.unify_classes(n as u32).unwrap_or_default();
                    eprintln!("rcbom-pta: static {d:?} in class {c}");
                }
            }
            for q in queries.iter().filter(|q| q.live) {
                let cs: Vec<String> = q
                    .args
                    .iter()
                    .map(|a| match a {
                        Some((o, _, _)) => {
                            let (_, p) = prog.unify_classes(*o).unwrap_or_default();
                            p.to_string()
                        }
                        None => "-".into(),
                    })
                    .collect();
                eprintln!(
                    "rcbom-pta: query {} {}:{} points to classes {}",
                    q.callee,
                    q.at.file,
                    q.at.line,
                    cs.join(",")
                );
            }
        }
        // what the locals of the instances whose names hold `RCBOM_PTA_TRACE` point to
        if let Ok(pat) = std::env::var("RCBOM_PTA_TRACE") {
            for n in 0..self.objs.len() {
                if !self.describe(n as u32).contains(&pat) {
                    continue;
                }
                for off in [0, 8, 16] {
                    let ts = prog.pts_of(n as u32, off);
                    if ts.is_empty() {
                        continue;
                    }
                    let ts: Vec<String> = ts
                        .iter()
                        .map(|(t, toff)| format!("{} +{toff}", self.describe(*t)))
                        .collect();
                    eprintln!(
                        "rcbom-pta: trace {} +{off} -> {}",
                        self.describe(n as u32),
                        ts.join(" | ")
                    );
                }
            }
        }
        // `dyn` calls whose receiver holds no vtable at all (a gap in the translation: no
        // method is bound, and nothing says so)
        let vt_known: HashSet<(u32, u32)> =
            prog.pts_tuples().map(|(o, off, _, _)| (o, off)).collect();
        let missing: Vec<u32> = prog
            .vcall_sites()
            .into_iter()
            .map(|(site, o, off)| (site, o, off, 0u32))
            .collect::<Vec<_>>()
            .iter()
            // (a receiver that points somewhere: a copy no value reaches is dead, not a gap)
            .filter(|(_, o, off, _)| {
                *o != UNKNOWN
                    && !vt_known.contains(&(*o, *off))
                    && vt_known.contains(&(*o, off - 8))
            })
            .map(|(_, o, _, _)| *o)
            .collect();
        let vcalls_without_vtable = missing.len();
        let missing_in: Vec<String> = missing.iter().take(20).map(|o| self.describe(*o)).collect();
        // liveness: copies reached from the roots
        let fn_inst: HashMap<u32, u32> = self
            .objs
            .iter()
            .enumerate()
            .filter_map(|(n, o)| match o {
                Obj::Fn(i) => Some((n as u32, *i)),
                _ => None,
            })
            .collect();
        for (site, fo) in prog.callee.iter() {
            if let (Some(from), Some(g)) = (site_copy.get(site), fn_inst.get(fo)) {
                edges.entry(*from).or_default().push((*g, 0));
            }
        }
        let mut live: HashSet<(u32, u32)> = HashSet::default();
        let mut stack: Vec<(u32, u32)> = self.roots.iter().map(|r| (*r, 0)).collect();
        while let Some(x) = stack.pop() {
            if live.insert(x) {
                stack.extend(edges.get(&x).into_iter().flatten().copied());
            }
        }
        for q in queries.iter_mut() {
            q.live = live.contains(&q.copy);
        }
        // why a query's arguments point where they do (`RCBOM_PTA_WHY`: text of the callee or
        // `file:line`): the copy holding it, its callers, and what each passes at the call
        if let Ok(pat) = std::env::var("RCBOM_PTA_WHY") {
            for q in queries.iter().filter(|q| {
                q.live
                    && (q.callee.contains(&pat)
                        || format!("{}:{}", q.at.file, q.at.line).ends_with(&pat))
            }) {
                let (f, c) = q.copy;
                eprintln!(
                    "rcbom-pta: why {} at {}:{} in {} (context {c})",
                    q.callee,
                    q.at.file,
                    q.at.line,
                    self.insts[f as usize].name()
                );
                for (k, a) in q.args.iter().enumerate() {
                    if let Some((o, off, _)) = a {
                        let ts: Vec<String> = prog
                            .pts_of(*o, *off)
                            .iter()
                            .map(|(t, toff)| format!("{} +{toff}", self.describe(*t)))
                            .collect();
                        eprintln!(
                            "rcbom-pta:   argument {k}: {} +{off} -> [{}]",
                            self.describe(*o),
                            ts.join(" | ")
                        );
                    }
                }
                // the copy's parameters
                if let Some(t) = self.templates.get(&f) {
                    for sl in t.slots.clone() {
                        let o = self.in_ctx(f, c, sl.local);
                        let ts: Vec<String> = prog
                            .pts_of(o, 0)
                            .iter()
                            .map(|(t, toff)| format!("{} +{toff}", self.describe(*t)))
                            .collect();
                        eprintln!(
                            "rcbom-pta:   parameter {}: {} -> [{}]",
                            sl.arg,
                            self.describe(o),
                            ts.join(" | ")
                        );
                    }
                }
                // its callers and what they pass, up the chain while what is passed is empty
                let mut todo = vec![(f, c, 0usize)];
                let mut seen = HashSet::default();
                while let Some((f, c, depth)) = todo.pop() {
                    if depth > 10 || !seen.insert((f, c)) {
                        continue;
                    }
                    let callers: Vec<(u32, u32)> = edges
                        .iter()
                        .filter(|(_, tos)| tos.contains(&(f, c)))
                        .map(|(from, _)| *from)
                        .collect();
                    let pad = "  ".repeat(depth + 1);
                    if callers.is_empty() {
                        eprintln!(
                            "rcbom-pta: {pad}{} (context {c}): no caller{}",
                            self.insts[f as usize].name(),
                            if self.roots.contains(&f) {
                                " (a root)"
                            } else {
                                ""
                            }
                        );
                    }
                    for (cf, cc) in callers.into_iter().take(6) {
                        let calls: Vec<Call> = self
                            .templates
                            .get(&cf)
                            .map(|t| t.calls.clone())
                            .unwrap_or_default();
                        let mut empty = false;
                        for call in calls {
                            let Callee::Inst(i) = &call.callee else {
                                continue;
                            };
                            if self.inst_ids.get(i) != Some(&f) {
                                continue;
                            }
                            for (k, a) in call.args.iter().enumerate() {
                                let a = self.loc_in_ctx(cf, cc, *a);
                                let desc = match a {
                                    Some((o, off, _)) => {
                                        let ts: Vec<String> = prog
                                            .pts_of(o, off)
                                            .iter()
                                            .take(6)
                                            .map(|(t, toff)| {
                                                format!("{} +{toff}", self.describe(*t))
                                            })
                                            .collect();
                                        empty |= ts.is_empty();
                                        format!(
                                            "{} +{off} -> [{}]",
                                            self.describe(o),
                                            ts.join(" | ")
                                        )
                                    }
                                    None => "none (not translated as a pointer)".into(),
                                };
                                eprintln!(
                                    "rcbom-pta: {pad}caller {} (context {cc}) line {} \
                                     argument {k}: {desc}",
                                    self.insts[cf as usize].name(),
                                    call.line
                                );
                            }
                        }
                        if empty {
                            todo.push((cf, cc, depth + 1));
                        }
                    }
                }
            }
        }
        if std::env::var_os("RCBOM_PTA_DEBUG").is_some() {
            // where the unknowns of live queries come from
            for q in queries.iter().filter(|q| q.live) {
                for (k, a) in q.args.iter().enumerate() {
                    let Some((o, off, _)) = a else { continue };
                    let chain = prog.explain_unknown(*o, *off);
                    if chain.is_empty() {
                        continue;
                    }
                    eprintln!(
                        "rcbom-pta: unknown in argument {k} of {} at {}:{}",
                        q.callee, q.at.file, q.at.line
                    );
                    for (o, off, havocked) in chain.iter().take(40) {
                        eprintln!(
                            "rcbom-pta:   from {} +{off}{}",
                            self.describe(*o),
                            if *havocked { " (havocked)" } else { "" }
                        );
                    }
                }
            }
        }
        if std::env::var_os("RCBOM_PTA_DEBUG").is_some() {
            // where the unknowns of `dyn` calls' vtable words come from (such a call returns
            // anything)
            for (site, o, off) in prog.vcall_sites() {
                let chain = prog.explain_unknown(o, off);
                if chain.is_empty() {
                    continue;
                }
                eprintln!(
                    "rcbom-pta: unknown vtable of dyn call {site} in {} +{off}",
                    self.describe(o)
                );
                for (o, off, havocked) in chain.iter().take(40) {
                    eprintln!(
                        "rcbom-pta:   from {} +{off}{}",
                        self.describe(*o),
                        if *havocked { " (havocked)" } else { "" }
                    );
                }
            }
        }
        // answers
        let answers = queries
            .iter()
            .map(|q| {
                q.args
                    .iter()
                    .enumerate()
                    .map(|(k, a)| {
                        let (o, off, _) = (*a)?;
                        let mut statics = Vec::new();
                        let mut unknown = false;
                        let mut others = 0;
                        // the pointers in the argument's first word (a reference, a fat
                        // pointer's data part)
                        let mut seen = HashSet::default();
                        for (t, _) in prog.pts_of(o, off) {
                            if !seen.insert(t) {
                                continue;
                            }
                            match &self.objs[t as usize] {
                                Obj::Unknown => unknown = true,
                                // (a static merged with other objects stands for them all)
                                Obj::Static(d) if prog.fixed.contains(&t) => statics.push(*d),
                                Obj::Mem(_) if self.mem_names.contains_key(&t) => {
                                    statics.extend(self.mem_names[&t].iter().copied())
                                }
                                _ => others += 1,
                            }
                        }
                        // (the solver ran out of its budget: anything)
                        unknown |= exhausted;
                        unknown |= prog.havocked_at(o, off);
                        if let Some(Some(p)) = q.pointees.get(k) {
                            statics
                                .retain(|d| self.static_adts.get(d).is_none_or(|v| v.contains(p)));
                        }
                        statics.sort_by_key(|d| (d.krate.as_u32(), d.index.as_u32()));
                        statics.dedup();
                        Some(Answer {
                            statics,
                            unknown,
                            others,
                        })
                    })
                    .collect()
            })
            .collect();
        stats.vcalls_without_vtable = vcalls_without_vtable;
        let mut types: Vec<_> = self
            .static_adts
            .iter()
            .filter(|(d, _)| self.kb_static(**d))
            .filter_map(|(d, a)| Some((*d, *a.first()?)))
            .collect();
        types.sort_by_key(|(d, _)| (d.krate.as_u32(), d.index.as_u32()));
        stats.static_types = types;
        stats.vcalls_without_vtable_in = missing_in;
        (queries, answers, stats)
    }

    /// An object, for diagnostics: the instance whose local or temporary it is.
    fn describe(&self, o: u32) -> String {
        match &self.objs[o as usize] {
            Obj::Local(f, l) => format!("{} _{l}", self.insts[*f as usize].name()),
            Obj::Temp(f, n) => format!("{} temp {n}", self.insts[*f as usize].name()),
            Obj::Heap(f, n) => format!("{} heap {n}", self.insts[*f as usize].name()),
            Obj::Ctx(c, inner) => {
                let sites: Vec<String> = self.ctxs[*c as usize]
                    .iter()
                    .map(|(f, k)| {
                        let line = self
                            .templates
                            .get(f)
                            .and_then(|t| t.calls.get(*k as usize))
                            .map_or(0, |c| c.line);
                        format!("{} line {line}", self.insts[*f as usize].name())
                    })
                    .collect();
                format!(
                    "{} (context {c}: {})",
                    self.describe(*inner),
                    sites.join(" < ")
                )
            }
            Obj::Static(d) => format!("static {d:?}"),
            Obj::Fn(i) => format!("fn {}", self.insts[*i as usize].name()),
            other => format!("{other:?}"),
        }
    }

    /// An object's kind and crate, for the debug tallies.
    fn kind_of(&self, o: u32) -> String {
        let krate = |f: u32| {
            let n = self.insts[f as usize].name();
            let n = n.trim_start_matches('<');
            n.split("::").next().unwrap_or("").to_string()
        };
        let lib = |f: u32| self.templates.get(&f).is_some_and(|t| t.lib);
        match &self.objs[o as usize] {
            Obj::Local(f, _) | Obj::Temp(f, _) => {
                if lib(*f) {
                    format!("library shared {}", krate(*f))
                } else {
                    format!("program {}", krate(*f))
                }
            }
            Obj::Heap(f, _) => format!("heap shared {}", krate(*f)),
            Obj::Ctx(_, inner) => match &self.objs[*inner as usize] {
                Obj::Heap(f, _) => format!("heap per entry {}", krate(*f)),
                Obj::Local(f, _) | Obj::Temp(f, _) => format!("library per entry {}", krate(*f)),
                _ => "context other".to_string(),
            },
            Obj::Static(_) => "static".to_string(),
            Obj::Mem(_) => "memory".to_string(),
            Obj::Fn(_) => "fn".to_string(),
            Obj::VTable(_) => "vtable".to_string(),
            Obj::Unknown => "unknown".to_string(),
            Obj::Exposed => "exposed".to_string(),
        }
    }

    fn local_obj(&mut self, f: u32, l: usize) -> u32 {
        self.obj(Obj::Local(f, l))
    }

    /// Binds a call made from a copy in context `c` at `site` to instance `g`: a library body
    /// in the call's context, any other in its single copy; havocked when `g` was not
    /// translated.
    #[allow(clippy::too_many_arguments)]
    fn bind(
        &mut self,
        c: u32,
        caller_lib: bool,
        site: (u32, u32),
        g: u32,
        args: &[Option<(u32, u32, u32)>],
        dest: Option<(u32, u32, u32)>,
        work: &mut Vec<(u32, u32)>,
    ) -> Option<(u32, u32)> {
        let Some((slots, ret, lib)) = self
            .templates
            .get(&g)
            .map(|t| (t.slots.clone(), t.ret, t.lib))
        else {
            // drop glue not translated (a stop crate's type, a body that did not translate):
            // a destructor frees or wipes what the dropped value owns, and hands out no
            // pointer, so nothing is havocked
            if self.drops.contains(&g) {
                self.havoc_why(format!(
                    "drop not followed: {}",
                    self.insts[g as usize].name()
                ));
                return None;
            }
            // the panic handler (`panic_impl`, declared in `core` without a body): it prints
            // the message and unwinds or aborts; it never returns, and the payload it makes is
            // the message's text, so the values the message formats do not escape
            if self.insts[g as usize].name().ends_with("::panic_impl") {
                self.havoc_why("panic handler: not followed".into());
                return None;
            }
            let why = format!("not translated: {}", self.insts[g as usize].name());
            self.havoc_why(why);
            self.havoc_call(args, dest);
            return None;
        };
        let cg = self.callee_ctx(c, caller_lib, site, lib);
        work.push((g, cg));
        for s in slots {
            if let Some(Some((ao, aoff, _))) = args.get(s.arg) {
                let off = aoff + s.part.unwrap_or(0);
                let local = self.in_ctx(g, cg, s.local);
                self.copy.push((local, 0, *ao, off, s.size));
            }
        }
        if let Some((d, doff, dsize)) = dest {
            let r = self.local_obj(g, 0);
            let r = self.in_ctx(g, cg, r);
            self.copy.push((d, doff, r, 0, dsize.min(ret)));
        }
        Some((g, cg))
    }

    fn havoc_why(&mut self, why: String) {
        *self.havoc_why.entry(why).or_default() += 1;
    }

    fn havoc_call(&mut self, args: &[Option<(u32, u32, u32)>], dest: Option<(u32, u32, u32)>) {
        for (ao, aoff, asize) in args.iter().flatten() {
            self.havoc_arg.push((*ao, *aoff, *asize));
        }
        if let Some((d, doff, dsize)) = dest {
            self.havocked.push((d, doff, dsize));
        }
    }
}

/// What an argument may point to.
pub(crate) struct Answer {
    pub(crate) statics: Vec<rustc_span::def_id::DefId>,
    pub(crate) unknown: bool,
    /// Locations that are neither statics nor `UNKNOWN` (locals, heap, constant memory).
    pub(crate) others: usize,
}

pub(crate) struct Stats {
    pub(crate) vcalls_without_vtable: usize,
    pub(crate) vcalls_without_vtable_in: Vec<String>,
    pub(crate) havoc_why: HashMap<String, usize>,
    pub(crate) objects: usize,
    pub(crate) instances: usize,
    pub(crate) copies: usize,
    pub(crate) failed: usize,
    pub(crate) constraints: usize,
    /// The struct or enum each knowledge-base static or constant read is.
    pub(crate) static_types: Vec<(rustc_span::def_id::DefId, rustc_span::def_id::DefId)>,
}

/// Offsets at or past this many bytes into an object share one location (the object's tail):
/// copies around a cycle that shift offsets would otherwise never reach a fixed point.
pub(crate) const TAIL: u32 = 1 << 12;

/// A location's offset in object `o`: `UNKNOWN` has one location, a large offset is the
/// object's tail, and offsets within one 8-byte word share it (a pointer is aligned: no two
/// share a word).
pub(crate) fn at(o: u32, off: u32) -> u32 {
    if o == UNKNOWN {
        0
    } else {
        (off & !7).min(TAIL)
    }
}

/// The translation of one body.
struct Tr<'a, 'tcx> {
    p: &'a mut Pta,
    t: Template,
    tcx: TyCtxt<'tcx>,
    f: u32,
    body: &'a Body,
    /// Which types can hold a pointer the queries may depend on (`relevant`).
    relevance: HashMap<(ITy<'tcx>, bool), bool>,
    /// The line of the call being translated.
    line: u32,
}

/// A place: a location, or one reached through the pointer held at a location (plus offset).
#[derive(Clone, Copy)]
enum Lv {
    Direct(u32, u32),
    Through(u32, u32, u32),
}

type ITy<'tcx> = rustc_middle::ty::Ty<'tcx>;

impl<'tcx> Tr<'_, 'tcx> {
    fn ity(&self, t: rustc_public::ty::Ty) -> ITy<'tcx> {
        rustc_internal::internal(self.tcx, t)
    }

    /// Whether a value of type `t` can hold a pointer a query may depend on (see `relevant`).
    fn relevant(&mut self, t: ITy<'tcx>) -> bool {
        if !self.p.prune {
            return true;
        }
        relevant(self.tcx, t, false, &self.p.stop, &mut self.relevance, 0)
    }

    fn size(&self, t: ITy<'tcx>) -> u32 {
        let env = rustc_middle::ty::TypingEnv::fully_monomorphized();
        self.tcx
            .layout_of(env.as_query_input(t))
            .map(|l| l.size.bytes() as u32)
            .unwrap_or(TAIL)
    }

    fn local(&mut self, l: usize) -> u32 {
        self.p.obj(Obj::Local(self.f, l))
    }

    /// Records which words of object `o` (a local or temporary of type `ty`) may hold a vtable
    /// or a function (`code_words`), when its type tells.
    fn type_obj(&mut self, o: u32, ty: ITy<'tcx>) {
        let mut words = Vec::new();
        if code_words(self.tcx, ty, 0, &mut words, 0) {
            self.p.typed.insert(o, words);
        }
    }

    /// Translates the body; its parameters and return size.
    fn body(&mut self) -> Option<(Vec<ParamSlot>, u32)> {
        let body = self.body;
        let nargs = body.arg_locals().len();
        let spread = body.spread_arg();
        let mut slots = Vec::new();
        // A closure's body takes its arguments one by one, but it is called through `Fn*`
        // (`call_mut(&mut f, (acc, elt))`): its callers pass them as one tuple, the second
        // argument. Its parameters after `self` are that tuple's fields, at their offsets. (A
        // body with `spread_arg` takes the tuple as one parameter, as its callers pass it.)
        let tupled_from = if spread.is_none() && nargs >= 2 {
            let self_ty = self.ity(body.locals()[1].ty);
            let env = self_ty.builtin_deref(true).unwrap_or(self_ty);
            if matches!(
                env.kind(),
                rustc_middle::ty::Closure(..) | rustc_middle::ty::CoroutineClosure(..)
            ) {
                let tys: Vec<ITy<'tcx>> =
                    (2..=nargs).map(|l| self.ity(body.locals()[l].ty)).collect();
                let tuple = rustc_middle::ty::Ty::new_tup(self.tcx, &tys);
                let env = rustc_middle::ty::TypingEnv::fully_monomorphized();
                let cx = LayoutCx::new(self.tcx, env);
                cx.layout_of(tuple).ok().map(|l| {
                    (0..tys.len())
                        .map(|i| l.fields.offset(i).bytes() as u32)
                        .collect::<Vec<u32>>()
                })
            } else {
                None
            }
        } else {
            None
        };
        for l in 1..=nargs {
            let ty = self.ity(body.locals()[l].ty);
            let size = self.size(ty);
            let local = self.local(l);
            let (arg, part) = match &tupled_from {
                Some(offs) if l >= 2 => (1, Some(offs[l - 2])),
                _ => (l - 1, None),
            };
            slots.push(ParamSlot {
                arg,
                part,
                local,
                size,
            });
        }
        let ret = self.size(self.ity(body.locals()[0].ty));
        // the words of each local that may hold a vtable or a function (the solver drops them
        // elsewhere)
        for l in 0..body.locals().len() {
            let ty = self.ity(body.locals()[l].ty);
            if !self.relevant(ty) {
                continue;
            }
            let o = self.local(l);
            self.type_obj(o, ty);
        }
        for (bb, block) in body.blocks.iter().enumerate() {
            for st in &block.statements {
                match &st.kind {
                    StatementKind::Assign(place, rv) => self.assign(place, rv),
                    StatementKind::Intrinsic(NonDivergingIntrinsic::CopyNonOverlapping(c)) => {
                        self.copy_through(&c.src, &c.dst);
                    }
                    _ => {}
                }
            }
            let _ = bb;
            self.terminator(&block.terminator);
        }
        Some((slots, ret))
    }

    /// `*dst = *src` for pointers `src` and `dst` (a byte copy of what one points to).
    fn copy_through(&mut self, src: &Operand, dst: &Operand) {
        let (Some((so, soff, _)), Some((d, doff, _))) = (self.operand(src), self.operand(dst))
        else {
            return;
        };
        let t = self.p.temp(self.f);
        if let Ok(st) = src.ty(self.body.locals())
            && let Some(pointee) = self.ity(st).builtin_deref(true)
        {
            self.type_copy(t, pointee);
        }
        self.t.load.push((t, 0, so, soff, 0, TAIL));
        self.t.store.push((d, doff, 0, t, 0, TAIL));
    }

    /// Types the temporary of a copy of `T`s: as a `T`, unless `T` is bytes or another scalar
    /// (a byte copy may move any value: the temporary stays untyped).
    fn type_copy(&mut self, t: u32, elem: ITy<'tcx>) {
        use rustc_middle::ty::TyKind as K;
        if !matches!(
            elem.kind(),
            K::Bool | K::Char | K::Int(_) | K::Uint(_) | K::Float(_)
        ) && !elem.is_unit()
        {
            self.type_obj(t, elem);
        }
    }

    /// The location a place designates, with its type.
    fn lvalue(&mut self, place: &Place) -> (Lv, ITy<'tcx>) {
        let mut ty = self.ity(self.body.locals()[place.local].ty);
        let mut lv = Lv::Direct(self.local(place.local), 0);
        let mut variant = None;
        for e in &place.projection {
            match e {
                ProjectionElem::Deref => {
                    let pointee = ty.builtin_deref(true).unwrap_or(ty);
                    lv = match lv {
                        Lv::Direct(o, off) => Lv::Through(o, off, 0),
                        Lv::Through(o, off, inner) => {
                            let t = self.p.temp(self.f);
                            self.type_obj(t, ty);
                            self.t.load.push((t, 0, o, off, inner, 16));
                            Lv::Through(t, 0, 0)
                        }
                    };
                    ty = pointee;
                    variant = None;
                }
                ProjectionElem::Field(i, fty) => {
                    let off = field_offset(self.tcx, ty, variant, *i).unwrap_or(0);
                    lv = match lv {
                        Lv::Direct(o, b) => Lv::Direct(o, b + off),
                        Lv::Through(o, b, inner) => Lv::Through(o, b, inner + off),
                    };
                    ty = self.ity(*fty);
                    variant = None;
                }
                ProjectionElem::Downcast(v) => {
                    variant = Some(rustc_internal::internal(self.tcx, v));
                }
                ProjectionElem::Index(_)
                | ProjectionElem::ConstantIndex { .. }
                | ProjectionElem::Subslice { .. } => {
                    // every element at the first's offsets
                    if !matches!(e, ProjectionElem::Subslice { .. }) {
                        ty = match ty.kind() {
                            rustc_middle::ty::Array(t, _) | rustc_middle::ty::Slice(t) => *t,
                            _ => ty,
                        };
                    }
                    variant = None;
                }
                ProjectionElem::OpaqueCast(t) => {
                    ty = self.ity(*t);
                }
            }
        }
        (lv, ty)
    }

    /// The location holding an operand's value and its size (`None`: holds no pointer).
    fn operand(&mut self, op: &Operand) -> Option<(u32, u32, u32)> {
        match op {
            Operand::Copy(p) | Operand::Move(p) => {
                let (lv, ty) = self.lvalue(p);
                if !self.relevant(ty) {
                    return None;
                }
                let size = self.size(ty);
                Some(match lv {
                    Lv::Direct(o, off) => (o, off, size),
                    Lv::Through(o, off, inner) => {
                        let t = self.p.temp(self.f);
                        self.type_obj(t, ty);
                        self.t.load.push((t, 0, o, off, inner, size));
                        (t, 0, size)
                    }
                })
            }
            Operand::Constant(c) => self.constant(c),
            Operand::RuntimeChecks(_) => None,
        }
    }

    /// A constant: a temporary holding the pointers its value has.
    fn constant(&mut self, c: &ConstOperand) -> Option<(u32, u32, u32)> {
        use rustc_middle::mir::ConstValue;
        let tcx = self.tcx;
        let ty = self.ity(c.ty());
        if !self.relevant(ty) {
            return None;
        }
        let size = self.size(ty);
        let k = rustc_internal::internal(tcx, c.const_.clone());
        let env = rustc_middle::ty::TypingEnv::fully_monomorphized();
        let span = rustc_internal::internal(tcx, c.span);
        let t = self.p.temp(self.f);
        self.type_obj(t, ty);
        match k.eval(tcx, env, span) {
            Ok(ConstValue::Scalar(rustc_middle::mir::interpret::Scalar::Ptr(ptr, _))) => {
                let (prov, _) = ptr.into_raw_parts();
                let pointee = ty.builtin_deref(true);
                if let Some(o) = self.p.global(tcx, prov.alloc_id(), pointee) {
                    self.t.addr.push((t, 0, o, 0));
                }
            }
            Ok(ConstValue::Scalar(_)) | Ok(ConstValue::ZeroSized) => return None,
            Ok(ConstValue::Slice { alloc_id, .. }) => {
                let pointee = ty.builtin_deref(true);
                if let Some(o) = self.p.global(tcx, alloc_id, pointee) {
                    self.t.addr.push((t, 0, o, 0));
                }
            }
            Ok(ConstValue::Indirect { alloc_id, offset }) => {
                let alloc = tcx.global_alloc(alloc_id).unwrap_memory();
                for (off, prov) in alloc.inner().provenance().ptrs().iter() {
                    let Some(rel) = off.bytes().checked_sub(offset.bytes()) else {
                        continue;
                    };
                    if rel >= size as u64 {
                        continue;
                    }
                    let rel = norm_offset(tcx, ty, rel).unwrap_or(rel) as u32;
                    let pointee = pointee_at(tcx, ty, rel as u64);
                    if let Some(o) = self.p.global(tcx, prov.alloc_id(), pointee) {
                        self.t.addr.push((t, rel, o, 0));
                    }
                }
            }
            Err(_) => {
                // a constant that does not evaluate here: anything
                self.t.havocked.push((t, 0, size));
            }
        }
        Some((t, 0, size))
    }

    /// Writes the value at location `src` into `dst`.
    fn write(&mut self, dst: Lv, src: (u32, u32), size: u32) {
        match dst {
            Lv::Direct(d, doff) => self.t.copy.push((d, doff, src.0, src.1, size)),
            Lv::Through(o, off, inner) => self.t.store.push((o, off, inner, src.0, src.1, size)),
        }
    }

    /// Writes a pointer to location `target` into `dst`.
    fn write_addr(&mut self, dst: Lv, target: (u32, u32)) {
        match dst {
            Lv::Direct(d, doff) => self.t.addr.push((d, doff, target.0, target.1)),
            Lv::Through(o, off, inner) => {
                let t = self.p.temp(self.f);
                self.t.addr.push((t, 0, target.0, target.1));
                self.t.store.push((o, off, inner, t, 0, 8));
            }
        }
    }

    fn assign(&mut self, place: &Place, rv: &Rvalue) {
        let (dst, dty) = self.lvalue(place);
        // a pointer exposed as an integer (`p as usize`): an integer cast to a pointer
        // (`a as *const T`) may point wherever an exposed pointer did
        if let Rvalue::Cast(CastKind::PointerExposeAddress, op, _) = rv {
            if let Some((o, off, _)) = self.operand(op) {
                let x = self.p.obj(Obj::Exposed);
                self.t.copy.push((x, 0, o, off, 8));
            }
            return;
        }
        if !self.relevant(dty) {
            return;
        }
        let dsize = self.size(dty);
        match rv {
            Rvalue::Use(op, _) | Rvalue::Repeat(op, _) => {
                if let Some((o, off, size)) = self.operand(op) {
                    let size = if matches!(rv, Rvalue::Repeat(..)) {
                        size
                    } else {
                        dsize.min(size)
                    };
                    self.write(dst, (o, off), size);
                }
            }
            Rvalue::Cast(kind, op, _) => {
                match kind {
                    CastKind::PointerCoercion(PointerCoercion::ReifyFnPointer(_)) => {
                        if let Ok(t) = op.ty(self.body.locals())
                            && let Some(RigidTy::FnDef(def, args)) = t.kind().rigid()
                            && let Ok(i) = Instance::resolve_for_fn_ptr(*def, args)
                        {
                            let n = self.p.inst(i);
                            let fo = self.p.obj(Obj::Fn(n));
                            self.write_addr(dst, (fo, 0));
                        }
                        return;
                    }
                    CastKind::PointerCoercion(PointerCoercion::ClosureFnPointer(_)) => {
                        if let Ok(t) = op.ty(self.body.locals())
                            && let Some(RigidTy::Closure(def, args)) = t.kind().rigid()
                            && let Ok(i) = Instance::resolve_closure(
                                *def,
                                args,
                                rustc_public::ty::ClosureKind::FnOnce,
                            )
                        {
                            let n = self.p.inst(i);
                            let fo = self.p.obj(Obj::Fn(n));
                            self.write_addr(dst, (fo, 0));
                        }
                        return;
                    }
                    CastKind::PointerCoercion(PointerCoercion::Unsize) => {
                        // (a `dyn` coerced to the same principal trait, as MIR does again at a
                        // function's return, `Box<dyn Tr>` to `Box<dyn Tr>`, or an auto trait
                        // dropped: the vtable is the source's, which the copy below carries)
                        if let Ok(src) = op.ty(self.body.locals())
                            && let Some((c, d)) = unsize_pair(self.tcx, self.ity(src), dty)
                            && !same_principal(c, d)
                            && let Some(vt) = self.p.coerced(self.tcx, c, d)
                        {
                            // the data pointer, then the vtable in the metadata word
                            if let Some((o, off, _)) = self.operand(op) {
                                self.write(dst, (o, off), 8);
                            }
                            let meta = match dst {
                                Lv::Direct(d, doff) => Lv::Direct(d, doff + 8),
                                Lv::Through(p, poff, inner) => Lv::Through(p, poff, inner + 8),
                            };
                            self.write_addr(meta, (vt, 0));
                            return;
                        }
                    }
                    CastKind::PointerWithExposedProvenance => {
                        let x = self.p.obj(Obj::Exposed);
                        self.write(dst, (x, 0), 8);
                        return;
                    }
                    _ => {}
                }
                if let Some((o, off, size)) = self.operand(op) {
                    self.write(dst, (o, off), dsize.min(size));
                }
            }
            Rvalue::CopyForDeref(p) | Rvalue::Reborrow(_, _, p) => {
                let op = Operand::Copy(p.clone());
                if let Some((o, off, size)) = self.operand(&op) {
                    self.write(dst, (o, off), dsize.min(size));
                }
            }
            Rvalue::Ref(_, _, q) | Rvalue::AddressOf(_, q) => {
                let (lv, qty) = self.lvalue(q);
                match lv {
                    Lv::Direct(o, off) => self.write_addr(dst, (o, off)),
                    Lv::Through(o, off, inner) => {
                        let t = self.p.temp(self.f);
                        self.type_obj(t, rustc_middle::ty::Ty::new_mut_ptr(self.tcx, qty));
                        self.t.addr_deref.push((t, 0, o, off, inner));
                        // a reference to an unsized place (`&mut **b` for a `Box<dyn Tr>`, a
                        // slice) carries the metadata of the pointer it is reached through: the
                        // vtable a `dyn` call dispatches on
                        if matches!(
                            qty.kind(),
                            rustc_middle::ty::Dynamic(..)
                                | rustc_middle::ty::Slice(_)
                                | rustc_middle::ty::Str
                        ) {
                            self.t.copy.push((t, 8, o, off + 8, 8));
                            self.write(dst, (t, 0), 16);
                        } else {
                            self.write(dst, (t, 0), 8);
                        }
                    }
                }
            }
            Rvalue::ThreadLocalRef(item) => {
                let def = rustc_internal::internal(self.tcx, item.def_id());
                let o = self.p.read_static(self.tcx, def);
                self.write_addr(dst, (o, 0));
            }
            Rvalue::Aggregate(kind, ops) => {
                let variant = match kind {
                    AggregateKind::Adt(_, v, ..) => Some(rustc_internal::internal(self.tcx, v)),
                    _ => None,
                };
                let is_enum = matches!(dty.kind(), rustc_middle::ty::Adt(a, _) if a.is_enum());
                let array = matches!(kind, AggregateKind::Array(_));
                let active = match kind {
                    AggregateKind::Adt(_, _, _, _, Some(f)) => Some(*f),
                    _ => None,
                };
                for (i, op) in ops.iter().enumerate() {
                    let off = if array {
                        0
                    } else {
                        let idx = active.unwrap_or(i);
                        field_offset(self.tcx, dty, if is_enum { variant } else { None }, idx)
                            .unwrap_or(0)
                    };
                    if let Some((o, soff, size)) = self.operand(op) {
                        let d = match dst {
                            Lv::Direct(d, doff) => Lv::Direct(d, doff + off),
                            Lv::Through(p, poff, inner) => Lv::Through(p, poff, inner + off),
                        };
                        self.write(d, (o, soff), size);
                    }
                }
            }
            Rvalue::BinaryOp(BinOp::Offset, a, _) => {
                if let Some((o, off, size)) = self.operand(a) {
                    self.write(dst, (o, off), size);
                }
            }
            _ => {}
        }
    }

    fn terminator(&mut self, term: &rustc_public::mir::Terminator) {
        match &term.kind {
            TerminatorKind::Call {
                func,
                args,
                destination,
                ..
            } => {
                self.call(func, args, destination, term.source_info.span);
            }
            // dropping a place runs its drop glue on a pointer to it: a `Drop` impl may move
            // the pointers the value holds
            TerminatorKind::Drop { place, .. } => {
                self.line = term.source_info.span.get_lines().start_line as u32;
                let Ok(ty) = place.ty(self.body.locals()) else {
                    return;
                };
                let inst = Instance::resolve_drop_in_place(ty);
                if inst.is_empty_shim() {
                    return;
                }
                let (lv, qty) = self.lvalue(place);
                if !self.relevant(qty) {
                    return;
                }
                let t = self.p.temp(self.f);
                self.type_obj(t, rustc_middle::ty::Ty::new_mut_ptr(self.tcx, qty));
                match lv {
                    Lv::Direct(o, off) => self.t.addr.push((t, 0, o, off)),
                    Lv::Through(o, off, inner) => self.t.addr_deref.push((t, 0, o, off, inner)),
                }
                let g = self.p.inst(inst);
                self.p.drops.insert(g);
                self.t.calls.push(Call {
                    callee: Callee::Inst(inst),
                    args: vec![Some((t, 0, 8))],
                    dest: None,
                    line: self.line,
                });
            }
            TerminatorKind::InlineAsm { operands, .. } => {
                for op in operands {
                    for o in [&op.in_value, &op.out_place.clone().map(Operand::Copy)]
                        .into_iter()
                        .flatten()
                    {
                        if let Some(a) = self.operand(o) {
                            self.t.havoc_arg.push(a);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn call(
        &mut self,
        func: &Operand,
        args: &[Operand],
        destination: &Place,
        span: rustc_public::ty::Span,
    ) {
        self.line = span.get_lines().start_line as u32;
        let arg_locs: Vec<Option<(u32, u32, u32)>> = args.iter().map(|a| self.operand(a)).collect();
        let (dlv, dty) = self.lvalue(destination);
        let dsize = self.size(dty);
        // the result in a temporary, then written to the destination (when it can hold a
        // pointer a query may depend on)
        let t = self.p.temp(self.f);
        self.type_obj(t, dty);
        let dest = if self.relevant(dty) {
            self.write(dlv, (t, 0), dsize);
            Some((t, 0, dsize))
        } else {
            None
        };
        let Ok(fty) = func.ty(self.body.locals()) else {
            self.p.havoc_why("callee type not converted".into());
            self.t.havoc_call(&arg_locs, dest);
            return;
        };
        match fty.kind().rigid() {
            Some(RigidTy::FnDef(def, gargs)) => {
                let Ok(inst) = Instance::resolve(*def, gargs) else {
                    self.p.havoc_why(format!("unresolved: {}", def.name()));
                    self.t.havoc_call(&arg_locs, dest);
                    return;
                };
                match inst.kind {
                    InstanceKind::Intrinsic => self.intrinsic(&inst, &arg_locs, dest),
                    InstanceKind::Virtual { idx } => {
                        // dispatched on the vtable the receiver's fat pointer holds
                        match arg_locs.first().copied().flatten() {
                            Some((ro, roff, _)) => self.t.calls.push(Call {
                                callee: Callee::Virtual(ro, roff, idx),
                                args: arg_locs,
                                dest,
                                line: self.line,
                            }),
                            None => {
                                self.p.havoc_why("dyn call, receiver not a place".into());
                                self.t.havoc_call(&arg_locs, dest)
                            }
                        }
                    }
                    _ => {
                        let krate = rustc_internal::internal(self.tcx, inst.def.def_id()).krate;
                        if self.p.stop.contains(&krate) {
                            // at the callee expression, as the walk places the call's site:
                            // a function item's own span (`UnboundKey::new`, `.encrypt`)
                            let at = match func {
                                Operand::Constant(c) => crate::locate_stable(self.tcx, c.span).0,
                                _ => {
                                    let call = rustc_internal::internal(self.tcx, span);
                                    let callee = crate::callee_span(self.tcx, call).unwrap_or(call);
                                    crate::locate(self.tcx, callee).0
                                }
                            };
                            let pointees = args
                                .iter()
                                .map(|a| {
                                    let t = self.ity(a.ty(self.body.locals()).ok()?);
                                    match pointee_at(self.tcx, t, 0)?.kind() {
                                        rustc_middle::ty::Adt(def, _) => Some(def.did()),
                                        _ => None,
                                    }
                                })
                                .collect();
                            let direct = args
                                .iter()
                                .map(|a| {
                                    a.ty(self.body.locals())
                                        .ok()
                                        .is_some_and(|t| self.ity(t).builtin_deref(true).is_some())
                                })
                                .collect();
                            self.t.queries.push(Query {
                                at,
                                callee: inst.name(),
                                callee_path: crate::path_of(
                                    self.tcx,
                                    rustc_internal::internal(self.tcx, def.def_id()),
                                ),
                                owner: self.p.insts[self.f as usize].mangled_name(),
                                owner_def: crate::def_hash(
                                    self.tcx,
                                    rustc_internal::internal(
                                        self.tcx,
                                        self.p.insts[self.f as usize].def.def_id(),
                                    ),
                                ),
                                args: arg_locs.clone(),
                                live: false,
                                copy: (0, 0),
                                pointees,
                                direct,
                            });
                        }
                        // the allocator's other entry points: freeing writes nothing a pointer can be
                        // in; reallocating keeps the object
                        let name = inst.name();
                        if name.ends_with("__rust_dealloc")
                            || name.contains("__rust_no_alloc_shim_is_unstable")
                            || name.ends_with("__rust_alloc_error_handler")
                        {
                            return;
                        }
                        if name.ends_with("__rust_realloc") {
                            if let Some(Some((o, off, _))) = arg_locs.first() {
                                self.t.copy.push((t, 0, *o, *off, 8));
                            }
                            return;
                        }
                        if is_alloc(&inst) {
                            let n = self.p.temps + 1;
                            self.p.temps = n;
                            let h = self.p.obj(Obj::Heap(self.f, n));
                            self.t.addr.push((t, 0, h, 0));
                            return;
                        }
                        self.t.calls.push(Call {
                            callee: Callee::Inst(inst),
                            args: arg_locs,
                            dest,
                            line: self.line,
                        });
                    }
                }
            }
            Some(RigidTy::FnPtr(_)) => {
                if let Some((o, off, _)) = self.operand(func) {
                    self.t.calls.push(Call {
                        callee: Callee::Ptr(o, off),
                        args: arg_locs,
                        dest,
                        line: self.line,
                    });
                } else {
                    self.t.havoc_call(&arg_locs, dest);
                }
            }
            _ => {
                self.p.havoc_why("callee of another kind".into());
                self.t.havoc_call(&arg_locs, dest)
            }
        }
    }

    /// The compiler's intrinsics: those that move pointers, by what they do; any other that is
    /// given pointers is not followed.
    fn intrinsic(
        &mut self,
        inst: &Instance,
        args: &[Option<(u32, u32, u32)>],
        dest: Option<(u32, u32, u32)>,
    ) {
        let name = inst.intrinsic_name().unwrap_or_default();
        let a = |k: usize| args.get(k).copied().flatten();
        let (dt, _, dsize) = dest.unwrap_or((0, 0, 0));
        match name.as_str() {
            "transmute"
            | "transmute_unchecked"
            | "offset"
            | "arith_offset"
            | "ptr_mask"
            | "black_box"
            | "assume_init" => {
                if let Some((o, off, size)) = a(0) {
                    self.t.copy.push((dt, 0, o, off, dsize.min(size)));
                }
            }
            "read_via_copy" | "volatile_load" | "unaligned_volatile_load" => {
                if let Some((o, off, _)) = a(0) {
                    self.t.load.push((dt, 0, o, off, 0, dsize));
                }
            }
            "write_via_move" | "volatile_store" | "unaligned_volatile_store" => {
                if let (Some((p, poff, _)), Some((s, soff, size))) = (a(0), a(1)) {
                    self.t.store.push((p, poff, 0, s, soff, size));
                }
            }
            "copy_nonoverlapping"
            | "copy"
            | "volatile_copy_memory"
            | "volatile_copy_nonoverlapping_memory" => {
                if let (Some((s, soff, _)), Some((d, doff, _))) = (a(0), a(1)) {
                    let t = self.p.temp(self.f);
                    if let Some(rustc_public::ty::GenericArgKind::Type(e)) = inst.args().0.first() {
                        let e = self.ity(*e);
                        self.type_copy(t, e);
                    }
                    self.t.load.push((t, 0, s, soff, 0, TAIL));
                    self.t.store.push((d, doff, 0, t, 0, TAIL));
                }
            }
            n if n.starts_with("atomic_load") => {
                if let Some((o, off, _)) = a(0) {
                    self.t.load.push((dt, 0, o, off, 0, dsize));
                }
            }
            n if n.starts_with("atomic_store") => {
                if let (Some((p, poff, _)), Some((s, soff, size))) = (a(0), a(1)) {
                    self.t.store.push((p, poff, 0, s, soff, size));
                }
            }
            // read-modify-write on integers (`fetch_add`, a reference count): no new pointer
            n if [
                "atomic_xadd",
                "atomic_xsub",
                "atomic_and",
                "atomic_or",
                "atomic_xor",
                "atomic_nand",
                "atomic_max",
                "atomic_min",
                "atomic_umax",
                "atomic_umin",
            ]
            .iter()
            .any(|p| n.starts_with(p)) =>
            {
                if let Some((o, off, _)) = a(0) {
                    self.t.load.push((dt, 0, o, off, 0, dsize));
                }
            }
            "typed_swap_nonoverlapping" => {
                if let (Some((x, xoff, _)), Some((y, yoff, _))) = (a(0), a(1)) {
                    let (tx, ty) = (self.p.temp(self.f), self.p.temp(self.f));
                    self.t.load.push((tx, 0, x, xoff, 0, TAIL));
                    self.t.load.push((ty, 0, y, yoff, 0, TAIL));
                    self.t.store.push((x, xoff, 0, ty, 0, TAIL));
                    self.t.store.push((y, yoff, 0, tx, 0, TAIL));
                }
            }
            // `catch_unwind(try_fn, data, catch_fn)`: calls `try_fn(data)`
            "catch_unwind" => {
                if let Some((o, off, _)) = a(0) {
                    self.t.calls.push(Call {
                        callee: Callee::Ptr(o, off),
                        args: vec![a(1)],
                        dest: None,
                        line: self.line,
                    });
                }
            }
            n if n.starts_with("atomic_xchg") || n.starts_with("atomic_cxchg") => {
                if let Some((p, poff, _)) = a(0) {
                    self.t.load.push((dt, 0, p, poff, 0, dsize));
                    for k in 1..args.len() {
                        if let Some((s, soff, size)) = a(k) {
                            self.t.store.push((p, poff, 0, s, soff, size));
                        }
                    }
                }
            }
            "select_unpredictable" => {
                for k in 1..3 {
                    if let Some((o, off, size)) = a(k) {
                        self.t.copy.push((dt, 0, o, off, dsize.min(size)));
                    }
                }
            }
            "slice_get_unchecked" => {
                if let Some((o, off, _)) = a(0) {
                    self.t.copy.push((dt, 0, o, off, 8));
                }
            }
            // a pointer from data and metadata (a vtable for `dyn`), and the metadata of one
            "aggregate_raw_ptr" => {
                if let Some((o, off, _)) = a(0) {
                    self.t.copy.push((dt, 0, o, off, 8));
                }
                if let Some((o, off, _)) = a(1) {
                    self.t.copy.push((dt, 8, o, off, 8));
                }
            }
            "ptr_metadata" => {
                if let Some((o, off, _)) = a(0) {
                    self.t.copy.push((dt, 0, o, off + 8, 8));
                }
            }
            // no pointer moves: sizes, arithmetic, comparisons, hints, checks, byte fills
            n if PURE.contains(&n) || PURE_PREFIX.iter().any(|p| n.starts_with(p)) => {}
            n => {
                self.p.havoc_why(format!("intrinsic: {n}"));
                self.t.havoc_call(args, dest);
            }
        }
    }
}

/// Intrinsics that move no pointer and write nothing a pointer can be in.
const PURE: &[&str] = &[
    "discriminant_value",
    "size_of_val",
    "align_of_val",
    "min_align_of_val",
    "size_of",
    "align_of",
    "ptr_guaranteed_cmp",
    "ptr_offset_from",
    "ptr_offset_from_unsigned",
    "compare_bytes",
    "raw_eq",
    "type_name",
    "type_id",
    "type_id_eq",
    "needs_drop",
    "likely",
    "unlikely",
    "cold_path",
    "assume",
    "ub_checks",
    "contract_checks",
    "abort",
    "unreachable",
    "exact_div",
    "ctpop",
    "ctlz",
    "ctlz_nonzero",
    "cttz",
    "cttz_nonzero",
    "bswap",
    "bitreverse",
    "rotate_left",
    "rotate_right",
    "three_way_compare",
    "write_bytes",
    "volatile_set_memory",
    "forget",
    "ptr_metadata",
    "variant_count",
    "is_val_statically_known",
    "disjoint_bitor",
    "carrying_mul_add",
    "breakpoint",
    "prefetch_read_data",
    "prefetch_write_data",
    "overflow_checks",
    "const_eval_select_rt",
];
const PURE_PREFIX: &[&str] = &[
    "add_with_overflow",
    "sub_with_overflow",
    "mul_with_overflow",
    "wrapping_",
    "saturating_",
    "unchecked_",
    "float_to_int",
    "fadd",
    "fsub",
    "fmul",
    "fdiv",
    "frem",
    "sqrt",
    "fabs",
    "floor",
    "ceil",
    "trunc",
    "round",
    "copysign",
    "minnum",
    "maxnum",
    "fma",
    "pow",
    "exp",
    "log",
    "sin",
    "cos",
    "simd_",
    "atomic_fence",
    "atomic_singlethreadfence",
];

/// The allocator's entry points: each call makes a fresh heap object.
fn is_alloc(inst: &Instance) -> bool {
    let n = inst.name();
    n.ends_with("__rust_alloc")
        || n.ends_with("__rust_alloc_zeroed")
        || n == "alloc::alloc::exchange_malloc"
        || n.ends_with("::__rdl_alloc")
}

/// Field `i`'s offset in a value of type `ty` (of variant `variant` for an enum).
fn field_offset<'tcx>(
    tcx: TyCtxt<'tcx>,
    ty: ITy<'tcx>,
    variant: Option<rustc_abi::VariantIdx>,
    i: rustc_public::mir::FieldIdx,
) -> Option<u32> {
    let env = rustc_middle::ty::TypingEnv::fully_monomorphized();
    let cx = LayoutCx::new(tcx, env);
    let l = cx.layout_of(ty).ok()?;
    let l = match variant {
        Some(v) => l.for_variant(&cx, v),
        None => l,
    };
    if i >= l.fields.count() {
        return None;
    }
    Some(l.fields.offset(i).bytes() as u32)
}

/// An offset in a value of type `ty`, with array elements folded onto the first.
fn norm_offset<'tcx>(tcx: TyCtxt<'tcx>, ty: ITy<'tcx>, off: u64) -> Option<u64> {
    norm(tcx, ty, off, 0)
}

fn norm<'tcx>(tcx: TyCtxt<'tcx>, ty: ITy<'tcx>, off: u64, depth: usize) -> Option<u64> {
    if depth > 12 {
        return Some(off);
    }
    let env = rustc_middle::ty::TypingEnv::fully_monomorphized();
    let cx = LayoutCx::new(tcx, env);
    match ty.kind() {
        rustc_middle::ty::Array(e, _) | rustc_middle::ty::Slice(e) => {
            let el = cx.layout_of(*e).ok()?;
            let stride = el.size.bytes().max(1);
            norm(tcx, *e, off % stride, depth + 1)
        }
        rustc_middle::ty::Str => Some(0),
        _ => {
            let l = cx.layout_of(ty).ok()?;
            let mut layouts = vec![l];
            if let rustc_abi::Variants::Multiple { variants, .. } = &l.variants {
                layouts.extend(variants.indices().map(|v| l.for_variant(&cx, v)));
            }
            for l in layouts {
                for i in 0..l.fields.count() {
                    let fo = l.fields.offset(i).bytes();
                    let f = l.field(&cx, i);
                    if fo <= off && off < fo + f.size.bytes() {
                        return Some(fo + norm(tcx, f.ty, off - fo, depth + 1)?);
                    }
                }
            }
            Some(off)
        }
    }
}

/// A word that may hold a vtable (`CODE_VT`) or a function (`CODE_FN`).
pub(crate) const CODE_VT: u8 = 1;
pub(crate) const CODE_FN: u8 = 2;
/// A word that may hold a pointer to data.
pub(crate) const CODE_PTR: u8 = 4;

/// The words of a value of type `ty` (at `base`) that may hold a pointer, and of what: data
/// (any pointer), a vtable (the metadata word of a `dyn` pointer), a function (a function
/// pointer); words whose type does not say (erased pointers) may hold any. `false` when the layout does not tell (a type it
/// cannot lay out): any word may hold either.
fn code_words<'tcx>(
    tcx: TyCtxt<'tcx>,
    ty: ITy<'tcx>,
    base: u64,
    out: &mut Vec<(u32, u8)>,
    depth: usize,
) -> bool {
    use rustc_middle::ty::TyKind as K;
    if depth > 12 {
        return false;
    }
    match ty.kind() {
        K::Bool | K::Char | K::Int(_) | K::Uint(_) | K::Float(_) | K::Never | K::FnDef(..) => true,
        K::FnPtr(..) => {
            out.push((base as u32, CODE_FN));
            true
        }
        K::Ref(_, t, _) | K::RawPtr(t, _) => {
            let erased = match t.kind() {
                K::Uint(rustc_middle::ty::UintTy::U8)
                | K::Int(rustc_middle::ty::IntTy::I8)
                | K::Foreign(_) => true,
                K::Tuple(ts) => ts.is_empty(),
                _ => false,
            };
            let kind = if erased {
                CODE_PTR | CODE_VT | CODE_FN
            } else {
                CODE_PTR
            };
            out.push((base as u32, kind));
            if matches!(t.kind(), K::Dynamic(..)) {
                out.push(((base + 8) as u32, CODE_VT));
            }
            true
        }
        // (elements share the first's words)
        K::Array(e, _) => code_words(tcx, *e, base, out, depth + 1),
        // (a union's word may hold what any of its fields may: they all sit at offset 0, as the
        // layout below gives them)
        _ => {
            let env = rustc_middle::ty::TypingEnv::fully_monomorphized();
            let cx = LayoutCx::new(tcx, env);
            let Ok(l) = cx.layout_of(ty) else {
                return false;
            };
            let mut layouts = vec![l];
            if let rustc_abi::Variants::Multiple { variants, .. } = &l.variants {
                layouts.extend(variants.indices().map(|v| l.for_variant(&cx, v)));
            }
            for l in layouts {
                for i in 0..l.fields.count() {
                    let fo = l.fields.offset(i).bytes();
                    let f = l.field(&cx, i);
                    if !code_words(tcx, f.ty, base + fo, out, depth + 1) {
                        return false;
                    }
                }
            }
            true
        }
    }
}

/// The type a pointer at `off` in a value of type `ty` points to, when the layout tells.
fn pointee_at<'tcx>(tcx: TyCtxt<'tcx>, ty: ITy<'tcx>, off: u64) -> Option<ITy<'tcx>> {
    pointee(tcx, ty, off, 0)
}

fn pointee<'tcx>(tcx: TyCtxt<'tcx>, ty: ITy<'tcx>, off: u64, depth: usize) -> Option<ITy<'tcx>> {
    if depth > 12 {
        return None;
    }
    if off == 0
        && let Some(p) = ty.builtin_deref(true)
    {
        return Some(p);
    }
    let env = rustc_middle::ty::TypingEnv::fully_monomorphized();
    let cx = LayoutCx::new(tcx, env);
    match ty.kind() {
        rustc_middle::ty::Array(e, _) | rustc_middle::ty::Slice(e) => {
            let el = cx.layout_of(*e).ok()?;
            pointee(tcx, *e, off % el.size.bytes().max(1), depth + 1)
        }
        _ => {
            let l = cx.layout_of(ty).ok()?;
            let mut layouts = vec![l];
            if let rustc_abi::Variants::Multiple { variants, .. } = &l.variants {
                layouts.extend(variants.indices().map(|v| l.for_variant(&cx, v)));
            }
            for l in layouts {
                for i in 0..l.fields.count() {
                    let fo = l.fields.offset(i).bytes();
                    let f = l.field(&cx, i);
                    if fo <= off && off < fo + f.size.bytes() {
                        return pointee(tcx, f.ty, off - fo, depth + 1);
                    }
                }
            }
            None
        }
    }
}

/// The concrete and `dyn` types of an unsizing coercion (`&T` to `&dyn Tr`, `Box<T>` to
/// `Box<dyn Tr>`).
fn unsize_pair<'tcx>(
    tcx: TyCtxt<'tcx>,
    src: ITy<'tcx>,
    dst: ITy<'tcx>,
) -> Option<(ITy<'tcx>, ITy<'tcx>)> {
    let (s, d) = tail_pair(tcx, src, dst, 0)?;
    matches!(d.kind(), rustc_middle::ty::Dynamic(..)).then_some((s, d))
}

/// Whether `c` and `d` are `dyn` types of the same principal trait (their vtables are one).
fn same_principal<'tcx>(c: ITy<'tcx>, d: ITy<'tcx>) -> bool {
    let (rustc_middle::ty::Dynamic(cp, ..), rustc_middle::ty::Dynamic(dp, ..)) =
        (c.kind(), d.kind())
    else {
        return false;
    };
    match (cp.principal(), dp.principal()) {
        (Some(a), Some(b)) => a.skip_binder() == b.skip_binder(),
        _ => false,
    }
}

fn tail_pair<'tcx>(
    tcx: TyCtxt<'tcx>,
    src: ITy<'tcx>,
    dst: ITy<'tcx>,
    depth: usize,
) -> Option<(ITy<'tcx>, ITy<'tcx>)> {
    if depth > 6 {
        return None;
    }
    if let (Some(s), Some(d)) = (src.builtin_deref(true), dst.builtin_deref(true)) {
        return Some((s, d));
    }
    // a smart pointer: the field that differs
    if let (rustc_middle::ty::Adt(sa, sargs), rustc_middle::ty::Adt(da, dargs)) =
        (src.kind(), dst.kind())
        && sa == da
    {
        for f in sa.all_fields() {
            let (sf, df) = (
                f.ty(tcx, sargs).skip_normalization(),
                f.ty(tcx, dargs).skip_normalization(),
            );
            if sf != df {
                return tail_pair(tcx, sf, df, depth + 1);
            }
        }
    }
    None
}

/// Whether a value of type `ty` can hold a pointer a query may depend on: a type of a stop
/// crate (the knowledge base's), anything holding one (a field, an element, a variant's field,
/// the `T` of `PhantomData<T>`), a pointer to one; also whatever can carry any pointer: `dyn`,
/// function pointers, coroutines, and raw pointers to bytes or `()` (allocators and
/// `RawVecInner` pass every heap pointer as one). References to bytes, `char`s and `str` are
/// data, and so are integers: a pointer becomes one only by an exposing cast, which the
/// translation follows (`exposed`). A container that names its element type only through a
/// `PhantomData<T>` marker (`RawVec<T>`, hashbrown's `RawTable<T>`) keeps `T`s behind its
/// erased pointers: it is relevant when `T` is (`strict`: erased pointers inside it do not
/// count). A type met again while computing it is relevant.
fn relevant<'tcx>(
    tcx: TyCtxt<'tcx>,
    ty: ITy<'tcx>,
    strict: bool,
    stop: &HashSet<rustc_span::def_id::CrateNum>,
    cache: &mut HashMap<(ITy<'tcx>, bool), bool>,
    depth: usize,
) -> bool {
    use rustc_middle::ty::TyKind as K;
    if let Some(&r) = cache.get(&(ty, strict)) {
        return r;
    }
    if depth > 10 {
        return true;
    }
    // (in progress: relevant until shown otherwise)
    cache.insert((ty, strict), true);
    let rel = |t: ITy<'tcx>, strict: bool, cache: &mut HashMap<(ITy<'tcx>, bool), bool>| {
        relevant(tcx, t, strict, stop, cache, depth + 1)
    };
    let r = match ty.kind() {
        K::Bool
        | K::Char
        | K::Int(_)
        | K::Uint(_)
        | K::Float(_)
        | K::Str
        | K::Never
        | K::FnDef(..) => false,
        K::Adt(def, args) => {
            if stop.contains(&def.did().krate) {
                true
            } else if def.is_phantom_data() {
                args.types().any(|t| rel(t, strict, cache))
            } else {
                let markers = element_markers(tcx, *def);
                let fields: Vec<(usize, ITy<'tcx>)> = def
                    .all_fields()
                    .enumerate()
                    .map(|(n, f)| (n, f.ty(tcx, args).skip_normalization()))
                    .collect();
                if markers.is_empty() {
                    fields.into_iter().any(|(_, t)| rel(t, strict, cache))
                } else {
                    markers
                        .iter()
                        .any(|(_, p)| rel(args.type_at(*p), strict, cache))
                        || fields
                            .into_iter()
                            .filter(|(n, _)| !markers.iter().any(|(m, _)| m == n))
                            .any(|(_, t)| rel(t, true, cache))
                }
            }
        }
        K::Ref(_, t, _) => rel(*t, strict, cache),
        K::RawPtr(t, _) => {
            let erased = match t.kind() {
                K::Uint(rustc_middle::ty::UintTy::U8)
                | K::Int(rustc_middle::ty::IntTy::I8)
                | K::Foreign(_)
                | K::Dynamic(..) => true,
                K::Tuple(ts) => ts.is_empty(),
                K::Slice(e) => matches!(e.kind(), K::Uint(rustc_middle::ty::UintTy::U8)),
                _ => false,
            };
            (erased && !strict) || rel(*t, strict, cache)
        }
        K::Array(t, _) | K::Slice(t) => rel(*t, strict, cache),
        K::Tuple(ts) => ts.iter().any(|t| rel(t, strict, cache)),
        K::Closure(_, args) => {
            let ups: Vec<ITy<'tcx>> = args.as_closure().upvar_tys().iter().collect();
            ups.into_iter().any(|t| rel(t, strict, cache))
        }
        _ => true,
    };
    cache.insert((ty, strict), r);
    r
}

/// The fields of an ADT that are `PhantomData<P>` markers of a type parameter `P` no other field
/// mentions (`RawVec<T>`'s `_marker`): (field index, parameter index).
fn element_markers<'tcx>(
    tcx: TyCtxt<'tcx>,
    def: rustc_middle::ty::AdtDef<'tcx>,
) -> Vec<(usize, usize)> {
    use rustc_middle::ty::TyKind as K;
    let identity = rustc_middle::ty::GenericArgs::identity_for_item(tcx, def.did());
    let fields: Vec<ITy<'tcx>> = def
        .all_fields()
        .map(|f| f.ty(tcx, identity).skip_normalization())
        .collect();
    let mut out = Vec::new();
    for (n, t) in fields.iter().enumerate() {
        let K::Adt(m, margs) = t.kind() else {
            continue;
        };
        if !m.is_phantom_data() {
            continue;
        }
        let Some(K::Param(p)) = margs.types().next().map(|t| t.kind()) else {
            continue;
        };
        let mentioned = fields.iter().enumerate().any(|(k, f)| {
            k != n
                && f.walk()
                    .any(|a| matches!(a.as_type().map(|t| t.kind()), Some(K::Param(q)) if q == p))
        });
        if !mentioned {
            out.push((n, p.index as usize));
        }
    }
    out
}

/// The public `const` items of a crate (its module tree, re-exports followed once).
fn crate_consts(
    tcx: TyCtxt<'_>,
    krate: rustc_span::def_id::CrateNum,
) -> Vec<rustc_span::def_id::DefId> {
    use rustc_hir::def::{DefKind, Res};
    let mut out = Vec::new();
    let mut seen = HashSet::default();
    let mut stack = vec![krate.as_def_id()];
    while let Some(m) = stack.pop() {
        if !seen.insert(m) {
            continue;
        }
        for child in tcx.module_children(m) {
            match child.res {
                Res::Def(DefKind::Mod, d) if d.krate == krate => stack.push(d),
                Res::Def(DefKind::Const, d) if d.krate == krate => out.push(d),
                _ => {}
            }
        }
    }
    out.sort_by_key(|d| d.index.as_u32());
    out.dedup();
    out
}

/// Whether constant item `c` evaluates to the value allocation `m` (of `size` bytes) holds:
/// equal bytes outside pointers, and pointers to equal things.
fn const_value_is(
    tcx: TyCtxt<'_>,
    c: rustc_span::def_id::DefId,
    m: &rustc_middle::mir::interpret::Allocation,
    size: usize,
) -> bool {
    use rustc_middle::mir::ConstValue;
    match tcx.const_eval_poly(c) {
        Ok(ConstValue::Indirect { alloc_id, offset }) => {
            let a = tcx.global_alloc(alloc_id).unwrap_memory();
            let o = offset.bytes() as usize;
            same_bytes(tcx, a.inner(), o, m, 0, size, 0)
        }
        _ => false,
    }
}

/// Whether `len` bytes of allocation `a` at `ao` and of `b` at `bo` are the same value: bytes
/// outside pointers equal, pointers at the same places, to equal targets.
fn same_bytes(
    tcx: TyCtxt<'_>,
    a: &rustc_middle::mir::interpret::Allocation,
    ao: usize,
    b: &rustc_middle::mir::interpret::Allocation,
    bo: usize,
    len: usize,
    depth: usize,
) -> bool {
    use rustc_middle::mir::interpret::GlobalAlloc;
    if depth > 4 || (a.size().bytes() as usize) < ao + len || (b.size().bytes() as usize) < bo + len
    {
        return false;
    }
    let pa: Vec<(usize, rustc_middle::mir::interpret::AllocId)> = a
        .provenance()
        .ptrs()
        .iter()
        .map(|(o, p)| (o.bytes() as usize, p.alloc_id()))
        .filter(|(o, _)| *o >= ao && *o < ao + len)
        .map(|(o, id)| (o - ao, id))
        .collect();
    let pb: Vec<(usize, rustc_middle::mir::interpret::AllocId)> = b
        .provenance()
        .ptrs()
        .iter()
        .map(|(o, p)| (o.bytes() as usize, p.alloc_id()))
        .filter(|(o, _)| *o >= bo && *o < bo + len)
        .map(|(o, id)| (o - bo, id))
        .collect();
    if pa.len() != pb.len() || pa.iter().zip(&pb).any(|(x, y)| x.0 != y.0) {
        return false;
    }
    let ba = a.inspect_with_uninit_and_ptr_outside_interpreter(ao..ao + len);
    let bb = b.inspect_with_uninit_and_ptr_outside_interpreter(bo..bo + len);
    let ptr = tcx.data_layout.pointer_size().bytes() as usize;
    for i in 0..len {
        if pa.iter().any(|(o, _)| i >= *o && i < *o + ptr) {
            continue;
        }
        if ba[i] != bb[i] {
            return false;
        }
    }
    for ((o, ia), (_, ib)) in pa.iter().zip(&pb) {
        let off = |bytes: &[u8]| {
            let mut w = [0u8; 8];
            w[..ptr].copy_from_slice(&bytes[*o..*o + ptr]);
            u64::from_le_bytes(w) as usize
        };
        let (offa, offb) = (off(ba), off(bb));
        if offa != offb {
            return false;
        }
        let same = match (tcx.global_alloc(*ia), tcx.global_alloc(*ib)) {
            (GlobalAlloc::Static(x), GlobalAlloc::Static(y)) => x == y,
            (GlobalAlloc::Function { instance: x }, GlobalAlloc::Function { instance: y }) => {
                x == y
            }
            (GlobalAlloc::VTable(tx, px), GlobalAlloc::VTable(ty, py)) => tx == ty && px == py,
            (GlobalAlloc::Memory(x), GlobalAlloc::Memory(y)) => {
                let (x, y) = (x.inner(), y.inner());
                x.size() == y.size()
                    && same_bytes(tcx, x, 0, y, 0, x.size().bytes() as usize, depth + 1)
            }
            _ => false,
        };
        if !same {
            return false;
        }
    }
    true
}
