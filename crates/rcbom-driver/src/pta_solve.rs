//! The solver of the points-to constraints (`pta.rs`): a worklist over locations with
//! difference propagation, as hand-written Andersen solvers do (Rupta's and SVF's among them).
//! A location is an object and a byte offset, interned to one id; each has its set of target
//! locations. Copies of byte ranges between objects become edges between their locations (made
//! when a location in the range exists); loads, stores and address computations through a
//! pointer add such copies, or targets, as the pointer's set grows; calls through function
//! pointers and vtables are bound the same way. Cycles of edges are collapsed from time to time
//! (their locations hold equal sets): the members share one representative. `UNKNOWN` (anything)
//! is a target; a havocked byte range of an object holds it at every location in the range,
//! present or created later.

use std::collections::VecDeque;

// (fixed-seed hashing: the same input gives the same objects, merges and answers)
use rustc_data_structures::fx::{FxHashMap as HashMap, FxHashSet as HashSet};

use roaring::RoaringBitmap;

use crate::pta::{CODE_FN, CODE_VT, TAIL, UNKNOWN, at};
use crate::pta_unify::{Bind, Calls, Unify};

/// A range copy: `size` bytes from offset `soff` of a source object into `(d, doff)`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct RangeCopy {
    soff: u32,
    size: u32,
    d: u32,
    doff: u32,
}

/// What happens through a pointer: loads (destination, its offset, offset through the pointer,
/// size), stores (offset through the pointer, source, its offset, size), address computations
/// (destination, its offset, offset through the pointer), calls through it (sites) and `dyn`
/// calls on it (site, slot, the receiver's own location).
#[derive(Default)]
struct Ops {
    loads: Vec<(u32, u32, u32, u32)>,
    stores: Vec<(u32, u32, u32, u32)>,
    derefs: Vec<(u32, u32, u32)>,
    icalls: Vec<u32>,
    vcalls: Vec<(u32, u32, u32)>,
}

/// The range copies of one object by the words they cover (small copies) or listed (large).
#[derive(Default)]
struct CopyIndex {
    words: HashMap<u32, Vec<u32>>,
    big: Vec<u32>,
}

impl CopyIndex {
    fn add(&mut self, i: u32, c: RangeCopy) {
        if c.size <= 128 {
            for w in c.soff / 8..=(c.soff.saturating_add(c.size) - 1) / 8 {
                self.words.entry(w).or_default().push(i);
            }
        } else {
            self.big.push(i);
        }
    }
}

/// A set of locations: a sorted vector while small, a compressed bitmap beyond.
enum PSet {
    Small(Vec<u32>),
    Big(RoaringBitmap),
}

impl Default for PSet {
    fn default() -> Self {
        PSet::Small(Vec::new())
    }
}

const SMALL: usize = 32;

impl PSet {
    fn insert(&mut self, t: u32) -> bool {
        match self {
            PSet::Small(v) => match v.binary_search(&t) {
                Ok(_) => false,
                Err(i) => {
                    if v.len() < SMALL {
                        v.insert(i, t);
                    } else {
                        let mut b: RoaringBitmap = v.iter().copied().collect();
                        b.insert(t);
                        *self = PSet::Big(b);
                    }
                    true
                }
            },
            PSet::Big(b) => b.insert(t),
        }
    }

    fn contains(&self, t: u32) -> bool {
        match self {
            PSet::Small(v) => v.binary_search(&t).is_ok(),
            PSet::Big(b) => b.contains(t),
        }
    }

    fn len(&self) -> usize {
        match self {
            PSet::Small(v) => v.len(),
            PSet::Big(b) => b.len() as usize,
        }
    }

    fn to_vec(&self) -> Vec<u32> {
        match self {
            PSet::Small(v) => v.clone(),
            PSet::Big(b) => b.iter().collect(),
        }
    }

    fn iter(&self) -> Box<dyn Iterator<Item = u32> + '_> {
        match self {
            PSet::Small(v) => Box::new(v.iter().copied()),
            PSet::Big(b) => Box::new(b.iter()),
        }
    }
}

#[derive(Default)]
pub(crate) struct Solver {
    // inputs (see `Pta`)
    pub(crate) addr: Vec<(u32, u32, u32, u32)>,
    pub(crate) copy: Vec<(u32, u32, u32, u32, u32)>,
    pub(crate) load: Vec<(u32, u32, u32, u32, u32, u32)>,
    pub(crate) store: Vec<(u32, u32, u32, u32, u32, u32)>,
    pub(crate) addr_deref: Vec<(u32, u32, u32, u32, u32)>,
    pub(crate) havoc_arg: Vec<(u32, u32, u32)>,
    pub(crate) havocked: Vec<(u32, u32, u32)>,
    pub(crate) icall: Vec<(u32, u32, u32)>,
    pub(crate) icall_arg: Vec<(u32, u32, u32, u32, u32)>,
    pub(crate) icall_dest: Vec<(u32, u32, u32, u32)>,
    pub(crate) vcall: Vec<(u32, u32, u32, u32)>,
    pub(crate) vt_entry: Vec<(u32, u32, u32)>,
    pub(crate) fn_param: Vec<(u32, u32, u32, bool, u32, u32)>,
    pub(crate) fn_ret: Vec<(u32, u32, u32)>,
    pub(crate) fn_untranslated: Vec<(u32,)>,
    /// Function objects of library bodies: bound per context (`requests`).
    pub(crate) fn_lib: Vec<u32>,
    /// Locations answers read (queries' arguments): made, so that ranges filled from merged
    /// objects or havocked reach them even when no other constraint names them.
    pub(crate) needed: Vec<(u32, u32)>,
    /// Calls through pointers and vtables to library functions not bound yet: (site, function
    /// object), for the caller to make the copy and `bind_to` it.
    pub(crate) requests: Vec<(u32, u32)>,

    // locations, by object
    loc_ids: HashMap<(u32, u32), u32>,
    locs: Vec<(u32, u32)>,
    /// (offset, location), sorted by offset
    obj_locs: Vec<Vec<(u32, u32)>>,
    // per location: its representative (union-find), its targets, those not yet propagated,
    // its edges, and whether code not translated may read it
    rep: Vec<u32>,
    pts: Vec<PSet>,
    delta: Vec<Vec<u32>>,
    queued: Vec<bool>,
    watched: Vec<bool>,
    succ: Vec<Vec<u32>>,
    work: VecDeque<u32>,
    // locations made and not yet given their edges
    fresh: Vec<u32>,
    // range copies by source object
    copies_from: Vec<Vec<RangeCopy>>,
    /// For objects with many range copies: the copies by the words they cover (indices into
    /// `copies_from`), and those too large to index that way.
    copy_idx: HashMap<u32, CopyIndex>,
    copies_n: usize,
    /// A location with more successors than this absorbs those holding exactly its set
    /// (`RCBOM_PTA_FANOUT`, 0: never); the successor count it is checked at next.
    fanout_limit: usize,
    /// Locations with more successors than this are hubs: no merge (of objects, of cycles)
    /// takes them in (`RCBOM_PTA_HUB`, 0: off, the default: on xh, skipping those merges left
    /// the sets they would have shrunk large). Skipping a merge is sound: merging only widens.
    hub_limit: usize,
    hubs_skipped: usize,
    /// Memory pressure: the share of the memory limit (`mem_cap_mb`) this process uses moves
    /// the merge limits down from the configured ones (`base_merge`, `base_code`): level 1 past
    /// 60%, 2 past 75%, 3 past 85%. At level 3 a set holds about one merged object
    /// (unification); at level 2 and up, library copies made in later rounds are shared. Sound:
    /// merging and sharing only widen sets.
    mem_cap_mb: u64,
    pressure: u8,
    /// resident memory at the last structure report (MB)
    last_report_mb: u64,
    base_merge: usize,
    base_code: usize,
    fanout_check: HashMap<u32, usize>,
    fanout_merged: usize,
    // what happens through a pointer, by the (representative) location holding it
    loads_at: HashMap<u32, Vec<(u32, u32, u32, u32)>>,
    stores_at: HashMap<u32, Vec<(u32, u32, u32, u32)>>,
    derefs_at: HashMap<u32, Vec<(u32, u32, u32)>>,
    icalls_at: HashMap<u32, Vec<u32>>,
    /// (site, slot, the receiver's own location: the key may be its cycle's representative)
    vcalls_at: HashMap<u32, Vec<(u32, u32, u32)>>,
    havoc_watch: HashMap<u32, Vec<(u32, u32)>>,
    // calls through pointers and vtables
    site_args: HashMap<u32, Vec<(u32, u32, u32, u32)>>,
    site_dest: HashMap<u32, (u32, u32, u32)>,
    vt: HashMap<(u32, u32), u32>,
    params: HashMap<u32, Vec<(u32, u32, u32, u32)>>,
    rets: HashMap<u32, (u32, u32)>,
    untranslated: HashSet<u32>,
    lib_fns: HashSet<u32>,
    bound: HashSet<(u32, u32)>,
    pub(crate) callee: Vec<(u32, u32)>,
    // havocked ranges by object, and objects code not translated may reach
    havoc: HashMap<u32, Vec<(u32, u32)>>,
    reached: HashSet<u32>,
    u_loc: u32,
    entries: usize,
    edges: usize,
    edges_at_collapse: usize,
    merged: usize,
    rounds: usize,
    steps: u64,
    /// Whether cycles are collapsed (`RCBOM_PTA_COLLAPSE=0` keeps them, for diagnostics).
    collapsing: bool,
    started: Option<std::time::Instant>,
    /// Objects merged into others (union-find over objects: `ofind`), and the objects never
    /// merged (statics, constant memory, functions, vtables: what answers and calls name).
    orep: Vec<u32>,
    pub(crate) fixed: HashSet<u32>,
    /// Objects whose type tells which words may hold a vtable or a function (offset, kinds),
    /// and the vtable and function objects: neither is added to another word of such an object
    /// (type safety), and nothing is loaded from or stored into them (they hold no pointer a
    /// program reads as data).
    pub(crate) typed: HashMap<u32, Vec<(u32, u8)>>,
    pub(crate) vtables: HashSet<u32>,
    pub(crate) fns: HashSet<u32>,
    /// A location whose set holds more than this many objects that may merge has them merged
    /// into one (`RCBOM_PTA_MERGE`, 0: never); the set size at which a location is checked next.
    merge_limit: usize,
    merge_check: HashMap<u32, usize>,
    /// Merged objects are field-insensitive: one location (offset 0) stands for every byte. A
    /// range copy out of one gives each word of the destination range what that location holds
    /// (`fill_range`).
    smashed: HashSet<u32>,
    debug: bool,
    pending_merges: Vec<(u32, Vec<u32>)>,
    /// Functions, and vtables, are grouped likewise when a set holds more than this many of
    /// one kind (`RCBOM_PTA_CODE_MERGE`, 0: never): a group stands for its members, and a call
    /// through it binds every member (`members`, by representative).
    code_limit: usize,
    pending_code: Vec<(u32, Vec<u32>)>,
    members: HashMap<u32, Vec<u32>>,
    code_grouped: usize,
    objs_merged: usize,
    objs_merged_at_collapse: usize,
    /// Time (ms) and work per phase, for the log: edges, pointer operations, collapses, object
    /// merges, settling; target-operation pairs applied, edge pushes, copies made.
    prof: [u128; 5],
    applied: u64,
    /// Inner-loop iterations: locations scanned by range copies, copies scanned by new
    /// locations, locations scanned by fills, by reach/havoc/watch.
    scans: [u64; 4],
    pushed: u64,
    edge_copies: u64,
    /// The unification tier (`pta_unify.rs`), when chosen: it reads the same inputs and call
    /// tables, and answers instead of the inclusion solver.
    unify: Option<Box<Unify>>,
    havocked_sites: HashSet<u32>,
    /// Set when the budget (`RCBOM_PTA_BUDGET` points-to entries) ran out: no answer holds.
    pub(crate) exhausted: bool,
}

impl Solver {
    fn find(&mut self, mut l: u32) -> u32 {
        while self.rep[l as usize] != l {
            let p = self.rep[l as usize];
            self.rep[l as usize] = self.rep[p as usize];
            l = p;
        }
        l
    }

    fn ensure_obj(&mut self, o: u32) {
        let n = o as usize + 1;
        if self.obj_locs.len() < n {
            self.obj_locs.resize_with(n, Vec::new);
            self.copies_from.resize_with(n, Vec::new);
            let k = self.orep.len() as u32;
            self.orep.extend(k..n as u32);
        }
    }

    /// The object `o` was merged into (itself when it was not).
    fn ofind(&mut self, mut o: u32) -> u32 {
        self.ensure_obj(o);
        while self.orep[o as usize] != o {
            let p = self.orep[o as usize];
            self.orep[o as usize] = self.orep[p as usize];
            o = p;
        }
        o
    }

    fn ofind_ro(&self, mut o: u32) -> u32 {
        while (o as usize) < self.orep.len() && self.orep[o as usize] != o {
            o = self.orep[o as usize];
        }
        o
    }

    /// The locations of object `o` at offsets in `[lo, hi)`.
    fn locs_in(&self, o: u32, lo: u32, hi: u32) -> Vec<u32> {
        if lo >= hi {
            return Vec::new();
        }
        let v = &self.obj_locs[o as usize];
        let a = v.partition_point(|(off, _)| *off < lo);
        v[a..]
            .iter()
            .take_while(|(off, _)| *off < hi)
            .map(|(_, l)| *l)
            .collect()
    }

    /// Whether object `s` has range copy `c` already.
    fn has_copy(&self, s: u32, c: &RangeCopy) -> bool {
        let all = &self.copies_from[s as usize];
        match self.copy_idx.get(&s) {
            None => all.contains(c),
            Some(ix) => {
                let v = if c.size <= 128 {
                    ix.words.get(&(c.soff / 8))
                } else {
                    Some(&ix.big)
                };
                v.is_some_and(|v| v.iter().any(|i| all.get(*i as usize) == Some(c)))
            }
        }
    }

    /// What a set holds, by kind (for the log): mergeable objects (distinct objects, targets),
    /// functions, vtables, other fixed objects, `UNKNOWN`.
    fn set_kinds(&self, r: u32) -> String {
        let (mut objs, mut data, mut f, mut v, mut fixed, mut u) =
            (HashSet::default(), 0, 0, 0, 0, 0);
        for t in self.pts[r as usize].iter() {
            let o = self.ofind_ro(self.locs[t as usize].0);
            if o == UNKNOWN {
                u += 1;
            } else if self.fns.contains(&o) {
                f += 1;
            } else if self.vtables.contains(&o) {
                v += 1;
            } else if self.fixed.contains(&o) {
                fixed += 1;
            } else {
                data += 1;
                objs.insert(o);
            }
        }
        format!(
            "data {data} in {} objects, fns {f}, vtables {v}, fixed {fixed}, unknown {u}",
            objs.len()
        )
    }

    /// Whether location `l`'s representative is a hub (`hub_limit`).
    fn is_hub(&self, l: u32) -> bool {
        let mut r = l;
        while self.rep[r as usize] != r {
            r = self.rep[r as usize];
        }
        self.hub_limit > 0 && self.succ[r as usize].len() > self.hub_limit
    }

    /// Whether one of object `o`'s locations is a hub.
    fn obj_has_hub(&self, o: u32) -> bool {
        self.obj_locs
            .get(o as usize)
            .is_some_and(|v| v.iter().any(|(_, l)| self.is_hub(*l)))
    }

    /// Whether representatives `a` and `b` hold the same set.
    fn same_set(&self, a: u32, b: u32) -> bool {
        let (pa, pb) = (&self.pts[a as usize], &self.pts[b as usize]);
        if pa.len() != pb.len() {
            return false;
        }
        match (pa, pb) {
            (PSet::Small(x), PSet::Small(y)) => x == y,
            (PSet::Big(x), PSet::Big(y)) => x == y,
            _ => pa.to_vec() == pb.to_vec(),
        }
    }

    /// A location with very many successors absorbs those holding exactly its set: they would
    /// receive everything it receives anyway; merged, nothing is pushed to them (sound: merged
    /// locations hold the union of what each would).
    fn check_fanout(&mut self, l: u32) {
        let _phase = Phase::enter(0);
        let n = self.succ[l as usize].len();
        if self.fanout_limit == 0
            || n <= self.fanout_limit
            || n < self.fanout_check.get(&l).copied().unwrap_or(0)
        {
            return;
        }
        self.fanout_check.insert(l, n * 2);
        let mut same = Vec::new();
        for &d in &self.succ[l as usize] {
            let mut r = d;
            while self.rep[r as usize] != r {
                r = self.rep[r as usize];
            }
            if r != l && self.same_set(r, l) {
                same.push(r);
            }
        }
        same.sort_unstable();
        same.dedup();
        for r in same {
            let (r, l2) = (self.find(r), self.find(l));
            if r != l2 {
                self.merge(r, l2);
                self.fanout_merged += 1;
            }
        }
        let l = self.find(l);
        let mut s: Vec<u32> = std::mem::take(&mut self.succ[l as usize])
            .into_iter()
            .map(|d| self.find(d))
            .filter(|d| *d != l)
            .collect();
        s.sort_unstable();
        s.dedup();
        self.succ[l as usize] = s;
    }

    /// The range copies out of object `o` whose source range overlaps `[lo, hi)`.
    fn copies_over(&self, o: u32, lo: u32, hi: u32) -> Vec<RangeCopy> {
        if lo >= hi {
            return Vec::new();
        }
        let all = &self.copies_from[o as usize];
        let overlaps = |c: &RangeCopy| c.soff < hi && lo < c.soff.saturating_add(c.size);
        let Some(ix) = self.copy_idx.get(&o) else {
            return all.iter().copied().filter(overlaps).collect();
        };
        if hi.saturating_sub(lo) > 512 {
            return all.iter().copied().filter(overlaps).collect();
        }
        let mut idx: Vec<u32> = Vec::new();
        for w in lo / 8..=(hi - 1) / 8 {
            if let Some(v) = ix.words.get(&w) {
                idx.extend(v);
            }
        }
        idx.extend(&ix.big);
        idx.sort_unstable();
        idx.dedup();
        idx.into_iter()
            .filter_map(|i| all.get(i as usize).copied())
            .filter(overlaps)
            .collect()
    }

    /// Target `t` as a location of the object its object was merged into.
    fn canon(&mut self, t: u32) -> u32 {
        let (o, off) = self.locs[t as usize];
        let r = self.ofind(o);
        if r == o && (off == 0 || !self.smashed.contains(&r)) {
            t
        } else {
            self.loc(r, off)
        }
    }

    /// An offset in object `o` as a location's: one location for a merged object.
    fn off_in(&self, o: u32, off: u32) -> u32 {
        if self.smashed.contains(&o) {
            0
        } else {
            at(o, off)
        }
    }

    /// The location `(o, off)`, made (without its edges: see `settle`) when new.
    fn loc(&mut self, o: u32, off: u32) -> u32 {
        let o = self.ofind(o);
        let off = self.off_in(o, off);
        if let Some(&l) = self.loc_ids.get(&(o, off)) {
            return l;
        }
        let l = self.locs.len() as u32;
        self.locs.push((o, off));
        self.loc_ids.insert((o, off), l);
        self.rep.push(l);
        self.pts.push(PSet::default());
        self.delta.push(Vec::new());
        self.queued.push(false);
        self.watched.push(false);
        self.succ.push(Vec::new());
        self.ensure_obj(o);
        let v = &mut self.obj_locs[o as usize];
        let i = v.partition_point(|(x, _)| *x < off);
        v.insert(i, (off, l));
        self.fresh.push(l);
        l
    }

    /// Gives the new locations what their object's havocked ranges, watches and range copies
    /// give them.
    fn settle(&mut self) {
        let _phase = Phase::enter(1);
        while let Some(l) = self.fresh.pop() {
            let (o, off) = self.locs[l as usize];
            let o = self.ofind(o);
            if o != UNKNOWN && self.havoc_covers(o, off) {
                let u = self.u_loc;
                self.add(l, u);
            }
            if self.reached.contains(&o) || covers(self.havoc_watch.get(&o), off) {
                let r = self.find(l);
                self.watched[r as usize] = true;
            }
            if !self.smashed.contains(&o) {
                let cs = self.copies_over(o, off, off.saturating_add(8));
                self.scans[1] += cs.len() as u64;
                for c in cs {
                    let d = self.loc(c.d, c.doff.saturating_add(off - c.soff));
                    self.add_edge(l, d);
                }
            }
        }
    }

    /// A range copy out of merged object `s`: from its one location to each destination
    /// location in the range.
    fn copy_out_smashed(&mut self, s: u32, c: RangeCopy) {
        let src = self.loc(s, 0);
        self.fill_range(c.d, c.doff, c.size, src);
    }

    /// Bytes `[off, off + size)` of object `o` hold what location `src` holds: each word of
    /// the range is made a location with an edge from `src` (range copies out of it then carry
    /// it on as for any location).
    fn fill_range(&mut self, o: u32, off: u32, size: u32, src: u32) {
        let o = self.ofind(o);
        if o == UNKNOWN || size == 0 {
            return;
        }
        if self.smashed.contains(&o) {
            let l = self.loc(o, 0);
            self.add_edge(src, l);
            return;
        }
        let end = off.saturating_add(size).min(TAIL + 8);
        // (an object whose type tells: only its words that may hold a pointer)
        if let Some(words) = self.typed.get(&o) {
            let ws: Vec<u32> = words
                .iter()
                .filter(|(w, _)| *w >= at(o, off) && *w < end)
                .map(|(w, _)| *w)
                .collect();
            for w in ws {
                let l = self.loc(o, w);
                self.add_edge(src, l);
            }
            return;
        }
        let mut w = at(o, off);
        while w < end {
            let l = self.loc(o, w);
            self.add_edge(src, l);
            if w >= TAIL {
                break;
            }
            w += 8;
        }
        self.scans[2] += u64::from(end.saturating_sub(off) / 8);
    }

    /// Makes object `b` field-insensitive: its locations become one.
    /// (`false` when it was already)
    fn smash(&mut self, b: u32) -> bool {
        if !self.smashed.insert(b) {
            return false;
        }
        // (a merged object holds what its members held: no one type describes it)
        self.typed.remove(&b);
        let l0 = self.loc(b, 0);
        let ls: Vec<u32> = self.obj_locs[b as usize].iter().map(|(_, l)| *l).collect();
        for l in ls {
            let (ra, r0) = (self.find(l), self.find(l0));
            if ra != r0 {
                self.merge(ra, r0);
            }
        }
        // (the others stand for it as targets only, as `canon` maps them)
        self.obj_locs[b as usize] = vec![(0, l0)];
        for c in self.copies_from[b as usize].clone() {
            self.copy_out_smashed(b, c);
        }
        if self.havoc.remove(&b).is_some() {
            self.havoc_range(b, 0, u32::MAX);
        }
        if self.havoc_watch.remove(&b).is_some() {
            self.watch_havoc(b, 0, u32::MAX);
        }
        true
    }

    fn havoc_covers(&self, o: u32, off: u32) -> bool {
        covers(self.havoc.get(&o), off)
    }

    /// Adds target `t` to location `l`.
    fn add(&mut self, l: u32, t: u32) {
        let t = self.canon(t);
        let to = self.locs[t as usize].0;
        let kind = if self.vtables.contains(&to) {
            CODE_VT
        } else if self.fns.contains(&to) {
            CODE_FN
        } else {
            0
        };
        if kind != 0 {
            let (o, off) = self.locs[l as usize];
            if self.ofind_ro(o) == o
                && let Some(words) = self.typed.get(&o)
                && !words.iter().any(|(w, k)| *w == off && k & kind != 0)
            {
                return;
            }
        }
        let r = self.find(l);
        if self.pts[r as usize].insert(t) {
            self.entries += 1;
            self.delta[r as usize].push(t);
            if !self.queued[r as usize] {
                self.queued[r as usize] = true;
                self.work.push_back(r);
            }
        }
    }

    /// An edge: `d` holds what `s` holds.
    fn add_edge(&mut self, s: u32, d: u32) {
        let (rs, rd) = (self.find(s), self.find(d));
        if rs == rd {
            return;
        }
        self.succ[rs as usize].push(d);
        self.edges += 1;
        self.edge_copies += self.pts[rs as usize].len() as u64;
        if self.pts[rs as usize].len() > 0 {
            for t in self.pts[rs as usize].to_vec() {
                self.add(rd, t);
            }
        }
    }

    /// Adds a range copy out of object `s`: edges from its locations in the range.
    fn add_copy(&mut self, s: u32, c: RangeCopy) {
        let s = self.ofind(s);
        if c.size == 0 {
            return;
        }
        self.ensure_obj(s);
        if self.has_copy(s, &c) {
            return;
        }
        self.copies_from[s as usize].push(c);
        self.copies_n += 1;
        let i = (self.copies_from[s as usize].len() - 1) as u32;
        if let Some(ix) = self.copy_idx.get_mut(&s) {
            ix.add(i, c);
        } else if self.copies_from[s as usize].len() > 64 {
            let mut ix = CopyIndex::default();
            for (j, c) in self.copies_from[s as usize].iter().enumerate() {
                ix.add(j as u32, *c);
            }
            self.copy_idx.insert(s, ix);
        }
        if self.smashed.contains(&s) {
            self.copy_out_smashed(s, c);
            if self.havoc.contains_key(&s) {
                self.havoc_range(c.d, c.doff, c.size);
            }
            return;
        }
        // (locations the copy itself makes in `s` get their edges in `settle`)
        let ls = self.locs_in(s, c.soff, c.soff.saturating_add(c.size));
        self.scans[0] += ls.len() as u64;
        for l in ls {
            let (_, off) = self.locs[l as usize];
            let d = self.loc(c.d, c.doff.saturating_add(off - c.soff));
            self.add_edge(l, d);
        }
        // a havocked source range: the copy's destination range holds anything too
        let hs: Vec<(u32, u32)> = self.havoc.get(&s).cloned().unwrap_or_default();
        for (ho, hsz) in hs {
            let lo = ho.max(c.soff);
            let hi = ho.saturating_add(hsz).min(c.soff.saturating_add(c.size));
            if lo < hi {
                self.havoc_range(c.d, c.doff.saturating_add(lo - c.soff), hi - lo);
            }
        }
    }

    /// Marks bytes `[off, off + size)` of object `o` as holding anything, and the ranges copies
    /// take from them.
    fn havoc_range(&mut self, o: u32, off: u32, size: u32) {
        let mut stack = vec![(o, off, size)];
        while let Some((o, off, size)) = stack.pop() {
            let o = self.ofind(o);
            if o == UNKNOWN || size == 0 {
                continue;
            }
            let (off, size) = if self.smashed.contains(&o) {
                (0, u32::MAX)
            } else {
                (off, size)
            };
            let e = self.havoc.entry(o).or_default();
            if e.iter()
                .any(|(ho, hs)| *ho <= off && off.saturating_add(size) <= ho.saturating_add(*hs))
            {
                continue;
            }
            e.push((off, size));
            self.ensure_obj(o);
            let u = self.u_loc;
            for l in self.locs_in(o, off, off.saturating_add(size)) {
                self.add(l, u);
            }
            for c in self.copies_over(o, off, off.saturating_add(size)) {
                let lo = off.max(c.soff);
                let hi = off.saturating_add(size).min(c.soff.saturating_add(c.size));
                if lo < hi {
                    stack.push((c.d, c.doff.saturating_add(lo - c.soff), hi - lo));
                }
            }
        }
    }

    /// Object `o` is reachable by code not translated: anything may be written in it, and what
    /// it points to is reachable too.
    fn reach(&mut self, o: u32) {
        let mut stack = vec![o];
        while let Some(o) = stack.pop() {
            let o = self.ofind(o);
            if o == UNKNOWN || !self.reached.insert(o) {
                continue;
            }
            self.havoc_range(o, 0, u32::MAX);
            let ls: Vec<u32> = self.obj_locs[o as usize].iter().map(|(_, l)| *l).collect();
            self.scans[3] += ls.len() as u64;
            for l in ls {
                let r = self.find(l);
                self.watched[r as usize] = true;
                for t in self.pts[r as usize].iter() {
                    stack.push(self.locs[t as usize].0);
                }
            }
        }
    }

    /// A call through a pointer or vtable bound to function object `f` at `site`. A library
    /// function is bound in the caller's context: its copy is requested (`requests`) and bound
    /// with `bind_to` once made.
    fn bind(&mut self, site: u32, f: u32) {
        if !self.bound.insert((site, f)) {
            return;
        }
        if self.lib_fns.contains(&f) {
            self.requests.push((site, f));
            return;
        }
        self.callee.push((site, f));
        if self.untranslated.contains(&f) {
            let args: Vec<(u32, u32, u32, u32)> =
                self.site_args.get(&site).cloned().unwrap_or_default();
            let dest = self.site_dest.get(&site).copied();
            self.havoc_site(&args, dest);
            return;
        }
        let ps: Vec<(u32, u32, u32, u32)> = self.params.get(&f).cloned().unwrap_or_default();
        let ret = self.rets.get(&f).copied();
        self.bind_to(site, &ps, ret);
    }

    /// Binds the call at `site` to a copy of a body: its parameters (argument, part, local,
    /// size) and its return value (local, size).
    pub(crate) fn bind_to(
        &mut self,
        site: u32,
        ps: &[(u32, u32, u32, u32)],
        ret: Option<(u32, u32)>,
    ) {
        if self.unify.is_some() {
            let mut binds = Vec::new();
            self.unify_bind_to(site, ps, ret, &mut binds);
            self.unify_binds(binds);
            return;
        }
        let args: Vec<(u32, u32, u32, u32)> =
            self.site_args.get(&site).cloned().unwrap_or_default();
        let dest = self.site_dest.get(&site).copied();
        for &(k, part, local, size) in ps {
            for &(ak, ao, aoff, _) in &args {
                if ak == k {
                    self.add_copy(
                        ao,
                        RangeCopy {
                            soff: aoff + part,
                            size,
                            d: local,
                            doff: 0,
                        },
                    );
                }
            }
        }
        if let (Some((d, doff, dsize)), Some((r, rsize))) = (dest, ret) {
            self.add_copy(
                r,
                RangeCopy {
                    soff: 0,
                    size: dsize.min(rsize),
                    d,
                    doff,
                },
            );
        }
        self.settle();
    }

    fn havoc_site(&mut self, args: &[(u32, u32, u32, u32)], dest: Option<(u32, u32, u32)>) {
        for &(_, ao, aoff, asize) in args {
            self.watch_havoc(ao, aoff, asize);
        }
        if let Some((d, doff, dsize)) = dest {
            self.havoc_range(d, doff, dsize);
        }
    }

    /// The pointers in bytes `[off, off + size)` of `o` are given to code not translated: what
    /// they point to, now or later, is reachable by it.
    fn watch_havoc(&mut self, o: u32, off: u32, size: u32) {
        let o = self.ofind(o);
        let (off, size) = if self.smashed.contains(&o) {
            (0, u32::MAX)
        } else {
            (off, size)
        };
        let e = self.havoc_watch.entry(o).or_default();
        if e.contains(&(off, size)) {
            return;
        }
        e.push((off, size));
        self.ensure_obj(o);
        for l in self.locs_in(o, off, off.saturating_add(size)) {
            let r = self.find(l);
            self.watched[r as usize] = true;
            for t in self.pts[r as usize].to_vec() {
                let to = self.locs[t as usize].0;
                self.reach(to);
            }
        }
    }

    /// Merges representative `a` into representative `r` (on a cycle of edges, or the same
    /// offset of merged objects). Incrementally: `a`'s edges and pointer operations get what
    /// `r` held and `a` did not, now; `r`'s get what `a` brings, as `r`'s delta.
    fn merge(&mut self, a: u32, r: u32) {
        let _phase = Phase::enter(2);
        self.rep[a as usize] = r;
        self.merged += 1;
        let pa = std::mem::take(&mut self.pts[a as usize]);
        let mut extra_a: Vec<u32> = self.pts[r as usize]
            .iter()
            .filter(|t| !pa.contains(*t))
            .collect();
        // (and what `a` held but had not propagated yet)
        extra_a.append(&mut self.delta[a as usize]);
        self.entries -= pa.len();
        let mut new_r = Vec::new();
        for t in pa.iter() {
            if self.pts[r as usize].insert(t) {
                self.entries += 1;
                new_r.push(t);
            }
        }
        let succ_a = std::mem::take(&mut self.succ[a as usize]);
        let ops_a = Ops {
            loads: self.loads_at.remove(&a).unwrap_or_default(),
            stores: self.stores_at.remove(&a).unwrap_or_default(),
            derefs: self.derefs_at.remove(&a).unwrap_or_default(),
            icalls: self.icalls_at.remove(&a).unwrap_or_default(),
            vcalls: self.vcalls_at.remove(&a).unwrap_or_default(),
        };
        let (wa, wr) = (self.watched[a as usize], self.watched[r as usize]);
        self.watched[r as usize] = wa || wr;
        // `a`'s side
        if !extra_a.is_empty() {
            for &d in &succ_a {
                let rd = self.find(d);
                if rd != r {
                    for &t in &extra_a {
                        self.add(rd, t);
                    }
                }
            }
            self.apply(&extra_a, &ops_a);
            if wa {
                for &t in &extra_a {
                    let to = self.locs[t as usize].0;
                    self.reach(to);
                }
            }
        }
        // `r`'s side, with `a`'s edges and operations from now on
        self.succ[r as usize].extend(succ_a);
        self.loads_at.entry(r).or_default().extend(ops_a.loads);
        self.stores_at.entry(r).or_default().extend(ops_a.stores);
        self.derefs_at.entry(r).or_default().extend(ops_a.derefs);
        self.icalls_at.entry(r).or_default().extend(ops_a.icalls);
        self.vcalls_at.entry(r).or_default().extend(ops_a.vcalls);
        if wr && !wa {
            // (`r`'s targets were reached already; `a`'s now are too)
            for &t in &new_r {
                let to = self.locs[t as usize].0;
                self.reach(to);
            }
        }
        if !new_r.is_empty() {
            self.delta[r as usize].extend(new_r);
            if !self.queued[r as usize] {
                self.queued[r as usize] = true;
                self.work.push_back(r);
            }
        }
    }

    /// Whether location `l`'s set holds more targets in objects that may merge than the
    /// limit: those objects are merged (at the next step).
    fn check_merge(&mut self, l: u32) {
        let n = self.pts[l as usize].len();
        let limit = match (self.merge_limit, self.code_limit) {
            (0, 0) => return,
            (0, c) => c,
            (m, 0) => m,
            (m, c) => m.min(c),
        };
        if n <= limit || n < self.merge_check.get(&l).copied().unwrap_or(0) {
            return;
        }
        self.merge_check.insert(l, n * 2);
        // (targets, not objects: a few objects pointed to at many fields count as many)
        let mut targets: Vec<(u32, u32)> = Vec::new();
        let mut fns: Vec<u32> = Vec::new();
        let mut vts: Vec<u32> = Vec::new();
        for t in self.pts[l as usize].iter() {
            let (o, off) = self.locs[t as usize];
            let o = self.ofind_ro(o);
            if o == UNKNOWN {
                continue;
            }
            if self.fns.contains(&o) {
                fns.push(o);
            } else if self.vtables.contains(&o) {
                vts.push(o);
            } else if !self.fixed.contains(&o) {
                targets.push((o, self.off_in(o, off)));
            }
        }
        targets.sort_unstable();
        targets.dedup();
        // a set mostly of targets merged since: rewritten with them as one
        let mut distinct = targets.len();
        for group in [&mut fns, &mut vts] {
            group.sort_unstable();
            group.dedup();
            distinct += group.len();
        }
        if distinct * 2 < n {
            self.canon_set(l);
        }
        if self.merge_limit > 0 && targets.len() > self.merge_limit {
            let mut objs: Vec<u32> = targets.into_iter().map(|(o, _)| o).collect();
            objs.dedup();
            let before = objs.len();
            objs.retain(|o| !self.obj_has_hub(*o));
            self.hubs_skipped += before - objs.len();
            if !objs.is_empty() {
                self.pending_merges.push((l, objs));
            }
        }
        for group in [fns, vts] {
            if self.code_limit > 0 && group.len() > self.code_limit {
                self.pending_code.push((l, group));
            }
        }
    }

    /// Raises the pressure level when this process's memory passes 60%, 75%, 85% of the limit:
    /// lower merge limits, and every set past them checked now.
    fn update_pressure(&mut self) {
        let _phase = Phase::enter(3);
        if self.mem_cap_mb == 0 {
            return;
        }
        let used = rss_mb() * 100 / self.mem_cap_mb;
        let level = match used {
            0..=59 => 0,
            60..=74 => 1,
            75..=84 => 2,
            _ => 3,
        };
        if level <= self.pressure {
            return;
        }
        self.pressure = level;
        let scale = |base: usize, level: u8| match level {
            1 => (base / 4).max(2),
            2 => 2,
            _ => 1,
        };
        if self.base_merge > 0 {
            self.merge_limit = scale(self.base_merge, level);
        }
        if self.base_code > 0 {
            self.code_limit = scale(self.base_code, level);
        }
        eprintln!(
            "rcbom-pta: memory at {used}% of {} MB: pressure {level}, merge limit {}, code \
             limit {}",
            self.mem_cap_mb, self.merge_limit, self.code_limit
        );
        // every set past the new limits, now
        self.merge_check.clear();
        let limit = self.merge_limit.min(self.code_limit).max(1);
        for l in 0..self.locs.len() as u32 {
            if self.rep[l as usize] == l && self.pts[l as usize].len() > limit {
                self.check_merge(l);
            }
        }
    }

    /// The sizes of the solver's structures (estimated bytes, MB), for the log.
    fn mem_report(&self, rss: u64) {
        let mb = |b: usize| b >> 20;
        let pts: usize = self
            .pts
            .iter()
            .map(|p| match p {
                PSet::Small(v) => v.capacity() * 4,
                PSet::Big(b) => b.serialized_size(),
            })
            .sum::<usize>()
            + self.pts.len() * 32;
        let delta: usize = self.delta.iter().map(|v| v.capacity() * 4 + 24).sum();
        let delta_len: usize = self.delta.iter().map(Vec::len).sum();
        let succ: usize = self.succ.iter().map(|v| v.capacity() * 4 + 24).sum();
        let obj_locs: usize = self.obj_locs.iter().map(|v| v.capacity() * 8 + 24).sum();
        let copies: usize = self
            .copies_from
            .iter()
            .map(|v| v.capacity() * 16 + 24)
            .sum();
        let copy_idx: usize = self
            .copy_idx
            .values()
            .map(|ix| {
                ix.words
                    .values()
                    .map(|v| v.capacity() * 4 + 40)
                    .sum::<usize>()
            })
            .sum();
        let ops: usize = self
            .loads_at
            .values()
            .map(|v| v.capacity() * 16)
            .sum::<usize>()
            + self
                .stores_at
                .values()
                .map(|v| v.capacity() * 16)
                .sum::<usize>()
            + self
                .derefs_at
                .values()
                .map(|v| v.capacity() * 12)
                .sum::<usize>()
            + self
                .vcalls_at
                .values()
                .map(|v| v.capacity() * 12)
                .sum::<usize>();
        let work = self.work.capacity() * 4;
        let locs =
            self.locs.capacity() * 8 + self.loc_ids.capacity() * 13 + self.rep.capacity() * 4;
        eprintln!(
            "rcbom-pta: memory {rss} MB at step {}: pts {} delta {} ({} pending) succ {} \
             obj_locs {} copies {} copy_idx {} ops {} work {} locs {}; {} locations, {} \
             merged, {} objects merged",
            self.steps,
            mb(pts),
            mb(delta),
            delta_len,
            mb(succ),
            mb(obj_locs),
            mb(copies),
            mb(copy_idx),
            mb(ops),
            mb(work),
            mb(locs),
            self.locs.len(),
            self.merged,
            self.objs_merged
        );
    }

    /// The memory pressure level (`update_pressure`).
    pub(crate) fn pressure(&self) -> u8 {
        self.pressure
    }

    fn has_pending(&self) -> bool {
        !self.pending_merges.is_empty() || !self.pending_code.is_empty()
    }

    /// The functions (or vtables) object `o` stands for: its group's members, or itself.
    fn members_of(&self, o: u32) -> Vec<u32> {
        self.members.get(&o).cloned().unwrap_or_else(|| vec![o])
    }

    /// Groups each pending set of functions (or of vtables) into one object: pointers to any
    /// member point to the group, and calls through it bind every member. Sound (a call binds
    /// at least the function the pointer held); it bounds the sets type-erased code and merged
    /// objects fill with code.
    fn do_code_merges(&mut self) {
        let _phase = Phase::enter(4);
        let mut touched = Vec::new();
        for (from, objs) in std::mem::take(&mut self.pending_code) {
            let grouped_before = self.code_grouped;
            let mut objs: Vec<u32> = objs.into_iter().map(|o| self.ofind(o)).collect();
            objs.sort_unstable();
            objs.dedup();
            let Some(&b) = objs.first() else {
                continue;
            };
            let lb = self.loc(b, 0);
            for &a in &objs[1..] {
                let (a, b) = (self.ofind(a), self.ofind(b));
                if a == b {
                    continue;
                }
                self.orep[a as usize] = b;
                self.code_grouped += 1;
                let ma = self.members.remove(&a).unwrap_or_else(|| vec![a]);
                self.members.entry(b).or_insert_with(|| vec![b]).extend(ma);
                // (code objects hold nothing; their locations only name them as targets)
                for (_, l) in std::mem::take(&mut self.obj_locs[a as usize]) {
                    let (ra, rb) = (self.find(l), self.find(lb));
                    if ra != rb {
                        self.merge(ra, rb);
                    }
                }
            }
            if self.code_grouped > grouped_before {
                touched.push(from);
            }
        }
        self.settle();
        for r in touched {
            let r = self.find(r);
            self.canon_set(r);
            self.merge_check.remove(&r);
        }
    }

    /// Merges each pending group of objects into one: their locations at each offset become
    /// one, and pointers to any of them point to the merged object. Sound (the merged object
    /// holds what each held); it bounds the sets an imprecise flow would otherwise grow.
    fn do_merges(&mut self) {
        let _phase = Phase::enter(5);
        if !self.pending_code.is_empty() {
            self.do_code_merges();
        }
        let mut touched = Vec::new();
        for (from, objs) in std::mem::take(&mut self.pending_merges) {
            let mut objs: Vec<u32> = objs.into_iter().map(|o| self.ofind(o)).collect();
            objs.sort_unstable();
            objs.dedup();
            objs.retain(|o| !self.obj_has_hub(*o));
            let Some(&first) = objs.first() else {
                continue;
            };
            let b = self.ofind(first);
            if self.debug {
                eprintln!(
                    "rcbom-pta: merging objects {objs:?} into {b} (asked by location {from})"
                );
            }
            let merged_before = self.objs_merged;
            let newly = self.smash(b);
            touched.push(self.loc(b, 0));
            for &a in &objs[1..] {
                let (a, b) = (self.ofind(a), self.ofind(first));
                if a == b {
                    continue;
                }
                self.orep[a as usize] = b;
                self.objs_merged += 1;
                self.typed.remove(&a);
                let la = std::mem::take(&mut self.obj_locs[a as usize]);
                let l0 = self.loc(b, 0);
                for (_, l) in la {
                    let (ra, r0) = (self.find(l), self.find(l0));
                    if ra != r0 {
                        self.merge(ra, r0);
                    }
                }
                self.copy_idx.remove(&a);
                for c in std::mem::take(&mut self.copies_from[a as usize]) {
                    self.add_copy(b, c);
                }
                if self.havoc.remove(&a).is_some() {
                    self.havoc_range(b, 0, u32::MAX);
                }
                if self.havoc_watch.remove(&a).is_some() {
                    self.watch_havoc(b, 0, u32::MAX);
                }
                if self.reached.remove(&a) {
                    self.reach(b);
                }
            }
            // (the asking location is checked again only when this changed something: a group
            // left with nothing to merge would otherwise be asked for again and again)
            if newly || self.objs_merged > merged_before {
                touched.push(from);
            }
        }
        self.settle();
        // the sets of the merged locations and of those that asked, with merged targets as one
        // (merging nodes propagated what each lacked; the targets in merged objects need not
        // go again: their range copies moved to the merged object)
        for r in touched {
            let r = self.find(r);
            self.canon_set(r);
            self.merge_check.remove(&r);
        }
    }

    /// Rewrites representative `r`'s set with targets in merged objects as the merged object's.
    fn canon_set(&mut self, r: u32) {
        let _phase = Phase::enter(6);
        let old = std::mem::take(&mut self.pts[r as usize]);
        self.entries -= old.len();
        let mut new = PSet::default();
        for t in old.iter() {
            let c = self.canon(t);
            if new.insert(c) {
                self.entries += 1;
            }
        }
        self.pts[r as usize] = new;
    }

    /// The strongly connected components of the edges between representatives (more than one
    /// member), by Tarjan's algorithm, iteratively.
    fn sccs(&mut self) -> Vec<Vec<u32>> {
        let n = self.locs.len();
        for l in 0..n as u32 {
            let r = self.find(l);
            self.rep[l as usize] = r;
        }
        const NONE: u32 = u32::MAX;
        let mut index = vec![NONE; n];
        let mut low = vec![0u32; n];
        let mut on_stack = vec![false; n];
        let mut stack: Vec<u32> = Vec::new();
        let mut call: Vec<(u32, usize)> = Vec::new();
        let mut next = 0u32;
        let mut comps: Vec<Vec<u32>> = Vec::new();
        for s in 0..n as u32 {
            if self.rep[s as usize] != s || index[s as usize] != NONE {
                continue;
            }
            index[s as usize] = next;
            low[s as usize] = next;
            next += 1;
            stack.push(s);
            on_stack[s as usize] = true;
            call.push((s, 0));
            while let Some(&(v, i)) = call.last() {
                if i < self.succ[v as usize].len() {
                    call.last_mut().unwrap().1 += 1;
                    let w = self.rep[self.succ[v as usize][i] as usize];
                    if w == v {
                        continue;
                    }
                    if index[w as usize] == NONE {
                        index[w as usize] = next;
                        low[w as usize] = next;
                        next += 1;
                        stack.push(w);
                        on_stack[w as usize] = true;
                        call.push((w, 0));
                    } else if on_stack[w as usize] {
                        low[v as usize] = low[v as usize].min(index[w as usize]);
                    }
                } else {
                    call.pop();
                    if let Some(&(p, _)) = call.last() {
                        low[p as usize] = low[p as usize].min(low[v as usize]);
                    }
                    if low[v as usize] == index[v as usize] {
                        let mut comp = Vec::new();
                        while let Some(w) = stack.pop() {
                            on_stack[w as usize] = false;
                            comp.push(w);
                            if w == v {
                                break;
                            }
                        }
                        if comp.len() > 1 {
                            comps.push(comp);
                        }
                    }
                }
            }
        }
        comps
    }

    /// Collapses the cycles of edges (Tarjan's strongly connected components, iterative).
    fn collapse(&mut self) {
        let _phase = Phase::enter(7);
        if !self.collapsing {
            return;
        }
        let comps = self.sccs();
        let n = self.locs.len();
        if self.objs_merged > self.objs_merged_at_collapse {
            self.objs_merged_at_collapse = self.objs_merged;
            for l in 0..n as u32 {
                if self.rep[l as usize] == l {
                    self.canon_set(l);
                }
            }
        }
        for comp in comps {
            // the member with the largest set represents the others
            let r = *comp
                .iter()
                .max_by_key(|l| self.pts[**l as usize].len())
                .unwrap();
            if self.is_hub(r) {
                self.hubs_skipped += 1;
                continue;
            }
            for a in comp {
                let (a, r) = (self.find(a), self.find(r));
                if a != r && !self.is_hub(a) {
                    self.merge(a, r);
                }
            }
        }
        // edges by representative, without duplicates and self-loops
        for l in 0..n as u32 {
            if self.rep[l as usize] != l {
                continue;
            }
            let mut s: Vec<u32> = std::mem::take(&mut self.succ[l as usize])
                .into_iter()
                .map(|d| self.find(d))
                .filter(|d| *d != l)
                .collect();
            s.sort_unstable();
            s.dedup();
            self.succ[l as usize] = s;
        }
        self.edges = self.succ.iter().map(Vec::len).sum();
        self.edges_at_collapse = self.edges;
    }

    /// Takes in the constraints added since the last call, then propagates to a fixed point (or
    /// until the budget runs out). Calls to library functions found on the way are left in
    /// `requests`: the caller binds them and runs again.
    /// Solves with the unification tier instead (before the first `run`).
    pub(crate) fn set_unify(&mut self) {
        self.unify = Some(Box::default());
    }

    /// In the unification tier: the classes of object `o` and of its pointee.
    pub(crate) fn unify_classes(&self, o: u32) -> Option<(u32, u32)> {
        self.unify.as_ref().map(|u| u.classes(o))
    }

    pub(crate) fn unifying(&self) -> bool {
        self.unify.is_some()
    }

    /// The unification tier's run: the call tables as for the inclusion solver, then each
    /// constraint once, then the calls the joins make possible, until none is new.
    fn run_unify(&mut self) {
        self.started.get_or_insert_with(std::time::Instant::now);
        self.rounds += 1;
        for (f, k, part, _, local, size) in std::mem::take(&mut self.fn_param) {
            self.params
                .entry(f)
                .or_default()
                .push((k, part, local, size));
        }
        for (f, r, rsize) in std::mem::take(&mut self.fn_ret) {
            self.rets.insert(f, (r, rsize));
        }
        for (f,) in std::mem::take(&mut self.fn_untranslated) {
            self.untranslated.insert(f);
        }
        for f in std::mem::take(&mut self.fn_lib) {
            self.lib_fns.insert(f);
        }
        for (vt, slot, f) in std::mem::take(&mut self.vt_entry) {
            self.vt.insert((vt, slot), f);
        }
        for (site, k, ao, aoff, asize) in std::mem::take(&mut self.icall_arg) {
            self.site_args
                .entry(site)
                .or_default()
                .push((k, ao, aoff, asize));
        }
        for (site, d, doff, dsize) in std::mem::take(&mut self.icall_dest) {
            self.site_dest.insert(site, (d, doff, dsize));
        }
        self.needed.clear();
        let mut u = self.unify.take().unwrap();
        let mut binds = Vec::new();
        {
            let k = Calls { fixed: &self.fixed };
            for (d, _, t, _) in std::mem::take(&mut self.addr) {
                u.addr(d, t, &k, &mut binds);
            }
            for (d, _, s, _, _) in std::mem::take(&mut self.copy) {
                u.copy(d, s, &k, &mut binds);
            }
            for (d, _, p, _, _, _) in std::mem::take(&mut self.load) {
                u.load(d, p, &k, &mut binds);
            }
            for (p, _, _, s, _, _) in std::mem::take(&mut self.store) {
                u.store(p, s, &k, &mut binds);
            }
            for (d, _, p, _, _) in std::mem::take(&mut self.addr_deref) {
                u.deref(d, p, &k, &mut binds);
            }
            for (o, _, _) in std::mem::take(&mut self.havocked) {
                u.havoc(o, &k, &mut binds);
            }
            for (o, _, _) in std::mem::take(&mut self.havoc_arg) {
                u.reach(o, &k, &mut binds);
            }
            for (site, o, _) in std::mem::take(&mut self.icall) {
                u.icall(site, o, &k, &mut binds);
            }
            for (site, o, _, slot) in std::mem::take(&mut self.vcall) {
                u.vcall(site, o, slot, &k, &mut binds);
            }
        }
        self.unify = Some(u);
        self.unify_binds(binds);
    }

    /// Binds the calls joins made possible, and those their bindings make possible in turn.
    fn unify_binds(&mut self, mut binds: Vec<Bind>) {
        while let Some(b) = binds.pop() {
            let (site, f) = match b {
                Bind::Call(site, f) => (site, Some(f)),
                Bind::Virtual(site, slot, v) => {
                    if v == UNKNOWN {
                        (site, Some(UNKNOWN))
                    } else {
                        (site, self.vt.get(&(v, slot)).copied())
                    }
                }
            };
            let Some(f) = f else {
                continue;
            };
            if f == UNKNOWN {
                if self.havocked_sites.insert(site) {
                    let args = self.site_args.get(&site).cloned().unwrap_or_default();
                    let dest = self.site_dest.get(&site).copied();
                    let mut u = self.unify.take().unwrap();
                    {
                        let k = Calls { fixed: &self.fixed };
                        for (_, ao, _, _) in args {
                            u.reach(ao, &k, &mut binds);
                        }
                        if let Some((d, _, _)) = dest {
                            u.havoc(d, &k, &mut binds);
                        }
                    }
                    self.unify = Some(u);
                }
                continue;
            }
            if !(self.params.contains_key(&f)
                || self.rets.contains_key(&f)
                || self.untranslated.contains(&f)
                || self.lib_fns.contains(&f))
                || !self.bound.insert((site, f))
            {
                continue;
            }
            if self.lib_fns.contains(&f) {
                self.requests.push((site, f));
                continue;
            }
            self.callee.push((site, f));
            if self.untranslated.contains(&f) {
                binds.push(Bind::Call(site, UNKNOWN));
                continue;
            }
            let ps = self.params.get(&f).cloned().unwrap_or_default();
            let ret = self.rets.get(&f).copied();
            self.unify_bind_to(site, &ps, ret, &mut binds);
        }
    }

    fn unify_bind_to(
        &mut self,
        site: u32,
        ps: &[(u32, u32, u32, u32)],
        ret: Option<(u32, u32)>,
        binds: &mut Vec<Bind>,
    ) {
        let args = self.site_args.get(&site).cloned().unwrap_or_default();
        let dest = self.site_dest.get(&site).copied();
        let mut u = self.unify.take().unwrap();
        {
            let k = Calls { fixed: &self.fixed };
            for &(pk, _, local, _) in ps {
                for &(ak, ao, _, _) in &args {
                    if ak == pk {
                        u.copy(local, ao, &k, binds);
                    }
                }
            }
            if let (Some((d, _, _)), Some((r, _))) = (dest, ret) {
                u.copy(d, r, &k, binds);
            }
        }
        self.unify = Some(u);
    }

    pub(crate) fn run(&mut self) {
        if self.unify.is_some() {
            self.run_unify();
            return;
        }
        let t0 = *self.started.get_or_insert_with(std::time::Instant::now);
        self.rounds += 1;
        if self.rounds == 1 {
            self.collapsing = std::env::var("RCBOM_PTA_COLLAPSE").as_deref() != Ok("0");
            self.debug = std::env::var_os("RCBOM_PTA_DEBUG").is_some();
            self.merge_limit = std::env::var("RCBOM_PTA_MERGE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(32);
            self.hub_limit = std::env::var("RCBOM_PTA_HUB")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            self.fanout_limit = std::env::var("RCBOM_PTA_FANOUT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(10_000);
            self.code_limit = std::env::var("RCBOM_PTA_CODE_MERGE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(16);
            self.base_merge = self.merge_limit;
            self.base_code = self.code_limit;
            self.mem_cap_mb = mem_cap_mb();
            if std::env::var_os("RCBOM_PTA_WATCHDOG").is_some() {
                watchdog();
            }
            eprintln!("rcbom-pta: memory limit {} MB", self.mem_cap_mb);
        }
        self.ingest();
        self.update_pressure();
        if self.rounds == 1 {
            self.collapse();
            eprintln!(
                "rcbom-pta: set up in {} ms (rss {} MB): {} locations, {} edges, {} merged",
                t0.elapsed().as_millis(),
                rss_mb(),
                self.locs.len(),
                self.edges,
                self.merged
            );
        }
        self.propagate(t0);
    }

    fn ingest(&mut self) {
        if self.locs.is_empty() {
            self.u_loc = self.loc(UNKNOWN, 0);
            let u = self.u_loc;
            self.add(u, u);
        }
        // calls through pointers and vtables
        for (f, k, part, _, local, size) in std::mem::take(&mut self.fn_param) {
            self.params
                .entry(f)
                .or_default()
                .push((k, part, local, size));
        }
        for (f, r, rsize) in std::mem::take(&mut self.fn_ret) {
            self.rets.insert(f, (r, rsize));
        }
        for (f,) in std::mem::take(&mut self.fn_untranslated) {
            self.untranslated.insert(f);
        }
        for f in std::mem::take(&mut self.fn_lib) {
            self.lib_fns.insert(f);
        }
        for (vt, slot, f) in std::mem::take(&mut self.vt_entry) {
            self.vt.insert((vt, slot), f);
        }
        for (site, k, ao, aoff, asize) in std::mem::take(&mut self.icall_arg) {
            self.site_args
                .entry(site)
                .or_default()
                .push((k, ao, aoff, asize));
        }
        for (site, d, doff, dsize) in std::mem::take(&mut self.icall_dest) {
            self.site_dest.insert(site, (d, doff, dsize));
        }
        for (o, off) in std::mem::take(&mut self.needed) {
            self.loc(o, off);
        }
        // what happens through pointers; applied below to what they already point to
        let mut new_ops: HashMap<u32, Ops> = HashMap::default();
        for (site, o, off) in std::mem::take(&mut self.icall) {
            let l = self.loc(o, off);
            let r = self.find(l);
            self.icalls_at.entry(r).or_default().push(site);
            new_ops.entry(r).or_default().icalls.push(site);
        }
        for (site, o, off, slot) in std::mem::take(&mut self.vcall) {
            let l = self.loc(o, off);
            let r = self.find(l);
            self.vcalls_at.entry(r).or_default().push((site, slot, l));
            new_ops.entry(r).or_default().vcalls.push((site, slot, l));
        }
        for (d, doff, p, poff, off, size) in std::mem::take(&mut self.load) {
            let l = self.loc(p, poff);
            let r = self.find(l);
            self.loads_at
                .entry(r)
                .or_default()
                .push((d, doff, off, size));
            new_ops
                .entry(r)
                .or_default()
                .loads
                .push((d, doff, off, size));
        }
        for (p, poff, off, s, soff, size) in std::mem::take(&mut self.store) {
            let l = self.loc(p, poff);
            let r = self.find(l);
            self.stores_at
                .entry(r)
                .or_default()
                .push((off, s, soff, size));
            new_ops
                .entry(r)
                .or_default()
                .stores
                .push((off, s, soff, size));
        }
        for (d, doff, p, poff, off) in std::mem::take(&mut self.addr_deref) {
            let l = self.loc(p, poff);
            let r = self.find(l);
            self.derefs_at.entry(r).or_default().push((d, doff, off));
            new_ops.entry(r).or_default().derefs.push((d, doff, off));
        }
        self.settle();
        for (r, ops) in new_ops {
            let r = self.find(r);
            if self.pts[r as usize].len() > 0 {
                let ts = self.pts[r as usize].to_vec();
                self.apply(&ts, &ops);
            }
        }
        // copies, havoc, addresses
        for (d, doff, s, soff, size) in std::mem::take(&mut self.copy) {
            self.add_copy(
                s,
                RangeCopy {
                    soff,
                    size,
                    d,
                    doff,
                },
            );
            self.settle();
        }
        for (o, off, size) in std::mem::take(&mut self.havocked) {
            self.havoc_range(o, off, size);
        }
        for (o, off, size) in std::mem::take(&mut self.havoc_arg) {
            self.watch_havoc(o, off, size);
        }
        for (d, doff, t, toff) in std::mem::take(&mut self.addr) {
            let dl = self.loc(d, doff);
            let tl = self.loc(t, toff);
            self.add(dl, tl);
        }
        self.settle();
    }

    /// What happens through the pointer at representative location `r`.
    fn ops_at(&self, r: u32) -> Ops {
        Ops {
            loads: self.loads_at.get(&r).cloned().unwrap_or_default(),
            stores: self.stores_at.get(&r).cloned().unwrap_or_default(),
            derefs: self.derefs_at.get(&r).cloned().unwrap_or_default(),
            icalls: self.icalls_at.get(&r).cloned().unwrap_or_default(),
            vcalls: self.vcalls_at.get(&r).cloned().unwrap_or_default(),
        }
    }

    /// Applies loads, stores, address computations and calls through a pointer to its targets
    /// `ts`.
    fn apply(&mut self, ts: &[u32], ops: &Ops) {
        let _phase = Phase::enter(8);
        for &t in ts {
            let (to, toff) = self.locs[t as usize];
            let to = self.ofind(to);
            // (a function or vtable as a pointer's target: only calls through it mean anything)
            let code = self.fns.contains(&to) || self.vtables.contains(&to);
            for &(d, doff, k, size) in &ops.loads {
                if code {
                    break;
                }
                if to == UNKNOWN {
                    self.havoc_range(d, doff, size);
                } else {
                    self.add_copy(
                        to,
                        RangeCopy {
                            soff: at(to, toff + k),
                            size,
                            d,
                            doff,
                        },
                    );
                }
            }
            for &(k, s, soff, size) in &ops.stores {
                if code {
                    break;
                }
                if to == UNKNOWN {
                    // written where code not translated may read it
                    self.watch_havoc(s, soff, size);
                } else {
                    self.add_copy(
                        s,
                        RangeCopy {
                            soff,
                            size,
                            d: to,
                            doff: at(to, toff + k),
                        },
                    );
                }
            }
            for &(d, doff, k) in &ops.derefs {
                if code {
                    break;
                }
                let dl = self.loc(d, doff);
                let tl = if to == UNKNOWN {
                    self.u_loc
                } else {
                    self.loc(to, at(to, toff + k))
                };
                self.add(dl, tl);
            }
            for &site in &ops.icalls {
                if to == UNKNOWN {
                    let args = self.site_args.get(&site).cloned().unwrap_or_default();
                    let dest = self.site_dest.get(&site).copied();
                    self.havoc_site(&args, dest);
                } else {
                    for f in self.members_of(to) {
                        if self.params.contains_key(&f)
                            || self.rets.contains_key(&f)
                            || self.untranslated.contains(&f)
                            || self.lib_fns.contains(&f)
                        {
                            self.bind(site, f);
                        }
                    }
                }
            }
            for &(site, slot, _) in &ops.vcalls {
                if to == UNKNOWN {
                    let args = self.site_args.get(&site).cloned().unwrap_or_default();
                    let dest = self.site_dest.get(&site).copied();
                    self.havoc_site(&args, dest);
                } else {
                    for m in self.members_of(to) {
                        if let Some(&f) = self.vt.get(&(m, slot)) {
                            self.bind(site, f);
                        }
                    }
                }
            }
        }
    }

    fn propagate(&mut self, t0: std::time::Instant) {
        let budget: usize = std::env::var("RCBOM_PTA_BUDGET")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(100_000_000);
        loop {
            let t1 = std::time::Instant::now();
            self.settle();
            self.prof[4] += t1.elapsed().as_micros();
            if self.has_pending() {
                self.do_merges();
            }
            let Some(l) = self.work.pop_front() else {
                break;
            };
            self.steps += 1;
            let steps = self.steps;
            if steps.is_multiple_of(10_000) {
                let rss = rss_mb();
                if rss > self.last_report_mb + 1024 {
                    self.last_report_mb = rss;
                    self.mem_report(rss);
                }
            }
            if steps.is_multiple_of(100_000) {
                self.update_pressure();
            }
            if steps.is_multiple_of(100_000) && self.edges > 2 * self.edges_at_collapse + 100_000 {
                let t1 = std::time::Instant::now();
                self.collapse();
                self.prof[2] += t1.elapsed().as_micros();
                if t1.elapsed().as_secs() >= 2 {
                    eprintln!("rcbom-pta: slow collapse {} ms", t1.elapsed().as_millis());
                }
            }
            if steps.is_multiple_of(1_000_000) {
                eprintln!(
                    "rcbom-pta: step {}M at {} ms: {} locations, {} entries, {} edges, {} merged, \
                     {} objects merged, {} copies, {} reached, work {}, round {}; ms edges {} ops \
                     {} collapse {} merges {} settle {}; applied {} pushed {} edge copies {}; scans \
                     {:?}; fan-out merged {}; hubs skipped {}; rss {} MB",
                    steps / 1_000_000,
                    t0.elapsed().as_millis(),
                    self.locs.len(),
                    self.entries,
                    self.edges,
                    self.merged,
                    self.objs_merged,
                    self.copies_n,
                    self.reached.len(),
                    self.work.len(),
                    self.rounds,
                    self.prof[0] / 1000,
                    self.prof[1] / 1000,
                    self.prof[2] / 1000,
                    self.prof[3] / 1000,
                    self.prof[4] / 1000,
                    self.applied,
                    self.pushed,
                    self.edge_copies,
                    self.scans,
                    self.fanout_merged,
                    self.hubs_skipped,
                    rss_mb()
                );
            }
            if self.entries > budget {
                self.exhausted = true;
                break;
            }
            if self.rep[l as usize] != l {
                continue;
            }
            self.queued[l as usize] = false;
            let step_start = std::time::Instant::now();
            // a set past the limit first has its objects merged: then it is propagated whole,
            // as one target per merged object
            self.check_merge(l);
            if self.has_pending() {
                let t1 = std::time::Instant::now();
                let n = self
                    .pending_merges
                    .iter()
                    .map(|(_, o)| o.len())
                    .sum::<usize>();
                self.do_merges();
                self.prof[3] += t1.elapsed().as_micros();
                if t1.elapsed().as_secs() >= 2 {
                    eprintln!(
                        "rcbom-pta: slow merge {} ms of {n} objects; rss {} MB",
                        t1.elapsed().as_millis(),
                        rss_mb()
                    );
                }
                let r = self.find(l);
                if !self.delta[r as usize].is_empty() && !self.queued[r as usize] {
                    self.queued[r as usize] = true;
                    self.work.push_back(r);
                }
                continue;
            }
            self.check_fanout(l);
            let l = self.find(l);
            let new = std::mem::take(&mut self.delta[l as usize]);
            if new.is_empty() {
                continue;
            }
            // (targets in objects merged since they were added: as the merged object's, once)
            let mut new: Vec<u32> = new.into_iter().map(|t| self.canon(t)).collect();
            new.sort_unstable();
            new.dedup();
            // along the edges
            let _phase = Phase::enter(PHASES.len() - 2);
            let t1 = std::time::Instant::now();
            let ss = std::mem::take(&mut self.succ[l as usize]);
            self.pushed += (ss.len() * new.len()) as u64;
            for &d in &ss {
                let rd = self.find(d);
                if rd != l {
                    for &t in &new {
                        self.add(rd, t);
                    }
                }
            }
            self.prof[0] += t1.elapsed().as_micros();
            // (`add` never adds edges: the list is put back whole)
            self.succ[l as usize] = ss;
            // given to code not translated, or in an object it reaches
            if self.watched[l as usize] {
                for &t in &new {
                    let to = self.locs[t as usize].0;
                    self.reach(to);
                }
            }
            // as a pointer: through it
            let t1 = std::time::Instant::now();
            let ops = self.ops_at(l);
            let (nl, ns, nd, ni, nv) = (
                ops.loads.len(),
                ops.stores.len(),
                ops.derefs.len(),
                ops.icalls.len(),
                ops.vcalls.len(),
            );
            self.applied += (new.len()
                * (ops.loads.len()
                    + ops.stores.len()
                    + ops.derefs.len()
                    + ops.icalls.len()
                    + ops.vcalls.len())) as u64;
            self.apply(&new, &ops);
            self.prof[1] += t1.elapsed().as_micros();
            if step_start.elapsed().as_secs() >= 2 {
                eprintln!(
                    "rcbom-pta: slow step {} ms at location {l} {:?}: delta {}, set {} ({}), \
                     edges {}, loads {nl} stores {ns} derefs {nd} icalls {ni} vcalls {nv}; rss {} \
                     MB",
                    step_start.elapsed().as_millis(),
                    self.locs[l as usize],
                    new.len(),
                    self.pts[l as usize].len(),
                    self.set_kinds(l),
                    self.succ[l as usize].len(),
                    rss_mb()
                );
            }
        }
    }

    /// The solver's state when it stopped, for the log.
    pub(crate) fn summary(&self) -> String {
        if let Some(u) = &self.unify {
            return format!(
                "{} ms, {} rounds, {}, {} calls bound; rss {} MB",
                self.started.map_or(0, |t| t.elapsed().as_millis()),
                self.rounds,
                u.summary(),
                self.bound.len(),
                rss_mb()
            );
        }
        // targets named by an object since merged (or a merged object's other offsets)
        let mut stale = 0usize;
        for l in 0..self.locs.len() {
            if self.rep[l] != l as u32 {
                continue;
            }
            for t in self.pts[l].iter() {
                let (o, off) = self.locs[t as usize];
                let r = self.ofind_ro(o);
                if r != o || (off != 0 && self.smashed.contains(&r)) {
                    stale += 1;
                }
            }
        }
        eprintln!("rcbom-pta: stale targets {stale} of {}", self.entries);
        format!(
            "{} ms, {} steps, {} rounds: {} locations, {} entries, {} edges, {} merged, {} \
             objects merged, {} code objects grouped, {} copies, {} reached",
            self.started.map_or(0, |t| t.elapsed().as_millis()),
            self.steps,
            self.rounds,
            self.locs.len(),
            self.entries,
            self.edges,
            self.merged,
            self.objs_merged,
            self.code_grouped,
            self.copies_n,
            self.reached.len()
        )
    }

    /// What each location points to: (object, offset, target object, target offset).
    pub(crate) fn pts_tuples(&self) -> impl Iterator<Item = (u32, u32, u32, u32)> + '_ {
        (0..self.locs.len()).flat_map(move |l| {
            let (o, off) = self.locs[l];
            let mut r = l as u32;
            while self.rep[r as usize] != r {
                r = self.rep[r as usize];
            }
            self.pts[r as usize].iter().map(move |t| {
                let (to, toff) = self.locs[t as usize];
                (o, off, to, toff)
            })
        })
    }

    /// Why location `(o, off)` holds `UNKNOWN`, for diagnostics: a chain of locations holding
    /// it, each with an edge to the next, back to one that got it otherwise (a havocked range, a
    /// pointer through `UNKNOWN`). Each element: object, offset, and whether its own range is
    /// havocked.
    pub(crate) fn explain_unknown(&self, o: u32, off: u32) -> Vec<(u32, u32, bool)> {
        let root = |mut l: u32| {
            while self.rep[l as usize] != l {
                l = self.rep[l as usize];
            }
            l
        };
        let o = self.ofind_ro(o);
        let Some(&start) = self.loc_ids.get(&(o, self.off_in(o, off))) else {
            return Vec::new();
        };
        let u = self.u_loc;
        let holds_u = |r: u32| match &self.pts[r as usize] {
            PSet::Small(v) => v.binary_search(&u).is_ok(),
            PSet::Big(b) => b.contains(u),
        };
        let mut pred: HashMap<u32, Vec<u32>> = HashMap::default();
        for l in 0..self.locs.len() as u32 {
            if self.rep[l as usize] != l || !holds_u(l) {
                continue;
            }
            for &d in &self.succ[l as usize] {
                pred.entry(root(d)).or_default().push(l);
            }
        }
        let mut seen: HashMap<u32, u32> = HashMap::default();
        let s = root(start);
        if !holds_u(s) {
            return Vec::new();
        }
        seen.insert(s, s);
        let mut queue = VecDeque::from([s]);
        let mut origin = s;
        while let Some(r) = queue.pop_front() {
            let (ro, roff) = self.locs[r as usize];
            if self.havoc_covers(ro, roff) {
                origin = r;
                break;
            }
            origin = r;
            for &p in pred.get(&r).into_iter().flatten() {
                if let std::collections::hash_map::Entry::Vacant(e) = seen.entry(p) {
                    e.insert(r);
                    queue.push_back(p);
                }
            }
        }
        let mut chain = Vec::new();
        let mut r = origin;
        loop {
            let (ro, roff) = self.locs[r as usize];
            chain.push((ro, roff, self.havoc_covers(ro, roff)));
            let next = seen[&r];
            if next == r {
                break;
            }
            r = next;
        }
        chain
    }

    /// The `n` largest groups of locations collapsed together, for diagnostics: their members.
    pub(crate) fn largest_groups(&self, n: usize) -> Vec<Vec<(u32, u32)>> {
        let mut groups: HashMap<u32, Vec<(u32, u32)>> = HashMap::default();
        for l in 0..self.locs.len() as u32 {
            let mut r = l;
            while self.rep[r as usize] != r {
                r = self.rep[r as usize];
            }
            if r != l {
                groups.entry(r).or_default().push(self.locs[l as usize]);
            }
        }
        for (r, g) in groups.iter_mut() {
            g.push(self.locs[*r as usize]);
        }
        let mut gs: Vec<Vec<(u32, u32)>> = groups.into_values().collect();
        gs.sort_by_key(|g| std::cmp::Reverse(g.len()));
        gs.truncate(n);
        gs
    }

    /// The largest cycle of edges (when cycles are not collapsed), for diagnostics: its
    /// members.
    pub(crate) fn largest_cycle(&mut self) -> Vec<u32> {
        self.sccs()
            .into_iter()
            .max_by_key(Vec::len)
            .unwrap_or_default()
    }

    /// A shortest path of edges from `a` to `b` through the locations of `within`.
    pub(crate) fn path_within(&self, within: &HashSet<u32>, a: u32, b: u32) -> Vec<(u32, u32)> {
        let mut prev: HashMap<u32, u32> = [(a, a)].into_iter().collect();
        let mut queue = VecDeque::from([a]);
        while let Some(x) = queue.pop_front() {
            if x == b {
                break;
            }
            for &d in &self.succ[x as usize] {
                if within.contains(&d) && !prev.contains_key(&d) {
                    prev.insert(d, x);
                    queue.push_back(d);
                }
            }
        }
        if !prev.contains_key(&b) {
            return Vec::new();
        }
        let mut path = vec![self.locs[b as usize]];
        let mut x = b;
        while x != a {
            x = prev[&x];
            path.push(self.locs[x as usize]);
        }
        path.reverse();
        path
    }

    /// The location of id `l`.
    pub(crate) fn loc_of(&self, l: u32) -> (u32, u32) {
        self.locs[l as usize]
    }

    /// What location `(o, off)` points to (objects as merged): (object, offset).
    pub(crate) fn pts_of(&self, o: u32, off: u32) -> Vec<(u32, u32)> {
        if let Some(u) = &self.unify {
            return u.pts_of(o).into_iter().map(|t| (t, 0)).collect();
        }
        let o = self.ofind_ro(o);
        let Some(&l) = self.loc_ids.get(&(o, self.off_in(o, off))) else {
            return Vec::new();
        };
        let mut r = l;
        while self.rep[r as usize] != r {
            r = self.rep[r as usize];
        }
        self.pts[r as usize]
            .iter()
            .map(|t| {
                let (to, toff) = self.locs[t as usize];
                (self.ofind_ro(to), toff)
            })
            .collect()
    }

    /// Whether byte `off` of object `o` (as merged) is havocked.
    pub(crate) fn havocked_at(&self, o: u32, off: u32) -> bool {
        if self.unify.is_some() {
            // (`UNKNOWN` is an object of the class `pts_of` gives)
            return false;
        }
        let o = self.ofind_ro(o);
        covers(self.havoc.get(&o), self.off_in(o, off))
    }

    pub(crate) fn vcall_sites(&self) -> Vec<(u32, u32, u32)> {
        self.vcalls_at
            .values()
            .flat_map(|v| {
                v.iter().map(|(site, _, l)| {
                    let (o, off) = self.locs[*l as usize];
                    (*site, o, off)
                })
            })
            .collect()
    }
}

/// The memory limit the solver measures its pressure against, in MB: `RCBOM_PTA_MEM_MB`, else
/// this process's cgroup limit, else 80% of the machine's memory.
fn mem_cap_mb() -> u64 {
    if let Some(v) = std::env::var("RCBOM_PTA_MEM_MB")
        .ok()
        .and_then(|v| v.parse().ok())
    {
        return v;
    }
    let cgroup = std::fs::read_to_string("/proc/self/cgroup")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("0::").map(str::to_string))
        })
        .and_then(|p| std::fs::read_to_string(format!("/sys/fs/cgroup{p}/memory.max")).ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(|b| b >> 20);
    let total = std::fs::read_to_string("/proc/meminfo").ok().and_then(|s| {
        s.lines()
            .find_map(|l| l.strip_prefix("MemTotal:"))
            .and_then(|v| v.split_whitespace().next()?.parse::<u64>().ok())
            .map(|kb| kb * 8 / 10 / 1024)
    });
    match (cgroup, total) {
        (Some(c), Some(t)) => c.min(t),
        (Some(c), None) => c,
        (None, Some(t)) => t,
        (None, None) => 0,
    }
}

/// This process's resident memory in MB (for the log).
fn rss_mb() -> u64 {
    std::fs::read_to_string("/proc/self/statm")
        .ok()
        .and_then(|s| s.split_whitespace().nth(1)?.parse::<u64>().ok())
        .map_or(0, |pages| pages * 4096 / (1 << 20))
}

/// The solver's current phase, for the watchdog's log (`watchdog`): set on entry, put back on
/// exit.
static PHASE: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(PHASES.len() - 1);
const PHASES: [&str; 11] = [
    "fanout",
    "settle",
    "merge",
    "pressure",
    "code merges",
    "object merges",
    "canon",
    "collapse",
    "apply",
    "edges",
    "step",
];

struct Phase(usize);

impl Phase {
    fn enter(p: usize) -> Phase {
        Phase(PHASE.swap(p, std::sync::atomic::Ordering::Relaxed))
    }
}

impl Drop for Phase {
    fn drop(&mut self) {
        PHASE.store(self.0, std::sync::atomic::Ordering::Relaxed);
    }
}

/// A thread that logs the solver's phase whenever this process's memory has grown by 512 MB
/// (`RCBOM_PTA_WATCHDOG`): spikes inside one long operation show where they happen.
fn watchdog() {
    std::thread::spawn(|| {
        let mut last = rss_mb();
        loop {
            std::thread::sleep(std::time::Duration::from_secs(2));
            let rss = rss_mb();
            if rss > last + 512 {
                last = rss;
                let p = PHASE.load(std::sync::atomic::Ordering::Relaxed);
                eprintln!("rcbom-pta: watchdog: {rss} MB in {}", PHASES[p]);
            }
        }
    });
}

/// Whether one of the ranges covers offset `off`.
fn covers(ranges: Option<&Vec<(u32, u32)>>, off: u32) -> bool {
    ranges.is_some_and(|rs| {
        rs.iter()
            .any(|(o, s)| *o <= off && off < o.saturating_add(*s))
    })
}
