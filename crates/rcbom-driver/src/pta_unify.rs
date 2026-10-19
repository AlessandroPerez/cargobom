//! The unification tier of the points-to engine (Steensgaard): one union-find over objects,
//! each class with a single pointee class, every constraint processed once. Field-insensitive;
//! memory and time grow with the objects and constraints, not with points-to sets, so it
//! finishes on programs the inclusion solver (`pta_solve.rs`) cannot hold. Sound and coarser:
//! objects any one pointer may reach become one class.
//!
//! It reads the same constraints as the inclusion solver. Calls through pointers and vtables
//! bind as the callee's class gains functions (vtables); `UNKNOWN` is an object that points to
//! itself, so what code not translated may reach is unified with it.

use rustc_data_structures::fx::{FxHashMap as HashMap, FxHashSet as HashSet};

use crate::pta::UNKNOWN;

const NONE: u32 = u32::MAX;

#[derive(Default)]
pub(crate) struct Unify {
    // union-find over nodes: objects first, then fresh nodes made as pointees
    parent: Vec<u32>,
    rank: Vec<u8>,
    /// the class pointers stored in this class's objects point to (`NONE`: none yet)
    pt: Vec<u32>,
    /// objects that answers and calls name (functions, vtables, the knowledge base's statics,
    /// `UNKNOWN`), by class; and whether the class holds any other object (one of them)
    named: HashMap<u32, Vec<u32>>,
    other: HashMap<u32, u32>,
    seen: Vec<bool>,
    /// calls through pointers whose callee is in this class: (site); `dyn` calls whose vtable
    /// is in this class: (site, slot)
    sites: HashMap<u32, Vec<u32>>,
    vsites: HashMap<u32, Vec<(u32, u32)>>,
    joins: usize,
}

/// What the unification tier needs of the inclusion solver's tables: the objects answers and
/// calls name.
pub(crate) struct Calls<'a> {
    pub(crate) fixed: &'a HashSet<u32>,
}

impl Unify {
    fn ensure(&mut self, n: u32) {
        let need = n as usize + 1;
        while self.parent.len() < need {
            let k = self.parent.len() as u32;
            self.parent.push(k);
            self.rank.push(0);
            self.pt.push(NONE);
            self.seen.push(false);
        }
    }

    fn find(&mut self, mut n: u32) -> u32 {
        self.ensure(n);
        while self.parent[n as usize] != n {
            let p = self.parent[n as usize];
            self.parent[n as usize] = self.parent[p as usize];
            n = p;
        }
        n
    }

    fn find_ro(&self, mut n: u32) -> u32 {
        if n as usize >= self.parent.len() {
            return n;
        }
        while self.parent[n as usize] != n {
            n = self.parent[n as usize];
        }
        n
    }

    /// The class of object `o`, recording what it is the first time.
    fn node(&mut self, o: u32, k: &Calls) -> u32 {
        self.ensure(o);
        if !self.seen[o as usize] {
            self.seen[o as usize] = true;
            let r = self.find(o);
            if k.fixed.contains(&o) || o == UNKNOWN {
                self.named.entry(r).or_default().push(o);
            } else {
                self.other.entry(r).or_insert(o);
            }
        }
        self.find(o)
    }

    fn fresh(&mut self) -> u32 {
        let n = self.parent.len() as u32;
        self.ensure(n);
        self.seen[n as usize] = true;
        n
    }

    /// The class the pointers in class `c` point to (made when none yet).
    fn pointee(&mut self, c: u32) -> u32 {
        let c = self.find(c);
        if self.pt[c as usize] == NONE {
            let f = self.fresh();
            self.pt[c as usize] = f;
        }
        let p = self.pt[c as usize];
        self.find(p)
    }

    /// Unifies classes `a` and `b` and, recursively, their pointees. Returns the calls (site,
    /// function or vtable-slot binding) the join makes newly possible.
    fn join(&mut self, a: u32, b: u32, out: &mut Vec<Bind>) {
        let mut work = vec![(a, b)];
        while let Some((a, b)) = work.pop() {
            let (a, b) = (self.find(a), self.find(b));
            if a == b {
                continue;
            }
            self.joins += 1;
            let (r, x) = if self.rank[a as usize] >= self.rank[b as usize] {
                (a, b)
            } else {
                (b, a)
            };
            if self.rank[r as usize] == self.rank[x as usize] {
                self.rank[r as usize] += 1;
            }
            self.parent[x as usize] = r;
            // calls: each side's sites with the other side's functions and vtables (the lists
            // are walked only when the other side has some)
            let nx = self.named.remove(&x).unwrap_or_default();
            let sx = self.sites.remove(&x).unwrap_or_default();
            let vx = self.vsites.remove(&x).unwrap_or_default();
            if (!sx.is_empty() || !vx.is_empty())
                && let Some(nr) = self.named.get(&r)
            {
                for &s in &sx {
                    out.extend(nr.iter().map(|&f| Bind::Call(s, f)));
                }
                for &(s, slot) in &vx {
                    out.extend(nr.iter().map(|&v| Bind::Virtual(s, slot, v)));
                }
            }
            if !nx.is_empty() {
                if let Some(sr) = self.sites.get(&r) {
                    for &s in sr {
                        out.extend(nx.iter().map(|&f| Bind::Call(s, f)));
                    }
                }
                if let Some(vr) = self.vsites.get(&r) {
                    for &(s, slot) in vr {
                        out.extend(nx.iter().map(|&v| Bind::Virtual(s, slot, v)));
                    }
                }
                self.named.entry(r).or_default().extend(nx);
            }
            if !sx.is_empty() {
                self.sites.entry(r).or_default().extend(sx);
            }
            if !vx.is_empty() {
                self.vsites.entry(r).or_default().extend(vx);
            }
            if let Some(o) = self.other.remove(&x) {
                self.other.entry(r).or_insert(o);
            }
            // pointees
            let (pr, px) = (self.pt[r as usize], self.pt[x as usize]);
            match (pr, px) {
                (NONE, NONE) => {}
                (NONE, p) => self.pt[r as usize] = p,
                (_, NONE) => {}
                (p, q) => work.push((p, q)),
            }
        }
    }

    /// `d`'s pointers point where `s`'s do (a copy).
    pub(crate) fn copy(&mut self, d: u32, s: u32, k: &Calls, out: &mut Vec<Bind>) {
        let (nd, ns) = (self.node(d, k), self.node(s, k));
        let (pd, ps) = (self.pointee(nd), self.pointee(ns));
        self.join(pd, ps, out);
    }

    /// `d`'s pointers point to `t`.
    pub(crate) fn addr(&mut self, d: u32, t: u32, k: &Calls, out: &mut Vec<Bind>) {
        let nd = self.node(d, k);
        let pd = self.pointee(nd);
        let nt = self.node(t, k);
        self.join(pd, nt, out);
    }

    /// `d` holds what the objects `p` points to hold (a load).
    pub(crate) fn load(&mut self, d: u32, p: u32, k: &Calls, out: &mut Vec<Bind>) {
        let np = self.node(p, k);
        let c = self.pointee(np);
        let pc = self.pointee(c);
        let nd = self.node(d, k);
        let pd = self.pointee(nd);
        self.join(pd, pc, out);
    }

    /// The objects `p` points to hold what `s` holds (a store).
    pub(crate) fn store(&mut self, p: u32, s: u32, k: &Calls, out: &mut Vec<Bind>) {
        let np = self.node(p, k);
        let c = self.pointee(np);
        let pc = self.pointee(c);
        let ns = self.node(s, k);
        let ps = self.pointee(ns);
        self.join(pc, ps, out);
    }

    /// `d` points where `p` does (an address computed through `p`).
    pub(crate) fn deref(&mut self, d: u32, p: u32, k: &Calls, out: &mut Vec<Bind>) {
        self.copy(d, p, k, out);
    }

    /// `o`'s pointers may point anywhere code not translated reaches.
    pub(crate) fn havoc(&mut self, o: u32, k: &Calls, out: &mut Vec<Bind>) {
        self.addr(o, UNKNOWN, k, out);
    }

    /// What `o`'s pointers point to is given to code not translated: it may write anything
    /// there (and what is reachable from there).
    pub(crate) fn reach(&mut self, o: u32, k: &Calls, out: &mut Vec<Bind>) {
        let no = self.node(o, k);
        let c = self.pointee(no);
        let pc = self.pointee(c);
        let u = self.node(UNKNOWN, k);
        self.join(pc, u, out);
    }

    /// A call through the pointer held in `o`: bound to each function its class holds, now
    /// and later.
    pub(crate) fn icall(&mut self, site: u32, o: u32, k: &Calls, out: &mut Vec<Bind>) {
        let no = self.node(o, k);
        let c = self.pointee(no);
        self.sites.entry(c).or_default().push(site);
        for f in self.named.get(&c).cloned().unwrap_or_default() {
            out.push(Bind::Call(site, f));
        }
    }

    /// A `dyn` call on the fat pointer held in `o` (its vtable in the same object).
    pub(crate) fn vcall(&mut self, site: u32, o: u32, slot: u32, k: &Calls, out: &mut Vec<Bind>) {
        let no = self.node(o, k);
        let c = self.pointee(no);
        self.vsites.entry(c).or_default().push((site, slot));
        for v in self.named.get(&c).cloned().unwrap_or_default() {
            out.push(Bind::Virtual(site, slot, v));
        }
    }

    /// What `o`'s pointers may point to: the named objects of the class (functions, vtables,
    /// the knowledge base's statics, `UNKNOWN`) and one of its other objects.
    pub(crate) fn pts_of(&self, o: u32) -> Vec<u32> {
        if o as usize >= self.parent.len() || !self.seen[o as usize] {
            return Vec::new();
        }
        let r = self.find_ro(o);
        let p = self.pt[r as usize];
        if p == NONE {
            return Vec::new();
        }
        let c = self.find_ro(p);
        let mut v = self.named.get(&c).cloned().unwrap_or_default();
        if let Some(&x) = self.other.get(&c) {
            v.push(x);
        }
        v
    }

    /// The class of object `o`'s pointee and of `o` itself (for diagnostics).
    pub(crate) fn classes(&self, o: u32) -> (u32, u32) {
        if o as usize >= self.parent.len() {
            return (NONE, NONE);
        }
        let r = self.find_ro(o);
        let p = self.pt[r as usize];
        (r, if p == NONE { NONE } else { self.find_ro(p) })
    }

    pub(crate) fn summary(&self) -> String {
        format!(
            "unification: {} nodes, {} joins, {} classes with named objects",
            self.parent.len(),
            self.joins,
            self.named.len()
        )
    }
}

/// A call a join made possible: through a pointer (site, function object), or `dyn` (site,
/// slot, vtable object).
pub(crate) enum Bind {
    Call(u32, u32),
    Virtual(u32, u32, u32),
}
