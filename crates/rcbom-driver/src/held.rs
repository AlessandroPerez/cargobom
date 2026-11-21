//! The functions the value of a static or a constant holds where code naming the item can
//! read them: a table of function pointers another crate exports (`pub static TABLE: &[(&str,
//! fn(&[u8]) -> Digest)]`), which a program calls through without naming any of the functions.
//!
//! The value is read as its type says, from the item's own memory: a function pointer is one
//! of the functions; a reference, a raw pointer, a slice and the fields of structs, tuples,
//! arrays, unions and every variant of an enum are followed, into the statics pointed at too.
//! A private field of a type a crate of the crypto set defines is not: only that crate's code
//! reads it, and what it does with it is its own (the functions inside aws-lc-rs's
//! `aead::CHACHA20_POLY1305`, which its `seal` calls). A private field of any other type is
//! followed: the code reading it is walked (`LazyLock`'s initializer, run by its `deref`).
//! Trait objects are not followed either: their methods are the coercion's.

use std::collections::HashSet;

use rustc_abi::{FieldsShape, Size, Variants};
use rustc_hir::def::DefKind;
use rustc_middle::mir::interpret::{AllocId, Allocation, GlobalAlloc, GlobalId, read_target_uint};
use rustc_middle::ty::layout::LayoutCx;
use rustc_middle::ty::{self, Ty, TypingEnv};
use rustc_span::def_id::DefId;

use crate::Cx;

/// A function in an item's value, with the item whose memory holds it: the item itself, or a
/// static its value points at.
pub(crate) type Held<'tcx> = (ty::Instance<'tcx>, DefId);

/// The elements of one array or slice read each by its type; past them, every function the
/// rest points at counts.
const MAX_ELEMENTS: u64 = 4096;
/// The values read of one item; past them, nothing more is (the item is then not read whole).
const MAX_VALUES: usize = 200_000;

/// The memory a value lies in: a static's, or one without a name.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Mem {
    Static(DefId),
    Alloc(AllocId),
}

struct Reader<'a, 'tcx> {
    cx: &'a Cx<'tcx>,
    lcx: LayoutCx<'tcx>,
    seen: HashSet<(Mem, u64, Ty<'tcx>)>,
    out: Vec<Held<'tcx>>,
    values: usize,
}

/// The functions `item`'s value holds that code naming `item` can read (see the module).
/// None for an item whose value the compiler does not evaluate on its own (a generic
/// constant, one whose evaluation may fail, a foreign static).
pub(crate) fn readable<'tcx>(cx: &Cx<'tcx>, item: DefId) -> Vec<Held<'tcx>> {
    let tcx = cx.tcx;
    let env = TypingEnv::fully_monomorphized();
    let mut r = Reader {
        cx,
        lcx: LayoutCx::new(tcx, env),
        seen: HashSet::new(),
        out: Vec::new(),
        values: 0,
    };
    match tcx.def_kind(item) {
        DefKind::Static { .. } if !tcx.is_foreign_item(item) => {
            if let Ok(a) = tcx.eval_static_initializer(item) {
                let ty =
                    tcx.normalize_erasing_regions(env, tcx.type_of(item).instantiate_identity());
                r.value(a.inner(), Mem::Static(item), Size::ZERO, ty, item, 0);
            }
        }
        DefKind::Const | DefKind::AssocConst
            if !tcx.generics_of(item).requires_monomorphization(tcx)
                && crate::statics::evaluable(tcx, item, None) =>
        {
            let id = GlobalId {
                instance: ty::Instance::mono(tcx, item),
                promoted: None,
            };
            if let Ok(c) = tcx.eval_to_allocation_raw(env.as_query_input(id))
                && let GlobalAlloc::Memory(m) = tcx.global_alloc(c.alloc_id)
            {
                r.value(m.inner(), Mem::Alloc(c.alloc_id), Size::ZERO, c.ty, item, 0);
            }
        }
        _ => {}
    }
    r.out
        .sort_by_key(|(i, h)| (tcx.def_path_hash(i.def_id()), tcx.def_path_hash(*h)));
    r.out.dedup();
    r.out
}

impl<'tcx> Reader<'_, 'tcx> {
    /// The value of type `ty` at `at` in `mem`, which `holder` holds.
    fn value(
        &mut self,
        mem: &'tcx Allocation,
        key: Mem,
        at: Size,
        ty: Ty<'tcx>,
        holder: DefId,
        depth: usize,
    ) {
        let tcx = self.cx.tcx;
        self.values += 1;
        if depth > 32 || self.values > MAX_VALUES {
            return;
        }
        let Ok(layout) = tcx.layout_of(self.lcx.typing_env.as_query_input(ty)) else {
            return;
        };
        let end = at + layout.size;
        // (no pointer in it: nothing to find)
        if end > mem.size() || mem.provenance().ptrs().range(at..end).is_empty() {
            return;
        }
        if !self.seen.insert((key, at.bytes(), ty)) {
            return;
        }
        match *ty.kind() {
            ty::FnPtr(..) => {
                if let Some(p) = mem.provenance().ptrs().get(&at)
                    && let GlobalAlloc::Function { instance } = tcx.global_alloc(p.alloc_id())
                {
                    self.out.push((instance, holder));
                }
            }
            ty::Ref(_, inner, _) | ty::RawPtr(inner, _) => {
                self.pointee(mem, at, inner, holder, depth)
            }
            ty::Adt(def, _) if def.is_enum() => match layout.variants {
                Variants::Empty => {}
                // (which variant the value is, its tag says; each is read as if it were: a
                // function pointer is found only where one is)
                _ => {
                    for (v, vd) in def.variants().iter_enumerated() {
                        if let Variants::Single { index } = layout.variants
                            && index != v
                        {
                            continue;
                        }
                        let vl = layout.for_variant(&self.lcx, v);
                        for i in 0..vd.fields.len().min(vl.fields.count()) {
                            let f = vl.field(&self.lcx, i);
                            let o = at + vl.fields.offset(i);
                            self.value(mem, key, o, f.ty, holder, depth + 1);
                        }
                    }
                }
            },
            ty::Adt(def, _) => {
                let closed = self.cx.kb_crate(def.did().krate);
                let fields = &def.non_enum_variant().fields;
                for (i, f) in fields.iter().enumerate().take(layout.fields.count()) {
                    if closed && !f.vis.is_public() {
                        continue;
                    }
                    let fl = layout.field(&self.lcx, i);
                    let o = at + layout.fields.offset(i);
                    self.value(mem, key, o, fl.ty, holder, depth + 1);
                }
            }
            _ => match layout.fields {
                FieldsShape::Primitive => {}
                FieldsShape::Array { stride, count } => {
                    let n = count.min(MAX_ELEMENTS);
                    for i in 0..n {
                        let e = layout.field(&self.lcx, i as usize);
                        self.value(mem, key, at + stride * i, e.ty, holder, depth + 1);
                    }
                    if count > n {
                        self.any(mem, at + stride * n, end, holder, 0);
                    }
                }
                _ => {
                    for i in 0..layout.fields.count() {
                        let f = layout.field(&self.lcx, i);
                        let o = at + layout.fields.offset(i);
                        self.value(mem, key, o, f.ty, holder, depth + 1);
                    }
                }
            },
        }
    }

    /// What the pointer at `at` points to, a value of type `inner` (or, for a slice, its
    /// elements).
    fn pointee(
        &mut self,
        mem: &'tcx Allocation,
        at: Size,
        inner: Ty<'tcx>,
        holder: DefId,
        depth: usize,
    ) {
        let tcx = self.cx.tcx;
        let Some(p) = mem.provenance().ptrs().get(&at) else {
            return;
        };
        let word = tcx.data_layout.pointer_size();
        let read = |o: Size| {
            let end = o + word;
            (end <= mem.size())
                .then(|| {
                    let bytes = mem.inspect_with_uninit_and_ptr_outside_interpreter(
                        o.bytes_usize()..end.bytes_usize(),
                    );
                    read_target_uint(tcx.data_layout.endian, bytes).ok()
                })
                .flatten()
                .and_then(|v| u64::try_from(v).ok())
        };
        let Some(offset) = read(at) else {
            return;
        };
        let id = p.alloc_id();
        let (target, key, holder) = match tcx.global_alloc(id) {
            GlobalAlloc::Memory(m) => (m.inner(), Mem::Alloc(id), holder),
            GlobalAlloc::Static(d) if !tcx.is_foreign_item(d) => {
                match tcx.eval_static_initializer(d) {
                    Ok(a) => (a.inner(), Mem::Static(d), d),
                    Err(_) => return,
                }
            }
            // (a function's address as data, a vtable: nothing called through as a function
            // pointer)
            _ => return,
        };
        let offset = Size::from_bytes(offset);
        match *inner.kind() {
            ty::Str | ty::Dynamic(..) => {}
            ty::Slice(elem) => {
                let Some(len) = read(at + word) else {
                    return;
                };
                let Ok(el) = tcx.layout_of(self.lcx.typing_env.as_query_input(elem)) else {
                    return;
                };
                let n = len.min(MAX_ELEMENTS);
                for i in 0..n {
                    self.value(target, key, offset + el.size * i, elem, holder, depth + 1);
                }
                if len > n {
                    self.any(target, offset + el.size * n, target.size(), holder, 0);
                }
            }
            _ if inner.is_sized(tcx, self.lcx.typing_env) => {
                self.value(target, key, offset, inner, holder, depth + 1)
            }
            // (a struct ending in a slice or a trait object: not read by its type)
            _ => self.any(target, offset, target.size(), holder, 0),
        }
    }

    /// Every function the bytes `from..to` of `mem` point at, through the memory they point
    /// at: for what is not read by its type.
    fn any(&mut self, mem: &'tcx Allocation, from: Size, to: Size, holder: DefId, depth: usize) {
        let tcx = self.cx.tcx;
        if depth > 8 || from >= to {
            return;
        }
        for (_, p) in mem.provenance().ptrs().range(from..to) {
            match tcx.global_alloc(p.alloc_id()) {
                GlobalAlloc::Function { instance } => self.out.push((instance, holder)),
                GlobalAlloc::Memory(m) => {
                    self.values += 1;
                    if self.values <= MAX_VALUES {
                        let m = m.inner();
                        self.any(m, Size::ZERO, m.size(), holder, depth + 1);
                    }
                }
                _ => {}
            }
        }
    }
}
