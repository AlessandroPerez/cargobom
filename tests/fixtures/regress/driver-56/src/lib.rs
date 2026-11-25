use ring::digest::{self, Algorithm};

pub trait Cx {
    /// What a search hands back: a type of the implementor's, which may hold a borrow.
    type It: Default + Next<Self>;
    fn first(&mut self, v: u32, it: &mut Self::It);
    fn see(&mut self, cfg: &mut Cfg<'_>);
}

pub struct Cfg<'a> {
    pub alg: &'static Algorithm,
    pub buf: &'a mut [u8],
}

pub trait Next<C: ?Sized> {
    fn next(&mut self, cx: &mut C) -> Option<u32>;
}

/// The code given, five times over.
macro_rules! x5 {
    ($($t:tt)*) => { $($t)* $($t)* $($t)* $($t)* $($t)* };
}

fn choose(a: &mut &'static Algorithm, wide: bool) {
    if wide {
        *a = &digest::SHA512_256;
    }
}

/// 3,125 searches one after the other, each with its own iterator lent to the context.
pub fn walk<C: Cx>(cx: &mut C, v: u32, data: &[u8], out: &mut Vec<u8>) {
    let mut early: &'static Algorithm = &digest::SHA256;
    choose(&mut early, v > 7);
    let mut late: &'static Algorithm = &digest::SHA256;
    choose(&mut late, v > 9);
    x5! { x5! { x5! { x5! { x5! {
        {
            let mut it = C::It::default();
            cx.first(v, &mut it);
            while let Some(w) = it.next(cx) {
                out.push(w as u8);
            }
        }
    } } } } }
    late = &digest::SHA384;
    out.extend_from_slice(digest::digest(early, data).as_ref());
    out.extend_from_slice(digest::digest(late, data).as_ref());
}

/// The algorithm is set after the last call that may write the configuration.
pub fn set_last<C: Cx>(cx: &mut C, mut cfg: Cfg<'_>, data: &[u8]) -> Vec<u8> {
    x5! {
        cx.see(&mut cfg);
    }
    cfg.alg = &digest::SHA512;
    digest::digest(cfg.alg, data).as_ref().to_vec()
}

/// A call that may write the configuration comes after the algorithm is set.
pub fn set_first<C: Cx>(cx: &mut C, mut cfg: Cfg<'_>, data: &[u8]) -> Vec<u8> {
    x5! {
        cx.see(&mut cfg);
    }
    cfg.alg = &digest::SHA1_FOR_LEGACY_USE_ONLY;
    x5! {
        cx.see(&mut cfg);
    }
    digest::digest(cfg.alg, data).as_ref().to_vec()
}
