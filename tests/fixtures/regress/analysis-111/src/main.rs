// audit 12 probe g1: generic items of other crates (instances named across crates), default bodies, assoc consts
use ilib::{CDef, CFast, Def, Fast, Mid};
use ring::digest::{digest, Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1};
use tlib::{Holder, Pick};

fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }
struct Local;
impl Pick for Local { fn alg(&self) -> &'static Digest { &SHA1 } }
fn gen_local<T: Pick>(t: &T) -> &'static Digest { tlib::pick(t) }

fn main() {
    let d = arg(0).into_bytes();
    let _ = digest(tlib::pick(&Fast), &d);
    let _ = digest(tlib::pick2(&Mid), &d);
    let _ = digest(tlib::clos(&Fast), &d);
    let _ = digest(Holder(Mid).get(), &d);
    let _ = digest(Fast.via(), &d);
    let _ = digest(Def.via(), &d);
    let _ = digest(gen_local(&Local), &d);
    let _ = digest(tlib::by_impl(&Mid), &d);
    let f = tlib::pick::<Fast>;
    let _ = digest(f(&Fast), &d);
    let b = tlib::boxed(Def);
    let _ = digest(b.alg(), &d);
    let _ = digest(tlib::by_dyn(&Fast), &d);
    tlib::hash_in(&Mid, &d);
    tlib::hash_c::<CFast>(&d);
    tlib::hash_c::<CDef>(&d);
    tlib::hash_clos(&Fast, &d);
}
