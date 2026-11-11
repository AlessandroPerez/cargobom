mod backend;
mod boxed;
mod chain;
mod content_hash;
mod futures;
mod iter;
mod keyed;
mod object_id;
mod rename;
mod rng;
mod select;
mod shown;

use std::collections::BTreeMap;

use backend::{Commit, CommitId, MillisSinceEpoch, Timestamp};

fn main() {
    let input = std::env::args().nth(1).unwrap_or_default().into_bytes();
    let ids = rng::Ids::new(input.first().map(|b| *b as u64));
    let time = Timestamp {
        timestamp: MillisSinceEpoch(input.len() as i64),
        tz_offset: 0,
    };
    let parent = CommitId::new(ids.id(20));
    let commit = Commit {
        parents: vec![parent.clone()],
        time: time.clone(),
        refs: BTreeMap::from([(parent, time)]),
    };
    let digest = content_hash::sha512_hash(&commit);
    let mut legacy = sha1_smol::Sha1::new();
    legacy.update(&digest);
    println!("{:x?} {:x?}", digest, chain::peer(&chain::Outer(legacy)));
    println!("{:x?}", futures::handle(&digest));

    let mut tee = rename::Tee(Default::default(), 0);
    shim::Feed::update(&mut tee, &digest);
    println!("{} {}", tee.1, iter::deal(&digest));
    println!("{:x?}", futures::block_on(select::connect(&digest)));

    let holder = shown::Holder {
        state: sha1_smol::Sha1::from(&digest[..]),
    };
    let key = keyed::Key::Plain(keyed::Inner([digest[0], digest[1], digest[2], digest[3]]));
    println!(
        "{:x?} {} {} {:?}",
        boxed::hash(digest[0] & 1, &digest),
        holder.show(),
        keyed::slot(&key),
        keyed::Key::Tagged(1) == key,
    );
}
