//! Types whose `hash` a derive macro writes: its call for a field is cited at the field's type,
//! in the body of the type the caller is a method of.

use std::collections::BTreeMap;

use crate::content_hash::ContentHash;
use crate::object_id::id_type;

id_type!(
    /// A commit's id.
    pub CommitId
);

impl CommitId {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

/// Milliseconds since the epoch.
#[derive(ContentHash, Clone)]
pub struct MillisSinceEpoch(pub i64);

#[derive(ContentHash, Clone)]
pub struct Timestamp {
    /// When.
    pub timestamp: MillisSinceEpoch,
    /// Minutes east of UTC.
    pub tz_offset: u8,
}

#[derive(ContentHash)]
pub struct Commit {
    pub parents: Vec<CommitId>,
    pub time: Timestamp,
    pub refs: BTreeMap<CommitId, Timestamp>,
}
