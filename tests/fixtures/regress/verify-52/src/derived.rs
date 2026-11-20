//! tendermint (`#[derive(\n    .., Serialize,\n)]`): a derive's code is cited where the attribute
//! names the derive, which of an attribute written over several lines is not its first.

use pm::Fingerprint;

#[derive(
    Clone, Debug, PartialEq,
    Fingerprint,
)]
pub struct Record(pub Vec<u8>);
