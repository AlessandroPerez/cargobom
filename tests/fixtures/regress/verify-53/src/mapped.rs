//! cryptographic-message-syntax (`.map(SignerInfo::try_from).collect::<Result<Vec<_>, _>>()`):
//! a function handed to `map` by its path and collected into a `Result` is run from a closure
//! the standard library's `map_try_fold` writes, cited where that function writes it.

pub struct Signer(pub String);

impl TryFrom<&Vec<u8>> for Signer {
    type Error = ();

    fn try_from(raw: &Vec<u8>) -> Result<Self, Self::Error> {
        let mut h = sha1_smol::Sha1::new();
        h.update(raw);
        if raw.is_empty() {
            return Err(());
        }
        Ok(Signer(h.digest().to_string()))
    }
}

pub fn all(raw: &[Vec<u8>]) -> Result<Vec<Signer>, ()> {
    raw.iter()
        .map(Signer::try_from)
        .collect::<Result<Vec<_>, _>>()
}
