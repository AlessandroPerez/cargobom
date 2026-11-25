use serde::Serialize;
use serde::ser::{self, Impossible, SerializeStruct, Serializer};
use sha2::{Digest, Sha256};
use std::fmt;

type Hash = [u8; 32];
type No = Impossible<Hash, Unsupported>;

#[derive(Debug)]
struct Unsupported;

impl fmt::Display for Unsupported {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a value the hash is not defined for")
    }
}

impl std::error::Error for Unsupported {}

impl ser::Error for Unsupported {
    fn custom<T: fmt::Display>(_: T) -> Self {
        Unsupported
    }
}

/// Hashes a value: text and numbers by their bytes, a struct by its fields' hashes.
struct Hasher;

struct Fields(Vec<(Hash, Hash)>);

impl SerializeStruct for Fields {
    type Ok = Hash;
    type Error = Unsupported;

    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Unsupported> {
        let hash = value.serialize(Hasher)?;
        self.0.push((Sha256::digest(key.as_bytes()).into(), hash));
        Ok(())
    }

    fn end(mut self) -> Result<Hash, Unsupported> {
        self.0.sort_unstable();
        let mut all = Sha256::new();
        for (key, value) in self.0 {
            all.update(key);
            all.update(value);
        }
        Ok(all.finalize().into())
    }
}

impl Serializer for Hasher {
    type Ok = Hash;
    type Error = Unsupported;
    type SerializeSeq = No;
    type SerializeTuple = No;
    type SerializeTupleStruct = No;
    type SerializeTupleVariant = No;
    type SerializeMap = No;
    type SerializeStruct = Fields;
    type SerializeStructVariant = No;

    fn serialize_str(self, v: &str) -> Result<Hash, Unsupported> {
        Ok(Sha256::digest(v.as_bytes()).into())
    }
    fn serialize_bytes(self, v: &[u8]) -> Result<Hash, Unsupported> {
        Ok(Sha256::digest(v).into())
    }
    fn serialize_u64(self, v: u64) -> Result<Hash, Unsupported> {
        Ok(Sha256::digest(v.to_be_bytes()).into())
    }
    fn serialize_struct(self, _: &'static str, len: usize) -> Result<Fields, Unsupported> {
        Ok(Fields(Vec::with_capacity(len)))
    }
    fn serialize_some<T: Serialize + ?Sized>(self, v: &T) -> Result<Hash, Unsupported> {
        v.serialize(self)
    }
    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        _: &'static str,
        v: &T,
    ) -> Result<Hash, Unsupported> {
        v.serialize(self)
    }
    fn serialize_bool(self, _: bool) -> Result<Hash, Unsupported> {
        Err(Unsupported)
    }
    fn serialize_i8(self, _: i8) -> Result<Hash, Unsupported> {
        Err(Unsupported)
    }
    fn serialize_i16(self, _: i16) -> Result<Hash, Unsupported> {
        Err(Unsupported)
    }
    fn serialize_i32(self, _: i32) -> Result<Hash, Unsupported> {
        Err(Unsupported)
    }
    fn serialize_i64(self, _: i64) -> Result<Hash, Unsupported> {
        Err(Unsupported)
    }
    fn serialize_u8(self, _: u8) -> Result<Hash, Unsupported> {
        Err(Unsupported)
    }
    fn serialize_u16(self, _: u16) -> Result<Hash, Unsupported> {
        Err(Unsupported)
    }
    fn serialize_u32(self, _: u32) -> Result<Hash, Unsupported> {
        Err(Unsupported)
    }
    fn serialize_f32(self, _: f32) -> Result<Hash, Unsupported> {
        Err(Unsupported)
    }
    fn serialize_f64(self, _: f64) -> Result<Hash, Unsupported> {
        Err(Unsupported)
    }
    fn serialize_char(self, _: char) -> Result<Hash, Unsupported> {
        Err(Unsupported)
    }
    fn serialize_none(self) -> Result<Hash, Unsupported> {
        Err(Unsupported)
    }
    fn serialize_unit(self) -> Result<Hash, Unsupported> {
        Err(Unsupported)
    }
    fn serialize_unit_struct(self, _: &'static str) -> Result<Hash, Unsupported> {
        Err(Unsupported)
    }
    fn serialize_unit_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
    ) -> Result<Hash, Unsupported> {
        Err(Unsupported)
    }
    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: &T,
    ) -> Result<Hash, Unsupported> {
        Err(Unsupported)
    }
    fn serialize_seq(self, _: Option<usize>) -> Result<No, Unsupported> {
        Err(Unsupported)
    }
    fn serialize_tuple(self, _: usize) -> Result<No, Unsupported> {
        Err(Unsupported)
    }
    fn serialize_tuple_struct(self, _: &'static str, _: usize) -> Result<No, Unsupported> {
        Err(Unsupported)
    }
    fn serialize_tuple_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> Result<No, Unsupported> {
        Err(Unsupported)
    }
    fn serialize_map(self, _: Option<usize>) -> Result<No, Unsupported> {
        Err(Unsupported)
    }
    fn serialize_struct_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> Result<No, Unsupported> {
        Err(Unsupported)
    }
}

mod digested {
    use sha2::Digest;

    // (generic over the serializer: an instance for each, made where it is called)
    pub fn serialize<S: serde::Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&sha2::Sha512::digest(v))
    }
}

#[derive(Serialize)]
struct Request {
    #[serde(with = "digested")]
    nonce: Vec<u8>,
    #[serde(serialize_with = "digested::serialize")]
    body: Vec<u8>,
    sender: String,
}

fn main() {
    let request = Request {
        nonce: std::env::args().next().unwrap_or_default().into_bytes(),
        body: vec![1, 2, 3],
        sender: "a".into(),
    };
    println!("{:x?}", request.serialize(Hasher));
}
