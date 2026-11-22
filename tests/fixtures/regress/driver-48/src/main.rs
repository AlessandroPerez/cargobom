use sha2::Digest;

pub enum Kind {
    Plain,
    Short(u8),
    Long(Vec<u8>),
    Hashed(Vec<u8>),
}

pub struct Builder {
    name: String,
    count: u32,
    kind: Option<Kind>,
}

impl Builder {
    // the write goes through the `&mut Kind` the call returns, into `self.kind`
    pub fn push(mut self, data: &[u8]) -> Self {
        if let Kind::Hashed(all) = self
            .kind
            .get_or_insert_with(|| Kind::Hashed(Vec::new()))
        {
            all.extend(sha2::Sha256::digest(data));
        }
        self.count += 1;
        self
    }
}

fn main() {
    let input = std::env::args().nth(1).unwrap_or_default();
    let b = Builder {
        name: input.clone(),
        count: 0,
        kind: None,
    }
    .push(input.as_bytes());
    let n = match b.kind {
        Some(Kind::Hashed(v)) | Some(Kind::Long(v)) => v.len(),
        Some(Kind::Short(_)) => 1,
        Some(Kind::Plain) | None => 0,
    };
    println!("{} {} {n}", b.name, b.count);
}
