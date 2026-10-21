// round 11 regress (audit 10 probe c1): std containers and static tables
use ring::digest::{digest, Algorithm as Digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA384, SHA512};
use std::collections::{BTreeMap, HashMap, VecDeque};

fn arg(i: usize) -> String { std::env::args().nth(i).unwrap_or_default() }

struct E { h: &'static Digest, legacy: &'static Digest }
static DIGESTS: [&Digest; 2] = [&SHA256, &SHA384];
static TABLE: [E; 2] = [E { h: &SHA256, legacy: &SHA1 }, E { h: &SHA512, legacy: &SHA1 }];
static NESTED: [[&Digest; 2]; 2] = [[&SHA256, &SHA384], [&SHA512, &SHA1]];
static TT: [&[&Digest; 2]; 1] = [&DIGESTS];

fn fill(m: &mut HashMap<u8, &'static Digest>) { m.insert(1, &SHA384); }
fn make() -> Vec<&'static Digest> { let mut v = Vec::new(); v.push(&SHA512); v }
fn use_map(m: &HashMap<&str, &'static Digest>, d: &[u8]) { let _ = digest(m["k"], d); }

fn main() {
    let d = arg(0).into_bytes();
    let i = arg(1).len() % 2;
    let j = arg(2).len() % 2;
    let mut m1 = HashMap::new();
    m1.insert("a", &SHA256);
    m1.insert("b", &SHA384);
    let _ = digest(m1["a"], &d);
    let mut m3 = BTreeMap::new();
    m3.insert(1u8, &SHA512);
    if let Some(a) = m3.get(&1) { let _ = digest(a, &d); }
    let mut v = Vec::new();
    v.push(&SHA1);
    v.push(&SHA256);
    let _ = digest(v[i], &d);
    let mut q = VecDeque::new();
    q.push_back(&SHA384);
    q.push_front(&SHA512);
    let _ = digest(q[0], &d);
    let _ = digest(q.pop_back().unwrap(), &d);
    let mut m4 = HashMap::new();
    m4.entry("k").or_insert(&SHA384);
    let _ = digest(m4["k"], &d);
    let mut v5: Vec<&'static Digest> = Vec::new();
    v5.extend([&SHA512]);
    let _ = digest(v5[0], &d);
    let v6 = vec![&SHA256, &SHA384];
    let f = v6.iter().find(|a| a.output_len() > 40).unwrap();
    let _ = digest(f, &d);
    let mut m7 = HashMap::new();
    fill(&mut m7);
    let _ = digest(m7[&1], &d);
    let v8 = make();
    let _ = digest(v8[0], &d);
    let mut m9 = HashMap::new();
    m9.insert("k", &SHA1);
    use_map(&m9, &d);
    let mut v10 = vec![&SHA256];
    v10[0] = &SHA512;
    let _ = digest(v10[0], &d);
    let v11 = vec![E { h: &SHA256, legacy: &SHA1 }];
    let _ = digest(v11[0].h, &d);
    let v12 = v.clone();
    let _ = digest(v12[1], &d);
    let v13: Vec<&'static Digest> = [&SHA384, &SHA512].into_iter().collect();
    let _ = digest(v13[0], &d);
    let mut v14 = vec![&SHA1, &SHA512];
    let x14 = v14.remove(1);
    let _ = digest(x14, &d);
    let _ = digest(v.last().unwrap(), &d);
    let mut m15 = HashMap::new();
    m15.insert("a", &SHA256);
    if let Some(old) = m15.insert("a", &SHA512) { let _ = digest(old, &d); }
    let _ = digest(DIGESTS[i], &d);
    let _ = digest(DIGESTS[0], &d);
    let _ = digest(TABLE[i].h, &d);
    let _ = digest(TABLE[i].legacy, &d);
    let _ = digest(NESTED[i][j], &d);
    let _ = digest(NESTED[0][1], &d);
    let _ = digest(TT[0][i], &d);
    let _ = digest(DIGESTS.get(i).unwrap(), &d);
    let _ = digest(DIGESTS.iter().find(|a| a.output_len() == 48).unwrap(), &d);
    for a in DIGESTS.iter() { let _ = digest(a, &d); }
}
