pub fn c(d: &[u8]) -> usize {
	let s = "é日🔑"; let x = ring::digest::digest(&ring::digest::SHA384, d);
	x.as_ref().len() + s.len()
}
