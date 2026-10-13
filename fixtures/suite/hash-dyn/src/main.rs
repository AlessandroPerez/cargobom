use ring::digest;

trait Source {
    fn alg(&self) -> &'static digest::Algorithm;
    fn label(&self) -> &'static str;
}

struct Blob;
struct Manifest;

impl Source for Blob {
    fn alg(&self) -> &'static digest::Algorithm { &digest::SHA384 }
    fn label(&self) -> &'static str { "blob" }
}

impl Source for Manifest {
    fn alg(&self) -> &'static digest::Algorithm { &digest::SHA1_FOR_LEGACY_USE_ONLY }
    fn label(&self) -> &'static str { "manifest" }
}

fn fingerprint(s: &dyn Source, data: &[u8]) -> digest::Digest {
    digest::digest(s.alg(), data)
}

fn main() {
    let blob: Box<dyn Source> = Box::new(Blob);
    let manifest: Box<dyn Source> = Box::new(Manifest);
    let d = fingerprint(blob.as_ref(), b"dyn");
    println!("{} {} {}", blob.label(), manifest.label(), d.as_ref().len());
}
