use ring::digest::{Algorithm, SHA384, SHA512};
use tlib::{HasConst, Pick};
pub struct Fast;
impl Pick for Fast { fn alg(&self) -> &'static Algorithm { &SHA512 } }
pub struct Mid;
impl Pick for Mid { fn alg(&self) -> &'static Algorithm { &SHA384 } }
pub struct Def;
impl Pick for Def {}
pub struct CFast;
impl HasConst for CFast { const ALG: &'static Algorithm = &SHA512; }
pub struct CDef;
impl HasConst for CDef {}
