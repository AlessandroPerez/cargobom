//! sqlx: drivers as constants a macro declares, each holding a function. The function is
//! instantiated where code uses the constant, whose definition leads to it: the macro's
//! `Driver::with::<..>()`, whose body names `connect_with`.

use sha2::{Digest, Sha256, Sha384};

pub struct Driver {
    pub name: &'static str,
    pub connect: fn(&[u8]) -> Vec<u8>,
}

impl Driver {
    pub const fn with<D: Digest>(name: &'static str) -> Driver {
        Driver {
            name,
            connect: connect_with::<D>,
        }
    }
}

fn connect_with<D: Digest>(data: &[u8]) -> Vec<u8> {
    D::digest(data).to_vec()
}

macro_rules! declare_driver {
    ($name:ident = $db:ty) => {
        pub const $name: Driver = Driver::with::<$db>(stringify!($name));
    };
}

declare_driver!(POSTGRES = Sha256);
declare_driver!(MYSQL = Sha384);

pub fn install(data: &[u8]) -> Vec<u8> {
    let drivers = &[
        POSTGRES,
        MYSQL,
    ];
    drivers
        .iter()
        .flat_map(|d| (d.connect)(format!("{}{:x?}", d.name, data).as_bytes()))
        .collect()
}
