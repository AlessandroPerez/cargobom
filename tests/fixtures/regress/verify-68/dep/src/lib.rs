// Macros for another crate's code: each hands what it is given to a procedural macro.
#[doc(hidden)]
pub use pm;

#[macro_export]
macro_rules! via {
    ($t:tt) => {
        $crate::pm::hashed!($t)
    };
}

// Hands the procedural macro the first of what it is given, and writes the rest itself.
#[macro_export]
macro_rules! part {
    ($t:tt, $body:expr) => {{
        let first = $crate::pm::hashed!($t);
        (first, $body)
    }};
}

// Invokes itself, then the procedural macro.
#[macro_export]
macro_rules! again {
    (@last $t:tt) => {
        $crate::pm::hashed!($t)
    };
    ($t:tt) => {
        $crate::again!(@last $t)
    };
}
