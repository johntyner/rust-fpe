#![allow(dead_code)]

pub(crate) mod ffx;

pub mod error {
    #[derive(Debug)]
    pub struct Error {
        why: String,
    }

    impl Error {
        pub fn new(why: &str) -> Self {
            Error {
                why: why.to_string(),
            }
        }
    }
}

pub mod result {
    pub type Result<T> = std::result::Result<T, crate::error::Error>;
}
