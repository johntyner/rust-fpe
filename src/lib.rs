#![allow(dead_code)]

pub mod ff1;
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

        #[allow(dead_code)]
        pub fn not_implemented() -> Self {
            Self::new("not implemented")
        }
    }

    impl From<openssl::error::ErrorStack> for Error {
        fn from(e: openssl::error::ErrorStack) -> Self {
            Error::new(&e.to_string())
        }
    }
}

pub mod result {
    pub type Result<T> = std::result::Result<T, crate::error::Error>;
}
