pub mod ff1;
pub(crate) mod ffx;

pub mod error {
    #[derive(Debug)]
    pub struct Error {
        #[allow(dead_code)]
        why: String,
    }

    impl Error {
        pub fn new(why: &str) -> Self {
            Error {
                why: why.to_string(),
            }
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
