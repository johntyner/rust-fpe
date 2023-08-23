pub(crate) mod aes;
pub mod ff1;
pub mod ff3_1;
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
}

pub mod result {
    pub type Result<T> = std::result::Result<T, crate::error::Error>;
}
