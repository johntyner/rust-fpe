use crate::error::Error;
use crate::result::Result;

use aes;
use cbc;

use aes::cipher::BlockEncryptMut;
use aes::cipher::BlockSizeUser;
use aes::cipher::KeyIvInit;

#[derive(Clone)]
enum CbcType {
    Aes128(cbc::Encryptor<aes::Aes128>),
    Aes192(cbc::Encryptor<aes::Aes192>),
    Aes256(cbc::Encryptor<aes::Aes256>),
}

#[derive(Clone)]
pub struct Cipher {
    enc: CbcType,
}

macro_rules! construct_cipher {
    ($type:ident, $key:expr, $iv:expr) => {
        Cipher {
            enc: CbcType::$type(cbc::Encryptor::<aes::$type>::new(
                $key.into(),
                $iv.into(),
            )),
        }
    };
}

impl Cipher {
    pub fn new(key: &[u8]) -> Result<Cipher> {
        const IV: &[u8] = &[0u8; 16];

        Ok(match key.len() {
            16 => construct_cipher!(Aes128, key, IV),
            24 => construct_cipher!(Aes192, key, IV),
            32 => construct_cipher!(Aes256, key, IV),
            _ => return Err(Error::new("invalid key length")),
        })
    }

    pub fn encrypt_block(&mut self, src: &[u8], dst: &mut [u8]) {
        match &mut self.enc {
            CbcType::Aes128(e) => {
                e.encrypt_block_b2b_mut(src.into(), dst.into())
            }
            CbcType::Aes192(e) => {
                e.encrypt_block_b2b_mut(src.into(), dst.into())
            }
            CbcType::Aes256(e) => {
                e.encrypt_block_b2b_mut(src.into(), dst.into())
            }
        }
    }

    pub fn block_size(&self) -> usize {
        match self.enc {
            CbcType::Aes128(_) => aes::Aes128::block_size(),
            CbcType::Aes192(_) => aes::Aes192::block_size(),
            CbcType::Aes256(_) => aes::Aes256::block_size(),
        }
    }
}
