use crate::error::Error;
use crate::result::Result;

use aes;
use cbc;

use aes::cipher::BlockEncryptMut;
use aes::cipher::BlockSizeUser;
use aes::cipher::KeyIvInit;

#[derive(Clone)]
enum AesType {
    Aes128Cbc(cbc::Encryptor<aes::Aes128>),
    Aes192Cbc(cbc::Encryptor<aes::Aes192>),
    Aes256Cbc(cbc::Encryptor<aes::Aes256>),
}

#[derive(Clone)]
pub struct Cipher {
    aes: AesType,
}

impl Cipher {
    pub fn new(key: &[u8]) -> Result<Cipher> {
        const IV: &[u8] = &[0u8; 16];

        Ok(match key.len() {
            16 => Cipher {
                aes: AesType::Aes128Cbc(cbc::Encryptor::<aes::Aes128>::new(
                    key.into(),
                    IV.into(),
                )),
            },
            24 => Cipher {
                aes: AesType::Aes192Cbc(cbc::Encryptor::<aes::Aes192>::new(
                    key.into(),
                    IV.into(),
                )),
            },
            32 => Cipher {
                aes: AesType::Aes256Cbc(cbc::Encryptor::<aes::Aes256>::new(
                    key.into(),
                    IV.into(),
                )),
            },
            _ => return Err(Error::new("invalid key length")),
        })
    }

    pub fn encrypt_block(&mut self, src: &[u8], dst: &mut [u8]) {
        match &mut self.aes {
            AesType::Aes128Cbc(e) => {
                e.encrypt_block_b2b_mut(src.into(), dst.into())
            }
            AesType::Aes192Cbc(e) => {
                e.encrypt_block_b2b_mut(src.into(), dst.into())
            }
            AesType::Aes256Cbc(e) => {
                e.encrypt_block_b2b_mut(src.into(), dst.into())
            }
        }
    }

    pub fn block_size(&self) -> usize {
        match self.aes {
            AesType::Aes128Cbc(_) => aes::Aes128::block_size(),
            AesType::Aes192Cbc(_) => aes::Aes192::block_size(),
            AesType::Aes256Cbc(_) => aes::Aes256::block_size(),
        }
    }
}
