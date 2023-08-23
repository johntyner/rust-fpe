use crate::error::Error;
use crate::result::Result;

use aes;
use cbc;

use aes::cipher::BlockEncryptMut;
use aes::cipher::BlockSizeUser;
use aes::cipher::KeyIvInit;

enum AesType {
    Aes128Cbc,
    Aes192Cbc,
    Aes256Cbc,
}

union AesCipher {
    aes128cbc: std::mem::ManuallyDrop<cbc::Encryptor<aes::Aes128>>,
    aes192cbc: std::mem::ManuallyDrop<cbc::Encryptor<aes::Aes192>>,
    aes256cbc: std::mem::ManuallyDrop<cbc::Encryptor<aes::Aes256>>,
}

pub struct Cipher {
    typ: AesType,
    aes: AesCipher,
}

impl Cipher {
    pub fn new(key: &[u8]) -> Result<Cipher> {
        const IV: &[u8] = &[0u8; 16];

        Ok(match key.len() {
            16 => Cipher {
                typ: AesType::Aes128Cbc,
                aes: AesCipher {
                    aes128cbc: std::mem::ManuallyDrop::new(cbc::Encryptor::<
                        aes::Aes128,
                    >::new(
                        key.into(),
                        IV.into(),
                    )),
                },
            },
            24 => Cipher {
                typ: AesType::Aes192Cbc,
                aes: AesCipher {
                    aes192cbc: std::mem::ManuallyDrop::new(cbc::Encryptor::<
                        aes::Aes192,
                    >::new(
                        key.into(),
                        IV.into(),
                    )),
                },
            },
            32 => Cipher {
                typ: AesType::Aes256Cbc,
                aes: AesCipher {
                    aes256cbc: std::mem::ManuallyDrop::new(cbc::Encryptor::<
                        aes::Aes256,
                    >::new(
                        key.into(),
                        IV.into(),
                    )),
                },
            },
            _ => return Err(Error::new("invalid key length")),
        })
    }

    pub fn encrypt_block(&mut self, src: &[u8], dst: &mut [u8]) {
        unsafe {
            match self.typ {
                AesType::Aes128Cbc => (*self.aes.aes128cbc)
                    .encrypt_block_b2b_mut(src.into(), dst.into()),
                AesType::Aes192Cbc => (*self.aes.aes192cbc)
                    .encrypt_block_b2b_mut(src.into(), dst.into()),
                AesType::Aes256Cbc => (*self.aes.aes256cbc)
                    .encrypt_block_b2b_mut(src.into(), dst.into()),
            }
        }
    }

    pub fn block_size(&self) -> usize {
        match self.typ {
            AesType::Aes128Cbc => aes::Aes128::block_size(),
            AesType::Aes192Cbc => aes::Aes192::block_size(),
            AesType::Aes256Cbc => aes::Aes256::block_size(),
        }
    }
}

impl Clone for Cipher {
    fn clone(&self) -> Self {
        unsafe {
            match self.typ {
                AesType::Aes128Cbc => Cipher {
                    typ: AesType::Aes128Cbc,
                    aes: AesCipher {
                        aes128cbc: self.aes.aes128cbc.clone(),
                    },
                },
                AesType::Aes192Cbc => Cipher {
                    typ: AesType::Aes192Cbc,
                    aes: AesCipher {
                        aes192cbc: self.aes.aes192cbc.clone(),
                    },
                },
                AesType::Aes256Cbc => Cipher {
                    typ: AesType::Aes256Cbc,
                    aes: AesCipher {
                        aes256cbc: self.aes.aes256cbc.clone(),
                    },
                },
            }
        }
    }
}

impl Drop for Cipher {
    fn drop(&mut self) {
        unsafe {
            match self.typ {
                AesType::Aes128Cbc => drop(&mut self.aes.aes128cbc),
                AesType::Aes192Cbc => drop(&mut self.aes.aes192cbc),
                AesType::Aes256Cbc => drop(&mut self.aes.aes256cbc),
            }
        }
    }
}
