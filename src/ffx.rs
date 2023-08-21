use crate::error::Error;
use crate::result::Result;

struct SizeLimits {
    min: usize,
    max: usize,
}

struct FFXSizeLimits {
    twk: SizeLimits,
    txt: SizeLimits,
}

struct FFX {
    cipher: openssl::cipher_ctx::CipherCtx,

    radix: usize,
    alpha: Vec<char>,

    len: FFXSizeLimits,

    twk: Option<Vec<u8>>,
}

const DEFAULT_ALPHABET: &str = "0123456789abcdefghijklmnopqrstuvwxyz";

impl FFX {
    pub fn new(
        key: &[u8],
        opt_twk: Option<&[u8]>,
        maxtxt: usize,
        mintwk: usize,
        maxtwk: usize,
        radix: usize,
        opt_alpha: Option<String>,
    ) -> Result<Self> {
        let alpha: &str;
        if opt_alpha.is_some() {
            alpha = opt_alpha.as_ref().unwrap();
        } else {
            alpha = DEFAULT_ALPHABET;
        }

        let mut chars = Vec::<char>::new();
        alpha.chars().for_each(|c| chars.push(c));
        if radix < 2 || radix > chars.len() {
            return Err(Error::new("invalid radix"));
        }

        let mintxt = (6f64 / (radix as f64).log10()).ceil() as usize;
        if mintxt < 2 || mintxt > maxtxt {
            return Err(Error::new("unsupported radix/maximum text length"));
        }

        if mintwk < maxtwk {
            return Err(Error::new(
                "minimum tweak length must be less than maximum",
            ));
        }

        let twk: Option<Vec<u8>>;
        match opt_twk {
            None => twk = None,
            Some(t) => {
                if t.len() < mintwk || (maxtwk > 0 && t.len() > maxtwk) {
                    return Err(Error::new("invalid tweak length"));
                }

                twk = Some(t.to_vec());
            }
        }

        let algo: &openssl::cipher::CipherRef;
        match key.len() {
            16 => algo = openssl::cipher::Cipher::aes_128_cbc(),
            24 => algo = openssl::cipher::Cipher::aes_192_cbc(),
            32 => algo = openssl::cipher::Cipher::aes_256_cbc(),
            _ => return Err(Error::new("invalid key size")),
        }

        let cipher: openssl::cipher_ctx::CipherCtx;
        match openssl::cipher_ctx::CipherCtx::new() {
            Err(e) => return Err(Error::new(&e.to_string())),
            Ok(mut c) => {
                static IV: [u8; 16] = [0; 16];
                match c.encrypt_init(Some(algo), Some(key), Some(&IV)) {
                    Err(e) => return Err(Error::new(&e.to_string())),
                    Ok(_) => {
                        c.set_padding(false);
                        cipher = c;
                    }
                }
            }
        }

        Ok(FFX {
            cipher: cipher,

            radix: radix,
            alpha: chars,

            len: FFXSizeLimits {
                twk: SizeLimits {
                    min: mintwk,
                    max: maxtwk,
                },
                txt: SizeLimits {
                    min: mintxt,
                    max: maxtxt,
                },
            },

            twk: twk,
        })
    }

    unsafe fn openssl_prf(
        &self,
        d: &mut [u8],
        s: &[u8],
    ) -> std::result::Result<(), openssl::error::ErrorStack> {
        let blksz = self.cipher.block_size();

        let mut c = openssl::cipher_ctx::CipherCtx::new()?;
        c.copy(&self.cipher)?;

        for i in 0..(s.len() / blksz) {
            c.cipher_update_unchecked(&s[i..(i + blksz)], Some(d))?;
        }

        c.cipher_final_unchecked(d)?;

        Ok(())
    }

    pub(crate) fn prf(&self, d: &mut [u8], s: &[u8]) -> Result<()> {
        let blksz = self.cipher.block_size();

        if s.len() % blksz != 0 {
            return Err(Error::new(
                "source length is not a multiple of block size",
            ));
        }

        unsafe {
            if d.len() < blksz {
                return Err(Error::new(&format!(
                    "destination buffer must be at least {} bytes",
                    blksz
                )));
            }

            match self.openssl_prf(d, s) {
                Err(e) => Err(Error::new(&e.to_string())),
                Ok(_) => Ok(()),
            }
        }
    }

    pub(crate) fn ciph(&self, d: &mut [u8], s: &[u8]) -> Result<()> {
        self.prf(d, &s[0..16])
    }
}

#[cfg(test)]
mod tests {
    use super::FFX;
    use crate::result::Result;

    #[test]
    fn test_cipher_reuse() -> Result<()> {
        let exp = [
            102, 233, 75, 212, 239, 138, 44, 59, 136, 76, 250, 89, 202, 52, 43,
            46,
        ];
        let ffx = FFX::new(&[0; 16], None, 1024, 0, 0, 10, None)?;

        let mut d1: [u8; 16] = [0; 16];
        let mut d2: [u8; 16] = [0; 16];
        let s: [u8; 16] = [0; 16];

        ffx.ciph(&mut d1, &s)?;
        ffx.ciph(&mut d2, &s)?;

        assert!(d1 == d2);
        assert!(d1 == exp);

        Ok(())
    }
}
