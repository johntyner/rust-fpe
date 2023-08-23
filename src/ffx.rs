use crate::error::Error;
use crate::result::Result;

use crate::aes;

pub enum CipherType {
    Encrypt,
    Decrypt,
}

struct SizeLimits {
    min: usize,
    max: usize,
}

struct FFXSizeLimits {
    twk: SizeLimits,
    txt: SizeLimits,
}

pub struct FFX {
    cipher: aes::Cipher,

    twk: Vec<u8>,
    len: FFXSizeLimits,
    alpha: Vec<char>,
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
        opt_alpha: Option<&str>,
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
        chars.truncate(radix);

        let mintxt = (6f64 / (radix as f64).log10()).ceil() as usize;
        if mintxt < 2 || mintxt > maxtxt {
            return Err(Error::new("unsupported radix/maximum text length"));
        }

        if mintwk > maxtwk {
            return Err(Error::new(
                "minimum tweak length must be less than maximum",
            ));
        }

        let twk: Vec<u8>;
        match opt_twk {
            None => twk = Vec::new(),
            Some(t) => {
                if t.len() < mintwk || (maxtwk > 0 && t.len() > maxtwk) {
                    return Err(Error::new("invalid tweak length"));
                }

                twk = t.to_vec();
            }
        }

        Ok(FFX {
            cipher: aes::Cipher::new(key)?,

            twk: twk,

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

            alpha: chars,
        })
    }

    pub fn get_tweak<'a>(&'a self, opt_twk: &Option<&'a [u8]>) -> &'a [u8] {
        match opt_twk {
            None => &self.twk,
            Some(t) => t,
        }
    }

    pub fn get_alphabet<'a>(&'a self) -> &'a Vec<char> {
        &self.alpha
    }

    pub fn validate_text_length(&self, n: usize) -> Result<()> {
        if n < self.len.txt.min || n > self.len.txt.max {
            return Err(Error::new("invalid text length"));
        }

        Ok(())
    }

    pub fn validate_tweak_length(&self, n: usize) -> Result<()> {
        if n < self.len.twk.min
            || (self.len.twk.max > 0 && n > self.len.twk.max)
        {
            return Err(Error::new("invalid tweak length"));
        }

        Ok(())
    }

    pub fn prf(&self, d: &mut [u8], s: &[u8]) -> Result<()> {
        let mut c = self.cipher.clone();
        let blksz = c.block_size();

        if s.len() % blksz != 0 {
            return Err(Error::new(
                "source length is not a multiple of block size",
            ));
        }

        if d.len() < blksz {
            return Err(Error::new(&format!(
                "destination buffer must be at least {} bytes",
                blksz
            )));
        }

        for i in 0..(s.len() / blksz) {
            let j = i * blksz;
            c.encrypt_block(&s[j..(j + blksz)], d);
        }

        Ok(())
    }

    pub fn ciph(&self, d: &mut [u8], s: &[u8]) -> Result<()> {
        self.prf(d, &s[0..16])
    }
}

pub fn chars_to_bignum(
    chars: &[char],
    alpha: &[char],
) -> Result<num_bigint::BigInt> {
    let radix = alpha.len();
    let mut digits = Vec::<u8>::with_capacity(chars.len());

    for i in 0..chars.len() {
        for j in 0..radix {
            if chars[i] == alpha[j] {
                digits.push(j as u8);
            }
        }
    }

    Ok(num_bigint::BigInt::from_radix_be(
        num_bigint::Sign::Plus,
        &digits,
        radix as u32,
    )
    .unwrap())
}

pub fn bignum_to_chars(
    n: &num_bigint::BigInt,
    alpha: &[char],
    opt_len: Option<usize>,
) -> Result<Vec<char>> {
    let (_, digits) = n.to_radix_le(alpha.len() as u32);
    let mut chars = Vec::<char>::with_capacity(digits.len());

    for i in 0..digits.len() {
        chars.push(alpha[digits[i] as usize]);
    }

    match opt_len {
        None => (),
        Some(l) => {
            while chars.len() < l {
                chars.push(alpha[0]);
            }
        }
    }

    chars.reverse();
    Ok(chars)
}

#[cfg(test)]
mod tests {
    use super::FFX;
    use crate::result::Result;

    use std::str::FromStr;

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

    #[test]
    fn test_bignum_conversion() -> Result<()> {
        let mut alpha = Vec::<char>::new();
        "0123456789".chars().for_each(|c| alpha.push(c));

        let n_str = "9037450980398204379409345039453045723049";
        let n = num_bigint::BigInt::from_str(n_str).unwrap();
        let s = n.to_str_radix(10);
        assert!(s == n_str);

        let c = super::bignum_to_chars(&n, &alpha, None)?;
        assert!(String::from_iter(c.clone()) == n_str);

        let r = super::chars_to_bignum(&c, &alpha)?;
        assert!(n == r);

        Ok(())
    }
}
