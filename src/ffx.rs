use crate::error::Error;
use crate::result::Result;

use std::ops::Add;

struct SizeLimits {
    min: usize,
    max: usize,
}

struct FFXSizeLimits {
    twk: SizeLimits,
    txt: SizeLimits,
}

pub struct FFX {
    cipher: openssl::cipher_ctx::CipherCtx,
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

        if mintwk < maxtwk {
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
        let blksz = self.cipher.block_size();

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

        let mut c = openssl::cipher_ctx::CipherCtx::new()?;
        c.copy(&self.cipher)?;

        unsafe {
            for i in 0..(s.len() / blksz) {
                let j = i * blksz;
                c.cipher_update_unchecked(&s[j..(j + blksz)], Some(d))?;
            }

            c.cipher_final_unchecked(d)?;
        }

        Ok(())
    }

    pub fn ciph(&self, d: &mut [u8], s: &[u8]) -> Result<()> {
        self.prf(d, &s[0..16])
    }
}

pub fn reverse<T: Copy>(s: &[T]) -> Vec<T> {
    let mut d = Vec::<T>::with_capacity(s.len());
    for i in 1..=s.len() {
        d.push(s[s.len() - i]);
    }
    d
}

pub fn chars_to_big_num(
    chars: &[char],
    alpha: &[char],
) -> Result<openssl::bn::BigNum> {
    let radix = alpha.len();

    let mut n = openssl::bn::BigNum::from_u32(0)?;
    let mut m = openssl::bn::BigNum::from_u32(1)?;

    for c in reverse(chars) {
        let mut idx = radix;

        for i in 0..radix {
            if c == alpha[i] {
                idx = i;
                break;
            }
        }

        if idx >= radix {
            return Err(Error::new("invalid character encountered"));
        } else if idx > 0 {
            let mut t = m.to_owned()?;
            t.mul_word(idx as u32)?;
            n = n.add(&t);
        }

        m.mul_word(radix as u32)?;
    }

    Ok(n)
}

pub fn big_num_to_chars(
    mut n: openssl::bn::BigNum,
    alpha: &[char],
    opt_len: Option<usize>,
) -> Result<Vec<char>> {
    let z = openssl::bn::BigNum::from_u32(0)?;

    let mut chars = Vec::<char>::new();

    while n.ne(&z) {
        let r = n.div_word(alpha.len() as u32)?;
        chars.push(alpha[r as usize]);
    }

    if opt_len.is_some() {
        let l = opt_len.unwrap();

        while chars.len() < l {
            chars.push(alpha[0]);
        }
    }

    chars.reverse();
    Ok(chars)
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

    #[test]
    fn test_bignum_conversion() -> Result<()> {
        let mut alpha = Vec::<char>::new();
        "0123456789".chars().for_each(|c| alpha.push(c));

        let n_str = "9037450980398204379409345039453045723049";
        let n = openssl::bn::BigNum::from_dec_str(n_str)?;

        let c = super::big_num_to_chars(n.to_owned()?, &alpha, None)?;
        assert!(String::from_iter(c.clone()) == n_str);

        let r = super::chars_to_big_num(&c, &alpha)?;
        assert!(n == r);

        Ok(())
    }
}
