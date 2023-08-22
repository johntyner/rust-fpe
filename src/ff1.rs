#![allow(non_snake_case)]

use crate::result::Result;

use crate::ffx;

use std::ops::Add;
use std::ops::Mul;
use std::ops::Rem;
use std::ops::Sub;

use byteorder::ByteOrder;

pub struct FF1 {
    ffx: ffx::FFX,
}

impl FF1 {
    pub fn new(
        key: &[u8],
        opt_twk: Option<&[u8]>,
        mintwk: usize,
        maxtwk: usize,
        radix: usize,
        opt_alpha: Option<&str>,
    ) -> Result<Self> {
        Ok(FF1 {
            ffx: ffx::FFX::new(
                key,
                opt_twk,
                1 << 32,
                mintwk,
                maxtwk,
                radix,
                opt_alpha,
            )?,
        })
    }

    fn cipher_chars(
        &self,
        X: &[char],
        opt_twk: Option<&[u8]>,
        which: ffx::CipherType,
    ) -> Result<Vec<char>> {
        let ffx = &self.ffx;

        let alpha = ffx.get_alphabet();
        let radix = alpha.len();

        let mut nA: openssl::bn::BigNum;
        let mut nB: openssl::bn::BigNum;
        let mut mU = openssl::bn::BigNum::new()?;
        let mut mV = openssl::bn::BigNum::new()?;
        let mut y = openssl::bn::BigNum::new()?;

        let n = X.len();
        let u = n / 2;
        let v = n - u;

        let b =
            ((((radix as f64).log2() * (v as f64)).ceil() as usize) + 7) / 8;
        let d = 4 * ((b + 3) / 4) + 4;

        let T = ffx.get_tweak(&opt_twk);

        let mut P = Vec::<u8>::new();
        P.resize(16 + ((T.len() + 1 + b + 15) / 16) * 16, 0);

        let mut R = Vec::<u8>::new();
        R.resize(((d + 15) / 16) * 16, 0);

        ffx.validate_text_length(n)?;
        ffx.validate_tweak_length(T.len())?;

        P[0] = 1;
        P[1] = 2;
        byteorder::BigEndian::write_u32(&mut P[2..6], radix as u32);
        P[2] = 1;
        P[6] = 10;
        P[7] = u as u8;
        byteorder::BigEndian::write_u32(&mut P[8..12], n as u32);
        byteorder::BigEndian::write_u32(&mut P[12..16], T.len() as u32);

        {
            let Q = &mut P[16..];
            // Q is already full of 0's due to initialization of P
            Q[0..T.len()].copy_from_slice(T);
        }

        nA = ffx::chars_to_bignum(&X[..u], alpha)?;
        nB = ffx::chars_to_bignum(&X[u..], alpha)?;

        y.clear();
        y.add_word(radix as u32)?;
        mV.clear();
        mV.add_word(u as u32)?;
        {
            let mut bn = openssl::bn::BigNumContext::new()?;
            mU.exp(&y, &mV, &mut bn)?;
        }
        mV = mU.to_owned()?;
        if u != v {
            mV = mV.mul(&y);
        }

        if let ffx::CipherType::Decrypt = which {
            std::mem::swap(&mut nA, &mut nB);
            std::mem::swap(&mut mU, &mut mV);
        }

        for i in 1..=10 {
            {
                let Q = &mut P[16..];
                let Q_len = Q.len();

                match which {
                    ffx::CipherType::Encrypt => Q[Q.len() - b - 1] = i - 1,
                    ffx::CipherType::Decrypt => Q[Q.len() - b - 1] = 10 - i,
                }

                Q[Q_len - b..].copy_from_slice(&nB.to_vec_padded(b as i32)?);
            }

            ffx.prf(&mut R[..16], &P)?;

            for j in 1..R.len() / 16 {
                let (s, d) = R.split_at_mut(16);
                let l = j * 16;

                let w = byteorder::BigEndian::read_u32(&s[12..16]);
                byteorder::BigEndian::write_u32(&mut s[12..16], w ^ j as u32);
                ffx.ciph(&mut d[l..l + 16], s)?;
                byteorder::BigEndian::write_u32(&mut s[12..16], w);
            }

            y.copy_from_slice(&R[..d])?;

            match which {
                ffx::CipherType::Encrypt => nA = nA.add(&y),
                ffx::CipherType::Decrypt => nA = nA.sub(&y),
            }

            std::mem::swap(&mut nA, &mut nB);

            nB = nB.rem(&mU);
            if nB.is_negative() {
                nB = nB.add(&mU);
            }
            std::mem::swap(&mut mU, &mut mV);
        }

        if let ffx::CipherType::Decrypt = which {
            std::mem::swap(&mut nA, &mut nB);
        }

        Ok([
            ffx::bignum_to_chars(nA, alpha, Some(u))?,
            ffx::bignum_to_chars(nB, alpha, Some(v))?,
        ]
        .concat())
    }

    fn cipher_string(
        &self,
        inp: &str,
        opt_twk: Option<&[u8]>,
        which: ffx::CipherType,
    ) -> Result<String> {
        let mut X = Vec::<char>::new();
        inp.chars().for_each(|c| X.push(c));

        let Y = self.cipher_chars(&X, opt_twk, which)?;
        Ok(String::from_iter(Y))
    }

    pub fn encrypt(&self, pt: &str, opt_twk: Option<&[u8]>) -> Result<String> {
        self.cipher_string(pt, opt_twk, ffx::CipherType::Encrypt)
    }

    pub fn decrypt(&self, ct: &str, opt_twk: Option<&[u8]>) -> Result<String> {
        self.cipher_string(ct, opt_twk, ffx::CipherType::Decrypt)
    }
}

#[cfg(test)]
mod tests {}
