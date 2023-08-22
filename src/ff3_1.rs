#![allow(non_snake_case)]

use crate::result::Result;

use crate::ffx;

use std::ops::Add;
use std::ops::Mul;
use std::ops::Rem;
use std::ops::Sub;

pub struct FF3_1 {
    ffx: ffx::FFX,
}

impl FF3_1 {
    pub fn new(
        key: &[u8],
        opt_twk: Option<&[u8]>,
        radix: usize,
        opt_alpha: Option<&str>,
    ) -> Result<Self> {
        let mut k = key.to_vec();

        k.reverse();

        Ok(FF3_1 {
            ffx: ffx::FFX::new(
                &k,
                opt_twk,
                (192f64 / (radix as f64).log2()).floor() as usize,
                7,
                7,
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

        let mut mU = openssl::bn::BigNum::new()?;
        let mut mV = openssl::bn::BigNum::new()?;
        let mut y = openssl::bn::BigNum::new()?;

        let n = X.len();
        let mut v = n / 2;
        let mut u = n - v;

        let mut P: [[u8; 16]; 2] = [[0; 16]; 2];

        let T = ffx.get_tweak(&opt_twk);
        ffx.validate_tweak_length(T.len())?;

        ffx.validate_text_length(n)?;

        let mut A = X[..u].to_vec();
        let mut B = X[u..].to_vec();

        let mut Tw: [[u8; 4]; 2] = [[0; 4]; 2];
        Tw[0][..3].copy_from_slice(&T[..3]);
        Tw[0][3] = T[3] & 0xf0;
        Tw[1][..3].copy_from_slice(&T[4..]);
        Tw[1][3] = (T[3] & 0x0f) << 4;

        y.clear();
        y.add_word(radix as u32)?;
        mU.clear();
        mU.add_word(v as u32)?;
        {
            let mut bn = openssl::bn::BigNumContext::new()?;
            mV.exp(&y, &mU, &mut bn)?;
        }
        mU = mV.to_owned()?;
        if v != u {
            mU = mU.mul(&y);
        }

        if let ffx::CipherType::Decrypt = which {
            std::mem::swap(&mut A, &mut B);

            std::mem::swap(&mut mU, &mut mV);
            std::mem::swap(&mut u, &mut v);

            let (T0, T1) = Tw.split_at_mut(1);
            std::mem::swap(&mut T0[0], &mut T1[0]);
        }

        for i in 1..=8 {
            let mut c: openssl::bn::BigNum;

            P[0][..4].copy_from_slice(&Tw[(i as u8 % 2) as usize]);

            match which {
                ffx::CipherType::Encrypt => P[0][3] ^= i - 1,
                ffx::CipherType::Decrypt => P[0][3] ^= 8 - i,
            }

            B.reverse();
            c = ffx::chars_to_bignum(&B, &alpha)?;
            P[0][4..16].copy_from_slice(&c.to_vec_padded(12)?);

            println!("{:?}", P[0]);

            P[0].reverse();
            {
                let (P0, P1) = P.split_at_mut(1);
                ffx.ciph(&mut P1[0], &P0[0])?;
            }
            P[1].reverse();

            y.copy_from_slice(&P[1])?;
            A.reverse();
            c = ffx::chars_to_bignum(&A, &alpha)?;
            match which {
                ffx::CipherType::Encrypt => c = c.add(&y),
                ffx::CipherType::Decrypt => c = c.sub(&y),
            }

            A = B;
            A.reverse();

            c = c.rem(&mU);
            if c.is_negative() {
                c = c.add(&mU);
            }

            B = ffx::bignum_to_chars(c, &alpha, Some(u))?;
            B.reverse();

            std::mem::swap(&mut mU, &mut mV);
            std::mem::swap(&mut u, &mut v);
        }

        if let ffx::CipherType::Decrypt = which {
            std::mem::swap(&mut A, &mut B);
        }

        Ok([A, B].concat())
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
