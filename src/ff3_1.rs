#![allow(non_snake_case)]

use crate::ffx;
use crate::result::Result;

use num_traits::Euclid;

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
        let radix = ffx.get_radix();

        let n = X.len();
        ffx.validate_text_length(n)?;

        let v = n / 2;
        let u = n - v;

        let mut P: [[u8; 16]; 2] = [[0; 16]; 2];

        let T = ffx.get_tweak(&opt_twk);
        ffx.validate_tweak_length(T.len())?;

        let mut Tw: [[u8; 4]; 2] = [[0; 4]; 2];
        Tw[0][..3].copy_from_slice(&T[..3]);
        Tw[0][3] = T[3] & 0xf0;
        Tw[1][..3].copy_from_slice(&T[4..]);
        Tw[1][3] = (T[3] & 0x0f) << 4;

        let mut mV: num_bigint::BigInt = radix.into();
        mV = mV.pow(v as u32);
        let mut mU = mV.clone();
        if v != u {
            mU *= radix;
        }

        let mut A = X[..u].to_vec();
        let mut B = X[u..].to_vec();

        A.reverse();
        B.reverse();

        let mut nA = ffx.chars_to_bignum(&A)?;
        let mut nB = ffx.chars_to_bignum(&B)?;

        if let ffx::CipherType::Decrypt = which {
            std::mem::swap(&mut nA, &mut nB);
            std::mem::swap(&mut mU, &mut mV);

            let (T0, T1) = Tw.split_at_mut(1);
            std::mem::swap(&mut T0[0], &mut T1[0]);
        }

        for i in 1..=8 {
            P[0][..4].copy_from_slice(&Tw[(i as u8 % 2) as usize]);
            match which {
                ffx::CipherType::Encrypt => P[0][3] ^= i - 1,
                ffx::CipherType::Decrypt => P[0][3] ^= 8 - i,
            }

            let (_, mut v) = nB.to_bytes_le();
            v.resize(12, 0);
            v.reverse();
            P[0][4..16].copy_from_slice(&v);

            P[0].reverse();
            {
                let (P0, P1) = P.split_at_mut(1);
                ffx.ciph(&P0[0], &mut P1[0])?;
            }
            P[1].reverse();

            let y = num_bigint::BigInt::from_bytes_be(
                num_bigint::Sign::Plus,
                &P[1],
            );
            match which {
                ffx::CipherType::Encrypt => nA += y,
                ffx::CipherType::Decrypt => nA -= y,
            }

            std::mem::swap(&mut nA, &mut nB);

            nB = nB.rem_euclid(&mU);

            std::mem::swap(&mut mU, &mut mV);
        }

        if let ffx::CipherType::Decrypt = which {
            std::mem::swap(&mut nA, &mut nB);
        }

        B = ffx.bignum_to_chars(&nB, Some(v))?;
        A = ffx.bignum_to_chars(&nA, Some(u))?;

        B.reverse();
        A.reverse();

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
