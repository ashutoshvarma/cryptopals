use std::marker::PhantomData;

use crate::{cipher::BlockCipher, padding::CipherPadding, utils::to_arr};

pub trait Modes<C: BlockCipher<B, Unit = u8>, const B: usize, D: CipherPadding> {
    // Assumes plain_text to be properly padded, otherwise panic
    fn encrypt<P: AsRef<[u8]>, T: AsRef<[u8]>>(
        &self,
        plain_text: P,
        key: T,
    ) -> anyhow::Result<Vec<u8>>;

    // Assumes cipher_text to be properly padded, otherwise panic
    fn decrypt<U: AsRef<[u8]>, T: AsRef<[u8]>>(
        &self,
        cipher_text: U,
        key: T,
    ) -> anyhow::Result<Vec<u8>>;
}

#[derive(Debug)]
pub struct EcbMode<C: BlockCipher<B, Unit = u8>, const B: usize, D: CipherPadding> {
    _marker_c: PhantomData<C>,
    _marker_d: PhantomData<D>,
}

impl<C: BlockCipher<B, Unit = u8>, const B: usize, D: CipherPadding> EcbMode<C, B, D> {
    pub fn new() -> Self {
        Self {
            _marker_c: PhantomData,
            _marker_d: PhantomData,
        }
    }
}

#[derive(Debug)]
pub struct CbcMode<C: BlockCipher<B, Unit = u8>, const B: usize, D: CipherPadding> {
    iv: Vec<u8>,
    _marker_c: PhantomData<C>,
    _marker_d: PhantomData<D>,
}

impl<C: BlockCipher<B, Unit = u8>, const B: usize, D: CipherPadding> CbcMode<C, B, D> {
    pub const DEFAULT_CBC_IV: [u8; B] = [0; B];
    pub fn new() -> Self {
        CbcMode {
            iv: Self::DEFAULT_CBC_IV.to_vec(),
            _marker_c: PhantomData,
            _marker_d: PhantomData,
        }
    }

    pub fn with_iv(iv: Vec<u8>) -> Self {
        CbcMode {
            iv,
            _marker_c: PhantomData,
            _marker_d: PhantomData,
        }
    }
}

impl<C: BlockCipher<B, Unit = u8>, const B: usize, D: CipherPadding> Modes<C, B, D>
    for EcbMode<C, B, D>
{
    fn encrypt<P: AsRef<[u8]>, T: AsRef<[u8]>>(
        &self,
        plain_text: P,
        key: T,
    ) -> anyhow::Result<Vec<u8>> {
        // add padding
        let padded = D::add_pad::<B>(plain_text.as_ref().to_vec());
        // apply cipher in ecb mode
        let encrypted = padded
            .chunks_exact(B)
            .flat_map(|chk| {
                // safe to unwarp
                // copy data here
                let block = *to_arr(chk).unwrap();
                C::cipher(block, key.as_ref())
            })
            .collect();

        Ok(encrypted)
    }

    fn decrypt<U: AsRef<[u8]>, T: AsRef<[u8]>>(
        &self,
        cipher_text: U,
        key: T,
    ) -> anyhow::Result<Vec<u8>> {
        let decrypted: Vec<u8> = cipher_text
            .as_ref()
            .chunks_exact(B)
            .flat_map(|chk| {
                // safe to unwarp
                // copy data here
                let block = *to_arr(chk).unwrap();
                C::inv_cipher(block, key.as_ref())
            })
            .collect();

        // remove padding
        Ok(D::remove_pad::<B>(decrypted))
    }
}

impl<C: BlockCipher<B, Unit = u8>, const B: usize, D: CipherPadding> Modes<C, B, D>
    for CbcMode<C, B, D>
{
    fn encrypt<P: AsRef<[u8]>, T: AsRef<[u8]>>(
        &self,
        plain_text: P,
        key: T,
    ) -> anyhow::Result<Vec<u8>> {
        // add padding
        let padded = D::add_pad::<B>(plain_text.as_ref().to_vec());
        let padded_len = padded.len();
        let encrypted = padded
            // get chunks of block size
            .chunks_exact(B)
            // apply cbc mode
            .fold(Vec::with_capacity(padded_len / B), |mut agg, p1| {
                // CBC Encrypt
                // C[i] = Cipher(P[i] ^ P[i-1])

                let c0 = agg.last().unwrap_or(&self.iv);
                // println!("p0                - {p0:?}");
                // println!("p1                - {p1:?}");

                // xor chunk (p0 ^ p1)
                let xored = c0.iter().zip(p1).map(|(a, b)| a ^ b).collect::<Vec<_>>();
                // println!("p0 ^ p1           - {xored:?}");
                let block = C::cipher(*to_arr(&xored).unwrap(), key.as_ref());
                // println!("Cipher(p0 ^ p1)   - {block:?}");
                agg.push(block.to_vec());
                agg
            })
            .into_iter()
            .flatten()
            .collect();
        Ok(encrypted)
    }

    fn decrypt<U: AsRef<[u8]>, T: AsRef<[u8]>>(
        &self,
        cipher_text: U,
        key: T,
    ) -> anyhow::Result<Vec<u8>> {
        let decrypted = [self.iv.as_slice(), cipher_text.as_ref()]
            .concat()
            // get chunks of block size
            .chunks_exact(B)
            .collect::<Vec<&[u8]>>()
            .windows(2)
            // apply cbc mode
            .flat_map(|win| {
                // CBC Decrypt
                // P[i] = InvCipher(C[i]) ^ C[i-1]

                // get the P[i-1] or in case of i=0, the IV
                let c0 = win[0];
                let c1 = win[1];

                // println!("p0                - {p0:?}");
                // println!("c1                - {c1:?}");

                // apply inv cipher
                let block = C::inv_cipher(*to_arr(c1).unwrap(), key.as_ref());
                // println!("InCipher(c1)      - {block:?}");

                // xor chunk (c0 ^ InvCipher(c1))
                let xored = c0
                    .iter()
                    .zip(&block)
                    .map(|(a, b)| a ^ b)
                    .collect::<Vec<_>>();
                // println!("c0 ^ InCipher(c1) - {xored:?}");

                xored
            })
            .collect();

        // remove padding
        Ok(D::remove_pad::<B>(decrypted))
    }
}

// fn a() {
//     let b = EcbMode;
//     b.decrypt("cipher_text", "key");
// }
