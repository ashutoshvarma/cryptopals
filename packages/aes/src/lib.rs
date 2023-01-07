use std::marker::PhantomData;

use cipher::AesCipher;
use modes::{CbcMode, EcbMode, Modes};
use padding::{CipherPadding, PKCS7Padding};

pub mod galios_tables;
pub mod sbox;

mod cipher;
mod modes;
pub mod padding;

// Aes128, ECB, PKCS7
pub type Aes128 = Aes<4, 10, 16, 176, EcbMode, PKCS7Padding>;
// Aes192, ECB, PKCS7
pub type Aes192 = Aes<6, 12, 24, 208, EcbMode, PKCS7Padding>;
// Aes256, ECB, PKCS7
pub type Aes256 = Aes<8, 14, 32, 240, EcbMode, PKCS7Padding>;

// Aes128, CBC, PKCS7
pub type Aes128CBC = Aes<4, 10, 16, 176, CbcMode, PKCS7Padding>;
// Aes192, CBC, PKCS7
pub type Aes192CBC = Aes<6, 12, 24, 208, CbcMode, PKCS7Padding>;
// Aes256, CBC, PKCS7
pub type Aes256CBC = Aes<8, 14, 32, 240, CbcMode, PKCS7Padding>;

pub struct Aes<
    const NK: usize = 4,
    const NR: usize = 10,
    const K: usize = 16,
    const E: usize = 176,
    M: Modes = EcbMode,
    P: CipherPadding = PKCS7Padding,
> {
    _marker_m: PhantomData<M>,
    _marker_p: PhantomData<P>,
}

impl<
        const NK: usize,
        const NR: usize,
        const K: usize,
        const E: usize,
        M: Modes,
        P: CipherPadding,
    > Aes<NK, NR, K, E, M, P>
{
    pub fn encrypt<T: AsRef<[u8]>, U: AsRef<[u8]>>(data: T, key: U) -> anyhow::Result<Vec<u8>> {
        //TODO: padding copies the `data` into vec and `M::encrypt()` again
        //      copies blocks. Prevent double copy

        // add padding
        let padded = P::add_pad::<16>(data.as_ref().into());
        // apply aes cipher with mode M
        // println!("padded={padded:?}");
        M::encrypt(padded, key, AesCipher::<NK, NR, K, E>)
    }
    pub fn decrypt<T: AsRef<[u8]>, U: AsRef<[u8]>>(data: T, key: U) -> anyhow::Result<Vec<u8>> {
        // apply aes inv cipher with mode M
        let decrypted = M::decrypt(data, key, AesCipher::<NK, NR, K, E>)?;
        // remove padding
        // println!("decrypted={decrypted:?}");
        Ok(P::remove_pad::<16>(decrypted))
    }
}

#[cfg(test)]
mod tests_helpers;
#[cfg(test)]
mod test {
    use crate::Aes128CBC;

    use super::tests_helpers::Directive;
    use datadriven::{walk, Result as DDResult};
    use hex::ToHex;

    #[test]
    fn test_aes() {
        walk("test_vectors", |f| {
            f.run(|test_case| -> DDResult<String> {
                let directive: Directive = test_case.clone().try_into()?;
                directive.run()
            })
        });
    }

    #[test]
    fn aes_cbc_test() {
        let text = "6bc1bee22e409f96e93d7e117393172a11111111".to_hex().unwrap();
        let key = "2b7e151628aed2a6abf7158809cf4f3c".to_hex().unwrap();
        // let iv = "000102030405060708090A0B0C0D0E0F".to_hex().unwrap();
        let enc = Aes128CBC::encrypt(&text, &key).unwrap();
        let dec = Aes128CBC::decrypt(enc.clone(), &key).unwrap();

        dbg!(text);
        dbg!(dec);
    }
}
