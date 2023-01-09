use cipher::AesCipher;
use modes::{CbcMode, EcbMode};
use padding::PKCS7Padding;

pub mod sbox;
pub mod tables;

pub mod cipher;
pub mod modes;
pub mod padding;
pub mod utils;

pub use modes::Modes;

// // Aes128, ECB, PKCS7
pub type Aes128 = EcbMode<AesCipher<128>, 16, PKCS7Padding>;
// // Aes192, ECB, PKCS7
pub type Aes192 = EcbMode<AesCipher<192>, 16, PKCS7Padding>;
// // Aes256, ECB, PKCS7
pub type Aes256 = EcbMode<AesCipher<256>, 16, PKCS7Padding>;

// Aes128, CBC, PKCS7
pub type Aes128CBC = CbcMode<AesCipher<128>, 16, PKCS7Padding>;
// Aes192, CBC, PKCS7
pub type Aes192CBC = CbcMode<AesCipher<192>, 16, PKCS7Padding>;
// Aes256, CBC, PKCS7
pub type Aes256CBC = CbcMode<AesCipher<256>, 16, PKCS7Padding>;

#[cfg(test)]
mod tests_helpers;
#[cfg(test)]
mod test {
    use crate::{Aes128, Aes128CBC, Modes};

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
        let text = "6bc1bee22e409f96e93d7e117393172a11111111111111"
            .to_hex()
            .unwrap();
        let key = "2b7e151628aed2a6abf7158809cf4f3c".to_hex().unwrap();
        // let iv = "000102030405060708090A0B0C0D0E0F".to_hex().unwrap();
        let enc = Aes128CBC::new().encrypt(&text, &key).unwrap();
        let dec = Aes128CBC::new().decrypt(enc.clone(), &key).unwrap();

        let enc_ecb = Aes128::new().encrypt(&text, &key).unwrap();
        let dec_ecb = Aes128::new().decrypt(enc_ecb.clone(), &key).unwrap();

        assert_eq!(text.data(), dec);
        assert_eq!(text.data(), dec_ecb);
    }
}
