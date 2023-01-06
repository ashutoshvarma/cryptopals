use std::marker::PhantomData;

use cipher::AesCipher;
use modes::{EcbMode, Modes};

pub mod galios_tables;
pub mod sbox;

mod cipher;
mod modes;

pub type Aes128 = Aes<4, 10, 16, 176>;
pub type Aes192 = Aes<6, 12, 24, 208>;
pub type Aes256 = Aes<8, 14, 32, 240>;

pub struct Aes<const NK: usize, const NR: usize, const K: usize, const E: usize, M: Modes = EcbMode>
{
    _marker: PhantomData<M>,
}

impl<const NK: usize, const NR: usize, const K: usize, const E: usize, M: Modes>
    Aes<NK, NR, K, E, M>
{
    pub fn encrypt<T: AsRef<[u8]>, U: AsRef<[u8]>>(data: T, key: U) -> anyhow::Result<Vec<u8>> {
        M::encrypt(data, key, AesCipher::<NK, NR, K, E>)
    }
    pub fn decrypt<T: AsRef<[u8]>, U: AsRef<[u8]>>(data: T, key: U) -> anyhow::Result<Vec<u8>> {
        M::decrypt(data, key, AesCipher::<NK, NR, K, E>)
    }
}

#[cfg(test)]
mod tests_helpers;
#[cfg(test)]
mod test {
    use super::tests_helpers::Directive;
    use datadriven::{walk, Result as DDResult};

    #[test]
    fn test_aes() {
        walk("test_vectors", |f| {
            f.run(|test_case| -> DDResult<String> {
                let directive: Directive = test_case.clone().try_into()?;
                directive.run()
            })
        });
    }
}
