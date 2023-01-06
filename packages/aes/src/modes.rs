use crate::cipher::{to_arr, AesCipher};

pub trait Modes {
    fn encrypt<
        P: AsRef<[u8]>,
        T: AsRef<[u8]>,
        const NB: usize,
        const NK: usize,
        const K: usize,
        const E: usize,
    >(
        plain_text: P,
        key: T,
        _cipher: AesCipher<NB, NK, K, E>,
    ) -> anyhow::Result<Vec<u8>>;

    fn decrypt<
        C: AsRef<[u8]>,
        T: AsRef<[u8]>,
        const NB: usize,
        const NK: usize,
        const K: usize,
        const E: usize,
    >(
        cipher_text: C,
        key: T,
        _cipher: AesCipher<NB, NK, K, E>,
    ) -> anyhow::Result<Vec<u8>>;
}

pub struct EcbMode;

impl Modes for EcbMode {
    fn encrypt<
        P: AsRef<[u8]>,
        T: AsRef<[u8]>,
        const NB: usize,
        const NK: usize,
        const K: usize,
        const E: usize,
    >(
        plain_text: P,
        key: T,
        _cipher: AesCipher<NB, NK, K, E>,
    ) -> anyhow::Result<Vec<u8>> {
        let plain_text = plain_text.as_ref();
        let key = to_arr(key.as_ref())?;
        let key_sch = AesCipher::<NB, NK, K, E>::key_expansion(key);

        let iter = plain_text.chunks_exact(16);
        let mut rem = iter.remainder().to_vec();

        let mut encrypted: Vec<u8> = iter
            .flat_map(|chk| {
                // safe to unwarp
                // copy data here
                let mut block = *to_arr(chk).unwrap();
                AesCipher::<NB, NK, K, E>::cipher(&mut block, &key_sch);
                block
            })
            .collect();

        if rem.len() > 0 {
            let old_len = rem.len();
            // add padding of zeros
            rem.extend(std::iter::repeat(0).take(16 - rem.len()));
            // copy block
            let mut last_block = *to_arr(&rem)?;
            AesCipher::<NB, NK, K, E>::cipher(&mut last_block, &key_sch);

            encrypted.extend(&rem[0..old_len]);
        }

        Ok(encrypted)
    }

    fn decrypt<
        C: AsRef<[u8]>,
        T: AsRef<[u8]>,
        const NB: usize,
        const NK: usize,
        const K: usize,
        const E: usize,
    >(
        cipher_text: C,
        key: T,
        _cipher: AesCipher<NB, NK, K, E>,
    ) -> anyhow::Result<Vec<u8>> {
        let cipher_text = cipher_text.as_ref();
        let key = to_arr(key.as_ref())?;
        let key_sch = AesCipher::<NB, NK, K, E>::key_expansion(key);

        let iter = cipher_text.chunks_exact(16);
        let mut rem = iter.remainder().to_vec();

        let mut decrypted: Vec<u8> = iter
            .flat_map(|chk| {
                // safe to unwarp
                // copy data here
                let mut block = *to_arr(chk).unwrap();
                AesCipher::<NB, NK, K, E>::inv_cipher(&mut block, &key_sch);
                block
            })
            .collect();

        if rem.len() > 0 {
            let old_len = rem.len();

            // add padding of zeros
            rem.extend(std::iter::repeat(0).take(16 - rem.len()));
            // copy block
            let mut last_block = *to_arr(&rem)?;
            AesCipher::<NB, NK, K, E>::inv_cipher(&mut last_block, &key_sch);

            decrypted.extend(&rem[0..old_len]);
        }

        Ok(decrypted)
    }
}
