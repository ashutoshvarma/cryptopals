use crate::cipher::{to_arr, AesCipher};

pub trait Modes {
    // Assumes plain_text to be properly padded, otherwise panic
    fn encrypt<
        P: AsRef<[u8]>,
        T: AsRef<[u8]>,
        const NR: usize,
        const NK: usize,
        const K: usize,
        const E: usize,
    >(
        plain_text: P,
        key: T,
        _cipher: AesCipher<NR, NK, K, E>,
    ) -> anyhow::Result<Vec<u8>>;

    // Assumes cipher_text to be properly padded, otherwise panic
    fn decrypt<
        C: AsRef<[u8]>,
        T: AsRef<[u8]>,
        const NR: usize,
        const NK: usize,
        const K: usize,
        const E: usize,
    >(
        cipher_text: C,
        key: T,
        _cipher: AesCipher<NR, NK, K, E>,
    ) -> anyhow::Result<Vec<u8>>;
}

pub struct EcbMode;

pub const CBC_IV: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
pub struct CbcMode;

impl Modes for EcbMode {
    fn encrypt<
        P: AsRef<[u8]>,
        T: AsRef<[u8]>,
        const NR: usize,
        const NK: usize,
        const K: usize,
        const E: usize,
    >(
        plain_text: P,
        key: T,
        _cipher: AesCipher<NR, NK, K, E>,
    ) -> anyhow::Result<Vec<u8>> {
        let key = to_arr(key.as_ref())?;
        let key_sch = AesCipher::<NR, NK, K, E>::key_expansion(key);

        let encrypted: Vec<u8> = plain_text
            .as_ref()
            .chunks_exact(16)
            .flat_map(|chk| {
                // safe to unwarp
                // copy data here
                let mut block = *to_arr(chk).unwrap();
                AesCipher::<NR, NK, K, E>::cipher(&mut block, &key_sch);
                block
            })
            .collect();

        Ok(encrypted)
    }

    fn decrypt<
        C: AsRef<[u8]>,
        T: AsRef<[u8]>,
        const NR: usize,
        const NK: usize,
        const K: usize,
        const E: usize,
    >(
        cipher_text: C,
        key: T,
        _cipher: AesCipher<NR, NK, K, E>,
    ) -> anyhow::Result<Vec<u8>> {
        let key = to_arr(key.as_ref())?;
        let key_sch = AesCipher::<NR, NK, K, E>::key_expansion(key);

        let decrypted: Vec<u8> = cipher_text
            .as_ref()
            .chunks_exact(16)
            .flat_map(|chk| {
                // safe to unwarp
                // copy data here
                let mut block = *to_arr(chk).unwrap();
                AesCipher::<NR, NK, K, E>::inv_cipher(&mut block, &key_sch);
                block
            })
            .collect();

        Ok(decrypted)
    }
}

impl Modes for CbcMode {
    fn encrypt<
        P: AsRef<[u8]>,
        T: AsRef<[u8]>,
        const NR: usize,
        const NK: usize,
        const K: usize,
        const E: usize,
    >(
        plain_text: P,
        key: T,
        _cipher: AesCipher<NR, NK, K, E>,
    ) -> anyhow::Result<Vec<u8>> {
        let key = to_arr(key.as_ref())?;
        let key_sch = AesCipher::<NR, NK, K, E>::key_expansion(key);

        let encrypted = [&CBC_IV, plain_text.as_ref()]
            // add IV before the plain text
            .concat()
            // get chunks of block size
            .chunks_exact(16)
            .collect::<Vec<&[u8]>>()
            // get window of 2 over chunks
            .windows(2)
            // apply cbc mode
            .flat_map(|win| {
                // CBC Encrypt
                // C[i] = Cipher(P[i] ^ P[i-1])

                let p0 = win[0];
                let p1 = win[1];
                // println!("p0                - {p0:?}");
                // println!("p1                - {p1:?}");

                // xor chunk (p0 ^ p1)
                let xored = p0.iter().zip(p1).map(|(a, b)| a ^ b).collect::<Vec<_>>();
                // println!("p0 ^ p1           - {xored:?}");
                let mut block = *to_arr(&xored).unwrap();
                // apply cipher
                AesCipher::<NR, NK, K, E>::cipher(&mut block, &key_sch);
                // println!("Cipher(p0 ^ p1)   - {block:?}");
                block
            })
            .collect();
        Ok(encrypted)
    }

    fn decrypt<
        C: AsRef<[u8]>,
        T: AsRef<[u8]>,
        const NR: usize,
        const NK: usize,
        const K: usize,
        const E: usize,
    >(
        cipher_text: C,
        key: T,
        _cipher: AesCipher<NR, NK, K, E>,
    ) -> anyhow::Result<Vec<u8>> {
        let key = to_arr(key.as_ref())?;
        let key_sch = AesCipher::<NR, NK, K, E>::key_expansion(key);

        let decrypted = cipher_text
            .as_ref()
            // get chunks of block size
            .chunks_exact(16)
            // apply cbc mode
            .fold(
                Vec::with_capacity(cipher_text.as_ref().len() / 16),
                |mut agg, c1| {
                    // CBC Decrypt
                    // P[i] = InvCipher(C[i]) ^ P[i-1]

                    let iv = CBC_IV.to_vec();
                    // get the P[i-1] or in case of i=0, the IV
                    let p0 = agg.last().unwrap_or(&iv);

                    // println!("p0                - {p0:?}");
                    // println!("c1                - {c1:?}");

                    let mut block = *to_arr(c1).unwrap();
                    // apply inv cipher
                    AesCipher::<NR, NK, K, E>::inv_cipher(&mut block, &key_sch);
                    // println!("InCipher(c1)      - {block:?}");

                    // xor chunk (c0 ^ InvCipher(c1))
                    let xored = p0
                        .iter()
                        .zip(&block)
                        .map(|(a, b)| a ^ b)
                        .collect::<Vec<_>>();
                    // println!("c0 ^ InCipher(c1) - {xored:?}");

                    agg.push(xored);
                    agg
                },
            )
            .into_iter()
            .flatten()
            .collect();
        Ok(decrypted)
    }
}
