pub mod galios_tables;
pub mod sbox;

use std::ops::RangeFull;

pub use galios_tables::{GMUL_2, GMUL_3};
pub use sbox::SBOX_TABLE;

struct Aes<const NK: usize, const NR: usize>;

static RCON_RC: [u8; 10] = [1, 2, 4, 8, 16, 32, 64, 128, 27, 54];

fn to_arr<'a, T, const N: usize>(
    slice: &'a [T],
    range: std::ops::Range<usize>,
) -> Result<&'a [T; N], <&'a [T] as TryInto<&'a [T; N]>>::Error>
where
    &'a [T]: TryInto<&'a [T; N]> + 'a,
    T: Copy,
{
    slice[range].try_into()
}

fn word<'a, T>(
    slice: &'a [T],
    word_idx: usize,
) -> Result<&'a [T; 4], <&'a [T] as TryInto<&'a [T; 4]>>::Error>
where
    &'a [T]: TryInto<&'a [T; 4]> + 'a,
    T: Copy,
{
    to_arr(slice, (word_idx * 4)..(4 + word_idx * 4))
    // slice[(word_idx * 4)..(4 + word_idx * 4)].try_into()
}

fn word4<'a, T>(
    slice: &'a [T],
    word_idx: usize,
) -> Result<&'a [T; 16], <&'a [T] as TryInto<&'a [T; 16]>>::Error>
where
    &'a [T]: TryInto<&'a [T; 16]> + 'a,
    T: Copy,
{
    to_arr(slice, (word_idx * 4)..(16 + word_idx * 4))
    // slice[(word_idx * 4)..(4 + word_idx * 4)].try_into()
}

fn sub_word(word: &mut [u8; 4]) {
    word[0] = SBOX_TABLE[word[0] as usize];
    word[1] = SBOX_TABLE[word[1] as usize];
    word[2] = SBOX_TABLE[word[2] as usize];
    word[3] = SBOX_TABLE[word[3] as usize];
}

fn rot_word(word: &mut [u8; 4]) {
    // std::mem::swap(&mut word[0], &mut word[1]);
    // std::mem::swap(&mut word[1], &mut word[2]);
    // std::mem::swap(&mut word[2], &mut word[3]);

    word.swap(0, 1);
    word.swap(1, 2);
    word.swap(2, 3);
}

impl<const NK: usize, const NR: usize> Aes<NK, NR> {
    // K is the key size in bytes
    // E is the Expanded Key buffers in bytes
    fn key_expansion<const K: usize, const E: usize>(key: &[u8; K]) -> [u8; E] {
        assert_eq!(
            K / 4,
            NK,
            "key_expansion: Key length K ({} bytes) should be Nk*4 bytes ({}).",
            K,
            NK * 4
        );
        assert_eq!(
            E,
            16 * (NR + 1),
            "key_expansion: Expaned E({} bytes) should be equal to Nb(Nr + 1) words ({} bytes).",
            E / 4,
            16 * (NR + 1)
        );
        let mut expanded = [0; E];

        // First NK words are equal to key.
        for i in 0..K {
            expanded[i] = key[i];
        }

        // iter over WORDS (4 bytes)
        for i in NK..(4 * (NR + 1)) {
            let mut temp = [
                expanded[(i - 1) * 4 + 0],
                expanded[(i - 1) * 4 + 1],
                expanded[(i - 1) * 4 + 2],
                expanded[(i - 1) * 4 + 3],
            ];
            if i % NK == 0 {
                rot_word(&mut temp);
                sub_word(&mut temp);
                // XOR by Rcon[i/NK] = XOR by [rc[i/NK], 0, 0, 0]
                // dbg!((i, NK, i / NK + 0));
                temp[0] ^= RCON_RC[(i / NK + 0) - 1];
                temp[1] ^= 0;
                temp[2] ^= 0;
                temp[3] ^= 0;
            } else if NK > 6 && i % NK == 4 {
                sub_word(&mut temp);
            }

            // 1 WORD = 4 bytes
            expanded[i * 4 + 0] = temp[0] ^ expanded[(i - NK) * 4 + 0];
            expanded[i * 4 + 1] = temp[1] ^ expanded[(i - NK) * 4 + 1];
            expanded[i * 4 + 2] = temp[2] ^ expanded[(i - NK) * 4 + 2];
            expanded[i * 4 + 3] = temp[3] ^ expanded[(i - NK) * 4 + 3];
        }

        expanded
    }

    fn cipher<const E: usize>(block: &mut [u8; 16], round_keys: &[u8; E]) {
        // println!("round[0].input = {}", hex::encode(&block).unwrap());
        // println!(
        //     "round[0].k_sch = {}",
        //     hex::encode(word4(round_keys, 0).unwrap()).unwrap()
        // );
        Self::add_round_key(block, word4(round_keys, 0).unwrap());

        for r in 1..NR {
            // println!("round[{r}].start = {}", hex::encode(&block).unwrap());
            Self::sub_bytes(block);
            // println!("round[{r}].s_box = {}", hex::encode(&block).unwrap());
            Self::shift_rows(block);
            // println!("round[{r}].s_row = {}", hex::encode(&block).unwrap());
            Self::mix_columns(block);
            // println!("round[{r}].m_col = {}", hex::encode(&block).unwrap());
            Self::add_round_key(block, word4(round_keys, r * 4).unwrap());
            // println!(
            //     "round[{r}].k_sch = {}",
            //     hex::encode(word4(round_keys, r * 4).unwrap()).unwrap()
            // );
        }

        // println!("round[{NR}].start = {}", hex::encode(&block).unwrap());
        Self::sub_bytes(block);
        // println!("round[{NR}].s_box = {}", hex::encode(&block).unwrap());
        Self::shift_rows(block);
        // println!("round[{NR}].s_row = {}", hex::encode(&block).unwrap());
        Self::add_round_key(block, word4(round_keys, NR * 4).unwrap());
        // println!(
        //     "round[{NR}].k_sch = {}",
        //     hex::encode(word4(round_keys, NR * 4).unwrap()).unwrap()
        // );
        // println!("round[{NR}].output = {}", hex::encode(&block).unwrap());
    }

    fn sub_bytes(block: &mut [u8; 16]) {
        for i in 0..16 {
            let r = block[i].to_le() & 15;
            let c = block[i].to_le() >> 4;
            block[i] = SBOX_TABLE[(r + 16 * c) as usize];
        }
    }

    fn shift_rows(block: &mut [u8; 16]) {
        // TODO: Implement inplace instead of copying block
        let copy = block.clone();

        // // 1st row is not changed
        // block[0 + 0 * 4] = copy[0 + 0 * 4];
        // block[0 + 1 * 4] = copy[0 + 1 * 4];
        // block[0 + 2 * 4] = copy[0 + 2 * 4];
        // block[0 + 3 * 4] = copy[0 + 3 * 4];

        block[1 + 0 * 4] = copy[1 + 1 * 4];
        block[2 + 0 * 4] = copy[2 + 2 * 4];
        block[3 + 0 * 4] = copy[3 + 3 * 4];
        block[1 + 1 * 4] = copy[1 + 2 * 4];
        block[2 + 1 * 4] = copy[2 + 3 * 4];
        block[3 + 1 * 4] = copy[3 + 0 * 4];
        block[1 + 2 * 4] = copy[1 + 3 * 4];
        block[2 + 2 * 4] = copy[2 + 0 * 4];
        block[3 + 2 * 4] = copy[3 + 1 * 4];
        block[1 + 3 * 4] = copy[1 + 0 * 4];
        block[2 + 3 * 4] = copy[2 + 1 * 4];
        block[3 + 3 * 4] = copy[3 + 2 * 4];

        // // same as above but with for loop
        // for r in 1..4 {
        //     for c in 0..4 {
        //         block[r + 4 * c] = copy[r + 4 * ((c + r) % 4)]
        //     }
        // }
    }

    fn mix_columns(block: &mut [u8; 16]) {
        // TODO: Implement inplace instead of copying block
        let copy = block.clone();

        for c in 0..4 {
            block[0 + c * 4] = GMUL_2[copy[0 + c * 4] as usize]
                ^ GMUL_3[copy[1 + c * 4] as usize]
                ^ copy[2 + c * 4]
                ^ copy[3 + c * 4];

            block[1 + c * 4] = copy[0 + c * 4]
                ^ GMUL_2[copy[1 + c * 4] as usize]
                ^ GMUL_3[copy[2 + c * 4] as usize]
                ^ copy[3 + c * 4];

            block[2 + c * 4] = copy[0 + c * 4]
                ^ copy[1 + c * 4]
                ^ GMUL_2[copy[2 + c * 4] as usize]
                ^ GMUL_3[copy[3 + c * 4] as usize];

            block[3 + c * 4] = GMUL_3[copy[0 + c * 4] as usize]
                ^ copy[1 + c * 4]
                ^ copy[2 + c * 4]
                ^ GMUL_2[copy[3 + c * 4] as usize];
        }
    }

    fn add_round_key(block: &mut [u8; 16], round_key: &[u8; 16]) {
        for c in 0..4 {
            block[0 + c * 4] ^= round_key[0 + c * 4];
            block[1 + c * 4] ^= round_key[1 + c * 4];
            block[2 + c * 4] ^= round_key[2 + c * 4];
            block[3 + c * 4] ^= round_key[3 + c * 4];
        }
    }
}

#[cfg(test)]
mod test {
    use hex::ToHex;

    use super::*;

    const KEY_EXPANSION_VECTORS_16: [([u8; 16], &str); 3] = [
        // 16-bit key
        ([0u8; 16], "00000000000000000000000000000000626363636263636362636363626363639b9898c9f9fbfbaa9b9898c9f9fbfbaa90973450696ccffaf2f457330b0fac99ee06da7b876a1581759e42b27e91ee2b7f2e2b88f8443e098dda7cbbf34b9290ec614b851425758c99ff09376ab49ba7217517873550620bacaf6b3cc61bf09b0ef903333ba9613897060a04511dfa9fb1d4d8e28a7db9da1d7bb3de4c664941b4ef5bcb3e92e21123e951cf6f8f188e"),
        ([255u8; 16], "ffffffffffffffffffffffffffffffffe8e9e9e917161616e8e9e9e917161616adaeae19bab8b80f525151e6454747f0090e2277b3b69a78e1e7cb9ea4a08c6ee16abd3e52dc2746b33becd8179b60b6e5baf3ceb766d488045d385013c658e671d07db3c6b6a93bc2eb916bd12dc98de90d208d2fbb89b6ed5018dd3c7dd15096337366b988fad054d8e20d68a5335d8bf03f233278c5f366a027fe0e0514a3d60a3588e472f07b82d2d7858cd7c326"),
        ([0 ,1 ,2 ,3 ,4 ,5 ,6 ,7 ,8 ,9 ,10 ,11 ,12 ,13 ,14 ,15], "000102030405060708090a0b0c0d0e0fd6aa74fdd2af72fadaa678f1d6ab76feb692cf0b643dbdf1be9bc5006830b3feb6ff744ed2c2c9bf6c590cbf0469bf4147f7f7bc95353e03f96c32bcfd058dfd3caaa3e8a99f9deb50f3af57adf622aa5e390f7df7a69296a7553dc10aa31f6b14f9701ae35fe28c440adf4d4ea9c02647438735a41c65b9e016baf4aebf7ad2549932d1f08557681093ed9cbe2c974e13111d7fe3944a17f307a78b4d2b30c5"),
        ];

    const KEY_EXPANSION_VECTORS_24: [([u8; 24], &str); 3] = [
        // 24-bit key
        ([0u8; 24], "0000000000000000000000000000000000000000000000006263636362636363626363636263636362636363626363639b9898c9f9fbfbaa9b9898c9f9fbfbaa9b9898c9f9fbfbaa90973450696ccffaf2f457330b0fac9990973450696ccffac81d19a9a171d65353858160588a2df9c81d19a9a171d6537bebf49bda9a22c8891fa3a8d1958e51198897f8b8f941abc26896f718f2b43f91ed1797407899c659f00e3ee1094f9583ecbc0f9b1e08300af31fa74a8b8661137b885ff272c7ca432ac886d834c0b6d2c7df11984c5970"),
        ([255u8; 24], "ffffffffffffffffffffffffffffffffffffffffffffffffe8e9e9e917161616e8e9e9e917161616e8e9e9e917161616adaeae19bab8b80f525151e6454747f0adaeae19bab8b80fc5c2d8ed7f7a60e22d2b3104686c76f4c5c2d8ed7f7a60e21712403f686820dd454311d92d2f672de8edbfc09797df228f8cd3b7e7e4f36aa2a7e2b38f88859e67653a5ef0f2e57c2655c33bc1b130516316d2e2ec9e577c8bfb6d227b09885e67919b1aa620ab4bc53679a929a82ed5a25343f7d95acba9598e482fffaee3643a989acd1330b418"),
        ([00, 01, 02, 03, 04, 05, 06, 07, 08, 09, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23], "000102030405060708090a0b0c0d0e0f10111213141516175846f2f95c43f4fe544afef55847f0fa4856e2e95c43f4fe40f949b31cbabd4d48f043b810b7b34258e151ab04a2a5557effb5416245080c2ab54bb43a02f8f662e3a95d66410c08f501857297448d7ebdf1c6ca87f33e3ce510976183519b6934157c9ea351f1e01ea0372a995309167c439e77ff12051edd7e0e887e2fff68608fc842f9dcc154859f5f237a8d5a3dc0c02952beefd63ade601e7827bcdf2ca223800fd8aeda32a4970a331a78dc09c418c271e3a41d5d"),
        ];

    #[test]
    fn test_sub_bytes() {
        let mut block = [53_u8; 16];
        Aes::<4, 10>::sub_bytes(&mut block);
        assert_eq!(block, [150; 16]);

        // let mut block = "00102030405060708090a0b0c0d0e0f0".to_hex().unwrap();
        let binding = "00102030405060708090a0b0c0d0e0f0".to_hex().unwrap();
        let mut block = *to_arr::<u8, 16>(binding.data(), 0..16).unwrap();
        Aes::<4, 4>::sub_bytes(&mut block);
        assert_eq!(
            "63cab7040953d051cd60e0e7ba70e18c",
            hex::encode(block).unwrap()
        );
    }

    #[test]
    fn test_shift_rows() {
        let mut block: [u8; 16] = [
            00, 01, 02, 03, 10, 11, 12, 13, 20, 21, 22, 23, 30, 31, 32, 33,
        ];
        Aes::<4, 4>::shift_rows(&mut block);
        assert_eq!(
            block,
            [0, 11, 22, 33, 10, 21, 32, 3, 20, 31, 2, 13, 30, 1, 12, 23]
        );
    }

    #[test]
    fn test_mix_columns() {
        let hex = hex::decode("db135345f20a225c01010101c6c6c6c6").unwrap();
        let mut block: [u8; 16] = hex.data().try_into().unwrap();
        Aes::<4, 4>::mix_columns(&mut block);
        // aes::Aes128::
        assert_eq!(
            block,
            [142, 77, 161, 188, 159, 220, 88, 157, 1, 1, 1, 1, 198, 198, 198, 198]
        )
    }

    fn assert_key_expansion<const K: usize, const E: usize, const NK: usize, const NR: usize>(
        key: &[u8; K],
        expected: &[u8; E],
    ) {
        let expanded: [u8; E] = Aes::<NK, NR>::key_expansion(key);
        assert_eq!(expected, &expanded);
    }

    #[test]
    fn test_key_expansion() {
        for (key, expected) in KEY_EXPANSION_VECTORS_16 {
            assert_key_expansion::<16, 176, 4, 10>(
                &key,
                to_arr::<u8, 176>(hex::decode(expected).unwrap().data(), 0..176).unwrap(),
            )
        }
        for (key, expected) in KEY_EXPANSION_VECTORS_24 {
            assert_key_expansion::<24, 208, 6, 12>(
                &key,
                to_arr::<u8, 208>(hex::decode(expected).unwrap().data(), 0..208).unwrap(),
            )
        }
    }

    #[test]
    fn test_cipher_128() {
        let text = hex::decode("00112233445566778899aabbccddeeff").unwrap();
        let key = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();

        let mut block: [u8; 16] = *to_arr(text.as_ref(), 0..16).unwrap();
        let round_keys: [u8; 176] =
            Aes::<4, 10>::key_expansion(to_arr::<u8, 16>(key.as_ref(), 0..16).unwrap());

        Aes::<4, 10>::cipher(&mut block, &round_keys);
        assert_eq!(
            "69c4e0d86a7b0430d8cdb78070b4c55a".to_hex().unwrap().data(),
            block
        );
    }

    #[test]
    fn test_cipher_192() {
        let text = hex::decode("00112233445566778899aabbccddeeff").unwrap();
        let key = hex::decode("000102030405060708090a0b0c0d0e0f1011121314151617").unwrap();

        let mut block = *to_arr(text.as_ref(), 0..16).unwrap();
        let round_keys: [u8; 208] =
            Aes::<6, 12>::key_expansion(to_arr::<u8, 24>(key.as_ref(), 0..24).unwrap());
        Aes::<6, 12>::cipher(&mut block, &round_keys);
        assert_eq!(
            "dda97ca4864cdfe06eaf70a0ec0d7191".to_hex().unwrap().data(),
            block
        );
    }
}
