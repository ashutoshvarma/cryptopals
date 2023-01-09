use crate::tables::{
    GMUL_11, GMUL_13, GMUL_14, GMUL_2, GMUL_3, GMUL_9, INV_SBOX_TABLE, RCON_RC, SBOX_TABLE,
};
use crate::utils::word4;

pub trait BlockCipher<const B: usize> {
    type Unit;

    fn cipher<T: AsRef<[u8]>>(block: [Self::Unit; B], key: T) -> [Self::Unit; B];
    fn inv_cipher<T: AsRef<[u8]>>(block: [Self::Unit; B], key: T) -> [Self::Unit; B];
}

impl<const NK: usize> BlockCipher<16> for AesCipher<NK> {
    type Unit = u8;

    fn cipher<T: AsRef<[u8]>>(mut block: [Self::Unit; 16], key: T) -> [Self::Unit; 16] {
        let key_sch = Self::key_expansion(key);
        Self::block_cipher(&mut block, key_sch);
        block
    }

    fn inv_cipher<T: AsRef<[u8]>>(mut block: [Self::Unit; 16], key: T) -> [Self::Unit; 16] {
        let key_sch = Self::key_expansion(key);
        Self::block_inv_cipher(&mut block, key_sch);
        block
    }
}

pub struct AesCipher<const K: usize>;

impl<const K: usize> AesCipher<K> {
    const NR: usize = match K {
        128 => 10,
        192 => 12,
        256 => 14,
        _ => panic!("Invalid Aes Key Length"),
    };
    const NK: usize = K / (4 * 8);

    pub(crate) fn key_expansion<T: AsRef<[u8]>>(key: T) -> Vec<u8> {
        let key = key.as_ref();
        assert_eq!(
            key.len() / 4,
            Self::NK,
            "key_expansion: Key length K ({} bytes) should be Nk*4 bytes ({}).",
            key.len(),
            Self::NK * 4
        );
        // assert_eq!(
        //     E,
        //     16 * (NR + 1),
        //     "key_expansion: Expaned E({} bytes) should be equal to Nb(Nr + 1) words ({} bytes).",
        //     E / 4,
        //     16 * (NR + 1)
        // );
        let mut expanded = vec![0; 16 * (Self::NR + 1)];

        // First NK words are equal to key.
        for i in 0..key.len() {
            expanded[i] = key[i];
        }

        // iter over WORDS (4 bytes)
        for i in Self::NK..(4 * (Self::NR + 1)) {
            let mut temp = [
                expanded[(i - 1) * 4 + 0],
                expanded[(i - 1) * 4 + 1],
                expanded[(i - 1) * 4 + 2],
                expanded[(i - 1) * 4 + 3],
            ];
            if i % Self::NK == 0 {
                rot_word(&mut temp);
                sub_word(&mut temp);
                // XOR by Rcon[i/NK] = XOR by [rc[i/NK], 0, 0, 0]
                // dbg!((i, NK, i / NK + 0));
                temp[0] ^= RCON_RC[(i / Self::NK + 0) - 1];
                temp[1] ^= 0;
                temp[2] ^= 0;
                temp[3] ^= 0;
            } else if Self::NK > 6 && i % Self::NK == 4 {
                sub_word(&mut temp);
            }

            // 1 WORD = 4 bytes
            expanded[i * 4 + 0] = temp[0] ^ expanded[(i - Self::NK) * 4 + 0];
            expanded[i * 4 + 1] = temp[1] ^ expanded[(i - Self::NK) * 4 + 1];
            expanded[i * 4 + 2] = temp[2] ^ expanded[(i - Self::NK) * 4 + 2];
            expanded[i * 4 + 3] = temp[3] ^ expanded[(i - Self::NK) * 4 + 3];
        }

        expanded
    }

    pub(crate) fn block_cipher(block: &mut [u8; 16], round_keys: Vec<u8>) {
        // println!("round[0].input = {}", hex::encode(&block).unwrap());
        // println!(
        //     "round[0].k_sch = {}",
        //     hex::encode(word4(round_keys, 0).unwrap()).unwrap()
        // );
        Self::add_round_key(block, word4(&round_keys, 0).unwrap());

        for r in 1..Self::NR {
            // println!("round[{r}].start = {}", hex::encode(&block).unwrap());
            Self::sub_bytes(block);
            // println!("round[{r}].s_box = {}", hex::encode(&block).unwrap());
            Self::shift_rows(block);
            // println!("round[{r}].s_row = {}", hex::encode(&block).unwrap());
            Self::mix_columns(block);
            // println!("round[{r}].m_col = {}", hex::encode(&block).unwrap());
            Self::add_round_key(block, word4(&round_keys, r * 4).unwrap());
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
        Self::add_round_key(block, word4(&round_keys, Self::NR * 4).unwrap());
        // println!(
        //     "round[{NR}].k_sch = {}",
        //     hex::encode(word4(round_keys, NR * 4).unwrap()).unwrap()
        // );
        // println!("round[{NR}].output = {}", hex::encode(&block).unwrap());
    }

    pub(crate) fn block_inv_cipher(block: &mut [u8; 16], round_keys: Vec<u8>) {
        // println!("round[0].iinput = {}", hex::encode(&block).unwrap());
        // println!(
        //     "round[0].ik_sch = {}",
        //     // hex::encode(round_keys).unwrap()
        //     hex::encode(word4(round_keys, NR * 4).unwrap()).unwrap()
        // );
        Self::add_round_key(block, word4(&round_keys, Self::NR * 4).unwrap());

        for r in (1..Self::NR).rev() {
            // println!("round[{r}].istart = {}", hex::encode(&block).unwrap());
            Self::inv_shift_rows(block);
            // println!("round[{r}].is_row = {}", hex::encode(&block).unwrap());
            Self::inv_sub_bytes(block);
            // println!("round[{r}].is_box = {}", hex::encode(&block).unwrap());
            Self::add_round_key(block, word4(&round_keys, r * 4).unwrap());
            // println!(
            //     "round[{r}].ik_sch = {}",
            //     hex::encode(word4(round_keys, r * 4).unwrap()).unwrap()
            // );
            // println!("round[{r}].ik_add = {}", hex::encode(&block).unwrap());
            Self::inv_mix_columns(block);
        }

        // println!("round[{NR}].istart = {}", hex::encode(&block).unwrap());
        Self::inv_shift_rows(block);
        // println!("round[{NR}].is_row = {}", hex::encode(&block).unwrap());
        Self::inv_sub_bytes(block);
        // println!("round[{NR}].is_box = {}", hex::encode(&block).unwrap());
        Self::add_round_key(block, word4(&round_keys, 0).unwrap());
        // println!(
        //     "round[{NR}].ik_sch = {}",
        //     hex::encode(word4(round_keys, 0).unwrap()).unwrap()
        // );
        // println!("round[{NR}].ioutput = {}", hex::encode(&block).unwrap());
    }

    pub(crate) fn sub_bytes(block: &mut [u8; 16]) {
        for i in 0..16 {
            let r = block[i].to_le() & 15;
            let c = block[i].to_le() >> 4;
            block[i] = SBOX_TABLE[(r + 16 * c) as usize];
        }
    }

    pub(crate) fn inv_sub_bytes(block: &mut [u8; 16]) {
        for i in 0..16 {
            let r = block[i].to_le() & 15;
            let c = block[i].to_le() >> 4;
            block[i] = INV_SBOX_TABLE[(r + 16 * c) as usize];
        }
    }

    pub(crate) fn shift_rows(block: &mut [u8; 16]) {
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

    pub(crate) fn inv_shift_rows(block: &mut [u8; 16]) {
        // TODO: Implement inplace instead of copying block
        let copy = block.clone();

        block[1 + 1 * 4] = copy[1 + 0 * 4];
        block[2 + 2 * 4] = copy[2 + 0 * 4];
        block[3 + 3 * 4] = copy[3 + 0 * 4];
        block[1 + 2 * 4] = copy[1 + 1 * 4];
        block[2 + 3 * 4] = copy[2 + 1 * 4];
        block[3 + 0 * 4] = copy[3 + 1 * 4];
        block[1 + 3 * 4] = copy[1 + 2 * 4];
        block[2 + 0 * 4] = copy[2 + 2 * 4];
        block[3 + 1 * 4] = copy[3 + 2 * 4];
        block[1 + 0 * 4] = copy[1 + 3 * 4];
        block[2 + 1 * 4] = copy[2 + 3 * 4];
        block[3 + 2 * 4] = copy[3 + 3 * 4];

        // // same as above but with for loop
        // for r in 1..4 {
        //     for c in 0..4 {
        //         block[r + 4 * ((c + r) % 4)] = copy[r + 4 * c]
        //     }
        // }
    }

    pub(crate) fn mix_columns(block: &mut [u8; 16]) {
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

    pub(crate) fn inv_mix_columns(block: &mut [u8; 16]) {
        // TODO: Implement inplace instead of copying block
        let copy = block.clone();

        for c in 0..4 {
            block[0 + c * 4] = GMUL_14[copy[0 + c * 4] as usize]
                ^ GMUL_11[copy[1 + c * 4] as usize]
                ^ GMUL_13[copy[2 + c * 4] as usize]
                ^ GMUL_9[copy[3 + c * 4] as usize];

            block[1 + c * 4] = GMUL_9[copy[0 + c * 4] as usize]
                ^ GMUL_14[copy[1 + c * 4] as usize]
                ^ GMUL_11[copy[2 + c * 4] as usize]
                ^ GMUL_13[copy[3 + c * 4] as usize];

            block[2 + c * 4] = GMUL_13[copy[0 + c * 4] as usize]
                ^ GMUL_9[copy[1 + c * 4] as usize]
                ^ GMUL_14[copy[2 + c * 4] as usize]
                ^ GMUL_11[copy[3 + c * 4] as usize];

            block[3 + c * 4] = GMUL_11[copy[0 + c * 4] as usize]
                ^ GMUL_13[copy[1 + c * 4] as usize]
                ^ GMUL_9[copy[2 + c * 4] as usize]
                ^ GMUL_14[copy[3 + c * 4] as usize];
        }
    }

    pub(crate) fn add_round_key(block: &mut [u8; 16], round_key: &[u8; 16]) {
        for c in 0..4 {
            block[0 + c * 4] ^= round_key[0 + c * 4];
            block[1 + c * 4] ^= round_key[1 + c * 4];
            block[2 + c * 4] ^= round_key[2 + c * 4];
            block[3 + c * 4] ^= round_key[3 + c * 4];
        }
    }
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
