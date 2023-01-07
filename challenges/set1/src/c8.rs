use std::{collections::HashMap, hash::Hash};

use hex::ToHex;

pub fn find_same_chunks<U, T>(data: T, chunk_size: usize) -> Vec<usize>
where
    U: Eq + Hash,
    T: AsRef<[U]>,
{
    let mut map = HashMap::new();
    for chunk in data.as_ref().chunks_exact(chunk_size) {
        // println!("{:?}", chunk);
        *map.entry(chunk).or_insert(0) += 1usize
    }

    let mut values = map.into_values().filter(|&v| v != 1).collect::<Vec<_>>();
    values.sort_by(|a, b| b.cmp(a));
    values
}

pub fn score_aes_ecb_data<T: AsRef<[u8]>>(data: T) -> usize {
    let mut max_score = 0;
    for k in [16usize, 24, 36] {
        let same = find_same_chunks(&data, k);
        let same_len = same.len();
        if same_len > 0 {
            max_score = max_score.max(same.into_iter().sum::<usize>() / same_len);
        }
    }
    max_score
}

#[test]
fn set1_c8_aes_ecb_detect() {
    let file_data = std::fs::read_to_string("src/c8_data.txt").unwrap();
    let datas = file_data
        .split('\n')
        .map(|h| h.to_hex().unwrap())
        .collect::<Vec<_>>();

    let (idx, _) = datas
        .iter()
        .enumerate()
        .fold((0, 0), |(m_idx, m_val), (c_idx, c_data)| {
            let score = score_aes_ecb_data(c_data);
            if m_val < score {
                (c_idx, score)
            } else {
                (m_idx, m_val)
            }
        });

    assert_eq!(idx, 132);
}
