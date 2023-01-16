use std::ops::BitXor;

use enscoring::TextMetric;

pub fn xor_slice_by_char<T, U, K>(value: U, xor_key: K) -> Vec<T>
where
    U: AsRef<[T]>,
    T: BitXor<K, Output = T> + Clone,
    K: Clone,
{
    value
        .as_ref()
        .iter()
        .map(|i| i.clone() ^ xor_key.clone())
        .collect()
}

// brutefore with all possible single xor keys and select the one with
// highest score.
pub fn guess_single_xor_key<T, I>(encrypted: T, char_iter: I) -> (char, f64, String)
where
    I: Iterator<Item = u8>,
    T: AsRef<[u8]>,
{
    char_iter
        // we use fold to reduce the iterator into max (key, score) tuple.
        .fold(
            (char::MAX, -1.0, " ".to_string()),
            |(mut max_c, mut max_score, mut decrypt), c| {
                let decoded = xor_slice_by_char(&encrypted, c);
                let ltr = std::str::from_utf8(decoded.as_ref())
                    // make it safe to use unwrap here
                    .or::<std::str::Utf8Error>(Ok(""))
                    .unwrap();
                let score = ltr.text_score();

                if max_score <= score {
                    max_c = c as char;
                    max_score = score;
                    decrypt = ltr.to_string();
                }

                (max_c, max_score, decrypt)
            },
        )
}

pub fn guess_repeating_xor_key<T: AsRef<[u8]>, I: Iterator<Item = usize> + Clone>(
    encrypted: T,
    key_range: I,
    num_block: usize,
) -> anyhow::Result<Vec<char>> {
    let key_sizes = guess_repeating_xor_key_size(&encrypted, key_range, num_block)?;
    Ok(break_repeating_xor(&encrypted, key_sizes[0].0))
}


//
// Private Functions
//

fn count_1s_bit(value: u8) -> u8 {
    let mut ones = 0;
    for i in 0..8u8 {
        ones += (value >> i) & 1;
    }
    ones
}

pub fn calculate_hamming_distance<T, U>(value1: T, value2: U) -> usize
where
    T: AsRef<[u8]>,
    U: AsRef<[u8]>,
{
    assert!(
        value1.as_ref().len() == value2.as_ref().len(),
        "calculate_hamming_distance:: Lhs & Rhs must be equal in length"
    );

    let mut distance = 0;
    for (a, b) in value1.as_ref().iter().zip(value2.as_ref().iter()) {
        distance += count_1s_bit(a ^ b) as usize;
    }

    distance
}

fn guess_repeating_xor_key_size<T: AsRef<[u8]>, I: Iterator<Item = usize> + Clone>(
    encrypted: T,
    key_range: I,
    num_block: usize,
) -> anyhow::Result<Vec<(usize, f64)>> {
    let data = encrypted.as_ref();
    if num_block == 0 || num_block % 2 != 0 {
        anyhow::bail!("num_block({num_block}) should be even and greater than 0");
    }

    let mut key_and_distance = Vec::<(usize, f64)>::with_capacity(key_range.clone().count());

    for k_size in key_range {
        if k_size * num_block > data.len() {
            anyhow::bail!(
                "total chunks size ({}) is greater than buffer len({}).",
                k_size * num_block,
                data.len()
            )
        }

        let mut dist: Vec<f64> = Vec::with_capacity(num_block / 2);
        let chunks_vec = data
            .chunks_exact(k_size)
            .take(num_block)
            .collect::<Vec<&[u8]>>();

        for chunks in chunks_vec.chunks_exact(2) {
            // safe to unwrap as iter is `num_block` in len which is even.
            let chunk1 = chunks[0];
            let chunk2 = chunks[1];
            dist.push(calculate_hamming_distance(chunk1, chunk2) as f64 / k_size as f64);
        }

        key_and_distance.push((
            k_size,
            dist.into_iter().sum::<f64>() / num_block as f64 / 2f64,
        ));
    }

    key_and_distance.sort_by(|(_, d1), (_, d2)| d1.total_cmp(d2));
    Ok(key_and_distance)
}

fn break_repeating_xor<T: AsRef<[u8]>>(encrypted: T, key_size: usize) -> Vec<char> {
    let data = encrypted.as_ref();
    let iter = data.chunks_exact(key_size);
    let mut transpose_blocks: Vec<Vec<u8>> = (0..key_size)
        .map(|_| Vec::with_capacity(data.len() / key_size))
        .collect();

    for chunk in iter {
        for (i, c) in chunk.iter().enumerate() {
            transpose_blocks[i].push(*c);
        }
    }

    let mut key = Vec::with_capacity(key_size);
    for t_chunk in transpose_blocks {
        let (k, _, _) = guess_single_xor_key(t_chunk, 0..=255);
        key.push(k);
    }
    key
}
