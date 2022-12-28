use std::fs;

use crate::c3::guess_single_xor_key;

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

pub fn guess_repeating_xor_key_size<T: AsRef<[u8]>, I: Iterator<Item = usize> + Clone>(
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

pub fn guess_repeating_xor_key<T: AsRef<[u8]>, I: Iterator<Item = usize> + Clone>(
    encrypted: T,
    key_range: I,
    num_block: usize,
) -> anyhow::Result<Vec<char>> {
    let key_sizes = guess_repeating_xor_key_size(&encrypted, key_range, num_block)?;
    Ok(break_repeating_xor(&encrypted, key_sizes[0].0))
}

#[test]
fn set1_c6_break_repeating_key_xor() {
    assert_eq!(
        calculate_hamming_distance("this is a test", "wokka wokka!!!"),
        37
    );

    let data_str = fs::read_to_string("src/c6_data.txt")
        .unwrap()
        .replace("\n", "");
    let encrypted = naivebase64::decode(data_str).unwrap();
    let key = guess_repeating_xor_key(&encrypted, 2..=40, 40).unwrap();

    // let key_u8: Vec<u8> = key.iter().map(|&c| c as u8).collect();
    // let decrypted = repeating_key_xor(&encrypted, &key_u8);
    // let key_range = 2..=40;
    // let num_blocks = {
    //     let n = encrypted.len() / 40;
    //     if n % 2 == 0 {
    //         n
    //     } else {
    //         n - 1
    //     }
    // };
    // let key_sizes = guess_repeating_xor_key_size(&encrypted, key_range, num_blocks).unwrap();
    // break_repeating_xor(&encrypted, key_sizes[0].0);
    // break_repeating_xor(&encrypted, key_sizes[1].0);
    // break_repeating_xor(&encrypted, key_sizes[2].0);
    // break_repeating_xor(&encrypted, key_sizes[3].0);
    // break_repeating_xor(&encrypted, key_sizes[4].0);
    // println!(
    //     "{}",
    //     String::from_utf8(decrypted.as_ref().to_vec()).unwrap()
    // );

    assert_eq!(
        &key.iter().collect::<String>(),
        "Terminator X: Bring the noise"
    );
}
