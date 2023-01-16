use std::fs;

use xor::{calculate_hamming_distance, guess_repeating_xor_key};

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
