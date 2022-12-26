use std::fs;

use crate::c3::guess_single_xor_key;

#[test]
fn set1_c4_multiple_xor_key() {
    let binding = fs::read_to_string("src/c4_data.txt").unwrap();
    let lines = binding.split('\n');

    let mut max_score = -1.0;
    let mut key = char::MAX;
    let mut decrypted = String::new();

    for line in lines {
        let enc = hex::decode(line).unwrap();
        let (k, s, d) = guess_single_xor_key(&enc, 0..=255);
        if s > max_score {
            max_score = s;
            key = k;
            decrypted = d;
        }
    }
    

    assert_eq!(decrypted, "Now that the party is jumping\n");
    assert_eq!(key, '5');
}
