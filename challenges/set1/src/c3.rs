use enscoring::TextMetric;
use hex::Hex;

// brutefore with all possible single xor keys and select the one with
// highest score.
pub fn guess_single_xor_key<I>(encrypted: &Hex, char_iter: I) -> (char, f64, String)
where
    I: Iterator<Item = u8>,
{
    char_iter
        // we use fold to reduce the iterator into max (key, score) tuple.
        .fold(
            (char::MAX, -1.0, " ".to_string()),
            |(mut max_c, mut max_score, mut decrypt), c| {
                let mut encrypted_copy = encrypted.clone();
                let decoded = encrypted_copy.xor_by_char(c as char);
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


#[test]
fn set1_c3_xor_key() {
    let encrypted =
        hex::decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
            .unwrap();

    let (key, _, decrypted) = guess_single_xor_key(&encrypted, 0..=255);

    assert_eq!(decrypted, "Cooking MC's like a pound of bacon");
    assert_eq!(key, 'X');
}
