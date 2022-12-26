use enscoring::TextMetric;

#[test]
fn set1_c3_xor_key() {
    let encoded =
        hex::decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
            .unwrap();

    let (key, _) = (b'a'..b'z')
        .chain(b'A'..b'Z')
        // we use fold to reduce the iterator into max (key, score) tuple.
        .fold((char::MAX, -1.0), |(mut max_c, mut max_score), c| {
            let mut encoded_copy = encoded.clone();
            let decoded = encoded_copy.xor_by_char(c as char);
            let ltr = std::str::from_utf8(decoded.as_ref())
                // make it safe to use unwrap here
                .or::<std::str::Utf8Error>(Ok(""))
                .unwrap();
            let score = ltr.text_score();

            if max_score <= score {
                max_c = c as char;
                max_score = score;
            }

            (max_c, max_score)
        });

    assert_eq!(key, 'X');
}
