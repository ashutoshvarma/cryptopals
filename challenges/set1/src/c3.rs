use enscoring::TextMetric;

#[test]
fn set1_c3_xor_key() {
    let mut encoded =
        hex::decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
            .unwrap();

    for c in (b'a'..b'z').chain(b'A'..b'Z') {
        let mut encoded_copy = encoded.clone();
        let decoded = encoded_copy.xor_by_char(c as char);
        let ltr = String::from_utf8(decoded.as_ref().to_vec()).unwrap();
        let metric = TextMetric::score(&ltr);
        println!("{} - {} - {:?}", c as char, ltr, metric.most_frequent_alphabet);
    }
}
