use xor::guess_single_xor_key;

#[test]
fn set1_c3_xor_key() {
    let encrypted =
        hex::decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
            .unwrap();

    let (key, _, decrypted) = guess_single_xor_key(&encrypted, 0..=255);

    assert_eq!(decrypted, "Cooking MC's like a pound of bacon");
    assert_eq!(key, 'X');
}
