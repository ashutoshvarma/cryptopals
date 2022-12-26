use hex::Hex;

pub fn repeating_key_xor<T: AsRef<[u8]>, K: AsRef<[u8]>>(value: T, key: K) -> Hex {
    let keys = key.as_ref();
    let keys_count = keys.len();

    Hex(value
        .as_ref()
        .chunks(keys_count)
        .flat_map(|chars| chars.iter().enumerate().map(|(i, c)| c ^ keys[i]))
        .collect())
}

#[test]
fn set1_c5_repeating_key_xor() {
    let value = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    let key = "ICE";

    let xored = repeating_key_xor(value, key);
    let expected = hex::decode("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f").unwrap();

    assert_eq!(xored, expected);
}
