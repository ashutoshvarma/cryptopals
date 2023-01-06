#[test]
fn set1_c7_aes_ecb_decrypt() {
    let data_str = std::fs::read_to_string("src/c7_data.txt")
        .unwrap()
        .replace("\n", "");

    let decrypted =
        aes::Aes128::decrypt(naivebase64::decode(data_str).unwrap(), "YELLOW SUBMARINE").unwrap();
    let dec_str = String::from_utf8(decrypted).unwrap();
    let first_line = dec_str.split('\n').next().unwrap();
    assert_eq!("I'm back and I'm ringin' the bell ", first_line);
}
