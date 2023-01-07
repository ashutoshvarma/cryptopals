use aes::padding::CipherPadding;

#[test]
fn set2_c9_pkcs7_padding() {
    let text = "YELLOW SUBMARINE";
    let padded = aes::padding::PKCS7Padding::add_pad::<20>(text.as_bytes().to_vec());
    assert_eq!("YELLOW SUBMARINE\x04\x04\x04\x04", String::from_utf8(padded).unwrap());
}