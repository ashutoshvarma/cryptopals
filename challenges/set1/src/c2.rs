#[test]
fn set1_c2_xor() {
    let a = hex::decode("1c0111001f010100061a024b53535009181c").unwrap();
    let b = hex::decode("686974207468652062756c6c277320657965").unwrap();
    let c = a ^ b;
    assert_eq!(
        hex::encode(c).unwrap(),
        "746865206b696420646f6e277420706c6179"
    );
}
