use std::fs;

use aes::{Aes128CBC, Modes};

#[test]
fn set2_c10_aes_cbc() {
    let data_str = naivebase64::decode(
        fs::read_to_string("src/c10_data.txt")
            .unwrap()
            .replace("\n", ""),
    )
    .unwrap();

    let key = "YELLOW SUBMARINE";
    let dec = &Aes128CBC::new().decrypt(data_str, key).unwrap();
    let dec_str = String::from_utf8_lossy(&dec);
    let first_line = dec_str.split('\n').next().unwrap();
    assert_eq!("I'm back and I'm ringin' the bell ", first_line);
}
