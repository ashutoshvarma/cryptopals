use datadriven::{Result as DDResult, TestCase};
use hex::{Hex, ToHex};

use super::*;

pub enum Directive {
    KeyExpansion { key: Hex },
    Cipher { key: Hex, plain_text: Hex },
    _InverseCipher { key: Hex, cipher_text: Hex },
    SubBytes { block: Hex },
    ShiftRows { block: Hex },
    MixColumns { block: Hex },
    AddRoundKey { block: Hex, key_sch: Hex },
}

impl Directive {
    pub fn run(self) -> DDResult<String> {
        match self {
            Directive::KeyExpansion { key } => match key.data().len() * 8 {
                128 => {
                    let _key = to_arr(key.data())?;
                    Ok(hex::encode_with_break_space(Aes128::key_expansion(_key), 32)? + "\n")
                }
                192 => {
                    let _key = to_arr(key.data())?;
                    Ok(hex::encode_with_break_space(Aes192::key_expansion(_key), 32)? + "\n")
                }
                256 => {
                    let _key = to_arr(key.data())?;
                    Ok(hex::encode_with_break_space(Aes256::key_expansion(_key), 32)? + "\n")
                }
                k => anyhow::bail!("Invalid key length - {}", k),
            },
            Directive::Cipher { key, plain_text } => match key.data().len() * 8 {
                128 => {
                    let _key = to_arr(key.data())?;
                    let _key_sch = Aes128::key_expansion(_key);
                    let mut block = *to_arr(plain_text.data())?;
                    Aes128::cipher(&mut block, &_key_sch);
                    Ok(hex::encode(block)? + "\n")
                }
                192 => {
                    let _key = to_arr(key.data())?;
                    let _key_sch = Aes192::key_expansion(_key);
                    let mut block = *to_arr(plain_text.data())?;
                    Aes192::cipher(&mut block, &_key_sch);
                    Ok(hex::encode(block)? + "\n")
                }
                256 => {
                    let _key = to_arr(key.data())?;
                    let _key_sch = Aes256::key_expansion(_key);
                    let mut block = *to_arr(plain_text.data())?;
                    Aes256::cipher(&mut block, &_key_sch);
                    Ok(hex::encode(block)? + "\n")
                }
                k => anyhow::bail!("Invalid key length - {}", k),
            },
            Directive::SubBytes { block } => {
                let mut _input = *to_arr(block.data())?;
                Aes128::sub_bytes(&mut _input);
                Ok(hex::encode(_input)? + "\n")
            }
            Directive::ShiftRows { block } => {
                let mut _input = *to_arr(block.data())?;
                Aes128::shift_rows(&mut _input);
                Ok(hex::encode(_input)? + "\n")
            }
            Directive::MixColumns { block } => {
                let mut _input = *to_arr(block.data())?;
                Aes128::mix_columns(&mut _input);
                Ok(hex::encode(_input)? + "\n")
            }
            Directive::AddRoundKey { block, key_sch } => {
                let mut _block = *to_arr(block.data())?;
                let _key_sch = to_arr(key_sch.data())?;
                Aes128::add_round_key(&mut _block, _key_sch);
                Ok(hex::encode(_block)? + "\n")
            }
            _ => anyhow::bail!("Unknown Directive"),
        }
    }
}

impl TryFrom<TestCase> for Directive {
    type Error = anyhow::Error;
    fn try_from(case: TestCase) -> Result<Self, Self::Error> {
        match case.directive.as_str() {
            "key_expansion" => {
                let key = remove_whitespace(&case.input).to_hex()?;
                Ok(Self::KeyExpansion { key })
            }
            "cipher" => {
                let plain_text = remove_whitespace(&case.input).to_hex()?;
                let key = remove_whitespace(
                    case.args
                        .get("key")
                        .ok_or(anyhow::anyhow!(
                            "key arg missing in cipher directive test case"
                        ))?
                        .get(0)
                        .ok_or(anyhow::anyhow!("key is empty"))?,
                )
                .to_hex()?;
                Ok(Self::Cipher { key, plain_text })
            }
            "sub_bytes" => {
                let block = remove_whitespace(&case.input).to_hex()?;
                Ok(Self::SubBytes { block })
            }
            "shift_rows" => {
                let block = remove_whitespace(&case.input).to_hex()?;
                Ok(Self::ShiftRows { block })
            }
            "mix_col" => {
                let block = remove_whitespace(&case.input).to_hex()?;
                Ok(Self::MixColumns { block })
            }
            "add_round_key" => {
                let block = remove_whitespace(&case.input).to_hex()?;
                let key_sch = remove_whitespace(
                    case.args
                        .get("key")
                        .ok_or(anyhow::anyhow!(
                            "key arg missing in add_round_key directive test case"
                        ))?
                        .get(0)
                        .ok_or(anyhow::anyhow!("key is empty"))?,
                )
                .to_hex()?;
                Ok(Self::AddRoundKey { block, key_sch })
            }
            u => Err(anyhow::anyhow!("Unknown directive - {}", u)),
        }
    }
}

fn remove_whitespace(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace()).collect()
}
