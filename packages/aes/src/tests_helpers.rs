use datadriven::{Result as DDResult, TestCase};
use hex::{Hex, ToHex};

use crate::{
    cipher::BlockCipher,
    padding::CipherPadding,
    utils::to_arr,
    Aes128CBC, Aes192CBC, Aes256CBC, Modes,
    {cipher::AesCipher, Aes128, Aes192, Aes256},
};

type AesCipher128 = AesCipher<128>;
type AesCipher192 = AesCipher<192>;
type AesCipher256 = AesCipher<256>;

pub enum Directive {
    Aes {
        key: Hex,
        plain_text: Hex,
        iv: Option<Hex>,
        mode: String,
    },
    KeyExpansion {
        key: Hex,
    },
    Cipher {
        key: Hex,
        plain_text: Hex,
    },
    InverseCipher {
        key: Hex,
        cipher_text: Hex,
    },
    SubBytes {
        block: Hex,
    },
    ShiftRows {
        block: Hex,
    },
    MixColumns {
        block: Hex,
    },
    AddRoundKey {
        block: Hex,
        key_sch: Hex,
    },
}

impl Directive {
    pub fn run(self) -> DDResult<String> {
        match self {
            Directive::Aes {
                key,
                plain_text,
                mode,
                iv,
            } => match key.data().len() * 8 {
                128 => match mode.as_str() {
                    "ecb" => run_aes(Aes128::new(), plain_text, key),
                    "cbc" => run_aes(
                        Aes128CBC::with_iv(
                            iv.map(|i| i.0)
                                .unwrap_or(Aes128CBC::DEFAULT_CBC_IV.to_vec()),
                        ),
                        plain_text,
                        key,
                    ),
                    m => anyhow::bail!("Invalid mode - {}", m),
                },
                192 => match mode.as_str() {
                    "ecb" => run_aes(Aes192::new(), plain_text, key),
                    "cbc" => run_aes(
                        Aes192CBC::with_iv(
                            iv.map(|i| i.0)
                                .unwrap_or(Aes192CBC::DEFAULT_CBC_IV.to_vec()),
                        ),
                        plain_text,
                        key,
                    ),
                    m => anyhow::bail!("Invalid mode - {}", m),
                },
                256 => match mode.as_str() {
                    "ecb" => run_aes(Aes256::new(), plain_text, key),
                    "cbc" => run_aes(
                        Aes256CBC::with_iv(
                            iv.map(|i| i.0)
                                .unwrap_or(Aes256CBC::DEFAULT_CBC_IV.to_vec()),
                        ),
                        plain_text,
                        key,
                    ),
                    m => anyhow::bail!("Invalid mode - {}", m),
                },
                k => anyhow::bail!("Invalid key length - {}", k),
            },
            Directive::KeyExpansion { key } => match key.data().len() * 8 {
                128 => {
                    Ok(hex::encode_with_break_space(AesCipher128::key_expansion(key), 32)? + "\n")
                }
                192 => {
                    Ok(hex::encode_with_break_space(AesCipher192::key_expansion(key), 32)? + "\n")
                }
                256 => {
                    Ok(hex::encode_with_break_space(AesCipher256::key_expansion(key), 32)? + "\n")
                }
                k => anyhow::bail!("Invalid key length - {}", k),
            },
            Directive::Cipher { key, plain_text } => match key.data().len() * 8 {
                128 => {
                    let block = AesCipher128::cipher(*to_arr(plain_text.data())?, key);
                    Ok(hex::encode(block)? + "\n")
                }
                192 => {
                    let block = AesCipher192::cipher(*to_arr(plain_text.data())?, key);
                    Ok(hex::encode(block)? + "\n")
                }
                256 => {
                    let block = AesCipher256::cipher(*to_arr(plain_text.data())?, key);
                    Ok(hex::encode(block)? + "\n")
                }
                k => anyhow::bail!("Invalid key length - {}", k),
            },
            Directive::InverseCipher { key, cipher_text } => match key.data().len() * 8 {
                128 => {
                    let block = AesCipher128::inv_cipher(*to_arr(cipher_text.data())?, key);
                    Ok(hex::encode(block)? + "\n")
                }
                192 => {
                    let block = AesCipher192::inv_cipher(*to_arr(cipher_text.data())?, key);
                    Ok(hex::encode(block)? + "\n")
                }
                256 => {
                    let block = AesCipher256::inv_cipher(*to_arr(cipher_text.data())?, key);
                    Ok(hex::encode(block)? + "\n")
                }
                k => anyhow::bail!("Invalid key length - {}", k),
            },
            Directive::SubBytes { block } => {
                let mut _input = *to_arr(block.data())?;
                AesCipher128::sub_bytes(&mut _input);
                Ok(hex::encode(_input)? + "\n")
            }
            Directive::ShiftRows { block } => {
                let mut _input = *to_arr(block.data())?;
                AesCipher128::shift_rows(&mut _input);
                Ok(hex::encode(_input)? + "\n")
            }
            Directive::MixColumns { block } => {
                let mut _input = *to_arr(block.data())?;
                AesCipher128::mix_columns(&mut _input);
                Ok(hex::encode(_input)? + "\n")
            }
            Directive::AddRoundKey { block, key_sch } => {
                let mut _block = *to_arr(block.data())?;
                let _key_sch = to_arr(key_sch.data())?;
                AesCipher128::add_round_key(&mut _block, _key_sch);
                Ok(hex::encode(_block)? + "\n")
            }
        }
    }
}

impl TryFrom<TestCase> for Directive {
    type Error = anyhow::Error;
    fn try_from(case: TestCase) -> Result<Self, Self::Error> {
        match case.directive.as_str() {
            "aes" => {
                let plain_text = case.input.as_bytes().to_vec();
                let key = remove_whitespace(
                    case.args
                        .get("key")
                        .ok_or(anyhow::anyhow!(
                            "key arg missing in aes directive test case"
                        ))?
                        .get(0)
                        .ok_or(anyhow::anyhow!("key is empty"))?,
                )
                .to_hex()?;
                let mode = remove_whitespace(
                    case.args
                        .get("mode")
                        .ok_or(anyhow::anyhow!(
                            "mode arg missing in aes directive test case"
                        ))?
                        .get(0)
                        .ok_or(anyhow::anyhow!("mode is empty"))?,
                );

                let iv = case.args.get("iv").and_then(|v| {
                    v.get(0)
                        .and_then(|i| remove_whitespace(i.as_str()).to_hex().ok())
                });

                Ok(Self::Aes {
                    key,
                    plain_text: Hex(plain_text),
                    mode,
                    iv,
                })
            }
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
            "inv_cipher" => {
                let cipher_text = remove_whitespace(&case.input).to_hex()?;
                let key = remove_whitespace(
                    case.args
                        .get("key")
                        .ok_or(anyhow::anyhow!(
                            "key arg missing in inv_cipher directive test case"
                        ))?
                        .get(0)
                        .ok_or(anyhow::anyhow!("key is empty"))?,
                )
                .to_hex()?;
                Ok(Self::InverseCipher { key, cipher_text })
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

fn run_aes<C: BlockCipher<B, Unit = u8>, const B: usize, D: CipherPadding, M: Modes<C, B, D>>(
    mode: M,
    plain_text: Hex,
    key: Hex,
) -> anyhow::Result<String> {
    let enc = mode.encrypt(&plain_text, &key)?;
    let dec = mode.decrypt(enc, &key)?;
    let dec_str = String::from_utf8(dec)?;

    Ok(dec_str)
}
