use std::fmt::Display;
use thiserror::Error;

pub mod xor;

pub fn decode<T: AsRef<[u8]>>(v: T) -> HexResult<Hex> {
    unpacked_u8_slice_to_hex(v.as_ref())
}

pub fn encode<T: AsRef<[u8]>>(v: T) -> HexResult<String> {
    let points = hex_to_codepoints(v)?;
    Ok(String::from_utf8(points)?)
}

pub fn encode_with_break<T: AsRef<[u8]>>(v: T, n: usize) -> HexResult<String> {
    let points = hex_to_codepoints(v)?;
    Ok(String::from_utf8(points)?
        .chars()
        .enumerate()
        .flat_map(|(i, c)| {
            if i != 0 && i % n == 0 {
                Some('\n')
            } else {
                None
            }
            .into_iter()
            .chain(std::iter::once(c))
        })
        .collect::<String>())
}

pub fn encode_with_break_space<T: AsRef<[u8]>>(v: T, n: usize) -> HexResult<String> {
    let points = hex_to_codepoints(v)?;
    Ok(String::from_utf8(points)?
        .chars()
        .enumerate()
        .flat_map(|(i, c)| {
            if i != 0 && i % n == 0 {
                Some('\n')
            } else if i != 0 && i % 2 == 0 {
                Some(' ')
            } else {
                None
            }
            .into_iter()
            .chain(std::iter::once(c))
        })
        .collect::<String>())
}

pub type HexResult<T> = anyhow::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Invalid hex literal ({val:?}) at position {idx:?}")]
    InvalidHexLiteral { idx: usize, val: char },

    #[error("Invalid hex codepoint ({val:?}) at position {idx:?}")]
    InvalidHexCodePoint { idx: usize, val: u8 },

    #[error("Odd length, hex should be even in length")]
    OddLength,

    #[error(transparent)]
    FromUtf8Error {
        #[from]
        source: std::string::FromUtf8Error,
    },
}

// resultant hex is unpacked, one u8 per hex point
fn char_to_hex_point(c: u8, idx: usize) -> HexResult<u8> {
    match c {
        b'0'..=b'9' => Ok(c - 48),
        b'A'..=b'F' => Ok(c - 65 + 10),
        b'a'..=b'f' => Ok(c - 97 + 10),
        _ => Err(Error::InvalidHexLiteral { idx, val: c.into() }.into()),
    }
}

// hex point is unpacked, means one hex per u8
fn hex_point_to_hex_char(c: u8, idx: usize) -> HexResult<u8> {
    match c {
        0..=9 => Ok(c + 48),
        10..=15 => Ok(c + 97 - 10),
        _ => Err(Error::InvalidHexCodePoint { idx, val: c }.into()),
    }
}

fn unpacked_u8_slice_to_hex(value: &[u8]) -> HexResult<Hex> {
    Ok(Hex(value
        .chunks(2)
        .enumerate()
        .map(|(idx, v)| {
            Ok((char_to_hex_point(v[0], idx * 2)? << 4) + (char_to_hex_point(v[1], idx * 2)?))
        })
        .collect::<HexResult<Vec<u8>>>()?))
}

// unpack the hex, to one u8 per hex codepoint
fn hex_to_codepoints<T: AsRef<[u8]>>(value: T) -> HexResult<Vec<u8>> {
    value
        .as_ref()
        .iter()
        .enumerate()
        .flat_map(|(idx, &v)| {
            let lo = v >> 4;
            let hi = v & 15;
            [
                hex_point_to_hex_char(lo, idx),
                hex_point_to_hex_char(hi, idx),
            ]
        })
        .collect()
}

pub trait ToHex<T> {
    fn to_hex(&self) -> HexResult<Hex>;
}

impl<T> ToHex<T> for T
where
    T: AsRef<[u8]>,
{
    fn to_hex(&self) -> HexResult<Hex> {
        decode(self.as_ref())
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Hex(pub Vec<u8>);

impl Hex {
    pub fn data(&self) -> &[u8] {
        &self.0
    }
}

impl Hex {
    pub fn encode<T: AsRef<[u8]>>(value: T) -> HexResult<String> {
        encode(value)
    }
    pub fn encode_with_break<T: AsRef<[u8]>>(value: T, n: usize) -> HexResult<String> {
        encode_with_break(value, n)
    }
}

impl Display for Hex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hex_str = encode(&self.0).map_err(|_| std::fmt::Error)?;
        write!(f, "{}", hex_str)
    }
}

impl AsRef<[u8]> for Hex {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for Hex {
    type Error = Error;

    fn try_from(value: &[u8]) -> HexResult<Self> {
        if value.len() % 2 != 0 {
            Err(Error::OddLength)
        } else {
            Ok(Hex(value.to_vec()))
        }
    }
}

impl TryFrom<&str> for Hex {
    type Error = Error;

    fn try_from(value: &str) -> HexResult<Self> {
        if value.len() % 2 != 0 {
            Err(Error::OddLength)
        } else {
            unpacked_u8_slice_to_hex(value.as_bytes())
        }
    }
}

impl TryFrom<String> for Hex {
    type Error = Error;

    fn try_from(value: String) -> HexResult<Self> {
        Hex::try_from(value.as_str())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_hex_decode() {
        let hex_str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let a = hex::decode(hex_str).unwrap();
        let b: Hex = hex_str.try_into().unwrap();

        assert_eq!(a, b.0);
    }

    #[test]
    fn test_hex_encode() {
        let hex_str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let a = hex::decode(hex_str).unwrap();
        let b: Hex = hex_str.try_into().unwrap();

        let encode_a = hex::encode(a).to_ascii_lowercase();
        let encode_b = format!("{b}").to_ascii_lowercase();

        assert_eq!(encode_a, encode_b);
    }
}
