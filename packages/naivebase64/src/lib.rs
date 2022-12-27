static BASE64_PADDING_CHAR: char = '=';
static BASE64_TABLE: [char; 64] = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
    'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
    'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9', '+', '/',
];

fn base64_char_value(v: char) -> anyhow::Result<u8> {
    match v {
        'A'..='Z' => Ok(v as u8 - 65),
        'a'..='z' => Ok(v as u8 - 97 + 26),
        '0'..='9' => Ok(v as u8 - 48 + 52),
        '+' => Ok(62),
        '/' => Ok(63),
        '=' => Ok(0),
        _ => Err(anyhow::anyhow!("Not a valid Base64 char - {v}")),
    }
}

fn calculate_base64_len_padding(data_len: usize) -> usize {
    let (q, r) = (data_len / 3, data_len % 3);
    (q * 4) + (3 - r)
}

pub fn encode<T: AsRef<[u8]>>(value: T) -> String {
    let data = value.as_ref();
    let iter = data.chunks_exact(3);
    let rem = iter.remainder();

    let len = calculate_base64_len_padding(data.len());
    let mut res = String::with_capacity(len);

    for chunk in iter {
        let lo = chunk[0];
        let mid = chunk[1];
        let hi = chunk[2];

        // 1st
        res.push(BASE64_TABLE[((lo >> 2) & 63) as usize]);
        // 2nd
        res.push(BASE64_TABLE[(((lo << 4) + (mid >> 4)) & 63) as usize]);
        // 3rd
        res.push(BASE64_TABLE[(((mid << 2) + (hi >> 6)) & 63) as usize]);
        // 4th
        res.push(BASE64_TABLE[(hi & 63) as usize]);
    }

    if rem.len() == 2 {
        let lo = rem[0];
        let mid = rem[1];

        // 1st
        res.push(BASE64_TABLE[((lo >> 2) & 63) as usize]);
        // 2nd
        res.push(BASE64_TABLE[(((lo << 4) + (mid >> 4)) & 63) as usize]);
        // 3rd
        res.push(BASE64_TABLE[((mid << 2) & 63) as usize]);
        // 4th
        res.push(BASE64_PADDING_CHAR);
    } else if rem.len() == 1 {
        let lo = rem[0];

        // 1st
        res.push(BASE64_TABLE[((lo >> 2) & 63) as usize]);
        // 2nd
        res.push(BASE64_TABLE[((lo << 4) & 63) as usize]);
        // 3rd
        res.push(BASE64_PADDING_CHAR);
        // 4th
        res.push(BASE64_PADDING_CHAR);
    }

    res
}

pub fn decode<T: AsRef<[u8]>>(value: T) -> anyhow::Result<Vec<u8>> {
    let data = value.as_ref();
    let mut res = Vec::with_capacity((data.len() / 4) * 3);
    for chunk in data.chunks_exact(4) {
        let b0 = base64_char_value(chunk[0] as char)?;
        let b1 = base64_char_value(chunk[1] as char)?;
        let b2 = base64_char_value(chunk[2] as char)?;
        let b3 = base64_char_value(chunk[3] as char)?;

        res.push((b0 << 2) + (b1 >> 4));
        if chunk[2] != b'=' {
            res.push((b1 << 4) + (b2 >> 2));
            if chunk[3] != b'=' {
                res.push((b2 << 6) + b3);
            }
        }
    }

    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base64_encode<const N: u8>() {
        let data: Vec<u8> = (0..N).collect();

        let a = base64::encode(data.clone());
        let b = encode(data);

        assert_eq!(a, b, "asserting for length {}", N);
    }

    fn base64_decode(data: &str) {
        let a = base64::decode(data.clone()).unwrap();
        let b = decode(data).unwrap();

        assert_eq!(a, b, "assetion for decode, data={data}, a={a:?}, b={b:?}");
    }

    #[test]
    fn test_base64_encode() {
        base64_encode::<100>();
        base64_encode::<101>();
        base64_encode::<102>();
        base64_encode::<104>();
    }

    #[test]
    fn test_base64_decode() {
        // let data = "cXdlcnR5dWlvcGFzZGZnaGprbHp4Y3Zibm0=";
        base64_decode("cXdlcnR5dWlvcGFzZGZnaGprbHp4Y3Zibm0wMA==");
    }
}
