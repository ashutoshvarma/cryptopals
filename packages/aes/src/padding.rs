pub trait CipherPadding {
    // add padding to a po
    fn add_pad<const B: usize>(data: Vec<u8>) -> Vec<u8>;
    fn remove_pad<const B: usize>(data: Vec<u8>) -> Vec<u8>;
}

impl CipherPadding for PKCS7Padding {
    fn add_pad<const B: usize>(mut data: Vec<u8>) -> Vec<u8> {
        let l = data.len();
        data.append(&mut vec![(B - (l % B)) as u8; B - (l % B)]);
        data
    }

    fn remove_pad<const B: usize>(mut data: Vec<u8>) -> Vec<u8> {
        let padding_len = data.last().map(|p| *p as usize).unwrap_or(usize::MAX);
        let new_len = data.len().saturating_sub(padding_len);
        data.truncate(new_len);
        data
    }
}

pub struct PKCS7Padding;

#[cfg(test)]
mod test {
    use super::{CipherPadding, PKCS7Padding};

    #[test]
    fn test_pkcs7_padding_empty() {
        let data = vec![];
        let padded = PKCS7Padding::add_pad::<16>(data.clone());
        let unpadded = PKCS7Padding::remove_pad::<16>(data.clone());

        assert_eq!(padded, vec![16; 16]);
        assert_eq!(unpadded, data);
    }

    #[test]
    fn test_pkcs7_padding_more_than_buffer() {
        let data = vec![1];
        let padded = PKCS7Padding::add_pad::<16>(data.clone());
        let unpadded = PKCS7Padding::remove_pad::<16>(padded.clone());

        assert_eq!(padded, [data.clone(), vec![15; 15]].concat());
        assert_eq!(unpadded, data);
    }

    #[test]
    fn test_pkcs7_padding_remove_more_than_buffer() {
        let padded = vec![1,3];
        let unpadded = PKCS7Padding::remove_pad::<16>(padded.clone());
        assert_eq!(unpadded, vec![]);
    }
}
