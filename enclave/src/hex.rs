// hex encoder and decoder used by rust-protobuf unittests

use sgx_types::*;
use std::char;
use std::prelude::v1::*;

use log::error;

fn decode_hex_digit(digit: char) -> SgxResult<u8> {
    match digit {
        '0'..='9' => Ok(digit as u8 - b'0'),
        'a'..='f' => Ok(digit as u8 - b'a' + 10),
        'A'..='F' => Ok(digit as u8 - b'A' + 10),
        _ => Err(sgx_status_t::SGX_ERROR_UNEXPECTED),
    }
}

pub fn decode_spid(hex: &str) -> SgxResult<sgx_spid_t> {
    let mut spid = sgx_spid_t::default();
    let hex = hex.trim();

    if hex.len() < 16 * 2 {
        println!("Input spid file len ({}) is incorrect!", hex.len());
        return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
    }

    let decoded_vec = decode_hex(hex)?;

    spid.id.copy_from_slice(&decoded_vec[..16]);

    Ok(spid)
}

pub fn decode_hex(hex: &str) -> SgxResult<Vec<u8>> {
    let mut r: Vec<u8> = Vec::new();
    let mut chars = hex.chars().enumerate();
    loop {
        let (pos, first) = match chars.next() {
            None => break,
            Some(elt) => elt,
        };
        if first == ' ' {
            continue;
        }
        let (_, second) = match chars.next() {
            None => {
                error!("Hex decode error at position = {}d", pos);
                return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
            }
            Some(elt) => elt,
        };
        r.push((decode_hex_digit(first)? << 4) | decode_hex_digit(second)?);
    }
    Ok(r)
}

#[allow(unused)]
fn encode_hex_digit(digit: u8) -> char {
    match char::from_digit(u32::from(digit), 16) {
        Some(c) => c,
        _ => panic!(),
    }
}

#[allow(unused)]
fn encode_hex_byte(byte: u8) -> [char; 2] {
    [encode_hex_digit(byte >> 4), encode_hex_digit(byte & 0x0Fu8)]
}

#[allow(unused)]
pub fn encode_hex(bytes: &[u8]) -> String {
    let strs: Vec<String> = bytes
        .iter()
        .map(|byte| encode_hex_byte(*byte).iter().copied().collect())
        .collect();
    strs.join("")
}

#[cfg(test)]
mod test {
    use super::decode_hex;
    use super::encode_hex;
    use crate::std::string::ToString;
    #[test]
    fn test_decode_hex() {
        assert!(decode_hex("").unwrap().len() == 0);
        assert_eq!(decode_hex("00").unwrap(), [0x00u8].to_vec());
        assert_eq!(decode_hex("ff").unwrap(), [0xffu8].to_vec());
        assert_eq!(decode_hex("AB").unwrap(), [0xabu8].to_vec());
        assert_eq!(decode_hex("fa19").unwrap(), [0xfau8, 0x19].to_vec());
    }

    #[test]
    fn test_encode_hex() {
        assert_eq!("".to_string(), encode_hex(&[]));
        assert_eq!("00".to_string(), encode_hex(&[0x00]));
        assert_eq!("ab".to_string(), encode_hex(&[0xab]));
        assert_eq!(
            "01a21afe".to_string(),
            encode_hex(&[0x01, 0xa2, 0x1a, 0xfe])
        );
    }
}
