use crate::std::slice;
use codec::Encode;
use sp_core::hashing::blake2_256;
use sp_core::H256;

pub fn header_hash<H: Encode>(header: &H) -> H256 {
    let data = header.encode();
    blake2_256(&data.as_slice()).into()
}
