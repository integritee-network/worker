/*
	Copyright 2021 Integritee AG and Supercomputing Systems AG

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

		http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.

*/

//! Hex encoding utility functions.

use crate::error::{Error, Result};
use codec::{Decode, Encode};
use std::{string::String, vec::Vec};

/// Trait to encode a given value to a hex string, prefixed with "0x".
pub trait ToHexPrefixed {
	fn to_hex(&self) -> String;
}

impl<T: Encode> ToHexPrefixed for T {
	fn to_hex(&self) -> String {
		hex_encode(&self.encode())
	}
}

/// Trait to decode a hex string to a given output.
pub trait FromHexPrefixed {
	type Output;

	fn from_hex(msg: &str) -> Result<Self::Output>;
}

impl<T: Decode> FromHexPrefixed for T {
	type Output = T;

	fn from_hex(msg: &str) -> Result<Self::Output> {
		let byte_array = decode_hex(msg)?;
		Decode::decode(&mut byte_array.as_slice()).map_err(Error::Codec)
	}
}

/// Hex encodes given data and preappends a "0x".
pub fn hex_encode(data: &[u8]) -> String {
	let mut hex_str = hex::encode(data);
	hex_str.insert_str(0, "0x");
	hex_str
}

/// Helper method for decoding hex.
pub fn decode_hex<T: AsRef<[u8]>>(message: T) -> Result<Vec<u8>> {
	let message = message.as_ref();
	let message = match message {
		[b'0', b'x', hex_value @ ..] => hex_value,
		_ => message,
	};

	let decoded_message = hex::decode(message).map_err(Error::Hex)?;
	Ok(decoded_message)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn hex_encode_decode_works() {
		let data = "Hello World!".to_string();

		let hex_encoded_data = hex_encode(&data.encode());
		let decoded_data =
			String::decode(&mut decode_hex(hex_encoded_data).unwrap().as_slice()).unwrap();

		assert_eq!(data, decoded_data);
	}

	#[test]
	fn hex_encode_decode_works_empty_input() {
		let data = String::new();

		let hex_encoded_data = hex_encode(&data.encode());
		let decoded_data =
			String::decode(&mut decode_hex(hex_encoded_data).unwrap().as_slice()).unwrap();

		assert_eq!(data, decoded_data);
	}

	#[test]
	fn hex_encode_decode_works_empty_input_for_decode() {
		let data = String::new();

		let decoded_data = decode_hex(&data).unwrap();

		assert!(decoded_data.is_empty());
	}

	#[test]
	fn to_hex_from_hex_works() {
		let data = "Hello World!".to_string();

		let hex_encoded_data = data.to_hex();
		let decoded_data = String::from_hex(&hex_encoded_data).unwrap();

		assert_eq!(data, decoded_data);
	}
}
