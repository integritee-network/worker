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

//! General utility functions.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(all(feature = "std", feature = "sgx"))]
compile_error!("feature \"std\" and feature \"sgx\" cannot be enabled at the same time");

#[cfg(all(not(feature = "std"), feature = "sgx"))]
extern crate sgx_tstd as std;

// re-export module to properly feature gate sgx and regular std environment
#[cfg(all(not(feature = "std"), feature = "sgx"))]
pub mod sgx_reexport_prelude {
	pub use thiserror_sgx as thiserror;
}

mod error;

pub use error::{Error, Result};

use codec::{Decode, Encode};
use frame_support::ensure;
use itp_sgx_crypto::{ShieldingCryptoDecrypt, ShieldingCryptoEncrypt};
use std::{format, string::String, vec::Vec};

/// Hex encodes given data and preappends a "0x".
pub fn hex_encode(data: Vec<u8>) -> String {
	let mut hex_str = hex::encode(data);
	hex_str.insert_str(0, "0x");
	hex_str
}

/// Encrypts and hex encodes data with a given public key.
pub fn shielding_encrypt_to_hex_bytes<Key: ShieldingCryptoEncrypt, E: Encode>(
	encryption_key: &Key,
	data: E,
) -> Result<Vec<u8>> {
	let encrypted = encryption_key
		.encrypt(data.encode().as_slice())
		.map_err(|e| Error::Other(format!("{:?}", e).into()))?;

	let hex_encoded = hex_encode(encrypted);

	Ok(hex_encoded.into_bytes())
}

/// Encrypts and hex encodes data with a given public key.
pub fn shielding_decrypt_from_hex_bytes<Key: ShieldingCryptoDecrypt, E: Decode>(
	decryption_key: &Key,
	hex_encoded_data: Vec<u8>,
) -> Result<E> {
	let encrypted_data = hex::decode(hex_encoded_data).map_err(Error::Hex)?;
	let encoded_data = decryption_key
		.decrypt(&encrypted_data)
		.map_err(|e| Error::Other(format!("{:?}", e).into()))?;
	let decoded_data = E::decode(&mut encoded_data.as_slice()).map_err(Error::Codec)?;
	Ok(decoded_data)
}

/// Fills a given buffer with data and fill the left over buffer space with white spaces.
pub fn write_slice_and_whitespace_pad(writable: &mut [u8], data: Vec<u8>) -> Result<()> {
	ensure!(
		data.len() <= writable.len(),
		Error::InsufficientBufferSize(writable.len(), data.len())
	);
	let (left, right) = writable.split_at_mut(data.len());
	left.clone_from_slice(&data);
	// fill the right side with whitespace
	right.iter_mut().for_each(|x| *x = 0x20);
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn write_slice_and_whitespace_pad_returns_error_if_buffer_too_small() {
		let mut writable = vec![0; 32];
		let data = vec![1; 33];
		assert!(write_slice_and_whitespace_pad(&mut writable, data).is_err());
	}

	#[test]
	fn hex_encoding_round_trip_works() {
		let mut writable = vec![0; 32];
		let data = vec![1; 33];
		assert!(write_slice_and_whitespace_pad(&mut writable, data).is_err());
	}
}
