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
use crate::Hash;
use codec::{Decode, Error, Input};
use std::{slice, vec::Vec};

pub fn hash_from_slice(hash_slize: &[u8]) -> Hash {
	let mut g = [0; 32];
	g.copy_from_slice(hash_slize);
	Hash::from(&mut g)
}

pub fn write_slice_and_whitespace_pad(writable: &mut [u8], data: Vec<u8>) {
	assert!(!data.len() > writable.len(), "Not enough bytes in output buffer for return value");
	let (left, right) = writable.split_at_mut(data.len());
	left.clone_from_slice(&data);
	// fill the right side with whitespace
	right.iter_mut().for_each(|x| *x = 0x20);
}

/// Helper trait to transform the sgx-ffi pointers to any type that implements
/// `parity-scale-codec::Decode`
pub unsafe trait DecodeRaw {
	/// the type to decode into
	type Decoded: Decode;

	unsafe fn decode_raw<'a, T>(data: *const T, len: usize) -> Result<Self::Decoded, codec::Error>
	where
		T: 'a,
		&'a [T]: Input;
}

unsafe impl<D: Decode> DecodeRaw for D {
	type Decoded = D;

	unsafe fn decode_raw<'a, T>(data: *const T, len: usize) -> Result<Self::Decoded, Error>
	where
		T: 'a,
		&'a [T]: Input,
	{
		let mut s = slice::from_raw_parts(data, len);

		Decode::decode(&mut s)
	}
}

pub unsafe fn utf8_str_from_raw<'a>(
	data: *const u8,
	len: usize,
) -> Result<&'a str, std::str::Utf8Error> {
	let bytes = slice::from_raw_parts(data, len);

	std::str::from_utf8(bytes)
}
