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

//! Buffer utility functions.

use frame_support::ensure;
use std::vec::Vec;

#[cfg(all(not(feature = "std"), feature = "sgx"))]
use crate::sgx_reexport_prelude::thiserror;

/// Fills a given buffer with data and the left over buffer space with white spaces.
pub fn write_slice_and_whitespace_pad(
	writable: &mut [u8],
	data: Vec<u8>,
) -> Result<(), BufferError> {
	ensure!(
		data.len() <= writable.len(),
		BufferError::InsufficientBufferSize(writable.len(), data.len())
	);
	let (left, right) = writable.split_at_mut(data.len());
	left.clone_from_slice(&data);
	// fill the right side with whitespace
	right.iter_mut().for_each(|x| *x = 0x20);
	Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum BufferError {
	#[error("Insufficient buffer size. Actual: {0}, required: {1}")]
	InsufficientBufferSize(usize, usize),
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
}
