/*
	Copyright 2021 Integritee AG and Supercomputing Systems AG
	Copyright (C) 2017-2019 Baidu, Inc. All Rights Reserved.

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

use crate::ocall_bridge::bridge_api::{Bridge, SidechainBridge};
use itp_utils::write_slice_and_whitespace_pad;
use log::*;
use sgx_types::sgx_status_t;
use std::{slice, sync::Arc};

/// # Safety
///
/// FFI are always unsafe
#[no_mangle]
pub unsafe extern "C" fn ocall_fetch_sidechain_blocks_from_peer(
	last_imported_block_hash_ptr: *const u8,
	last_imported_block_hash_size: u32,
	maybe_until_block_hash_ptr: *const u8,
	maybe_until_block_hash_size: u32,
	shard_identifier_ptr: *const u8,
	shard_identifier_size: u32,
	sidechain_blocks_ptr: *mut u8,
	sidechain_blocks_size: u32,
) -> sgx_status_t {
	fetch_sidechain_blocks_from_peer(
		last_imported_block_hash_ptr,
		last_imported_block_hash_size,
		maybe_until_block_hash_ptr,
		maybe_until_block_hash_size,
		shard_identifier_ptr,
		shard_identifier_size,
		sidechain_blocks_ptr,
		sidechain_blocks_size,
		Bridge::get_sidechain_api(),
	)
}

#[allow(clippy::too_many_arguments)]
fn fetch_sidechain_blocks_from_peer(
	last_imported_block_hash_ptr: *const u8,
	last_imported_block_hash_size: u32,
	maybe_until_block_hash_ptr: *const u8,
	maybe_until_block_hash_size: u32,
	shard_identifier_ptr: *const u8,
	shard_identifier_size: u32,
	sidechain_blocks_ptr: *mut u8,
	sidechain_blocks_size: u32,
	sidechain_api: Arc<dyn SidechainBridge>,
) -> sgx_status_t {
	let last_imported_block_hash_encoded = unsafe {
		Vec::from(slice::from_raw_parts(
			last_imported_block_hash_ptr,
			last_imported_block_hash_size as usize,
		))
	};
	let maybe_until_block_hash = unsafe {
		Vec::from(slice::from_raw_parts(
			maybe_until_block_hash_ptr,
			maybe_until_block_hash_size as usize,
		))
	};
	let shard_identifier_encoded = unsafe {
		Vec::from(slice::from_raw_parts(shard_identifier_ptr, shard_identifier_size as usize))
	};

	let sidechain_blocks_encoded = match sidechain_api.fetch_sidechain_blocks_from_peer(
		last_imported_block_hash_encoded,
		maybe_until_block_hash,
		shard_identifier_encoded,
	) {
		Ok(r) => r,
		Err(e) => {
			error!("fetch sidechain blocks from peer failed: {:?}", e);
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	};

	let sidechain_blocks_encoded_slice =
		unsafe { slice::from_raw_parts_mut(sidechain_blocks_ptr, sidechain_blocks_size as usize) };
	if let Err(e) =
		write_slice_and_whitespace_pad(sidechain_blocks_encoded_slice, sidechain_blocks_encoded)
	{
		error!("Failed to transfer encoded sidechain blocks to o-call buffer: {:?}", e);
		return sgx_status_t::SGX_ERROR_UNEXPECTED
	}

	sgx_status_t::SGX_SUCCESS
}

#[cfg(test)]
mod tests {

	use super::*;
	use crate::ocall_bridge::test::mocks::sidechain_bridge_mock::SidechainBridgeMock;
	use codec::{Decode, Encode};
	use its_primitives::types::block::SignedBlock;
	use its_test::sidechain_block_builder::{SidechainBlockBuilder, SidechainBlockBuilderTrait};
	use primitive_types::H256;

	#[test]
	fn fetch_sidechain_blocks_from_peer_works() {
		let sidechain_blocks = vec![
			SidechainBlockBuilder::random().build_signed(),
			SidechainBlockBuilder::random().build_signed(),
		];

		let sidechain_bridge_mock =
			Arc::new(SidechainBridgeMock::default().with_peer_blocks(sidechain_blocks.encode()));

		let last_known_block_hash = H256::random();
		let shard_identifier = H256::random();
		let mut block_buffer = vec![0; 16 * 4096];

		let result = call_fetch_sidechain_blocks_from_peer(
			last_known_block_hash,
			None,
			shard_identifier,
			&mut block_buffer,
			sidechain_bridge_mock,
		);

		let decoded_blocks: Vec<SignedBlock> =
			Decode::decode(&mut block_buffer.as_slice()).unwrap();

		assert_eq!(result, sgx_status_t::SGX_SUCCESS);
		assert_eq!(sidechain_blocks, decoded_blocks);
	}

	#[test]
	fn returns_error_if_buffer_is_too_small() {
		let sidechain_blocks = vec![
			SidechainBlockBuilder::random().build_signed(),
			SidechainBlockBuilder::random().build_signed(),
			SidechainBlockBuilder::random().build_signed(),
			SidechainBlockBuilder::random().build_signed(),
		];

		let sidechain_bridge_mock =
			Arc::new(SidechainBridgeMock::default().with_peer_blocks(sidechain_blocks.encode()));

		let last_known_block_hash = H256::random();
		let shard_identifier = H256::random();
		let mut block_buffer = vec![0; 16]; // way too small to hold the encoded blocks

		let result = call_fetch_sidechain_blocks_from_peer(
			last_known_block_hash,
			None,
			shard_identifier,
			&mut block_buffer,
			sidechain_bridge_mock,
		);

		assert_eq!(result, sgx_status_t::SGX_ERROR_UNEXPECTED);
	}

	fn call_fetch_sidechain_blocks_from_peer(
		last_imported_block_hash: H256,
		maybe_until_block_hash: Option<H256>,
		shard_identifier: H256,
		buffer: &mut Vec<u8>,
		sidechain_bridge: Arc<dyn SidechainBridge>,
	) -> sgx_status_t {
		let last_imported_block_hash_encoded = last_imported_block_hash.encode();
		let maybe_until_block_hash_encoded = maybe_until_block_hash.encode();
		let shard_identifier_encoded = shard_identifier.encode();

		fetch_sidechain_blocks_from_peer(
			last_imported_block_hash_encoded.as_ptr(),
			last_imported_block_hash_encoded.len() as u32,
			maybe_until_block_hash_encoded.as_ptr(),
			maybe_until_block_hash_encoded.len() as u32,
			shard_identifier_encoded.as_ptr(),
			shard_identifier_encoded.len() as u32,
			buffer.as_mut_ptr(),
			buffer.len() as u32,
			sidechain_bridge,
		)
	}
}
