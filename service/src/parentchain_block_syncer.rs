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

use crate::error::Error;
use itp_enclave_api::{enclave_base::EnclaveBase, sidechain::Sidechain, teerex_api::TeerexApi};
use itp_node_api::api_client::ChainApi;
use itp_types::SignedBlock;
use log::*;
use my_node_runtime::Header;
use sp_runtime::traits::Header as HeaderTrait;
use std::{cmp::min, sync::Arc};

const BLOCK_SYNC_BATCH_SIZE: u32 = 1000;

pub trait SyncParentchainBlocks {
	/// Fetches the parentchainblocks to sync from the parentchain and feeds them to the enclave.
	/// Returns the latest synced block Header.
	fn sync_parentchain(&self, last_synced_header: Header) -> Header;
}
/// Supplies functionality to sync parentchain blocks.
pub(crate) struct ParentchainBlockSyncer<ParentchainApi: ChainApi, EnclaveApi: Sidechain> {
	parentchain_api: ParentchainApi,
	enclave_api: Arc<EnclaveApi>,
}

impl<ParentchainApi, EnclaveApi> ParentchainBlockSyncer<ParentchainApi, EnclaveApi>
where
	ParentchainApi: ChainApi,
	EnclaveApi: Sidechain,
{
	pub fn new(parentchain_api: ParentchainApi, enclave_api: Arc<EnclaveApi>) -> Self {
		ParentchainBlockSyncer { parentchain_api, enclave_api }
	}
}

impl<ParentchainApi, EnclaveApi> SyncParentchainBlocks
	for ParentchainBlockSyncer<ParentchainApi, EnclaveApi>
where
	ParentchainApi: ChainApi,
	EnclaveApi: Sidechain,
{
	fn sync_parentchain(&self, last_synced_header: Header) -> Header {
		trace!("Getting current head");
		let curr_block: SignedBlock = self.parentchain_api.last_finalized_block().unwrap().unwrap();
		let curr_block_number = curr_block.block.header.number;

		let mut until_synced_header = last_synced_header;
		loop {
			let block_chunk_to_sync = self
				.parentchain_api
				.get_blocks(
					until_synced_header.number + 1,
					min(until_synced_header.number + BLOCK_SYNC_BATCH_SIZE, curr_block_number),
				)
				.unwrap();
			println!("[+] Found {} block(s) to sync", block_chunk_to_sync.len());
			if block_chunk_to_sync.is_empty() {
				return until_synced_header
			}

			if let Err(e) = self.enclave_api.sync_parentchain(block_chunk_to_sync.as_slice(), 0) {
				error!("{:?}", e);
				// enclave might not have synced
				return until_synced_header
			};
			until_synced_header = block_chunk_to_sync
				.last()
				.map(|b| b.block.header.clone())
				.expect("Chunk can't be empty; qed");
			println!(
				"Synced {} out of {} finalized parentchain blocks",
				until_synced_header.number, curr_block_number,
			)
		}
	}
}

/// Ensure we're synced up until the parentchain block where we have registered ourselves.
pub(crate) fn import_parentchain_blocks_until_self_registry<
	E: EnclaveBase + TeerexApi + Sidechain,
	ParentchainSyncer: SyncParentchainBlocks,
>(
	enclave_api: Arc<E>,
	parentchain_block_syncer: Arc<ParentchainSyncer>,
	last_synced_header: &Header,
	register_enclave_xt_header: &Header,
) -> Result<Header, Error> {
	info!(
		"We're the first validateer to be registered, syncing parentchain blocks until the one we have registered ourselves on."
	);
	let mut last_synced_header = last_synced_header.clone();

	while last_synced_header.number() < register_enclave_xt_header.number() {
		last_synced_header = parentchain_block_syncer.sync_parentchain(last_synced_header);
	}
	enclave_api.trigger_parentchain_block_import()?;

	Ok(last_synced_header)
}
