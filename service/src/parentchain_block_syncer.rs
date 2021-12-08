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

use crate::enclave_account;
use itp_api_client_extensions::{AccountApi, ChainApi};
use itp_enclave_api::{enclave_base::EnclaveBase, sidechain::Sidechain};
use itp_types::SignedBlock;
use log::{error, trace};
use my_node_runtime::{BlockNumber, Header};
use sp_core::sr25519;
use std::cmp::min;
use substrate_api_client::{rpc::WsRpcClient, Api};

const BLOCK_SYNC_BATCH_SIZE: u32 = 1000;

pub(crate) struct ParentchainBlockSyncer {
	api: Api<sr25519::Pair, WsRpcClient>,
}

impl ParentchainBlockSyncer {
	pub fn new(api: Api<sr25519::Pair, WsRpcClient>) -> Self {
		ParentchainBlockSyncer { api }
	}

	/// Fetches the amount of blocks to sync from the parentchain and feeds them to the enclave.
	/// Returns the latest synced block Header.
	///
	pub fn sync_parentchain<E: EnclaveBase + Sidechain>(
		&self,
		enclave_api: &E,
		last_synced_header: Header,
	) -> Header {
		let tee_accountid = enclave_account(enclave_api);
		trace!("Getting current head");
		//unwraps were there before me
		let curr_block: SignedBlock = self.api.last_finalized_block().unwrap().unwrap();
		let curr_block_number = curr_block.block.header.number;

		let mut until_synced_header = last_synced_header;
		loop {
			let block_chunk_to_sync =
				self.get_block_chunk_to_sync(&until_synced_header.number, &curr_block);
			println!("[+] Found {} block(s) to sync", block_chunk_to_sync.len());
			if block_chunk_to_sync.is_empty() {
				return until_synced_header
			}

			let tee_nonce = self.api.get_nonce_of(&tee_accountid).unwrap();
			if let Err(e) = enclave_api.sync_parentchain(block_chunk_to_sync.as_slice(), tee_nonce)
			{
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

	/// gets a list of blocks that need to be synced, ordered from oldest to most recent header
	/// starting from the last synced head until the current head but at most BLOCK_SYNC_BATCH_SIZE.
	fn get_block_chunk_to_sync(
		&self,
		last_synced_head_number: &BlockNumber,
		curr_block: &SignedBlock,
	) -> Vec<SignedBlock> {
		let no_blocks_to_sync = curr_block.block.header.number - last_synced_head_number;
		if no_blocks_to_sync > 1 {
			println!("light client is synced until block: {:?}", last_synced_head_number);
			println!("Last finalized block number: {:?}\n", curr_block.block.header.number);
		}
		if no_blocks_to_sync > BLOCK_SYNC_BATCH_SIZE {
			println!(
				"Remaining blocks to fetch until last synced header: {:?}",
				curr_block.block.header.number - last_synced_head_number
			);
		}

		self.api
			.get_blocks(
				last_synced_head_number + 1,
				min(
					last_synced_head_number + BLOCK_SYNC_BATCH_SIZE,
					curr_block.block.header.number,
				),
			)
			.unwrap()
	}
}
