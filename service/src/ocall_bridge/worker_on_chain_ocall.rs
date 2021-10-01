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

use crate::{
	node_api_factory::CreateNodeApi,
	ocall_bridge::bridge_api::{OCallBridgeError, OCallBridgeResult, WorkerOnChainBridge},
	sidechain_storage::BlockStorage,
	sync_block_gossiper::GossipBlocks,
	utils::hex_encode,
};
use codec::{Decode, Encode};
use itp_types::{WorkerRequest, WorkerResponse};
use its_primitives::types::SignedBlock as SignedSidechainBlock;
use log::*;
use sp_core::storage::StorageKey;
use sp_runtime::OpaqueExtrinsic;
use std::{sync::Arc, vec::Vec};
use substrate_api_client::XtStatus;

pub struct WorkerOnChainOCall<F, S, D> {
	node_api_factory: Arc<F>,
	block_gossiper: Arc<S>,
	block_storage: Arc<D>,
}

impl<F, S, D> WorkerOnChainOCall<F, S, D> {
	pub fn new(node_api_factory: Arc<F>, block_gossiper: Arc<S>, block_storage: Arc<D>) -> Self {
		WorkerOnChainOCall { node_api_factory, block_gossiper, block_storage }
	}
}

impl<F, S, D> WorkerOnChainBridge for WorkerOnChainOCall<F, S, D>
where
	F: CreateNodeApi,
	S: GossipBlocks,
	D: BlockStorage<SignedSidechainBlock>,
{
	fn worker_request(&self, request: Vec<u8>) -> OCallBridgeResult<Vec<u8>> {
		debug!("    Entering ocall_worker_request");

		let requests: Vec<WorkerRequest> = Decode::decode(&mut request.as_slice()).unwrap();
		if requests.is_empty() {
			debug!("requests is empty, returning empty vector");
			return Ok(Vec::<u8>::new().encode())
		}

		let api = self.node_api_factory.create_api();

		let resp: Vec<WorkerResponse<Vec<u8>>> = requests
			.into_iter()
			.map(|req| match req {
				WorkerRequest::ChainStorage(key, hash) => WorkerResponse::ChainStorage(
					key.clone(),
					api.get_opaque_storage_by_key_hash(StorageKey(key.clone()), hash).unwrap(),
					api.get_storage_proof_by_keys(vec![StorageKey(key)], hash).unwrap().map(
						|read_proof| read_proof.proof.into_iter().map(|bytes| bytes.0).collect(),
					),
				),
			})
			.collect();

		let encoded_response: Vec<u8> = resp.encode();

		Ok(encoded_response)
	}

	fn send_block_and_confirmation(
		&self,
		confirmations: Vec<u8>,
		signed_blocks_encoded: Vec<u8>,
	) -> OCallBridgeResult<()> {
		debug!("    Entering ocall_send_block_and_confirmation");

		// TODO: improve error handling, using a mut status is not good design?
		let mut status: OCallBridgeResult<()> = Ok(());
		let api = self.node_api_factory.create_api();

		// send confirmations to layer one
		let confirmation_calls: Vec<OpaqueExtrinsic> =
			match Decode::decode(&mut confirmations.as_slice()) {
				Ok(calls) => calls,
				Err(_) => {
					status = Err(OCallBridgeError::SendBlockAndConfirmation(
						"Could not decode confirmation calls".to_string(),
					));
					Default::default()
				},
			};

		if !confirmation_calls.is_empty() {
			println!("Enclave wants to send {} extrinsics", confirmation_calls.len());
			for call in confirmation_calls.into_iter() {
				api.send_extrinsic(hex_encode(call.encode()), XtStatus::Ready).unwrap();
			}
		}

		// handle blocks
		let signed_blocks: Vec<SignedSidechainBlock> =
			match Decode::decode(&mut signed_blocks_encoded.as_slice()) {
				Ok(blocks) => blocks,
				Err(_) => {
					status = Err(OCallBridgeError::SendBlockAndConfirmation(
						"Could not decode signed blocks".to_string(),
					));
					vec![]
				},
			};

		if !signed_blocks.is_empty() {
			println!("Enclave produced sidechain blocks: {:?}", signed_blocks);
		} else {
			debug!("Enclave did not produce sidechain blocks");
		}

		if let Err(e) = self.block_gossiper.gossip_blocks(signed_blocks.clone()) {
			error!("Error gossiping blocks: {:?}", e);
			// Fixme: returning an error here results in a `HeaderAncestryMismatch` error.
			// status = sgx_status_t::SGX_ERROR_UNEXPECTED;
		}

		if let Err(e) = self.block_storage.store_blocks(signed_blocks) {
			error!("Error storing blocks: {:?}", e);
		}
		status
	}
}

#[cfg(test)]
mod tests {

	use super::*;
	use crate::{
		node_api_factory::MockCreateNodeApi, sidechain_storage::interface::MockBlockStorage,
		sync_block_gossiper::MockGossipBlocks,
	};

	#[test]
	fn given_empty_worker_request_when_submitting_then_return_empty_response() {
		let mock_node_api_factory = Arc::new(MockCreateNodeApi::new());
		let mock_block_gossiper = Arc::new(MockGossipBlocks::new());
		let mock_block_storage = Arc::new(MockBlockStorage::new());

		let on_chain_ocall =
			WorkerOnChainOCall::new(mock_node_api_factory, mock_block_gossiper, mock_block_storage);

		let response = on_chain_ocall.worker_request(Vec::<u8>::new().encode()).unwrap();

		assert!(!response.is_empty()); // the encoded empty vector is not empty
		let decoded_response: Vec<u8> = Decode::decode(&mut response.as_slice()).unwrap();
		assert!(decoded_response.is_empty()); // decode the response, and we get an empty vector again
	}
}
