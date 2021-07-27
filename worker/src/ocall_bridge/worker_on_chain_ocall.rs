/*
	Copyright 2019 Supercomputing Systems AG
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
	sync_block_gossiper::GossipBlocks,
	utils::hex_encode,
};
use codec::{Decode, Encode};
use log::*;
use sp_core::storage::StorageKey;
use std::{
	sync::{mpsc::channel, Arc},
	vec::Vec,
};
use substrate_api_client::XtStatus;
use substratee_worker_primitives::{
	block::SignedBlock as SignedSidechainBlock, WorkerRequest, WorkerResponse,
};

pub struct WorkerOnChainOCall<F, S> {
	node_api_factory: Arc<F>,
	block_gossiper: Arc<S>,
}

impl<F, S> WorkerOnChainOCall<F, S> {
	pub fn new(node_api_factory: Arc<F>, block_gossiper: Arc<S>) -> Self {
		WorkerOnChainOCall { node_api_factory, block_gossiper }
	}
}

impl<F, S> WorkerOnChainBridge for WorkerOnChainOCall<F, S>
where
	F: CreateNodeApi,
	S: GossipBlocks,
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
		signed_blocks: Vec<u8>,
	) -> OCallBridgeResult<()> {
		debug!("    Entering ocall_send_block_and_confirmation");

		// TODO: improve error handling, using a mut status is not good design?
		let mut status: OCallBridgeResult<()> = Ok(());
		let api = self.node_api_factory.create_api();

		// send confirmations to layer one
		let confirmation_calls: Vec<Vec<u8>> = match Decode::decode(&mut confirmations.as_slice()) {
			Ok(calls) => calls,
			Err(_) => {
				status = Err(OCallBridgeError::SendBlockAndConfirmation(
					"Could not decode confirmation calls".to_string(),
				));
				vec![vec![]]
			},
		};

		if !confirmation_calls.is_empty() {
			println!("Enclave wants to send {} extrinsics", confirmation_calls.len());
			for call in confirmation_calls.into_iter() {
				api.send_extrinsic(hex_encode(call), XtStatus::Ready).unwrap();
			}
			// await next block to avoid #37
			let (events_in, events_out) = channel();
			api.subscribe_events(events_in).unwrap();
			let _ = events_out.recv().unwrap();
			let _ = events_out.recv().unwrap();
			// FIXME: we should unsubscribe here or the thread will throw a SendError because the channel is destroyed
		}

		// handle blocks
		let signed_blocks: Vec<SignedSidechainBlock> =
			match Decode::decode(&mut signed_blocks.as_slice()) {
				Ok(blocks) => blocks,
				Err(_) => {
					status = Err(OCallBridgeError::SendBlockAndConfirmation(
						"Could not decode signed blocks".to_string(),
					));
					vec![]
				},
			};

		println! {"Received blocks: {:?}", signed_blocks};

		if let Err(e) = self.block_gossiper.gossip_blocks(signed_blocks) {
			error!("Error gossiping blocks: {:?}", e);
			// Fixme: returning an error here results in a `HeaderAncestryMismatch` error.
			// status = sgx_status_t::SGX_ERROR_UNEXPECTED;
		}
		// TODO: M8.3: Store blocks

		status
	}
}

#[cfg(test)]
mod tests {

	use super::*;
	use crate::{node_api_factory::MockCreateNodeApi, sync_block_gossiper::MockGossipBlocks};

	#[test]
	fn given_empty_worker_request_when_submitting_then_return_empty_response() {
		let mock_node_api_factory = Arc::new(MockCreateNodeApi::new());
		let mock_block_gossiper = Arc::new(MockGossipBlocks::new());

		let on_chain_ocall = WorkerOnChainOCall::new(mock_node_api_factory, mock_block_gossiper);

		let response = on_chain_ocall.worker_request(Vec::<u8>::new().encode()).unwrap();

		assert!(!response.is_empty()); // the encoded empty vector is not empty
		let decoded_response: Vec<u8> = Decode::decode(&mut response.as_slice()).unwrap();
		assert!(decoded_response.is_empty()); // decode the response, and we get an empty vector again
	}
}
