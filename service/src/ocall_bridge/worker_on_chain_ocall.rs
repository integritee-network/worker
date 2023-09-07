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

use crate::ocall_bridge::bridge_api::{OCallBridgeError, OCallBridgeResult, WorkerOnChainBridge};
use codec::{Decode, Encode};
use itp_api_client_types::ParentchainApi;
use itp_node_api::node_api_factory::CreateNodeApi;
use itp_types::{parentchain::ParentchainId, WorkerRequest, WorkerResponse};
use log::*;
use sp_runtime::OpaqueExtrinsic;
use std::{sync::Arc, vec::Vec};
use substrate_api_client::{serde_impls::StorageKey, GetStorage, SubmitExtrinsic};

pub struct WorkerOnChainOCall<F> {
	integritee_api_factory: Arc<F>,
	target_a_parentchain_api_factory: Option<Arc<F>>,
}

impl<F> WorkerOnChainOCall<F> {
	pub fn new(
		integritee_api_factory: Arc<F>,
		target_a_parentchain_api_factory: Option<Arc<F>>,
	) -> Self {
		WorkerOnChainOCall { integritee_api_factory, target_a_parentchain_api_factory }
	}
}

impl<F: CreateNodeApi> WorkerOnChainOCall<F> {
	pub fn create_api(&self, parentchain_id: ParentchainId) -> OCallBridgeResult<ParentchainApi> {
		Ok(match parentchain_id {
			ParentchainId::Integritee => self.integritee_api_factory.create_api()?,
			ParentchainId::TargetA => self
				.target_a_parentchain_api_factory
				.as_ref()
				.ok_or(OCallBridgeError::TargetAParentchainNotInitialized)
				.and_then(|f| f.create_api().map_err(Into::into))?,
		})
	}
}

impl<F> WorkerOnChainBridge for WorkerOnChainOCall<F>
where
	F: CreateNodeApi,
{
	fn worker_request(
		&self,
		request: Vec<u8>,
		parentchain_id: Vec<u8>,
	) -> OCallBridgeResult<Vec<u8>> {
		debug!("    Entering ocall_worker_request");

		let requests: Vec<WorkerRequest> = Decode::decode(&mut request.as_slice())?;
		if requests.is_empty() {
			debug!("requests is empty, returning empty vector");
			return Ok(Vec::<u8>::new().encode())
		}

		let parentchain_id = ParentchainId::decode(&mut parentchain_id.as_slice())?;

		let api = self.create_api(parentchain_id)?;

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

	fn send_to_parentchain(
		&self,
		extrinsics_encoded: Vec<u8>,
		parentchain_id: Vec<u8>,
	) -> OCallBridgeResult<()> {
		// TODO: improve error handling, using a mut status is not good design?
		let mut status: OCallBridgeResult<()> = Ok(());

		let extrinsics: Vec<OpaqueExtrinsic> =
			match Decode::decode(&mut extrinsics_encoded.as_slice()) {
				Ok(calls) => calls,
				Err(_) => {
					status = Err(OCallBridgeError::SendExtrinsicsToParentchain(
						"Could not decode extrinsics".to_string(),
					));
					Default::default()
				},
			};

		if !extrinsics.is_empty() {
			let parentchain_id = ParentchainId::decode(&mut parentchain_id.as_slice())?;
			debug!(
				"Enclave wants to send {} extrinsics to parentchain: {:?}",
				extrinsics.len(),
				parentchain_id
			);
			let api = self.create_api(parentchain_id)?;
			for call in extrinsics.into_iter() {
				if let Err(e) = api.submit_opaque_extrinsic(call.encode().into()) {
					error!(
						"Could not send extrinsic to node: {:?}, error: {:?}",
						serde_json::to_string(&call),
						e
					);
				}
			}
		}

		status
	}
}

#[cfg(test)]
mod tests {

	use super::*;
	use itp_node_api::{
		api_client::ParentchainApi,
		node_api_factory::{CreateNodeApi, Result as NodeApiResult},
	};
	use mockall::mock;

	#[test]
	fn given_empty_worker_request_when_submitting_then_return_empty_response() {
		mock! {
			NodeApiFactory {}
			impl CreateNodeApi for NodeApiFactory {
				fn create_api(&self) -> NodeApiResult<ParentchainApi>;
			}
		}

		let mock_node_api_factory = Arc::new(MockNodeApiFactory::new());

		let on_chain_ocall = WorkerOnChainOCall::new(mock_node_api_factory, None);

		let response = on_chain_ocall
			.worker_request(Vec::<u8>::new().encode(), ParentchainId::Integritee.encode())
			.unwrap();

		assert!(!response.is_empty()); // the encoded empty vector is not empty
		let decoded_response: Vec<u8> = Decode::decode(&mut response.as_slice()).unwrap();
		assert!(decoded_response.is_empty()); // decode the response, and we get an empty vector again
	}
}
