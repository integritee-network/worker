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

use itp_api_client_types::{JsonrpseeClient, ParentchainApi, ParentchainExtrinsicSigner};
use sp_core::sr25519;
use std::thread;
use tokio::task::JoinError;

/// Trait to create a node API, based on a node URL and signer.
pub trait CreateNodeApi {
	fn create_api(&self) -> Result<ParentchainApi>;
}

/// Node API factory error.
#[derive(Debug, thiserror::Error)]
pub enum NodeApiFactoryError {
	#[error("Could not connect to node with rpc client")]
	FailedToCreateRpcClient(itp_api_client_types::RpcClientError),
	#[error("Failed to create a node API")]
	FailedToCreateNodeApi(itp_api_client_types::ApiClientError),
	#[error(transparent)]
	Other(#[from] Box<dyn std::error::Error + Sync + Send + 'static>),
}

impl From<itp_api_client_types::RpcClientError> for NodeApiFactoryError {
	fn from(error: itp_api_client_types::RpcClientError) -> Self {
		NodeApiFactoryError::FailedToCreateRpcClient(error)
	}
}

impl From<itp_api_client_types::ApiClientError> for NodeApiFactoryError {
	fn from(error: itp_api_client_types::ApiClientError) -> Self {
		NodeApiFactoryError::FailedToCreateNodeApi(error)
	}
}

pub type Result<T> = std::result::Result<T, NodeApiFactoryError>;

/// Node API factory implementation.
pub struct NodeApiFactory {
	node_url: String,
	signer: ParentchainExtrinsicSigner,
}

impl NodeApiFactory {
	pub fn new(url: String, signer: sr25519::Pair) -> Self {
		NodeApiFactory { node_url: url, signer: ParentchainExtrinsicSigner::new(signer) }
	}

	async fn get_json_rpsee_client_from_new_thread_helper(node_url: String) -> JsonrpseeClient {
		tokio::task::spawn_blocking(move || {
			let rpc_client: JsonrpseeClient = JsonrpseeClient::new(node_url.as_str())
				.map_err(NodeApiFactoryError::FailedToCreateRpcClient)
				.expect("Failed to create RPC client");
			rpc_client
		})
		.await
		.expect("Failed to get JsonrpseeClient in get_json_rpsee_client_from_new_thread_helper()")
	}

	// This uses `block_on` inside to call an `async` constructor, which can have unintended consenquences (e.g., nested `block_on` panics out of the blue)
	// By moving it to a seperate thread, this should help with the nested `block_on` panic, but this is just a workaround.
	fn get_json_rpsee_client_from_new_thread(node_url: String) -> JsonrpseeClient {
		let handle =
			thread::spawn(move || Self::get_json_rpsee_client_from_new_thread_helper(node_url));

		futures::executor::block_on(handle.join().expect("Failed to create RPC client"))
	}
}

impl CreateNodeApi for NodeApiFactory {
	fn create_api(&self) -> Result<ParentchainApi> {
		// This is a rather ugly workaround, please see the function for explanation.
		let node_url = self.node_url.clone();

		let handle = thread::spawn(move || Self::get_json_rpsee_client_from_new_thread(node_url));
		let rpc_client = handle.join().expect("Failed to create RPC client, outer thread");

		let mut api =
			ParentchainApi::new(rpc_client).map_err(NodeApiFactoryError::FailedToCreateNodeApi)?;
		api.set_signer(self.signer.clone());
		Ok(api)
	}
}
