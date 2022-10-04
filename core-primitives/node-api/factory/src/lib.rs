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

use itp_api_client_types::{ParentchainApi, WsRpcClient};
use sp_core::sr25519;

/// Trait to create a node API, based on a node URL and signer.
pub trait CreateNodeApi {
	fn create_api(&self) -> Result<ParentchainApi>;
}

/// Node API factory error.
#[derive(Debug, thiserror::Error)]
pub enum NodeApiFactoryError {
	#[error("Failed to create a node API: {0}")]
	FailedToCreateNodeApi(#[from] itp_api_client_types::ApiClientError),
	#[error(transparent)]
	Other(#[from] Box<dyn std::error::Error + Sync + Send + 'static>),
}

pub type Result<T> = std::result::Result<T, NodeApiFactoryError>;

/// Node API factory implementation.
pub struct NodeApiFactory {
	node_url: String,
	signer: sr25519::Pair,
}

impl NodeApiFactory {
	pub fn new(url: String, signer: sr25519::Pair) -> Self {
		NodeApiFactory { node_url: url, signer }
	}
}

impl CreateNodeApi for NodeApiFactory {
	fn create_api(&self) -> Result<ParentchainApi> {
		ParentchainApi::new(WsRpcClient::new(self.node_url.as_str()))
			.map_err(NodeApiFactoryError::FailedToCreateNodeApi)
			.map(|a| a.set_signer(self.signer.clone()))
	}
}
