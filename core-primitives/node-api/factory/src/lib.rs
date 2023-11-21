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

use itp_api_client_extensions::PalletTeerexApi;
use itp_api_client_types::{Request, TungsteniteRpcClient};
use sp_core::sr25519;
use std::marker::PhantomData;

/// Trait to create a node API, based on a node URL and signer.
pub trait CreateNodeApi {
	type Api: PalletTeerexApi;
	fn create_api(&self) -> Result<Self::Api>;
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

pub trait ParentchainApiWrapper {
	type Api: PalletTeerexApi;
	type Client;
	fn new_api(client: Self::Client, signer: sr25519::Pair) -> Result<Self::Api>;
}

/// Node API factory implementation.
pub struct NodeApiFactory<ApiWrapper> {
	node_url: String,
	signer: sr25519::Pair,
	_phantom: PhantomData<ApiWrapper>,
}

impl<ApiWrapper> NodeApiFactory<ApiWrapper> {
	pub fn new(url: String, signer: sr25519::Pair) -> Self {
		NodeApiFactory { node_url: url, signer, _phantom: Default::default() }
	}
}

impl<ApiWrapper> CreateNodeApi for NodeApiFactory<ApiWrapper>
where
	ApiWrapper: ParentchainApiWrapper<Client = TungsteniteRpcClient>,
{
	type Api = ApiWrapper::Api;
	fn create_api(&self) -> Result<Self::Api> {
		let rpc_client = TungsteniteRpcClient::new(self.node_url.as_str(), 5)
			.map_err(NodeApiFactoryError::FailedToCreateRpcClient)?;
		let mut api = ApiWrapper::new_api(rpc_client, self.signer.clone())?;
		Ok(api)
	}
}
