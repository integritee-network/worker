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

use super::api_client_types::TargetATip;
use crate::ParentchainRuntimeConfig;
use itp_api_client_types::{Api, TungsteniteRpcClient};
use itp_node_api::node_api_factory::{CreateNodeApi, NodeApiFactoryError, Result};
use sp_core::sr25519;

/// Node API factory implementation.
pub struct TargetANodeApiFactory {
	node_url: String,
	signer: sr25519::Pair,
}

impl TargetANodeApiFactory {
	pub fn new(url: String, signer: sr25519::Pair) -> Self {
		Self { node_url: url, signer }
	}
}

impl CreateNodeApi<ParentchainRuntimeConfig<TargetATip>, TungsteniteRpcClient>
	for TargetANodeApiFactory
{
	fn create_api(
		&self,
	) -> Result<Api<ParentchainRuntimeConfig<TargetATip>, TungsteniteRpcClient>> {
		let rpc_client = TungsteniteRpcClient::new(self.node_url.as_str(), 5)
			.map_err(NodeApiFactoryError::FailedToCreateRpcClient)?;
		let mut api = Api::new(rpc_client).map_err(NodeApiFactoryError::FailedToCreateNodeApi)?;
		api.set_signer(self.signer.clone().into());
		Ok(api)
	}
}
