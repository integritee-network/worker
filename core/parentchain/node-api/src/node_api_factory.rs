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

use crate::error::{Error, Result};
use sp_core::sr25519;
use substrate_api_client::{rpc::WsRpcClient, Api};

#[cfg(test)]
use mockall::predicate::*;
#[cfg(test)]
use mockall::*;

/// trait to create a node API, based on a node URL
#[cfg_attr(test, automock)]
pub trait CreateNodeApi {
	fn create_api(&self) -> Result<Api<sr25519::Pair, WsRpcClient>>;
}

pub struct NodeApiFactory {
	node_url: String,
	signer: sr25519::Pair,
}

impl NodeApiFactory {
	/// creates a new instance and initializes the global state
	pub fn new(url: String, signer: sr25519::Pair) -> Self {
		NodeApiFactory { node_url: url, signer }
	}
}

impl CreateNodeApi for NodeApiFactory {
	fn create_api(&self) -> Result<Api<sr25519::Pair, WsRpcClient>> {
		Api::<sr25519::Pair, WsRpcClient>::new(WsRpcClient::new(self.node_url.as_str()))
			.map_err(Error::FailedToCreateNodeApi)
			.map(|a| a.set_signer(self.signer.clone()))
	}
}
