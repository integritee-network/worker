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

use lazy_static::lazy_static;
use parking_lot::RwLock;
use sp_core::sr25519;
use substrate_api_client::{rpc::WsRpcClient, Api};

#[cfg(test)]
use mockall::predicate::*;
#[cfg(test)]
use mockall::*;

lazy_static! {
	// todo: replace with &str, but use &str in api-client first
	static ref NODE_URL: RwLock<String> = RwLock::new("".to_string());
}

/// trait to create a node API, based on a node URL
#[cfg_attr(test, automock)]
pub trait CreateNodeApi {
	fn create_api(&self) -> Api<sr25519::Pair, WsRpcClient>;
}

pub struct GlobalUrlNodeApiFactory;

impl GlobalUrlNodeApiFactory {
	/// creates a new instance and initializes the global state
	pub fn new(url: String) -> Self {
		GlobalUrlNodeApiFactory::write_node_url(url);

		GlobalUrlNodeApiFactory
	}

	fn write_node_url(url: String) {
		*NODE_URL.write() = url;
	}

	fn read_node_url() -> String {
		NODE_URL.read().clone()
	}
}

impl CreateNodeApi for GlobalUrlNodeApiFactory {
	fn create_api(&self) -> Api<sr25519::Pair, WsRpcClient> {
		Api::<sr25519::Pair, WsRpcClient>::new(WsRpcClient::new(
			&GlobalUrlNodeApiFactory::read_node_url(),
		))
		.unwrap()
	}
}
