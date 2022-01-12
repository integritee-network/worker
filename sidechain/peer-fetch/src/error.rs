/*
	Copyright 2021 Integritee AG and Supercomputing Systems AG

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

//! Sidechain peer fetch error.

use its_primitives::types::ShardIdentifier;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
	#[error("RPC client error: {0}")]
	RpcClient(#[from] itc_rpc_client::error::Error),
	#[error("Node API error: {0}")]
	NodeApi(#[from] itp_api_client_extensions::ApiClientError),
	#[error("Serialization error: {0}")]
	Serialization(#[from] serde_json::Error),
	#[error("Could not find any peers onchain for shard: {0:?}")]
	NoPeerFoundForShard(ShardIdentifier),
	#[error("JSON RPC error: {0}")]
	JsonRpc(#[from] jsonrpsee::types::Error),
	#[error(transparent)]
	Other(#[from] Box<dyn std::error::Error + Sync + Send + 'static>),
}
