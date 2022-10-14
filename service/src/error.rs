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

use codec::Error as CodecError;
use itp_types::ShardIdentifier;
use substrate_api_client::ApiClientError;

pub type ServiceResult<T> = Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
	#[error("{0}")]
	Codec(#[from] CodecError),
	#[error("{0}")]
	ApiClient(#[from] ApiClientError),
	#[error("Node API terminated subscription unexpectedly: {0}")]
	ApiSubscriptionDisconnected(#[from] std::sync::mpsc::RecvError),
	#[error("Enclave API error: {0}")]
	EnclaveApi(#[from] itp_enclave_api::error::Error),
	#[error("Trusted Rpc Client error: {0}")]
	TrustedRpcClient(#[from] itc_rpc_client::error::Error),
	#[error("{0}")]
	JsonRpSeeClient(#[from] jsonrpsee::types::Error),
	#[error("{0}")]
	Serialization(#[from] serde_json::Error),
	#[error("{0}")]
	FromUtf8(#[from] std::string::FromUtf8Error),
	#[error("Application setup error!")]
	ApplicationSetup,
	#[error("Failed to find any peer worker")]
	NoPeerWorkerFound,
	#[error("No worker for shard {0} found on parentchain")]
	NoWorkerForShardFound(ShardIdentifier),
	#[error("Returned empty parentchain block vec after sync, even though there have been blocks given as input")]
	EmptyChunk,
	#[error("Could not find genesis header of the parentchain")]
	MissingGenesisHeader,
	#[error("Could not find last finalized block of the parentchain")]
	MissingLastFinalizedBlock,
	#[error("{0}")]
	Custom(Box<dyn std::error::Error + Sync + Send + 'static>),
}
