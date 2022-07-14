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
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(test, feature(assert_matches))]

#[cfg(all(feature = "std", feature = "sgx"))]
compile_error!("feature \"std\" and feature \"sgx\" cannot be enabled at the same time");

#[cfg(all(not(feature = "std"), feature = "sgx"))]
extern crate sgx_tstd as std;

// re-export module to properly feature gate sgx and regular std environment
#[cfg(all(not(feature = "std"), feature = "sgx"))]
pub mod sgx_reexport_prelude {
	pub use jsonrpc_core_sgx as jsonrpc_core;
	pub use thiserror_sgx as thiserror;
}

#[cfg(all(not(feature = "std"), feature = "sgx"))]
use crate::sgx_reexport_prelude::*;

use crate::rpc_watch_extractor::RpcWatchExtractor;
use codec::{Encode, Error as CodecError};
use itc_tls_websocket_server::error::WebSocketError;
use itp_rpc::RpcResponse;
use itp_types::TrustedOperationStatus;
use serde_json::error::Error as SerdeJsonError;
use sp_runtime::traits;
use std::{boxed::Box, fmt::Debug, vec::Vec};

#[cfg(test)]
mod mocks;

#[cfg(test)]
mod builders;

pub mod response_channel;
pub mod rpc_connection_registry;
pub mod rpc_responder;
pub mod rpc_watch_extractor;
pub mod rpc_ws_handler;

/// General web-socket error type
#[derive(Debug, thiserror::Error)]
pub enum DirectRpcError {
	#[error("Invalid connection hash")]
	InvalidConnectionHash,
	#[error("RPC serialization error: {0}")]
	SerializationError(SerdeJsonError),
	#[error("Web socket error: {0}")]
	WebSocketError(#[from] WebSocketError),
	#[error("Encoding error: {0}")]
	EncodingError(CodecError),
	#[error("Other error: {0}")]
	Other(Box<dyn std::error::Error + Sync + Send + 'static>),
}

pub type DirectRpcResult<T> = Result<T, DirectRpcError>;

/// trait helper to mix-in all necessary traits for a hash
pub trait RpcHash: std::hash::Hash + traits::Member + Encode {}
impl<T: std::hash::Hash + traits::Member + Encode> RpcHash for T {}

/// Registry for RPC connections (i.e. connections that are kept alive to send updates).
pub trait RpcConnectionRegistry: Send + Sync {
	type Hash: RpcHash;
	type Connection: Copy + Debug;

	fn store(&self, hash: Self::Hash, connection: Self::Connection, rpc_response: RpcResponse);

	fn withdraw(&self, hash: &Self::Hash) -> Option<(Self::Connection, RpcResponse)>;
}

/// Sends an RPC response back to the client.
pub trait SendRpcResponse: Send + Sync {
	type Hash: RpcHash;

	fn update_status_event(
		&self,
		hash: Self::Hash,
		status_update: TrustedOperationStatus,
	) -> DirectRpcResult<()>;

	fn send_state(&self, hash: Self::Hash, state_encoded: Vec<u8>) -> DirectRpcResult<()>;
}

/// Determines if a given connection must be watched (i.e. kept alive),
/// based on the information in the RpcResponse.
pub trait DetermineWatch: Send + Sync {
	type Hash: RpcHash;

	fn must_be_watched(&self, rpc_response: &RpcResponse) -> DirectRpcResult<Option<Self::Hash>>;
}

/// Convenience method to create a do_watch extractor.
pub fn create_determine_watch<Hash>() -> RpcWatchExtractor<Hash>
where
	Hash: RpcHash,
{
	RpcWatchExtractor::<Hash>::new()
}
