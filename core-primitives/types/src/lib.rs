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

#![cfg_attr(all(not(target_env = "sgx"), not(feature = "std")), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

use crate::storage::StorageEntry;
use codec::{Decode, Encode};
#[cfg(feature = "sgx")]
use sgx_tstd as std;
use sp_std::vec::Vec;

pub mod parentchain;
pub mod storage;

/// Substrate runtimes provide no string type. Hence, for arbitrary data of varying length the
/// `Vec<u8>` is used. In the polkadot-js the typedef `Text` is used to automatically
/// utf8 decode bytes into a string.
#[cfg(not(feature = "std"))]
pub type PalletString = Vec<u8>;

#[cfg(feature = "std")]
pub type PalletString = String;

pub use sp_core::{crypto::AccountId32 as AccountId, H256};

pub use itp_sgx_runtime_primitives::types::*;

pub type IpfsHash = [u8; 46];
pub type MrEnclave = [u8; 32];

pub type ConfirmCallFn = ([u8; 2], ShardIdentifier, H256, Vec<u8>);
pub type ShieldFundsFn = ([u8; 2], ShardIdentifier, Vec<u8>, Balance);
pub type CallWorkerFn = ([u8; 2], Request);

use enclave_bridge_primitives::ShardSignerStatus as ShardSignerStatusGen;
pub type ShardSignerStatus = ShardSignerStatusGen<AccountId, BlockNumber>;
pub type ShardStatus = Vec<ShardSignerStatus>;
pub use enclave_bridge_primitives::Request;
pub use teerex_primitives::{
	EnclaveFingerprint, MultiEnclave, SgxBuildMode, SgxEnclave, SgxReportData, SgxStatus,
};
pub type Enclave = MultiEnclave<Vec<u8>>;

/// Simple blob to hold an encoded call
#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct OpaqueCall(pub Vec<u8>);

impl OpaqueCall {
	/// Convert call tuple to an `OpaqueCall`.
	pub fn from_tuple<C: Encode>(call: &C) -> Self {
		OpaqueCall(call.encode())
	}
}

impl Encode for OpaqueCall {
	fn encode(&self) -> Vec<u8> {
		self.0.clone()
	}
}

#[derive(Debug, Clone, PartialEq, Encode, Decode)]
pub enum DirectRequestStatus {
	/// Direct request was successfully executed
	Ok,
	/// Trusted Call Status
	TrustedOperationStatus(TrustedOperationStatus),
	/// Direct request could not be executed
	Error,
}

#[derive(Debug, Clone, PartialEq, Encode, Decode)]
pub enum TrustedOperationStatus {
	/// TrustedOperation is submitted to the top pool.
	Submitted,
	/// TrustedOperation is part of the future queue.
	Future,
	/// TrustedOperation is part of the ready queue.
	Ready,
	/// The operation has been broadcast to the given peers.
	Broadcast,
	/// TrustedOperation has been included in block with given hash.
	InSidechainBlock(BlockHash),
	/// The block this operation was included in has been retracted.
	Retracted,
	/// Maximum number of finality watchers has been reached,
	/// old watchers are being removed.
	FinalityTimeout,
	/// TrustedOperation has been finalized by a finality-gadget, e.g GRANDPA
	Finalized,
	/// TrustedOperation has been replaced in the pool, by another operation
	/// that provides the same tags. (e.g. same (sender, nonce)).
	Usurped,
	/// TrustedOperation has been dropped from the pool because of the limit.
	Dropped,
	/// TrustedOperation is no longer valid in the current state.
	Invalid,
}

#[derive(Encode, Decode, Clone, Debug, PartialEq)]
pub enum WorkerRequest {
	ChainStorage(Vec<u8>, Option<BlockHash>), // (storage_key, at_block)
}

#[derive(Encode, Decode, Clone, Debug, PartialEq)]
pub enum WorkerResponse<V: Encode + Decode> {
	ChainStorage(Vec<u8>, Option<V>, Option<Vec<Vec<u8>>>), // (storage_key, storage_value, storage_proof)
}

impl From<WorkerResponse<Vec<u8>>> for StorageEntry<Vec<u8>> {
	fn from(response: WorkerResponse<Vec<u8>>) -> Self {
		match response {
			WorkerResponse::ChainStorage(key, value, proof) => StorageEntry { key, value, proof },
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn opaque_call_encodes_correctly() {
		let call_tuple = ([1u8, 2u8], 5u8);
		let call = OpaqueCall::from_tuple(&call_tuple);
		assert_eq!(call.encode(), call_tuple.encode())
	}
}
