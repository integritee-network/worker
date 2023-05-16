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

use crate::error::Result;
use ita_stf::{TrustedCall, TrustedCallSigned};
use itp_stf_primitives::types::AccountId;
use itp_types::{OpaqueCall, ShardIdentifier, H256};
use sp_runtime::traits::{Block as ParentchainBlockTrait, Header};
use std::vec::Vec;

/// Trait to execute the indirect calls found in the extrinsics of a block.
pub trait ExecuteIndirectCalls {
	/// Scans blocks for extrinsics that ask the enclave to execute some actions.
	/// Executes indirect invocation calls, including shielding and unshielding calls.
	/// Returns all unshielding call confirmations as opaque calls and the hashes of executed shielding calls.
	fn execute_indirect_calls_in_extrinsics<ParentchainBlock>(
		&self,
		block: &ParentchainBlock,
		events: &[u8],
	) -> Result<OpaqueCall>
	where
		ParentchainBlock: ParentchainBlockTrait<Hash = H256>;

	/// Creates a processed_parentchain_block extrinsic for a given parentchain block hash and the merkle executed extrinsics.
	///
	/// Calculates the merkle root of the extrinsics. In case no extrinsics are supplied, the root will be a hash filled with zeros.
	fn create_processed_parentchain_block_call<ParentchainBlock>(
		&self,
		block_hash: H256,
		extrinsics: Vec<H256>,
		block_number: <<ParentchainBlock as ParentchainBlockTrait>::Header as Header>::Number,
	) -> Result<OpaqueCall>
	where
		ParentchainBlock: ParentchainBlockTrait<Hash = H256>;
}

/// Trait that should be implemented on indirect calls to be executed.
pub trait IndirectDispatch<E: IndirectExecutor> {
	fn dispatch(&self, executor: &E) -> Result<()>;
}

/// Trait to be implemented on the executor to serve helper methods of the executor
/// to the `IndirectDispatch` implementation.
pub trait IndirectExecutor {
	fn submit_trusted_call(&self, shard: ShardIdentifier, encrypted_trusted_call: Vec<u8>);

	fn decrypt(&self, encrypted: &[u8]) -> Result<Vec<u8>>;

	fn encrypt(&self, value: &[u8]) -> Result<Vec<u8>>;

	fn get_enclave_account(&self) -> Result<AccountId>;

	fn sign_call_with_self(
		&self,
		trusted_call: &TrustedCall,
		shard: &ShardIdentifier,
	) -> Result<TrustedCallSigned>;
}
