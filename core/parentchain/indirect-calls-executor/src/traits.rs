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
	) -> Result<OpaqueCall>
	where
		ParentchainBlock: ParentchainBlockTrait<Hash = H256>;

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
	fn execute(&self, executor: &E) -> Result<()>;
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
