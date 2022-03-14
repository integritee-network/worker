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

use crate::{error::Result, TopPoolOperationHandler};
use ita_stf::TrustedCallSigned;
use itp_stf_executor::traits::{StateUpdateProposer, StfExecuteTimedGettersBatch};
use itp_types::H256;
use its_primitives::traits::{
	Block as SidechainBlockTrait, ShardIdentifierFor, SignedBlock as SignedSidechainBlockTrait,
};
use its_state::{SidechainState, SidechainSystemExt, StateHash};
use its_top_pool_rpc_author::traits::{AuthorApi, OnBlockImported, SendState};
use log::*;
use sgx_externalities::SgxExternalitiesTrait;
use sp_runtime::{traits::Block as ParentchainBlockTrait, MultiSignature};
use std::{vec, vec::Vec};

// Reexport since it's part of this API.
pub use itp_stf_executor::ExecutedOperation;

/// Interface to the trusted calls within the top pool
pub trait TopPoolCallOperator<
	ParentchainBlock: ParentchainBlockTrait,
	SignedSidechainBlock: SignedSidechainBlockTrait,
>
{
	/// Retrieves trusted calls from the top pool.
	fn get_trusted_calls(
		&self,
		shard: &ShardIdentifierFor<SignedSidechainBlock>,
	) -> Result<Vec<TrustedCallSigned>>;

	/// Removes the given trusted calls from the top pool.
	/// Returns all hashes that were NOT successfully removed.
	fn remove_calls_from_pool(
		&self,
		shard: &ShardIdentifierFor<SignedSidechainBlock>,
		executed_calls: Vec<ExecutedOperation>,
	) -> Vec<ExecutedOperation>;

	// Notify pool about block import for status updates
	fn on_block_imported(&self, block: &SignedSidechainBlock::Block);
}

impl<ParentchainBlock, SignedSidechainBlock, RpcAuthor, StfExecutor>
	TopPoolCallOperator<ParentchainBlock, SignedSidechainBlock>
	for TopPoolOperationHandler<ParentchainBlock, SignedSidechainBlock, RpcAuthor, StfExecutor>
where
	ParentchainBlock: ParentchainBlockTrait<Hash = H256>,
	SignedSidechainBlock:
		SignedSidechainBlockTrait<Public = sp_core::ed25519::Public, Signature = MultiSignature>,
	SignedSidechainBlock::Block:
		SidechainBlockTrait<ShardIdentifier = H256, Public = sp_core::ed25519::Public>,
	RpcAuthor: AuthorApi<H256, ParentchainBlock::Hash>
		+ OnBlockImported<Hash = ParentchainBlock::Hash>
		+ SendState<Hash = ParentchainBlock::Hash>,
	StfExecutor: StateUpdateProposer + StfExecuteTimedGettersBatch,
	<StfExecutor as StateUpdateProposer>::Externalities:
		SgxExternalitiesTrait + SidechainState + SidechainSystemExt + StateHash,
{
	fn get_trusted_calls(
		&self,
		shard: &ShardIdentifierFor<SignedSidechainBlock>,
	) -> Result<Vec<TrustedCallSigned>> {
		Ok(self.rpc_author.get_pending_tops_separated(*shard)?.0)
	}

	fn remove_calls_from_pool(
		&self,
		shard: &ShardIdentifierFor<SignedSidechainBlock>,
		executed_calls: Vec<ExecutedOperation>,
	) -> Vec<ExecutedOperation> {
		let mut failed_to_remove = Vec::new();
		for executed_call in executed_calls {
			if let Err(e) = self.rpc_author.remove_top(
				vec![executed_call.trusted_operation_or_hash.clone()],
				*shard,
				executed_call.is_success(),
			) {
				// We don't want to return here before all calls have been iterated through,
				// hence only throwing an error log and push to `failed_to_remove` vec.
				error!("Error removing trusted call from top pool: Error: {:?}", e);
				failed_to_remove.push(executed_call);
			}
		}
		failed_to_remove
	}

	fn on_block_imported(&self, block: &SignedSidechainBlock::Block) {
		self.rpc_author.on_block_imported(block.signed_top_hashes(), block.hash());
	}
}
