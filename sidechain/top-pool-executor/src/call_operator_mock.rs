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

//! Call operator mock implementation.

use crate::{
	call_operator::{ExecutedOperation, TopPoolCallOperator},
	error::Result,
};
use core::marker::PhantomData;
use ita_stf::{hash::TrustedOperationOrHash, TrustedCallSigned};
use its_primitives::traits::{Block, ShardIdentifierFor, SignedBlock as SignedSidechainBlockTrait};
use sp_runtime::traits::Block as ParentchainBlockTrait;
use std::{collections::HashMap, sync::RwLock};

pub struct TopPoolCallOperatorMock<ParentchainBlock, SignedSidechainBlock>
where
	ParentchainBlock: ParentchainBlockTrait,
	SignedSidechainBlock: SignedSidechainBlockTrait,
{
	trusted_calls: HashMap<ShardIdentifierFor<SignedSidechainBlock>, Vec<TrustedCallSigned>>,
	remove_calls_invoked:
		RwLock<Vec<(ShardIdentifierFor<SignedSidechainBlock>, Vec<ExecutedOperation>)>>,
	_phantom: PhantomData<ParentchainBlock>,
}

impl<ParentchainBlock, SignedSidechainBlock> Default
	for TopPoolCallOperatorMock<ParentchainBlock, SignedSidechainBlock>
where
	ParentchainBlock: ParentchainBlockTrait,
	SignedSidechainBlock: SignedSidechainBlockTrait,
{
	fn default() -> Self {
		TopPoolCallOperatorMock {
			trusted_calls: Default::default(),
			remove_calls_invoked: Default::default(),
			_phantom: Default::default(),
		}
	}
}

impl<ParentchainBlock, SignedSidechainBlock>
	TopPoolCallOperatorMock<ParentchainBlock, SignedSidechainBlock>
where
	ParentchainBlock: ParentchainBlockTrait,
	SignedSidechainBlock: SignedSidechainBlockTrait,
{
	pub fn add_trusted_calls(
		&mut self,
		shard: ShardIdentifierFor<SignedSidechainBlock>,
		trusted_calls: Vec<TrustedCallSigned>,
	) {
		self.trusted_calls.insert(shard, trusted_calls);
	}

	pub fn remove_calls_invoked(
		&self,
	) -> Vec<(ShardIdentifierFor<SignedSidechainBlock>, Vec<ExecutedOperation>)> {
		self.remove_calls_invoked.read().unwrap().clone()
	}
}

impl<ParentchainBlock, SignedSidechainBlock>
	TopPoolCallOperator<ParentchainBlock, SignedSidechainBlock>
	for TopPoolCallOperatorMock<ParentchainBlock, SignedSidechainBlock>
where
	ParentchainBlock: ParentchainBlockTrait,
	SignedSidechainBlock: SignedSidechainBlockTrait,
{
	fn get_trusted_calls(
		&self,
		shard: &ShardIdentifierFor<SignedSidechainBlock>,
	) -> Result<Vec<TrustedCallSigned>> {
		Ok(self.trusted_calls.get(shard).map(|v| v.clone()).unwrap_or_default())
	}

	fn remove_calls_from_pool(
		&self,
		shard: &ShardIdentifierFor<SignedSidechainBlock>,
		calls: Vec<ExecutedOperation>,
	) -> Vec<ExecutedOperation> {
		let mut remove_call_invoked_lock = self.remove_calls_invoked.write().unwrap();
		remove_call_invoked_lock.push((*shard, calls));
		Default::default()
	}

	fn on_block_imported(&self, block: &SignedSidechainBlock::Block) -> Vec<ExecutedOperation> {
		let signed_top_hashes = block.signed_top_hashes();
		let executed_operations = signed_top_hashes
			.iter()
			.map(|hash| {
				// Only successfully executed operations are included in a block.
				ExecutedOperation::success(*hash, TrustedOperationOrHash::Hash(*hash), Vec::new())
			})
			.collect();

		self.remove_calls_from_pool(&block.shard_id(), executed_operations)
	}
}
