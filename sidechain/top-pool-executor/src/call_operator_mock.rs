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
use ita_stf::TrustedCallSigned;
use its_primitives::traits::{ShardIdentifierFor, SignedBlock as SignedBlockT};
use sp_runtime::traits::Block as BlockT;
use std::{collections::HashMap, sync::RwLock};

pub struct TopPoolCallOperatorMock<PB, SB>
where
	PB: BlockT,
	SB: SignedBlockT,
{
	trusted_calls: HashMap<ShardIdentifierFor<SB>, Vec<TrustedCallSigned>>,
	remove_calls_invoked: RwLock<Vec<(ShardIdentifierFor<SB>, Vec<ExecutedOperation>)>>,
	_phantom: PhantomData<PB>,
}

impl<PB, SB> Default for TopPoolCallOperatorMock<PB, SB>
where
	PB: BlockT,
	SB: SignedBlockT,
{
	fn default() -> Self {
		TopPoolCallOperatorMock {
			trusted_calls: Default::default(),
			remove_calls_invoked: Default::default(),
			_phantom: Default::default(),
		}
	}
}

impl<PB, SB> TopPoolCallOperatorMock<PB, SB>
where
	PB: BlockT,
	SB: SignedBlockT,
{
	pub fn add_trusted_calls(
		&mut self,
		shard: ShardIdentifierFor<SB>,
		trusted_calls: Vec<TrustedCallSigned>,
	) {
		self.trusted_calls.insert(shard, trusted_calls);
	}

	pub fn remove_calls_invoked(&self) -> Vec<(ShardIdentifierFor<SB>, Vec<ExecutedOperation>)> {
		self.remove_calls_invoked.read().unwrap().clone()
	}
}

impl<PB, SB> TopPoolCallOperator<PB, SB> for TopPoolCallOperatorMock<PB, SB>
where
	PB: BlockT,
	SB: SignedBlockT,
{
	fn get_trusted_calls(&self, shard: &ShardIdentifierFor<SB>) -> Result<Vec<TrustedCallSigned>> {
		Ok(self.trusted_calls.get(shard).map(|v| v.clone()).unwrap_or_default())
	}

	fn remove_calls_from_pool(
		&self,
		shard: &ShardIdentifierFor<SB>,
		calls: Vec<ExecutedOperation>,
	) -> Vec<ExecutedOperation> {
		let mut remove_call_invoked_lock = self.remove_calls_invoked.write().unwrap();
		remove_call_invoked_lock.push((*shard, calls));
		Default::default()
	}
}
