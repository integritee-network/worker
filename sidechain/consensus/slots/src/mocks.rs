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

use crate::{slots::Slot, SimpleSlotWorker, SlotInfo, SlotResult};
use its_consensus_common::{Proposal, Proposer, Result};
use its_primitives::{traits::ShardIdentifierFor, types::SignedBlock as SignedSidechainBlock};
use sp_runtime::traits::{Block as ParentchainBlockTrait, Header as ParentchainHeaderTrait};
use std::{marker::PhantomData, thread, time::Duration};

#[derive(Default)]
pub(crate) struct ProposerMock<ParentchainBlock> {
	_phantom: PhantomData<ParentchainBlock>,
}

impl<B> Proposer<B, SignedSidechainBlock> for ProposerMock<B>
where
	B: ParentchainBlockTrait,
{
	fn propose(&self, _max_duration: Duration) -> Result<Proposal<SignedSidechainBlock>> {
		todo!()
	}
}

#[derive(Default)]
pub(crate) struct SimpleSlotWorkerMock<B>
where
	B: ParentchainBlockTrait,
{
	pub slot_infos: Vec<SlotInfo<B>>,
	pub slot_time_spent: Option<Duration>,
}

impl<B> SimpleSlotWorker<B> for SimpleSlotWorkerMock<B>
where
	B: ParentchainBlockTrait,
{
	type Proposer = ProposerMock<B>;

	type Claim = u64;

	type EpochData = u64;

	type Output = SignedSidechainBlock;

	fn logging_target(&self) -> &'static str {
		"test"
	}

	fn epoch_data(
		&self,
		_header: &B::Header,
		_shard: ShardIdentifierFor<Self::Output>,
		_slot: Slot,
	) -> Result<Self::EpochData> {
		todo!()
	}

	fn authorities_len(&self, _epoch_data: &Self::EpochData) -> Option<usize> {
		todo!()
	}

	fn claim_slot(
		&self,
		_header: &B::Header,
		_slot: Slot,
		_epoch_data: &Self::EpochData,
	) -> Option<Self::Claim> {
		todo!()
	}

	fn proposer(
		&mut self,
		_header: B::Header,
		_shard: ShardIdentifierFor<Self::Output>,
	) -> Result<Self::Proposer> {
		todo!()
	}

	fn proposing_remaining_duration(&self, _slot_info: &SlotInfo<B>) -> Duration {
		todo!()
	}

	fn import_parentchain_blocks_until(
		&self,
		_last_imported_parentchain_header: &<B::Header as ParentchainHeaderTrait>::Hash,
	) -> Result<Option<B::Header>> {
		todo!()
	}

	fn peek_latest_parentchain_header(&self) -> Result<Option<B::Header>> {
		todo!()
	}

	fn on_slot(
		&mut self,
		slot_info: SlotInfo<B>,
		_shard: ShardIdentifierFor<Self::Output>,
	) -> Option<SlotResult<Self::Output>> {
		self.slot_infos.push(slot_info);

		if let Some(sleep_duration) = self.slot_time_spent {
			thread::sleep(sleep_duration);
		}

		None
	}
}
