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

//! Slots functionality for the integritee-sidechain.
//!
//! Some consensus algorithms have a concept of *slots*, which are intervals in
//! time during which certain events can and/or must occur.  This crate
//! provides generic functionality for slots.

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(test, feature(assert_matches))]

#[cfg(all(feature = "std", feature = "sgx"))]
compile_error!("feature \"std\" and feature \"sgx\" cannot be enabled at the same time");

#[cfg(all(not(feature = "std"), feature = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

use codec::Encode;
use derive_more::From;
use itp_time_utils::{duration_difference, duration_now};
use itp_types::OpaqueCall;
use its_consensus_common::{Error as ConsensusError, Proposer};
use its_primitives::traits::{
	Block as SidechainBlockTrait, Header as HeaderTrait, ShardIdentifierFor,
	SignedBlock as SignedSidechainBlockTrait,
};
use log::*;
pub use slots::*;
use sp_runtime::traits::{Block as ParentchainBlockTrait, Header as ParentchainHeaderTrait};
use std::{fmt::Debug, time::Duration, vec::Vec};

#[cfg(feature = "std")]
mod slot_stream;
mod slots;

#[cfg(test)]
mod mocks;

#[cfg(test)]
mod per_shard_slot_worker_tests;

#[cfg(feature = "std")]
pub use slot_stream::*;
pub use slots::*;

/// The result of [`SlotWorker::on_slot`].
#[derive(Debug, Clone, Encode, From)]
pub struct SlotResult<SignedSidechainBlock: SignedSidechainBlockTrait> {
	/// The result of a slot operation.
	pub block: SignedSidechainBlock,
	/// Parentchain state transitions triggered by sidechain state transitions.
	///
	/// Any sidechain stf that invokes a parentchain stf must not commit its state change
	/// before the parentchain effect has been finalized.
	pub parentchain_effects: Vec<OpaqueCall>,
}

/// A worker that should be invoked at every new slot for a specific shard.
///
/// The implementation should not make any assumptions of the slot being bound to the time or
/// similar. The only valid assumption is that the slot number is always increasing.
pub trait SlotWorker<ParentchainBlock: ParentchainBlockTrait> {
	/// Output generated after a slot
	type Output: SignedSidechainBlockTrait + Send + 'static;

	/// Called when a new slot is triggered.
	///
	/// Returns a [`SlotResult`] iff a block was successfully built in
	/// the slot. Otherwise `None` is returned.
	fn on_slot(
		&mut self,
		slot_info: SlotInfo<ParentchainBlock>,
		shard: ShardIdentifierFor<Self::Output>,
	) -> Option<SlotResult<Self::Output>>;
}

/// A slot worker scheduler that should be invoked at every new slot.
///
/// It manages the timeslots of individual per shard `SlotWorker`s. It gives each shard an equal
/// amount of time to produce it's result, equally distributing leftover time from a previous shard's
/// slot share to all subsequent slots.
pub trait PerShardSlotWorkerScheduler<ParentchainBlock: ParentchainBlockTrait> {
	/// Output generated after a slot
	type Output: Send + 'static;

	/// The shard type 'PerShardWorker's operate on.
	type ShardIdentifier: Send + 'static + Debug + Clone;

	/// Called when a new slot is triggered.
	///
	/// Returns a [`SlotResult`] iff a block was successfully built in
	/// the slot. Otherwise `None` is returned.
	fn on_slot(
		&mut self,
		slot_info: SlotInfo<ParentchainBlock>,
		shard: Vec<Self::ShardIdentifier>,
	) -> Self::Output;
}

/// A skeleton implementation for `SlotWorker` which tries to claim a slot at
/// its beginning and tries to produce a block if successfully claimed, timing
/// out if block production takes too long.
pub trait SimpleSlotWorker<ParentchainBlock: ParentchainBlockTrait> {
	/// The type of proposer to use to build blocks.
	type Proposer: Proposer<ParentchainBlock, Self::Output>;

	/// Data associated with a slot claim.
	type Claim: Send + 'static;

	/// Epoch data necessary for authoring.
	type EpochData: Send + 'static;

	/// Output generated after a slot
	type Output: SignedSidechainBlockTrait + Send + 'static;

	/// The logging target to use when logging messages.
	fn logging_target(&self) -> &'static str;

	/// Returns the epoch data necessary for authoring. For time-dependent epochs,
	/// use the provided slot number as a canonical source of time.
	fn epoch_data(
		&self,
		header: &ParentchainBlock::Header,
		shard: ShardIdentifierFor<Self::Output>,
		slot: Slot,
	) -> Result<Self::EpochData, ConsensusError>;

	/// Returns the number of authorities given the epoch data.
	/// None indicate that the authorities information is incomplete.
	fn authorities_len(&self, epoch_data: &Self::EpochData) -> Option<usize>;

	/// Tries to claim the given slot, returning an object with claim data if successful.
	fn claim_slot(
		&self,
		header: &ParentchainBlock::Header,
		slot: Slot,
		epoch_data: &Self::EpochData,
	) -> Option<Self::Claim>;

	/// Creates the proposer for the current slot
	fn proposer(
		&mut self,
		header: ParentchainBlock::Header,
		shard: ShardIdentifierFor<Self::Output>,
	) -> Result<Self::Proposer, ConsensusError>;

	/// Remaining duration for proposing.
	fn proposing_remaining_duration(&self, slot_info: &SlotInfo<ParentchainBlock>) -> Duration;

	/// Trigger the import of the given parentchain block.
	///
	/// Returns the header of the latest imported block. In case no block was imported with this trigger,
	/// None is returned.
	fn import_parentchain_blocks_until(
		&self,
		last_imported_parentchain_header: &<ParentchainBlock::Header as ParentchainHeaderTrait>::Hash,
	) -> Result<Option<ParentchainBlock::Header>, ConsensusError>;

	/// Peek the parentchain import queue for the latest block in queue.
	/// Does not perform the import or mutate the queue.
	fn peek_latest_parentchain_header(
		&self,
	) -> Result<Option<ParentchainBlock::Header>, ConsensusError>;

	/// Implements [`SlotWorker::on_slot`]. This is an adaption from
	/// substrate's sc-consensus-slots implementation. There, the slot worker handles all the
	/// scheduling itself. Unfortunately, we can't use the same principle in the enclave due to some
	/// futures-primitives not being available in sgx, e.g. `Delay` in our case. Hence, before
	/// reimplementing the those things ourselves, we take a simplified approach and simply call
	/// this function from the outside at each slot.
	fn on_slot(
		&mut self,
		slot_info: SlotInfo<ParentchainBlock>,
		shard: ShardIdentifierFor<Self::Output>,
	) -> Option<SlotResult<Self::Output>> {
		let (_timestamp, slot) = (slot_info.timestamp, slot_info.slot);
		let logging_target = self.logging_target();

		let remaining_duration = self.proposing_remaining_duration(&slot_info);

		if remaining_duration == Duration::default() {
			debug!(
				target: logging_target,
				"Skipping proposal slot {} since there's no time left to propose", *slot,
			);

			return None
		}

		let latest_parentchain_header = match self.peek_latest_parentchain_header() {
			Ok(Some(peeked_header)) => peeked_header,
			Ok(None) => slot_info.last_imported_parentchain_head.clone(),
			Err(e) => {
				warn!(
					target: logging_target,
					"Failed to peek latest parentchain block header: {:?}", e
				);
				return None
			},
		};

		let epoch_data = match self.epoch_data(&latest_parentchain_header, shard, slot) {
			Ok(epoch_data) => epoch_data,
			Err(e) => {
				warn!(
					target: logging_target,
					"Unable to fetch epoch data at block {:?}: {:?}",
					latest_parentchain_header.hash(),
					e,
				);

				return None
			},
		};

		let authorities_len = self.authorities_len(&epoch_data);

		if !authorities_len.map(|a| a > 0).unwrap_or(false) {
			debug!(
				target: logging_target,
				"Skipping proposal slot. Authorities len {:?}", authorities_len
			);
		}

		let _claim = self.claim_slot(&latest_parentchain_header, slot, &epoch_data)?;

		// Import the peeked parentchain header(s).
		let last_imported_header =
			match self.import_parentchain_blocks_until(&latest_parentchain_header.hash()) {
				Ok(h) => h,
				Err(e) => {
					warn!(
						target: logging_target,
						"Failed to import and retrieve parentchain block header: {:?}", e
					);
					return None
				},
			};

		let proposer = match self.proposer(latest_parentchain_header.clone(), shard) {
			Ok(p) => p,
			Err(e) => {
				warn!(target: logging_target, "Could not create proposer: {:?}", e);
				return None
			},
		};

		let proposing = match proposer.propose(remaining_duration) {
			Ok(p) => p,
			Err(e) => {
				warn!(target: logging_target, "Could not propose: {:?}", e);
				return None
			},
		};

		if !timestamp_within_slot(&slot_info, &proposing.block) {
			warn!(
				target: logging_target,
				"⌛️ Discarding proposal for slot {}, block number {}; block production took too long",
				*slot, proposing.block.block().header().block_number(),
			);

			return None
		}

		if last_imported_header.is_some() {
			println!(
				"Syncing Parentchain block number {:?} at Sidechain block number  {:?} ",
				latest_parentchain_header.number(),
				proposing.block.block().header().block_number()
			);
		}

		info!("Proposing sidechain block (number: {}, hash: {}) based on parentchain block (number: {:?}, hash: {:?})",
			proposing.block.block().header().block_number(), proposing.block.hash(),
			latest_parentchain_header.number(), latest_parentchain_header.hash()
		);

		Some(SlotResult {
			block: proposing.block,
			parentchain_effects: proposing.parentchain_effects,
		})
	}
}

impl<ParentchainBlock: ParentchainBlockTrait, T: SimpleSlotWorker<ParentchainBlock> + Send>
	SlotWorker<ParentchainBlock> for T
{
	type Output = T::Output;

	fn on_slot(
		&mut self,
		slot_info: SlotInfo<ParentchainBlock>,
		shard: ShardIdentifierFor<T::Output>,
	) -> Option<SlotResult<Self::Output>> {
		SimpleSlotWorker::on_slot(self, slot_info, shard)
	}
}

impl<ParentchainBlock: ParentchainBlockTrait, T: SimpleSlotWorker<ParentchainBlock>>
	PerShardSlotWorkerScheduler<ParentchainBlock> for T
{
	type Output = Vec<SlotResult<T::Output>>;

	type ShardIdentifier = ShardIdentifierFor<T::Output>;

	fn on_slot(
		&mut self,
		slot_info: SlotInfo<ParentchainBlock>,
		shards: Vec<Self::ShardIdentifier>,
	) -> Self::Output {
		let logging_target = SimpleSlotWorker::logging_target(self);

		let mut remaining_shards = shards.len();
		let mut slot_results = Vec::with_capacity(remaining_shards);

		for shard in shards.into_iter() {
			let now = duration_now(); // It's important we have a common `now` for all following computations.
			let shard_remaining_duration = duration_difference(now, slot_info.ends_at)
				.and_then(|time| time.checked_div(remaining_shards as u32))
				.unwrap_or_default();

			// important to check against millis here. We had the corner-case in production
			// setup where `shard_remaining_duration` contained only nanos.
			if shard_remaining_duration.as_millis() == u128::default() {
				info!(
					target: logging_target,
					"⌛️ Could not produce blocks for all shards; block production took too long",
				);

				return slot_results
			}

			let shard_slot_ends_at = now + shard_remaining_duration;
			let shard_slot = SlotInfo::new(
				slot_info.slot,
				now,
				shard_remaining_duration,
				shard_slot_ends_at,
				slot_info.last_imported_parentchain_head.clone(),
			);

			match SimpleSlotWorker::on_slot(self, shard_slot, shard) {
				Some(res) => slot_results.push(res),
				None => info!(
					target: logging_target,
					"Did not produce a block for slot {} in shard {:?}", *slot_info.slot, shard
				),
			}

			remaining_shards -= 1;
		}

		slot_results
	}
}
