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
use itp_time_utils::{duration_now, remaining_time};
use itp_types::OpaqueCall;
use its_consensus_common::{Error as ConsensusError, Proposer};
use its_primitives::traits::{ShardIdentifierFor, SignedBlock as SignedSidechainBlock};
use log::{debug, info, warn};
pub use slots::*;
use sp_runtime::traits::{Block as ParentchainBlock, Header};
use std::{fmt::Debug, time::Duration, vec::Vec};

mod slots;

pub use slots::*;

/// The result of [`SlotWorker::on_slot`].
#[derive(Debug, Clone, Encode, From)]
pub struct SlotResult<B: SignedSidechainBlock> {
	/// The result of a slot operation.
	pub block: B,
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
pub trait SlotWorker<B: ParentchainBlock> {
	/// Output generated after a slot
	type Output: SignedSidechainBlock + Send + 'static;

	/// Called when a new slot is triggered.
	///
	/// Returns a [`SlotResult`] iff a block was successfully built in
	/// the slot. Otherwise `None` is returned.
	fn on_slot(
		&mut self,
		slot_info: SlotInfo<B>,
		shard: ShardIdentifierFor<Self::Output>,
	) -> Option<SlotResult<Self::Output>>;
}

/// A slot worker scheduler that should be invoked at every new slot.
///
/// It manages the timeslots of individual per shard `SlotWorker`s. It gives each shard an equal
/// amount of time to produce it's result, equally distributing leftover time from a previous shard's
/// slot share to all subsequent slots.
pub trait PerShardSlotWorkerScheduler<B: ParentchainBlock> {
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
		slot_info: SlotInfo<B>,
		shard: Vec<Self::ShardIdentifier>,
	) -> Self::Output;
}

/// A skeleton implementation for `SlotWorker` which tries to claim a slot at
/// its beginning and tries to produce a block if successfully claimed, timing
/// out if block production takes too long.
pub trait SimpleSlotWorker<B: ParentchainBlock> {
	/// The type of proposer to use to build blocks.
	type Proposer: Proposer<B, Self::Output>;

	/// Data associated with a slot claim.
	type Claim: Send + 'static;

	/// Epoch data necessary for authoring.
	type EpochData: Send + 'static;

	/// Output generated after a slot
	type Output: SignedSidechainBlock + Send + 'static;

	/// The logging target to use when logging messages.
	fn logging_target(&self) -> &'static str;

	/// Returns the epoch data necessary for authoring. For time-dependent epochs,
	/// use the provided slot number as a canonical source of time.
	fn epoch_data(&self, header: &B::Header, slot: Slot)
		-> Result<Self::EpochData, ConsensusError>;

	/// Returns the number of authorities given the epoch data.
	/// None indicate that the authorities information is incomplete.
	fn authorities_len(&self, epoch_data: &Self::EpochData) -> Option<usize>;

	/// Tries to claim the given slot, returning an object with claim data if successful.
	fn claim_slot(
		&self,
		header: &B::Header,
		slot: Slot,
		epoch_data: &Self::EpochData,
	) -> Option<Self::Claim>;

	/// Creates the proposer for the current slot
	fn proposer(
		&mut self,
		header: B::Header,
		shard: ShardIdentifierFor<Self::Output>,
	) -> Result<Self::Proposer, ConsensusError>;

	/// Remaining duration for proposing.
	fn proposing_remaining_duration(&self, slot_info: &SlotInfo<B>) -> Duration;

	/// Check if should propose even if the timestamp of the proposal is no longer within the slot.
	///
	/// Remove when #447 is resolved.
	fn allow_delayed_proposal(&self) -> bool;

	/// Implements [`SlotWorker::on_slot`]. This is an adaption from
	/// substrate's sc-consensus-slots implementation. There, the slot worker handles all the
	/// scheduling itself. Unfortunately, we can't use the same principle in the enclave due to some
	/// futures-primitives not being available in sgx, e.g. `Delay` in our case. Hence, before
	/// reimplementing the those things ourselves, we take a simplified approach and simply call
	/// this function from the outside at each slot.
	fn on_slot(
		&mut self,
		slot_info: SlotInfo<B>,
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

		let epoch_data = match self.epoch_data(&slot_info.parentchain_head, slot) {
			Ok(epoch_data) => epoch_data,
			Err(e) => {
				warn!(
					target: logging_target,
					"Unable to fetch epoch data at block {:?}: {:?}",
					slot_info.parentchain_head.hash(),
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

		let _ = self.claim_slot(&slot_info.parentchain_head, slot, &epoch_data)?;

		let proposer = match self.proposer(slot_info.parentchain_head.clone(), shard) {
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

		if !timestamp_within_slot(&slot_info, &proposing.block) && !self.allow_delayed_proposal() {
			debug!(
				target: logging_target,
				"⌛️ Discarding proposal for slot {}; block production took too long", *slot,
			);

			return None
		}

		Some(SlotResult {
			block: proposing.block,
			parentchain_effects: proposing.parentchain_effects,
		})
	}
}

impl<B: ParentchainBlock, T: SimpleSlotWorker<B> + Send> SlotWorker<B> for T {
	type Output = T::Output;

	fn on_slot(
		&mut self,
		slot_info: SlotInfo<B>,
		shard: ShardIdentifierFor<T::Output>,
	) -> Option<SlotResult<Self::Output>> {
		SimpleSlotWorker::on_slot(self, slot_info, shard)
	}
}

impl<B: ParentchainBlock, T: SimpleSlotWorker<B>> PerShardSlotWorkerScheduler<B> for T {
	type Output = Vec<SlotResult<T::Output>>;

	type ShardIdentifier = ShardIdentifierFor<T::Output>;

	fn on_slot(
		&mut self,
		slot_info: SlotInfo<B>,
		shards: Vec<Self::ShardIdentifier>,
	) -> Self::Output {
		let logging_target = SimpleSlotWorker::logging_target(self);

		let mut remaining_shards = shards.len();
		let mut slot_results = Vec::with_capacity(remaining_shards);

		for shard in shards.into_iter() {
			let shard_remaining_duration = remaining_time(slot_info.ends_at)
				.map(|time| time.checked_div(remaining_shards as u32))
				.flatten()
				.unwrap_or_default();

			// important to check against millis here. We had the corner-case in production
			// setup where `shard_remaining_duration` contained only nanos.
			if shard_remaining_duration.as_millis() == Default::default() {
				info!(
					target: logging_target,
					"⌛️ Could not produce blocks for all shards; block production took too long",
				);

				return slot_results
			}

			let shard_slot = SlotInfo::new(
				slot_info.slot,
				duration_now(),
				shard_remaining_duration,
				slot_info.parentchain_head.clone(),
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
