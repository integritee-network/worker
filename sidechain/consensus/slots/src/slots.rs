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

//! Utility stream for yielding slots in a loop.
//!
//! This is used instead of `futures_timer::Interval` because it was unreliable.

use itp_time_utils::duration_now;
use its_block_verification::slot::slot_from_timestamp_and_duration;
use its_consensus_common::Error as ConsensusError;
use its_primitives::traits::{
	Block as SidechainBlockTrait, BlockData, SignedBlock as SignedSidechainBlockTrait,
};
use lazy_static::lazy_static;
use log::warn;
use sp_runtime::traits::Block as ParentchainBlockTrait;
use std::time::Duration;

#[cfg(all(not(feature = "std"), feature = "sgx"))]
use std::sync::SgxRwLock as RwLock;

#[cfg(all(feature = "std", not(feature = "sgx")))]
use std::sync::RwLock;

pub use sp_consensus_slots::Slot;

/// Returns the duration until the next slot from now.
pub fn time_until_next_slot(slot_duration: Duration) -> Duration {
	let now = duration_now().as_millis();

	if slot_duration.as_millis() == u128::default() {
		log::warn!("[Slots]: slot_duration.as_millis() is 0");
		return Default::default()
	}

	let next_slot = (now + slot_duration.as_millis()) / slot_duration.as_millis();
	let remaining_millis = next_slot * slot_duration.as_millis() - now;
	Duration::from_millis(remaining_millis as u64)
}

/// Information about a slot.
#[derive(Debug, Clone)]
pub struct SlotInfo<ParentchainBlock: ParentchainBlockTrait> {
	/// The slot number as found in the inherent data.
	pub slot: Slot,
	/// Current timestamp as found in the inherent data.
	pub timestamp: Duration,
	/// Slot duration.
	pub duration: Duration,
	/// The time at which the slot ends.
	pub ends_at: Duration,
	/// Last imported parentchain header, potentially outdated.
	pub last_imported_parentchain_head: ParentchainBlock::Header,
}

impl<ParentchainBlock: ParentchainBlockTrait> SlotInfo<ParentchainBlock> {
	/// Create a new [`SlotInfo`].
	///
	/// `ends_at` is calculated using `now` and `time_until_next_slot`.
	pub fn new(
		slot: Slot,
		timestamp: Duration,
		duration: Duration,
		ends_at: Duration,
		parentchain_head: ParentchainBlock::Header,
	) -> Self {
		Self {
			slot,
			timestamp,
			duration,
			ends_at,
			last_imported_parentchain_head: parentchain_head,
		}
	}

	pub fn duration_remaining(&self) -> Option<Duration> {
		let duration_now = duration_now();
		if self.ends_at <= duration_now {
			return None
		}
		Some(self.ends_at - duration_now)
	}
}

/// The time at which the slot ends.
///
/// !! Slot duration needs to be the 'global' slot duration that is used for the sidechain.
/// Do not use this with 'custom' slot durations, as used e.g. for the shard slots.  
pub fn slot_ends_at(slot: Slot, slot_duration: Duration) -> Duration {
	Duration::from_millis(*slot.saturating_add(1u64) * (slot_duration.as_millis() as u64))
}

pub(crate) fn timestamp_within_slot<
	ParentchainBlock: ParentchainBlockTrait,
	SignedSidechainBlock: SignedSidechainBlockTrait,
>(
	slot: &SlotInfo<ParentchainBlock>,
	proposal: &SignedSidechainBlock,
) -> bool {
	let proposal_stamp = proposal.block().block_data().timestamp();

	let is_within_slot = slot.timestamp.as_millis() as u64 <= proposal_stamp
		&& slot.ends_at.as_millis() as u64 >= proposal_stamp;

	if !is_within_slot {
		warn!(
			"Proposed block slot time: {} ms, slot start: {} ms , slot end: {} ms",
			proposal_stamp,
			slot.timestamp.as_millis(),
			slot.ends_at.as_millis()
		);
	}

	is_within_slot
}

pub fn yield_next_slot<SlotGetter, ParentchainBlock>(
	timestamp: Duration,
	duration: Duration,
	header: ParentchainBlock::Header,
	last_slot_getter: &mut SlotGetter,
) -> Result<Option<SlotInfo<ParentchainBlock>>, ConsensusError>
where
	SlotGetter: LastSlotTrait,
	ParentchainBlock: ParentchainBlockTrait,
{
	if duration == Default::default() {
		return Err(ConsensusError::Other("Tried to yield next slot with 0 duration".into()))
	}

	let last_slot = last_slot_getter.get_last_slot()?;
	let slot = slot_from_timestamp_and_duration(timestamp, duration);

	if slot <= last_slot {
		return Ok(None)
	}

	last_slot_getter.set_last_slot(slot)?;

	let slot_ends_time = slot_ends_at(slot, duration);
	Ok(Some(SlotInfo::new(slot, timestamp, duration, slot_ends_time, header)))
}

pub trait LastSlotTrait {
	fn get_last_slot(&self) -> Result<Slot, ConsensusError>;
	fn set_last_slot(&mut self, slot: Slot) -> Result<(), ConsensusError>;
}

pub struct LastSlot;

lazy_static! {
	static ref LAST_SLOT: RwLock<Slot> = Default::default();
}

impl LastSlotTrait for LastSlot {
	fn get_last_slot(&self) -> Result<Slot, ConsensusError> {
		Ok(*LAST_SLOT.read().map_err(|e| ConsensusError::Other(format!("{:?}", e).into()))?)
	}

	fn set_last_slot(&mut self, slot: Slot) -> Result<(), ConsensusError> {
		*LAST_SLOT
			.write()
			.map_err(|e| ConsensusError::Other(format!("{:?}", e).into()))? = slot;
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use core::assert_matches::assert_matches;
	use itc_parentchain_test::ParentchainHeaderBuilder;
	use itp_types::Block as ParentchainBlock;
	use its_primitives::{
		traits::{Block as BlockT, SignBlock},
		types::block::{Block, SignedBlock},
	};
	use its_test::{
		sidechain_block_data_builder::SidechainBlockDataBuilder,
		sidechain_header_builder::SidechainHeaderBuilder,
	};
	use sp_keyring::ed25519::Keyring;
	use std::{fmt::Debug, thread, time::SystemTime};

	const SLOT_DURATION: Duration = Duration::from_millis(1000);
	const ALLOWED_THRESHOLD: Duration = Duration::from_millis(1);

	fn test_block_with_time_stamp(timestamp: u64) -> SignedBlock {
		let header = SidechainHeaderBuilder::default().build();

		let block_data = SidechainBlockDataBuilder::default().with_timestamp(timestamp).build();

		Block::new(header, block_data).sign_block(&Keyring::Alice.pair())
	}

	fn slot(slot: u64) -> SlotInfo<ParentchainBlock> {
		SlotInfo {
			slot: slot.into(),
			timestamp: duration_now(),
			duration: SLOT_DURATION,
			ends_at: duration_now() + SLOT_DURATION,
			last_imported_parentchain_head: ParentchainHeaderBuilder::default().build(),
		}
	}

	fn timestamp_in_the_future(later: Duration) -> u64 {
		let moment = SystemTime::now() + later;
		let dur = moment.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_else(|e| {
			panic!("Current time {:?} is before unix epoch. Something is wrong: {:?}", moment, e)
		});
		dur.as_millis() as u64
	}

	fn timestamp_in_the_past(earlier: Duration) -> u64 {
		let moment = SystemTime::now() - earlier;
		let dur = moment.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_else(|e| {
			panic!("Current time {:?} is before unix epoch. Something is wrong: {:?}", moment, e)
		});
		dur.as_millis() as u64
	}

	fn assert_consensus_other_err<T: Debug>(result: Result<T, ConsensusError>, msg: &str) {
		assert_matches!(result.unwrap_err(), ConsensusError::Other(
			m,
		) if m.to_string() == msg)
	}

	#[test]
	fn time_until_next_slot_returns_default_on_nano_duration() {
		// prevent panic: https://github.com/integritee-network/worker/issues/439
		assert_eq!(time_until_next_slot(Duration::from_nanos(999)), Default::default())
	}

	#[test]
	fn slot_info_ends_at_does_not_change_after_second_calculation() {
		let timestamp = duration_now();
		let pc_header = ParentchainHeaderBuilder::default().build();
		let slot: Slot = 1000.into();

		let slot_end_time = slot_ends_at(slot, SLOT_DURATION);
		let slot_one: SlotInfo<ParentchainBlock> =
			SlotInfo::new(slot, timestamp, SLOT_DURATION, slot_end_time, pc_header.clone());
		thread::sleep(Duration::from_millis(200));
		let slot_two: SlotInfo<ParentchainBlock> =
			SlotInfo::new(slot, timestamp, SLOT_DURATION, slot_end_time, pc_header);

		let difference_of_ends_at =
			(slot_one.ends_at.as_millis()).abs_diff(slot_two.ends_at.as_millis());

		assert!(
			difference_of_ends_at < ALLOWED_THRESHOLD.as_millis(),
			"Diff in ends at timestamp: {} ms, tolerance: {} ms",
			difference_of_ends_at,
			ALLOWED_THRESHOLD.as_millis()
		);
	}

	#[test]
	fn duration_remaing_returns_none_if_ends_at_is_in_the_past() {
		let slot: SlotInfo<ParentchainBlock> = SlotInfo {
			slot: 1.into(),
			timestamp: duration_now() - Duration::from_secs(5),
			duration: SLOT_DURATION,
			ends_at: duration_now() + SLOT_DURATION - Duration::from_secs(5),
			last_imported_parentchain_head: ParentchainHeaderBuilder::default().build(),
		};
		assert!(slot.duration_remaining().is_none());
	}

	#[test]
	fn duration_remaining_returns_some_if_ends_at_is_in_the_future() {
		let slot: SlotInfo<ParentchainBlock> = SlotInfo {
			slot: 1.into(),
			timestamp: duration_now() - Duration::from_secs(5),
			duration: SLOT_DURATION,
			ends_at: duration_now() + Duration::from_secs(60),
			last_imported_parentchain_head: ParentchainHeaderBuilder::default().build(),
		};
		let maybe_duration_remaining = slot.duration_remaining();
		assert!(maybe_duration_remaining.is_some());
		assert!(maybe_duration_remaining.unwrap() > Duration::from_secs(30));
	}

	#[test]
	fn slot_info_ends_at_does_is_correct_even_if_delay_is_more_than_slot_duration() {
		let timestamp = duration_now();
		let pc_header = ParentchainHeaderBuilder::default().build();
		let slot: Slot = 1000.into();
		let slot_end_time = slot_ends_at(slot, SLOT_DURATION);

		thread::sleep(SLOT_DURATION * 2);
		let slot: SlotInfo<ParentchainBlock> =
			SlotInfo::new(slot, timestamp, SLOT_DURATION, slot_end_time, pc_header);

		assert!(slot.ends_at < duration_now());
	}

	#[test]
	fn timestamp_within_slot_returns_true_for_correct_timestamp() {
		let slot = slot(1);
		let time_stamp_in_slot = timestamp_in_the_future(SLOT_DURATION / 2);

		let block = test_block_with_time_stamp(time_stamp_in_slot);

		assert!(timestamp_within_slot(&slot, &block));
	}

	#[test]
	fn timestamp_within_slot_returns_false_if_timestamp_after_slot() {
		let slot = slot(1);
		let time_stamp_after_slot =
			timestamp_in_the_future(SLOT_DURATION + Duration::from_millis(10));

		let block_too_late = test_block_with_time_stamp(time_stamp_after_slot);

		assert!(!timestamp_within_slot(&slot, &block_too_late));
	}

	#[test]
	fn timestamp_within_slot_returns_false_if_timestamp_before_slot() {
		let slot = slot(1);
		let time_stamp_before_slot = timestamp_in_the_past(Duration::from_millis(10));

		let block_too_early = test_block_with_time_stamp(time_stamp_before_slot);

		assert!(!timestamp_within_slot(&slot, &block_too_early));
	}

	#[test]
	fn yield_next_slot_returns_none_when_slot_equals_last_slot() {
		assert!(yield_next_slot::<_, ParentchainBlock>(
			duration_now(),
			SLOT_DURATION,
			ParentchainHeaderBuilder::default().build(),
			&mut LastSlot,
		)
		.unwrap()
		.is_none())
	}

	#[test]
	fn yield_next_slot_returns_next_slot() {
		assert!(yield_next_slot::<_, ParentchainBlock>(
			duration_now() + SLOT_DURATION,
			SLOT_DURATION,
			ParentchainHeaderBuilder::default().build(),
			&mut LastSlot
		)
		.unwrap()
		.is_some())
	}

	#[test]
	fn yield_next_slot_returns_err_on_0_duration() {
		assert_consensus_other_err(
			yield_next_slot::<_, ParentchainBlock>(
				duration_now(),
				Default::default(),
				ParentchainHeaderBuilder::default().build(),
				&mut LastSlot,
			),
			"Tried to yield next slot with 0 duration",
		)
	}
}
