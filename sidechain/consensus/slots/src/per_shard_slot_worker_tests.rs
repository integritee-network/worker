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

use crate::{mocks::SimpleSlotWorkerMock, PerShardSlotWorkerScheduler, SlotInfo};
use itc_parentchain_test::ParentchainHeaderBuilder;
use itp_settings::sidechain::SLOT_DURATION;
use itp_time_utils::duration_now;
use itp_types::{Block as ParentchainBlock, ShardIdentifier};
use its_block_verification::slot::slot_from_timestamp_and_duration;

type TestSlotWorker = SimpleSlotWorkerMock<ParentchainBlock>;

#[test]
fn slot_timings_are_correct_with_multiple_shards() {
	let slot_info = slot_info_from_now();
	let mut slot_worker =
		TestSlotWorker { slot_infos: Vec::new(), slot_time_spent: Some(SLOT_DURATION / 10) };

	let shards =
		vec![ShardIdentifier::default(), ShardIdentifier::default(), ShardIdentifier::default()];

	let _slot_results =
		PerShardSlotWorkerScheduler::on_slot(&mut slot_worker, slot_info.clone(), shards.clone());

	assert_eq!(slot_worker.slot_infos.len(), shards.len());

	// end-time of the first shard slot should not exceed timestamp + 1/(n_shards) of the total slot duration
	let first_shard_slot_end_time = slot_worker.slot_infos.first().unwrap().ends_at.as_millis();
	let expected_upper_bound = (slot_info.timestamp.as_millis()
		+ SLOT_DURATION.as_millis().checked_div(shards.len() as u128).unwrap())
		+ 2u128;
	assert!(
		first_shard_slot_end_time <= expected_upper_bound,
		"First shard end time, expected: {}, actual: {}",
		expected_upper_bound,
		first_shard_slot_end_time
	);

	// none of the shard slot end times should exceed the global slot end time
	for shard_slot_info in slot_worker.slot_infos {
		assert!(
			shard_slot_info.ends_at.as_millis() <= slot_info.ends_at.as_millis(),
			"shard slot info ends at: {} ms, total slot info ends at: {} ms",
			shard_slot_info.ends_at.as_millis(),
			slot_info.ends_at.as_millis()
		);
	}
}

#[test]
fn if_shard_takes_up_all_slot_time_subsequent_shards_are_not_served() {
	let slot_info = slot_info_from_now();
	let mut slot_worker =
		TestSlotWorker { slot_infos: Vec::new(), slot_time_spent: Some(SLOT_DURATION) };

	let shards =
		vec![ShardIdentifier::default(), ShardIdentifier::default(), ShardIdentifier::default()];

	let _slot_results =
		PerShardSlotWorkerScheduler::on_slot(&mut slot_worker, slot_info.clone(), shards.clone());

	assert_eq!(1, slot_worker.slot_infos.len());
}

fn slot_info_from_now() -> SlotInfo<ParentchainBlock> {
	let timestamp_now = duration_now();
	let slot = slot_from_timestamp_and_duration(timestamp_now, SLOT_DURATION);
	let slot_ends_at = timestamp_now + SLOT_DURATION;
	SlotInfo::new(
		slot,
		timestamp_now,
		SLOT_DURATION,
		slot_ends_at,
		ParentchainHeaderBuilder::default().build(),
	)
}
