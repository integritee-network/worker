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

#![cfg_attr(test, feature(assert_matches))]

use its_primitives::types::BlockNumber;
use std::{
	sync::Arc,
	thread,
	time::{Duration, SystemTime},
};

mod db;
mod error;
pub mod interface;
mod storage;

#[cfg(test)]
mod storage_tests_get_blocks_after;

#[cfg(test)]
mod test_utils;

#[cfg(feature = "mocks")]
pub mod fetch_blocks_mock;

pub use error::{Error, Result};
pub use interface::{BlockPruner, BlockStorage, SidechainStorageLock};

pub fn start_sidechain_pruning_loop<D>(
	storage: &Arc<D>,
	purge_interval: u64,
	purge_limit: BlockNumber,
) where
	D: BlockPruner,
{
	let interval_time = Duration::from_secs(purge_interval);
	let mut interval_start = SystemTime::now();
	loop {
		if let Ok(elapsed) = interval_start.elapsed() {
			if elapsed >= interval_time {
				// update interval time
				interval_start = SystemTime::now();
				storage.prune_blocks_except(purge_limit);
			} else {
				// sleep for the rest of the interval
				let sleep_time = interval_time - elapsed;
				thread::sleep(sleep_time);
			}
		}
	}
}
