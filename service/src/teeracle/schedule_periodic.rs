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

use std::{
	thread,
	time::{Duration, Instant},
};

/// Schedules a periodic task in the current thread.
///
/// In case the task takes longer than is scheduled by the interval duration,
/// the interval timing will drift. The task is responsible for
/// ensuring it does not use up more time than is scheduled.
pub(super) fn schedule_periodic<T>(task: T, period: Duration)
where
	T: Fn(),
{
	let mut interval_start = Instant::now();
	loop {
		let elapsed = interval_start.elapsed();

		if elapsed >= period {
			// update interval time
			interval_start = Instant::now();
			task();
		} else {
			// sleep for the rest of the interval
			let sleep_time = period - elapsed;
			thread::sleep(sleep_time);
		}
	}
}
