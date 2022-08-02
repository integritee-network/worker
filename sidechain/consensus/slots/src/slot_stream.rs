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

//! Slots functionality for Substrate.
//!
//! Some consensus algorithms have a concept of *slots*, which are intervals in
//! time during which certain events can and/or must occur.  This crate
//! provides generic functionality for slots.

use crate::time_until_next_slot;
use futures_timer::Delay;
use std::time::Duration;

/// Executes given `task` repeatedly when the next slot becomes available.
pub async fn start_slot_worker<F>(task: F, slot_duration: Duration)
where
	F: Fn(),
{
	let mut slot_stream = SlotStream::new(slot_duration);

	loop {
		slot_stream.next_slot().await;
		task();
	}
}

/// Stream to calculate the slot schedule with.
pub struct SlotStream {
	slot_duration: Duration,
	inner_delay: Option<Delay>,
}

impl SlotStream {
	pub fn new(slot_duration: Duration) -> Self {
		SlotStream { slot_duration, inner_delay: None }
	}
}

impl SlotStream {
	/// Waits for the duration of `inner_delay`.
	/// Upon timeout, `inner_delay` is reset according to the time left until next slot.
	pub async fn next_slot(&mut self) {
		self.inner_delay = match self.inner_delay.take() {
			None => {
				// Delay is not initialized in this case,
				// so we have to initialize with the time until the next slot.
				let wait_dur = time_until_next_slot(self.slot_duration);
				Some(Delay::new(wait_dur))
			},
			Some(d) => Some(d),
		};

		if let Some(inner_delay) = self.inner_delay.take() {
			inner_delay.await;
		}

		let ends_in = time_until_next_slot(self.slot_duration);

		// Re-schedule delay for next slot.
		self.inner_delay = Some(Delay::new(ends_in));
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::{thread, time::Instant};

	const SLOT_DURATION: Duration = Duration::from_millis(300);
	const SLOT_TOLERANCE: Duration = Duration::from_millis(10);

	#[tokio::test]
	async fn short_task_execution_does_not_influence_next_slot() {
		let mut slot_stream = SlotStream::new(SLOT_DURATION);

		slot_stream.next_slot().await;
		let now = Instant::now();
		// Task execution is shorter than slot duration.
		thread::sleep(Duration::from_millis(200));
		slot_stream.next_slot().await;

		let elapsed = now.elapsed();
		assert!(elapsed >= SLOT_DURATION - SLOT_TOLERANCE);
		assert!(elapsed <= SLOT_DURATION + SLOT_TOLERANCE);
	}

	#[tokio::test]
	async fn long_task_execution_does_not_cause_drift() {
		let mut slot_stream = SlotStream::new(SLOT_DURATION);

		slot_stream.next_slot().await;
		let now = Instant::now();
		// Task execution is longer than slot duration.
		thread::sleep(Duration::from_millis(500));
		slot_stream.next_slot().await;
		slot_stream.next_slot().await;

		let elapsed = now.elapsed();
		assert!(elapsed >= 2 * SLOT_DURATION - SLOT_TOLERANCE);
		assert!(elapsed <= 2 * SLOT_DURATION + SLOT_TOLERANCE);
	}
}
