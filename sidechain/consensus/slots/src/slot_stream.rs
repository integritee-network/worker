use crate::time_until_next_slot;
use futures_timer::Delay;
use std::time::Duration;

/// Triggers the enclave to produce a block based on a fixed time schedule.
pub async fn start_interval_block_production<F>(trusted_call: F, slot_duration: Duration)
where
	F: Fn() -> (),
{
	let mut slot_stream = SlotStream::new(slot_duration);

	loop {
		slot_stream.next_slot().await;
		trusted_call();
	}
}

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
	pub async fn next_slot(&mut self) {
		self.inner_delay = match self.inner_delay.take() {
			None => {
				// schedule wait.
				let wait_dur = time_until_next_slot(self.slot_duration);
				Some(Delay::new(wait_dur))
			},
			Some(d) => Some(d),
		};

		if let Some(inner_delay) = self.inner_delay.take() {
			inner_delay.await;
		}
		// timeout has fired.

		let ends_in = time_until_next_slot(self.slot_duration);

		// reschedule delay for next slot.
		self.inner_delay = Some(Delay::new(ends_in));
	}
}
