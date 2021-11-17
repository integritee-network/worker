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
//! General time utility functions.
#![feature(trait_alias)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(all(feature = "std", feature = "sgx"))]
compile_error!("feature \"std\" and feature \"sgx\" cannot be enabled at the same time");

#[cfg(all(not(feature = "std"), feature = "sgx"))]
extern crate sgx_tstd as std;

use std::time::{Duration, SystemTime};

/// Returns current duration since unix epoch in millis as u64.
pub fn now_as_u64() -> u64 {
	duration_now().as_millis() as u64
}

/// Calculates the remaining time `until`.
pub fn remaining_time(until: Duration) -> Option<Duration> {
	until.checked_sub(duration_now())
}

/// Returns current duration since unix epoch.
pub fn duration_now() -> Duration {
	let now = SystemTime::now();
	now.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_else(|e| {
		panic!("Current time {:?} is before unix epoch. Something is wrong: {:?}", now, e)
	})
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn subsequent_nows_are_increasing_in_time() {
		let before = duration_now();
		let now = duration_now();

		assert!(before < now);
	}
}
