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

/// Returns the current timestamp based on the unix epoch in seconds.
pub fn now_as_secs() -> u64 {
	duration_now().as_secs()
}

/// Returns current duration since unix epoch in millis as u64.
pub fn now_as_millis() -> u64 {
	duration_now().as_millis() as u64
}

/// Returns the current timestamp based on the unix epoch in nanoseconds.
pub fn now_as_nanos() -> u128 {
	duration_now().as_nanos()
}

/// Calculates the remaining time from now to `until`.
pub fn remaining_time(until: Duration) -> Option<Duration> {
	duration_difference(duration_now(), until)
}

/// Calculate the difference in duration between `from` and `to`.
/// Returns `None` if `to` < `from`.
pub fn duration_difference(from: Duration, to: Duration) -> Option<Duration> {
	to.checked_sub(from)
}

/// Returns current duration since unix epoch with SystemTime::now().
/// Note: subsequent calls are not guaranteed to be monotonic.
/// (https://doc.rust-lang.org/std/time/struct.SystemTime.html)
pub fn duration_now() -> Duration {
	let now = SystemTime::now();
	now.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_else(|e| {
		panic!("Current time {:?} is before unix epoch. Something is wrong: {:?}", now, e)
	})
}
