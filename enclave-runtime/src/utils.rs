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
use crate::Hash;
use codec::{Decode, Error, Input};
use core::time::Duration;
use log::*;
use sgx_types::sgx_status_t;
use std::{slice, time::SystemTime, untrusted::time::SystemTimeEx, vec::Vec};

pub fn hash_from_slice(hash_slize: &[u8]) -> Hash {
	let mut g = [0; 32];
	g.copy_from_slice(hash_slize);
	Hash::from(&mut g)
}

pub fn write_slice_and_whitespace_pad(writable: &mut [u8], data: Vec<u8>) {
	if data.len() > writable.len() {
		panic!("not enough bytes in output buffer for return value");
	}
	let (left, right) = writable.split_at_mut(data.len());
	left.clone_from_slice(&data);
	// fill the right side with whitespace
	right.iter_mut().for_each(|x| *x = 0x20);
}

/// Helper trait to transform the sgx-ffi pointers to any type that implements
/// `parity-scale-codec::Decode`
pub unsafe trait DecodeRaw {
	/// the type to decode into
	type Decoded: Decode;

	unsafe fn decode_raw<'a, T>(data: *const T, len: usize) -> Result<Self::Decoded, codec::Error>
	where
		T: 'a,
		&'a [T]: Input;
}

unsafe impl<D: Decode> DecodeRaw for D {
	type Decoded = D;

	unsafe fn decode_raw<'a, T>(data: *const T, len: usize) -> Result<Self::Decoded, Error>
	where
		T: 'a,
		&'a [T]: Input,
	{
		let mut s = slice::from_raw_parts(data, len);

		Decode::decode(&mut s)
	}
}

/// Returns current duration since unix epoch.
pub fn duration_now() -> Duration {
	let now = SystemTime::now();
	now.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_else(|e| {
		panic!("Current time {:?} is before unix epoch. Something is wrong: {:?}", now, e)
	})
}

/// Returns the duration until the next slot from now.
pub fn time_until_next_slot(slot_duration: Duration) -> Duration {
	let now = duration_now().as_millis();

	let next_slot = (now + slot_duration.as_millis()) / slot_duration.as_millis();
	let remaining_millis = next_slot * slot_duration.as_millis() - now;
	Duration::from_millis(remaining_millis as u64)
}

pub fn remaining_time(until: Duration) -> Option<Duration> {
	until.checked_sub(duration_now())
}

pub trait UnwrapOrSgxErrorUnexpected {
	type ReturnType;
	fn sgx_error(self) -> Result<Self::ReturnType, sgx_status_t>;
	fn sgx_error_with_log(self, err_mgs: &str) -> Result<Self::ReturnType, sgx_status_t>;
}

impl<T> UnwrapOrSgxErrorUnexpected for Option<T> {
	type ReturnType = T;
	fn sgx_error(self) -> Result<Self::ReturnType, sgx_status_t> {
		match self {
			Some(r) => Ok(r),
			None => Err(sgx_status_t::SGX_ERROR_UNEXPECTED),
		}
	}

	fn sgx_error_with_log(self, log_msg: &str) -> Result<Self::ReturnType, sgx_status_t> {
		match self {
			Some(r) => Ok(r),
			None => {
				error!("{}", log_msg);
				Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
			},
		}
	}
}

impl<T, S> UnwrapOrSgxErrorUnexpected for Result<T, S> {
	type ReturnType = T;
	fn sgx_error(self) -> Result<Self::ReturnType, sgx_status_t> {
		match self {
			Ok(r) => Ok(r),
			Err(_) => Err(sgx_status_t::SGX_ERROR_UNEXPECTED),
		}
	}

	fn sgx_error_with_log(self, log_msg: &str) -> Result<Self::ReturnType, sgx_status_t> {
		match self {
			Ok(r) => Ok(r),
			Err(_) => {
				error!("{}", log_msg);
				Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
			},
		}
	}
}
