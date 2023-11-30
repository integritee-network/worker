/*
	Copyright 2021 Integritee AG

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

#![cfg_attr(all(not(target_env = "sgx"), not(feature = "std")), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

#[cfg(all(not(feature = "std"), feature = "sgx"))]
extern crate sgx_tstd as std;

use codec::Decode;

pub mod indirect_calls;
pub mod integritee;
pub mod target_a;
pub mod target_b;

pub fn decode_and_log_error<V: Decode>(encoded: &mut &[u8]) -> Option<V> {
	match V::decode(encoded) {
		Ok(v) => Some(v),
		Err(e) => {
			log::warn!("Could not decode. {:?}", e);
			None
		},
	}
}
