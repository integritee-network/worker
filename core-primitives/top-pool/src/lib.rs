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

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(all(feature = "std", feature = "sgx"))]
compile_error!("feature \"std\" and feature \"sgx\" cannot be enabled at the same time");

#[cfg(all(not(feature = "std"), feature = "sgx"))]
extern crate sgx_tstd as std;

// re-export module to properly feature gate sgx and regular std environment
#[cfg(all(not(feature = "std"), feature = "sgx"))]
pub mod sgx_reexport_prelude {
	pub use jsonrpc_core_sgx as jsonrpc_core;
	pub use linked_hash_map_sgx as linked_hash_map;
	pub use thiserror_sgx as thiserror;
}

pub mod base_pool;
pub mod basic_pool;
pub mod error;
pub mod future;
pub mod listener;
pub mod pool;
pub mod primitives;
pub mod ready;
pub mod rotator;
pub mod tracked_map;
pub mod validated_pool;
pub mod watcher;

#[cfg(any(test, feature = "mocks"))]
pub mod mocks;
