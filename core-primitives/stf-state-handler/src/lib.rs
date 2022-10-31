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
#![feature(assert_matches)]

#[cfg(all(feature = "std", feature = "sgx"))]
compile_error!("feature \"std\" and feature \"sgx\" cannot be enabled at the same time");

#[cfg(all(not(feature = "std"), feature = "sgx"))]
extern crate sgx_tstd as std;

// re-export module to properly feature gate sgx and regular std environment
#[cfg(all(not(feature = "std"), feature = "sgx"))]
pub mod sgx_reexport_prelude {
	pub use rust_base58_sgx as base58;
	pub use thiserror_sgx as thiserror;
}

pub mod error;
pub mod file_io;
pub mod handle_state;
pub mod in_memory_state_file_io;
pub mod query_shard_state;
pub mod state_handler;
pub mod state_initializer;
mod state_snapshot_primitives;
pub mod state_snapshot_repository;
pub mod state_snapshot_repository_loader;
pub mod test;

pub use state_handler::StateHandler;
