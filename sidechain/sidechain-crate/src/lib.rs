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

//! Reexport all the sidechain stuff in one crate

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(all(feature = "std", feature = "sgx"))]
compile_error!("feature \"std\" and feature \"sgx\" cannot be enabled at the same time");

pub use its_block_composer as block_composer;

pub use its_consensus_aura as aura;

pub use its_consensus_common as consensus_common;

pub use its_consensus_slots as slots;

pub use its_primitives as primitives;

pub use its_rpc_handler as rpc_handler;

pub use its_state as state;

pub use its_top_pool_executor as top_pool_executor;

pub use its_validateer_fetch as validateer_fetch;
