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

//! Provides a state interface.
//! This allow to easily mock the stf and exchange it with another storage.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use itp_types::OpaqueCall;

#[cfg(feature = "mocks")]
pub mod mocks;
pub mod parentchain_pallet;
pub mod sudo_pallet;
pub mod system_pallet;

pub trait StateInterface<State, StateDiff> {
	fn init_state(&self, initial_input: Vec<u8>) -> State;
	fn apply_state_diff(&self, state: &mut State, state_diff: StateDiff);
	fn storage_hashes_to_update_on_block(&self) -> Vec<Vec<u8>>;
}

pub trait StateCallInterface<Call, State> {
	type Error;

	fn execute_call(
		&self,
		state: &mut State,
		call: Call,
		calls: &mut Vec<OpaqueCall>,
		unshield_funds_fn: [u8; 2],
	) -> Result<(), Self::Error>;
}

pub trait StateGetterInterface<Getter, State> {
	fn execute_getter(&self, state: &mut State, getter: Getter) -> Option<Vec<u8>>;
}

pub trait ExecuteCall {
	type Error;

	fn execute(
		self,
		calls: &mut Vec<OpaqueCall>,
		unshield_funds_fn: [u8; 2],
	) -> Result<(), Self::Error>;

	fn get_storage_hashes_to_update(self) -> Vec<Vec<u8>>;
}

pub trait ExecuteGetter {
	fn execute(self) -> Option<Vec<u8>>;
	fn get_storage_hashes_to_update(self) -> Vec<Vec<u8>>;
}
