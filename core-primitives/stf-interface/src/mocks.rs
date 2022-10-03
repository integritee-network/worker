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

extern crate alloc;
use crate::{
	system_pallet::SystemPalletAccountInterface, ExecuteCall, ExecuteGetter, StateCallInterface,
	StateGetterInterface, StateInterface,
};
use alloc::{string::String, vec::Vec};
use core::marker::PhantomData;
use itp_types::{AccountData, AccountId, Index, OpaqueCall};

#[derive(Default)]
pub struct StateInterfaceMock<State, StateDiff> {
	_phantom: PhantomData<(State, StateDiff)>,
}

impl<State, StateDiff> StateInterfaceMock<State, StateDiff> {
	pub fn new() -> Self {
		StateInterfaceMock { _phantom: Default::default() }
	}
}

impl<State, StateDiff> StateInterface<State, StateDiff> for StateInterfaceMock<State, StateDiff> {
	fn init_state(_initial_input: Vec<u8>) -> State {
		unimplemented!()
	}

	fn apply_state_diff(_state: &mut State, _state_diff: StateDiff) {
		unimplemented!()
	}

	fn storage_hashes_to_update_on_block() -> Vec<Vec<u8>> {
		unimplemented!()
	}
}

impl<Call, State, StateDiff> StateCallInterface<Call, State>
	for StateInterfaceMock<State, StateDiff>
{
	type Error = String;

	fn execute_call(
		_state: &mut State,
		_call: Call,
		_calls: &mut Vec<OpaqueCall>,
		_unshield_funds_fn: [u8; 2],
	) -> Result<(), Self::Error> {
		unimplemented!()
	}
}

impl<Getter, State, StateDiff> StateGetterInterface<Getter, State>
	for StateInterfaceMock<State, StateDiff>
{
	fn execute_getter(_state: &mut State, _getter: Getter) -> Option<Vec<u8>> {
		unimplemented!()
	}
}

impl<State, StateDiff> SystemPalletAccountInterface<State>
	for StateInterfaceMock<State, StateDiff>
{
	fn get_account_nonce(_state: &mut State, _account_id: &AccountId) -> Index {
		unimplemented!()
	}
	fn get_account_data(_state: &mut State, _account_id: &AccountId) -> AccountData {
		unimplemented!()
	}
}

pub struct CallExecutorMock {}

impl CallExecutorMock {
	pub fn new() -> Self {
		Self::default()
	}
}

impl CallExecutorMock {
	fn default() -> Self {
		Self {}
	}
}

impl ExecuteCall for CallExecutorMock {
	type Error = String;

	fn execute(
		self,
		_calls: &mut Vec<OpaqueCall>,
		_unshield_funds_fn: [u8; 2],
	) -> Result<(), Self::Error> {
		unimplemented!()
	}

	fn get_storage_hashes_to_update(self) -> Vec<Vec<u8>> {
		unimplemented!()
	}
}

pub struct GetterExecutorMock {}

impl GetterExecutorMock {
	pub fn new() -> Self {
		Self::default()
	}
}

impl GetterExecutorMock {
	fn default() -> Self {
		Self {}
	}
}

impl ExecuteGetter for GetterExecutorMock {
	fn execute(self) -> Option<Vec<u8>> {
		unimplemented!()
	}

	fn get_storage_hashes_to_update(self) -> Vec<Vec<u8>> {
		unimplemented!()
	}
}
