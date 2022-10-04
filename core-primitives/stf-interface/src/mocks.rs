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

//! Provides a mock which implements all traits within this crate.


extern crate alloc;
use crate::{
	system_pallet::SystemPalletAccountInterface, ExecuteCall, ExecuteGetter, InitState,
	StateCallInterface, StateGetterInterface, UpdateState,
};
use alloc::{string::String, vec::Vec};
use core::marker::PhantomData;
use itp_types::OpaqueCall;



lazy_static! {
	/// Global counter for event access.
	pub static ref EVENT_HANDLER: RwLock<<EventCounter> = RwLock::new(EventCounter::new(0))
}

pub struct EventCounter {
	counter: u32;
}

impl EventCounter {
	pub fn new(counter: u32) -> Self {
		Self { counter }
	}

	fn set_counter(&mut self, counter: u32) {
		*self.counter = counter;
	}

	fn reset_counter(&mut self) {
		*self.counter = 0;
	}

	fn get_counter(&self) -> u32 {
		self.counter
	}
}

pub fn set_event_counter(counter: u32) {
	let mut rw_lock = cache.write().unwrap();
	rw_lock.set_counter(counter);
}

#[derive(Default)]
pub struct StateInterfaceMock<State, StateDiff> {
	_phantom: PhantomData<(State, StateDiff)>,
}

impl<State, StateDiff, AccountId> InitState<State, AccountId>
	for StateInterfaceMock<State, StateDiff>
{
	fn init_state(_enclave_account: AccountId) -> State {
		unimplemented!()
	}
}

impl<State, StateDiff> UpdateState<State, StateDiff> for StateInterfaceMock<State, StateDiff> {
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

impl<State, StateDiff, AccountId> SystemPalletAccountInterface<State, AccountId>
	for StateInterfaceMock<State, StateDiff>
{
	type AccountData = String;
	type Index = u32;
	type EventRecord = String;
	type EventIndex = u32;
	type BlockNumber = u32;
	type Hash = String;

	fn get_account_nonce(_state: &mut State, _account_id: &AccountId) -> Self::Index {
		unimplemented!()
	}
	fn get_account_data(_state: &mut State, _account_id: &AccountId) -> Self::AccountData {
		unimplemented!()
	}
	fn get_events(_state: &mut State) -> Vec<Box<Self::EventRecord>>{
		unimplemented!()
	}

	fn get_event_count(_state: &mut State) -> Self::EventIndex{
		let lock = EVENT_HANDLER.read().unwrap();
		lock.get_counter();
	}

	fn get_event_topics(
		_state: &mut State,
		_topic: &Self::Hash,
	) -> Vec<(Self::BlockNumber, Self::EventIndex)>{
		unimplemented!()
	}

	fn reset_events(state: &mut State){
		let mut lock = EVENT_HANDLER.write().unwrap();
		lock.reset_counter();
	}

pub struct CallExecutorMock {}

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

impl ExecuteGetter for GetterExecutorMock {
	fn execute(self) -> Option<Vec<u8>> {
		unimplemented!()
	}

	fn get_storage_hashes_to_update(self) -> Vec<Vec<u8>> {
		unimplemented!()
	}
}
