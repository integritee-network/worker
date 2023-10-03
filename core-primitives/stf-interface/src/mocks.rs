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
use alloc::{string::String, sync::Arc, vec::Vec};
use core::marker::PhantomData;
use itp_node_api_metadata::metadata_mocks::NodeMetadataMock;
use itp_node_api_metadata_provider::NodeMetadataRepository;
use itp_types::{parentchain::ParentchainId, AccountId, Index, OpaqueCall};

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

	fn storage_hashes_to_update_on_block(_: &ParentchainId) -> Vec<Vec<u8>> {
		unimplemented!()
	}
}

impl<Call, State, StateDiff>
	StateCallInterface<Call, State, NodeMetadataRepository<NodeMetadataMock>>
	for StateInterfaceMock<State, StateDiff>
{
	type Error = String;

	fn execute_call(
		_state: &mut State,
		_call: Call,
		_calls: &mut Vec<OpaqueCall>,
		_node_metadata_repo: Arc<NodeMetadataRepository<NodeMetadataMock>>,
	) -> Result<(), Self::Error> {
		unimplemented!()
	}
}

impl<Getter, State, StateDiff> StateGetterInterface<Getter, State>
	for StateInterfaceMock<State, StateDiff>
{
	fn execute_getter(_state: &mut State, _getter: Getter) -> Option<Vec<u8>> {
		None
	}
}

impl<State, StateDiff> SystemPalletAccountInterface<State, AccountId>
	for StateInterfaceMock<State, StateDiff>
{
	type AccountData = String;
	type Index = Index;

	fn get_account_nonce(_state: &mut State, _account_id: &AccountId) -> Self::Index {
		unimplemented!()
	}
	fn get_account_data(_state: &mut State, _account_id: &AccountId) -> Self::AccountData {
		unimplemented!()
	}
}

pub struct CallExecutorMock;

impl ExecuteCall<NodeMetadataRepository<NodeMetadataMock>> for CallExecutorMock {
	type Error = String;

	fn execute(
		self,
		_calls: &mut Vec<OpaqueCall>,
		_node_metadata_repo: Arc<NodeMetadataRepository<NodeMetadataMock>>,
	) -> Result<(), Self::Error> {
		unimplemented!()
	}

	fn get_storage_hashes_to_update(self) -> Vec<Vec<u8>> {
		unimplemented!()
	}
}

pub struct GetterExecutorMock;

impl ExecuteGetter for GetterExecutorMock {
	fn execute(self) -> Option<Vec<u8>> {
		unimplemented!()
	}

	fn get_storage_hashes_to_update(self) -> Vec<Vec<u8>> {
		unimplemented!()
	}
}
