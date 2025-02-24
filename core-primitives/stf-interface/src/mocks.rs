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
use codec::{Decode, Encode};
use core::{fmt::Debug, marker::PhantomData};
use itp_node_api_metadata::metadata_mocks::NodeMetadataMock;
use itp_node_api_metadata_provider::NodeMetadataRepository;
use itp_stf_primitives::traits::TrustedCallVerification;
use itp_types::{
	parentchain::{BlockNumber, ParentchainCall, ParentchainId},
	AccountId, Index, Moment, ShardIdentifier,
};

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

	fn storage_hashes_to_update_on_block(
		_state: &mut State,
		_: &ParentchainId,
		_: &ShardIdentifier,
	) -> Vec<Vec<u8>> {
		unimplemented!()
	}
}

impl<TCS, State, StateDiff> StateCallInterface<TCS, State, NodeMetadataRepository<NodeMetadataMock>>
	for StateInterfaceMock<State, StateDiff>
where
	TCS: PartialEq + Encode + Decode + Debug + Clone + Send + Sync + TrustedCallVerification,
{
	type Error = String;

	fn execute_call(
		_state: &mut State,
		_shard: &ShardIdentifier,
		_call: TCS,
		_calls: &mut Vec<ParentchainCall>,
		_node_metadata_repo: Arc<NodeMetadataRepository<NodeMetadataMock>>,
	) -> Result<(), Self::Error> {
		unimplemented!()
	}

	fn on_initialize(
		_state: &mut State,
		_: &ShardIdentifier,
		_number: BlockNumber,
		_now: Moment,
	) -> Result<(), Self::Error> {
		unimplemented!()
	}

	fn maintenance_mode_tasks(
		_state: &mut State,
		_shard: &itp_stf_primitives::types::ShardIdentifier,
		_integritee_block_number: BlockNumber,
		_calls: &mut Vec<ParentchainCall>,
		_node_metadata_repo: Arc<NodeMetadataRepository<NodeMetadataMock>>,
	) -> Result<(), Self::Error> {
		todo!()
	}

	fn on_finalize(_state: &mut State) -> Result<(), Self::Error> {
		unimplemented!()
	}
}

impl<Getter, State, StateDiff> StateGetterInterface<Getter, State>
	for StateInterfaceMock<State, StateDiff>
{
	fn execute_getter(_state: &mut State, _getter: Getter) -> Option<Vec<u8>> {
		None
	}

	fn get_parentchain_mirror_state<V: Decode>(
		_state: &mut State,
		_parentchain_key: Vec<u8>,
		_parentchain_id: &ParentchainId,
	) -> Option<V> {
		todo!()
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
		_calls: &mut Vec<ParentchainCall>,
		_shard: &ShardIdentifier,
		_node_metadata_repo: Arc<NodeMetadataRepository<NodeMetadataMock>>,
	) -> Result<(), Self::Error> {
		unimplemented!()
	}
}

pub struct GetterExecutorMock;

impl ExecuteGetter for GetterExecutorMock {
	fn execute(self) -> Option<Vec<u8>> {
		unimplemented!()
	}
}
