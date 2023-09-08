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

#[cfg(feature = "test")]
use crate::test_genesis::test_genesis_setup;

use crate::{helpers::enclave_signer_account, Stf, StfError, ENCLAVE_ACCOUNT_KEY};
use codec::Encode;
use frame_support::traits::{OriginTrait, UnfilteredDispatchable};
use itp_node_api::metadata::{provider::AccessNodeMetadata, NodeMetadataTrait};
use itp_sgx_externalities::SgxExternalitiesTrait;
use itp_stf_interface::{
	parentchain_pallet::ParentchainPalletInterface,
	sudo_pallet::SudoPalletInterface,
	system_pallet::{SystemPalletAccountInterface, SystemPalletEventInterface},
	ExecuteCall, ExecuteGetter, InitState, StateCallInterface, StateGetterInterface, UpdateState,
};
use itp_stf_primitives::types::ShardIdentifier;
use itp_storage::storage_value_key;
use itp_types::{parentchain::ParentchainId, OpaqueCall};
use itp_utils::stringify::account_id_to_string;
use log::*;
use sp_runtime::traits::StaticLookup;
use std::{fmt::Debug, format, prelude::v1::*, sync::Arc, vec};

impl<Call, Getter, State, Runtime, AccountId> InitState<State, AccountId>
	for Stf<Call, Getter, State, Runtime>
where
	State: SgxExternalitiesTrait + Debug,
	<State as SgxExternalitiesTrait>::SgxExternalitiesType: core::default::Default,
	Runtime: frame_system::Config<AccountId = AccountId> + pallet_balances::Config,
	<<Runtime as frame_system::Config>::Lookup as StaticLookup>::Source:
		std::convert::From<AccountId>,
	AccountId: Encode,
{
	fn init_state(enclave_account: AccountId) -> State {
		debug!("initializing stf state, account id {}", account_id_to_string(&enclave_account));
		let mut state = State::new(Default::default());

		state.execute_with(|| {
			// Do not set genesis for pallets that are meant to be on-chain
			// use get_storage_hashes_to_update instead.

			sp_io::storage::set(&storage_value_key("Balances", "TotalIssuance"), &11u128.encode());
			sp_io::storage::set(&storage_value_key("Balances", "CreationFee"), &1u128.encode());
			sp_io::storage::set(&storage_value_key("Balances", "TransferFee"), &1u128.encode());
			sp_io::storage::set(
				&storage_value_key("Balances", "TransactionBaseFee"),
				&1u128.encode(),
			);
			sp_io::storage::set(
				&storage_value_key("Balances", "TransactionByteFee"),
				&1u128.encode(),
			);
			sp_io::storage::set(
				&storage_value_key("Balances", "ExistentialDeposit"),
				&1u128.encode(),
			);
		});

		#[cfg(feature = "test")]
		test_genesis_setup(&mut state);

		state.execute_with(|| {
			sp_io::storage::set(
				&storage_value_key("Sudo", ENCLAVE_ACCOUNT_KEY),
				&enclave_account.encode(),
			);

			if let Err(e) = create_enclave_self_account::<Runtime, AccountId>(enclave_account) {
				error!("Failed to initialize the enclave signer account: {:?}", e);
			}
		});

		trace!("Returning updated state: {:?}", state);
		state
	}
}

impl<Call, Getter, State, Runtime>
	UpdateState<State, <State as SgxExternalitiesTrait>::SgxExternalitiesDiffType>
	for Stf<Call, Getter, State, Runtime>
where
	State: SgxExternalitiesTrait + Debug,
	<State as SgxExternalitiesTrait>::SgxExternalitiesType: core::default::Default,
	<State as SgxExternalitiesTrait>::SgxExternalitiesDiffType:
		IntoIterator<Item = (Vec<u8>, Option<Vec<u8>>)>,
{
	fn apply_state_diff(
		state: &mut State,
		map_update: <State as SgxExternalitiesTrait>::SgxExternalitiesDiffType,
	) {
		state.execute_with(|| {
			map_update.into_iter().for_each(|(k, v)| {
				match v {
					Some(value) => sp_io::storage::set(&k, &value),
					None => sp_io::storage::clear(&k),
				};
			});
		});
	}

	fn storage_hashes_to_update_on_block(parentchain_id: &ParentchainId) -> Vec<Vec<u8>> {
		// Get all shards that are currently registered.
		match parentchain_id {
			ParentchainId::Integritee => vec![shards_key_hash()],
			ParentchainId::TargetA => vec![],
			ParentchainId::TargetB => vec![],
		}
	}
}

impl<Call, Getter, State, Runtime, NodeMetadataRepository>
	StateCallInterface<Call, State, NodeMetadataRepository> for Stf<Call, Getter, State, Runtime>
where
	Call: ExecuteCall<NodeMetadataRepository>,
	State: SgxExternalitiesTrait + Debug,
	NodeMetadataRepository: AccessNodeMetadata,
	NodeMetadataRepository::MetadataType: NodeMetadataTrait,
{
	type Error = Call::Error;

	fn execute_call(
		state: &mut State,
		call: Call,
		calls: &mut Vec<OpaqueCall>,
		node_metadata_repo: Arc<NodeMetadataRepository>,
	) -> Result<(), Self::Error> {
		state.execute_with(|| call.execute(calls, node_metadata_repo))
	}
}

impl<Call, Getter, State, Runtime> StateGetterInterface<Getter, State>
	for Stf<Call, Getter, State, Runtime>
where
	Getter: ExecuteGetter,
	State: SgxExternalitiesTrait + Debug,
{
	fn execute_getter(state: &mut State, getter: Getter) -> Option<Vec<u8>> {
		state.execute_with(|| getter.execute())
	}
}

impl<Call, Getter, State, Runtime> SudoPalletInterface<State> for Stf<Call, Getter, State, Runtime>
where
	State: SgxExternalitiesTrait,
	Runtime: frame_system::Config + pallet_sudo::Config,
{
	type AccountId = Runtime::AccountId;

	fn get_root(state: &mut State) -> Self::AccountId {
		state.execute_with(|| pallet_sudo::Pallet::<Runtime>::key().expect("No root account"))
	}

	fn get_enclave_account(state: &mut State) -> Self::AccountId {
		state.execute_with(enclave_signer_account::<Self::AccountId>)
	}
}

impl<Call, Getter, State, Runtime, AccountId> SystemPalletAccountInterface<State, AccountId>
	for Stf<Call, Getter, State, Runtime>
where
	State: SgxExternalitiesTrait,
	Runtime: frame_system::Config<AccountId = AccountId>,
	AccountId: Encode,
{
	type Index = Runtime::Index;
	type AccountData = Runtime::AccountData;

	fn get_account_nonce(state: &mut State, account: &AccountId) -> Self::Index {
		state.execute_with(|| {
			let nonce = frame_system::Pallet::<Runtime>::account_nonce(account);
			debug!("Account {} nonce is {:?}", account_id_to_string(account), nonce);
			nonce
		})
	}

	fn get_account_data(state: &mut State, account: &AccountId) -> Self::AccountData {
		state.execute_with(|| frame_system::Pallet::<Runtime>::account(account).data)
	}
}

impl<Call, Getter, State, Runtime> SystemPalletEventInterface<State>
	for Stf<Call, Getter, State, Runtime>
where
	State: SgxExternalitiesTrait,
	Runtime: frame_system::Config,
{
	type EventRecord = frame_system::EventRecord<Runtime::RuntimeEvent, Runtime::Hash>;
	type EventIndex = u32; // For some reason this is not a pub type in frame_system
	type BlockNumber = Runtime::BlockNumber;
	type Hash = Runtime::Hash;

	fn get_events(state: &mut State) -> Vec<Box<Self::EventRecord>> {
		// Fixme: Not nice to have to call collect here, but we can't use impl Iterator<..>
		// in trait method return types yet, see:
		// https://rust-lang.github.io/impl-trait-initiative/RFCs/rpit-in-traits.html
		state.execute_with(|| frame_system::Pallet::<Runtime>::read_events_no_consensus().collect())
	}

	fn get_event_count(state: &mut State) -> Self::EventIndex {
		state.execute_with(|| frame_system::Pallet::<Runtime>::event_count())
	}

	fn get_event_topics(
		state: &mut State,
		topic: &Self::Hash,
	) -> Vec<(Self::BlockNumber, Self::EventIndex)> {
		state.execute_with(|| frame_system::Pallet::<Runtime>::event_topics(topic))
	}

	fn reset_events(state: &mut State) {
		state.execute_with(|| frame_system::Pallet::<Runtime>::reset_events())
	}
}

impl<Call, Getter, State, Runtime, ParentchainHeader>
	ParentchainPalletInterface<State, ParentchainHeader> for Stf<Call, Getter, State, Runtime>
where
	State: SgxExternalitiesTrait,
	Runtime: frame_system::Config<Header = ParentchainHeader> + pallet_parentchain::Config,
{
	type Error = StfError;

	fn update_parentchain_block(
		state: &mut State,
		header: ParentchainHeader,
	) -> Result<(), Self::Error> {
		state.execute_with(|| {
			pallet_parentchain::Call::<Runtime>::set_block { header }
				.dispatch_bypass_filter(Runtime::RuntimeOrigin::root())
				.map_err(|e| {
					Self::Error::Dispatch(format!("Update parentchain block error: {:?}", e.error))
				})
		})?;
		Ok(())
	}
}

pub fn storage_hashes_to_update_per_shard(_shard: &ShardIdentifier) -> Vec<Vec<u8>> {
	Vec::new()
}

pub fn shards_key_hash() -> Vec<u8> {
	// here you have to point to a storage value containing a Vec of
	// ShardIdentifiers the enclave uses this to autosubscribe to no shards
	vec![]
}

/// Creates valid enclave account with a balance that is above the existential deposit.
/// !! Requires a root to be set.
fn create_enclave_self_account<Runtime, AccountId>(
	enclave_account: AccountId,
) -> Result<(), StfError>
where
	Runtime: frame_system::Config<AccountId = AccountId> + pallet_balances::Config,
	<<Runtime as frame_system::Config>::Lookup as StaticLookup>::Source: From<AccountId>,
	Runtime::Balance: From<u32>,
{
	pallet_balances::Call::<Runtime>::force_set_balance {
		who: enclave_account.into(),
		new_free: 1000.into(),
	}
	.dispatch_bypass_filter(Runtime::RuntimeOrigin::root())
	.map_err(|e| {
		StfError::Dispatch(format!("Set Balance for enclave signer account error: {:?}", e.error))
	})
	.map(|_| ())
}
