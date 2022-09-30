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

use crate::{
	helpers::enclave_signer_account, AccountData, AccountId, Index, ParentchainHeader,
	ShardIdentifier, Stf, StfError, ENCLAVE_ACCOUNT_KEY,
};
use codec::{Decode, Encode};
use ita_sgx_runtime::{Runtime, Sudo, System};
use itp_sgx_externalities::SgxExternalitiesTrait;
use itp_stf_interface::{
	parentchain_pallet::ParentchainPalletInterface, sudo_pallet::SudoPalletInterface,
	system_pallet::SystemPalletAccountInterface, ExecuteCall, ExecuteGetter, StateCallInterface,
	StateGetterInterface, StateInterface,
};
use itp_storage::storage_value_key;
use itp_types::OpaqueCall;
use itp_utils::stringify::account_id_to_string;
use log::*;
use sp_runtime::MultiAddress;
use std::{fmt::Debug, format, prelude::v1::*, vec};
use support::traits::UnfilteredDispatchable;

impl<Call, Getter, State>
	StateInterface<State, <State as SgxExternalitiesTrait>::SgxExternalitiesDiffType>
	for Stf<Call, Getter, State>
where
	State: SgxExternalitiesTrait + Debug,
	<State as SgxExternalitiesTrait>::SgxExternalitiesType: core::default::Default,
	<State as SgxExternalitiesTrait>::SgxExternalitiesDiffType:
		IntoIterator<Item = (Vec<u8>, Option<Vec<u8>>)>,
{
	fn init_state(initial_input: Vec<u8>) -> State {
		let enclave_account = AccountId::decode(&mut initial_input.as_slice()).unwrap();
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

			if let Err(e) = create_enclave_self_account(&enclave_account) {
				error!("Failed to initialize the enclave signer account: {:?}", e);
			}
		});

		trace!("Returning updated state: {:?}", state);
		state
	}

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

	fn storage_hashes_to_update_on_block() -> Vec<Vec<u8>> {
		let mut key_hashes = Vec::new();

		// get all shards that are currently registered
		key_hashes.push(shards_key_hash());
		key_hashes
	}
}

impl<Call, Getter, State> StateCallInterface<Call, State> for Stf<Call, Getter, State>
where
	Call: ExecuteCall,
	State: SgxExternalitiesTrait + Debug,
{
	type Error = Call::Error;

	fn execute_call(
		state: &mut State,
		call: Call,
		calls: &mut Vec<OpaqueCall>,
		unshield_funds_fn: [u8; 2],
	) -> Result<(), Self::Error> {
		state.execute_with(|| call.execute(calls, unshield_funds_fn))
	}
}

impl<Call, Getter, State> StateGetterInterface<Getter, State> for Stf<Call, Getter, State>
where
	Getter: ExecuteGetter,
	State: SgxExternalitiesTrait + Debug,
{
	fn execute_getter(state: &mut State, getter: Getter) -> Option<Vec<u8>> {
		state.execute_with(|| getter.execute())
	}
}

impl<Call, Getter, State> SudoPalletInterface<State> for Stf<Call, Getter, State>
where
	State: SgxExternalitiesTrait,
{
	fn get_root(state: &mut State) -> AccountId {
		state.execute_with(|| Sudo::key().expect("No root account"))
	}
	fn get_enclave_account(state: &mut State) -> AccountId {
		state.execute_with(|| enclave_signer_account())
	}
}

impl<Call, Getter, State> SystemPalletAccountInterface<State> for Stf<Call, Getter, State>
where
	State: SgxExternalitiesTrait,
{
	fn get_account_nonce(state: &mut State, account: &AccountId) -> Index {
		state.execute_with(|| {
			let nonce = System::account_nonce(account);
			debug!("Account {} nonce is {}", account_id_to_string(&account), nonce);
			nonce
		})
	}
	fn get_account_data(state: &mut State, account: &AccountId) -> AccountData {
		state.execute_with(|| System::account(account).data)
	}
}

impl<Call, Getter, State> ParentchainPalletInterface<State, ParentchainHeader>
	for Stf<Call, Getter, State>
where
	State: SgxExternalitiesTrait,
{
	type Error = StfError;

	fn update_parentchain_block(
		state: &mut State,
		header: ParentchainHeader,
	) -> Result<(), Self::Error> {
		state.execute_with(|| {
			ita_sgx_runtime::ParentchainCall::<Runtime>::set_block { header }
				.dispatch_bypass_filter(ita_sgx_runtime::Origin::root())
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

pub fn is_root(account: &AccountId) -> bool {
	Sudo::key().map_or(false, |k| account == &k)
}

/// Creates valid enclave account with a balance that is above the existential deposit.
/// !! Requires a root to be set.
fn create_enclave_self_account(enclave_account: &AccountId) -> Result<(), StfError> {
	ita_sgx_runtime::BalancesCall::<Runtime>::set_balance {
		who: MultiAddress::Id(enclave_account.clone()),
		new_free: 1000,
		new_reserved: 0,
	}
	.dispatch_bypass_filter(ita_sgx_runtime::Origin::root())
	.map_err(|e| {
		StfError::Dispatch(format!("Set Balance for enclave signer account error: {:?}", e.error))
	})
	.map(|_| ())
}
