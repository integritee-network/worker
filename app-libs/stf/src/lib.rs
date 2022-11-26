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

/////////////////////////////////////////////////////////////////////////////
#![feature(structural_match)]
#![feature(rustc_attrs)]
#![feature(core_intrinsics)]
#![feature(derive_eq)]
#![cfg_attr(all(not(target_env = "sgx"), not(feature = "std")), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

#[cfg(all(not(feature = "std"), feature = "sgx"))]
extern crate sgx_tstd as std;

#[cfg(feature = "sgx")]
pub use ita_sgx_runtime::{Balance, Index};
#[cfg(feature = "std")]
pub use my_node_runtime::{Balance, Index};

pub use itp_stf_primitives::*;

//#[cfg(all(feature = "test", feature = "sgx"))]
pub mod stf_sgx_tests;

//use crate::test_genesis_setup;
use codec::{Compact, Encode};
use derive_more::Display;
use frame_support::traits::{OriginTrait, UnfilteredDispatchable};
use itp_sgx_externalities::SgxExternalitiesTrait;
use itp_stf_interface::{
	parentchain_pallet::ParentchainPalletInterface,
	sudo_pallet::SudoPalletInterface,
	system_pallet::{SystemPalletAccountInterface, SystemPalletEventInterface},
	ExecuteCall, ExecuteGetter, InitState, StateCallInterface, StateGetterInterface, UpdateState,
};
pub use itp_stf_primitives::{
	helpers, stf_sgx_primitives::types::*, types::KeyPair, TrustedOperation,
};
use itp_stf_primitives::{helpers::enclave_signer_account, stf_sgx::shards_key_hash};
use itp_storage::storage_value_key;
use itp_types::OpaqueCall;
use itp_utils::stringify::account_id_to_string;
use log::*;
use sp_core::{crypto::AccountId32, H256};
use sp_runtime::{
	traits::{StaticLookup, Verify},
	MultiSignature,
};
use std::{fmt::Debug, format, marker::PhantomData, prelude::v1::*, string::String, vec};
pub use trusted_call::*;

#[cfg(feature = "evm")]
pub mod evm_helpers;

#[cfg(all(feature = "test", feature = "sgx"))]
pub mod test_genesis;

pub type Signature = MultiSignature;
pub type AuthorityId = <Signature as Verify>::Signer;
pub type AccountId = AccountId32;
pub type Hash = H256;
pub type BalanceTransferFn = ([u8; 2], AccountId, Compact<u128>);

pub type ShardIdentifier = H256;

pub type StfResult<T> = Result<T, StfError>;

#[derive(Debug, Display, PartialEq, Eq)]
pub enum StfError {
	#[display(fmt = "Insufficient privileges {:?}, are you sure you are root?", _0)]
	MissingPrivileges(AccountId),
	#[display(fmt = "Valid enclave signer account is required")]
	RequireEnclaveSignerAccount,
	#[display(fmt = "Error dispatching runtime call. {:?}", _0)]
	Dispatch(String),
	#[display(fmt = "Not enough funds to perform operation")]
	MissingFunds,
	#[display(fmt = "Invalid Nonce {:?}", _0)]
	InvalidNonce(Index),
	StorageHashMismatch,
	InvalidStorageDiff,
}
pub struct Stf<Call, Getter, State, Runtime> {
	phantom_data: PhantomData<(Call, Getter, State, Runtime)>,
}

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
		crate::test_genesis::test_genesis_setup(&mut state);

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

	fn storage_hashes_to_update_on_block() -> Vec<Vec<u8>> {
		// Get all shards that are currently registered.
		vec![shards_key_hash()]
	}
}

impl<Call, Getter, State, Runtime> StateCallInterface<Call, State>
	for Stf<Call, Getter, State, Runtime>
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
	type EventRecord = frame_system::EventRecord<Runtime::Event, Runtime::Hash>;
	type EventIndex = u32; // For some reason this is not a pub type in frame_system
	type BlockNumber = Runtime::BlockNumber;
	type Hash = Runtime::Hash;

	fn get_events(state: &mut State) -> Vec<Box<Self::EventRecord>> {
		state.execute_with(|| frame_system::Pallet::<Runtime>::read_events_no_consensus())
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
				.dispatch_bypass_filter(Runtime::Origin::root())
				.map_err(|e| {
					Self::Error::Dispatch(format!("Update parentchain block error: {:?}", e.error))
				})
		})?;
		Ok(())
	}
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
	pallet_balances::Call::<Runtime>::set_balance {
		who: enclave_account.into(),
		new_free: 1000.into(),
		new_reserved: 0.into(),
	}
	.dispatch_bypass_filter(Runtime::Origin::root())
	.map_err(|e| {
		StfError::Dispatch(format!("Set Balance for enclave signer account error: {:?}", e.error))
	})
	.map(|_| ())
}
