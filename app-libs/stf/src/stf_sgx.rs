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
	helpers::{enclave_signer_account, ensure_enclave_signer_account},
	AccountData, AccountId, Getter, Index, ParentchainHeader, PublicGetter, ShardIdentifier, State,
	StateTypeDiff, Stf, StfError, StfResult, TrustedCall, TrustedCallSigned, TrustedGetter,
	ENCLAVE_ACCOUNT_KEY,
};
use codec::Encode;
use ita_sgx_runtime::{Runtime, Sudo, System};
use itp_sgx_externalities::SgxExternalitiesTrait;
use itp_storage::storage_value_key;
use itp_types::OpaqueCall;
use itp_utils::stringify::account_id_to_string;
use its_state::SidechainSystemExt;
use log::*;
use sidechain_primitives::types::{BlockHash, BlockNumber as SidechainBlockNumber, Timestamp};
use sp_io::hashing::blake2_256;
use sp_runtime::MultiAddress;
use std::{format, prelude::v1::*, vec};
use support::{ensure, traits::UnfilteredDispatchable};

#[cfg(feature = "evm")]
use ita_sgx_runtime::{AddressMapping, HashedAddressMapping};

#[cfg(feature = "evm")]
use crate::evm_helpers::{
	create_code_hash, evm_create2_address, evm_create_address, get_evm_account,
	get_evm_account_codes, get_evm_account_storages,
};

impl Stf {
	pub fn init_state(enclave_account: AccountId) -> State {
		debug!("initializing stf state, account id {}", account_id_to_string(&enclave_account));
		let mut ext = State::new();

		ext.execute_with(|| {
			// do not set genesis for pallets that are meant to be on-chain
			// use get_storage_hashes_to_update instead

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
		test_genesis_setup(&mut ext);

		ext.execute_with(|| {
			sp_io::storage::set(
				&storage_value_key("Sudo", ENCLAVE_ACCOUNT_KEY),
				&enclave_account.encode(),
			);

			if let Err(e) = Self::create_enclave_self_account(&enclave_account) {
				error!("Failed to initialize the enclave signer account: {:?}", e);
			}
		});

		trace!("Returning updated state: {:?}", ext);
		ext
	}

	pub fn get_state(ext: &mut impl SgxExternalitiesTrait, getter: Getter) -> Option<Vec<u8>> {
		ext.execute_with(|| match getter {
			Getter::trusted(g) => match g.getter {
				TrustedGetter::free_balance(who) => {
					let info = System::account(&who);
					debug!("TrustedGetter free_balance");
					debug!("AccountInfo for {} is {:?}", account_id_to_string(&who), info);
					debug!("Account free balance is {}", info.data.free);
					Some(info.data.free.encode())
				},

				TrustedGetter::reserved_balance(who) => {
					let info = System::account(&who);
					debug!("TrustedGetter reserved_balance");
					debug!("AccountInfo for {} is {:?}", account_id_to_string(&who), info);
					debug!("Account reserved balance is {}", info.data.reserved);
					Some(info.data.reserved.encode())
				},
				TrustedGetter::nonce(who) => {
					let info = System::account(&who);
					debug!("TrustedGetter nonce");
					debug!("AccountInfo for {} is {:?}", account_id_to_string(&who), info);
					debug!("Account nonce is {}", info.nonce);
					Some(info.nonce.encode())
				},
				#[cfg(feature = "evm")]
				TrustedGetter::evm_nonce(who) => {
					let evm_account = get_evm_account(&who);
					let evm_account = HashedAddressMapping::into_account_id(evm_account);
					let info = System::account(&who);
					debug!("TrustedGetter evm_nonce");
					debug!("AccountInfo for {} is {:?}", account_id_to_string(&evm_account), info);
					debug!("Account nonce is {}", info.nonce);
					Some(info.nonce.encode())
				},
				#[cfg(feature = "evm")]
				TrustedGetter::evm_account_codes(_who, evm_account) =>
				// TODO: This probably needs some security check if who == evm_account (or assosciated)
					if let Some(info) = get_evm_account_codes(&evm_account) {
						debug!("TrustedGetter Evm Account Codes");
						debug!("AccountCodes for {} is {:?}", evm_account, info);
						Some(info) // TOOD: encoded?
					} else {
						None
					},
				#[cfg(feature = "evm")]
				TrustedGetter::evm_account_storages(_who, evm_account, index) =>
				// TODO: This probably needs some security check if who == evm_account (or assosciated)
					if let Some(value) = get_evm_account_storages(&evm_account, &index) {
						debug!("TrustedGetter Evm Account Storages");
						debug!("AccountStorages for {} is {:?}", evm_account, value);
						Some(value.encode())
					} else {
						None
					},
			},
			Getter::public(g) => match g {
				PublicGetter::some_value => Some(42u32.encode()),
			},
		})
	}

	pub fn execute(
		ext: &mut impl SgxExternalitiesTrait,
		call: TrustedCallSigned,
		calls: &mut Vec<OpaqueCall>,
		unshield_funds_fn: [u8; 2],
	) -> StfResult<()> {
		let call_hash = blake2_256(&call.encode());
		ext.execute_with(|| {
			let sender = call.call.sender_account().clone();
			ensure!(
				call.nonce == System::account_nonce(&sender),
				StfError::InvalidNonce(call.nonce)
			);
			match call.call {
				TrustedCall::balance_set_balance(root, who, free_balance, reserved_balance) => {
					ensure!(is_root(&root), StfError::MissingPrivileges(root));
					debug!(
						"balance_set_balance({}, {}, {})",
						account_id_to_string(&who),
						free_balance,
						reserved_balance
					);
					ita_sgx_runtime::BalancesCall::<Runtime>::set_balance {
						who: MultiAddress::Id(who),
						new_free: free_balance,
						new_reserved: reserved_balance,
					}
					.dispatch_bypass_filter(ita_sgx_runtime::Origin::root())
					.map_err(|e| {
						StfError::Dispatch(format!("Balance Set Balance error: {:?}", e.error))
					})?;
					Ok(())
				},
				TrustedCall::balance_transfer(from, to, value) => {
					let origin = ita_sgx_runtime::Origin::signed(from.clone());
					debug!(
						"balance_transfer({}, {}, {})",
						account_id_to_string(&from),
						account_id_to_string(&to),
						value
					);
					ita_sgx_runtime::BalancesCall::<Runtime>::transfer {
						dest: MultiAddress::Id(to),
						value,
					}
					.dispatch_bypass_filter(origin)
					.map_err(|e| {
						StfError::Dispatch(format!("Balance Transfer error: {:?}", e.error))
					})?;
					Ok(())
				},
				TrustedCall::balance_unshield(account_incognito, beneficiary, value, shard) => {
					debug!(
						"balance_unshield({}, {}, {}, {})",
						account_id_to_string(&account_incognito),
						account_id_to_string(&beneficiary),
						value,
						shard
					);

					Self::unshield_funds(account_incognito, value)?;
					calls.push(OpaqueCall::from_tuple(&(
						unshield_funds_fn,
						beneficiary,
						value,
						shard,
						call_hash,
					)));
					Ok(())
				},
				TrustedCall::balance_shield(enclave_account, who, value) => {
					ensure_enclave_signer_account(&enclave_account)?;
					debug!("balance_shield({}, {})", account_id_to_string(&who), value);
					Self::shield_funds(who, value)?;
					Ok(())
				},
				#[cfg(feature = "evm")]
				TrustedCall::evm_withdraw(from, address, value) => {
					debug!("evm_withdraw({}, {}, {})", account_id_to_string(&from), address, value);
					ita_sgx_runtime::EvmCall::<Runtime>::withdraw { address, value }
						.dispatch_bypass_filter(ita_sgx_runtime::Origin::signed(from))
						.map_err(|e| {
							StfError::Dispatch(format!("Evm Withdraw error: {:?}", e.error))
						})?;
					Ok(())
				},
				#[cfg(feature = "evm")]
				TrustedCall::evm_call(
					from,
					source,
					target,
					input,
					value,
					gas_limit,
					max_fee_per_gas,
					max_priority_fee_per_gas,
					nonce,
					access_list,
				) => {
					debug!(
						"evm_call(from: {}, source: {}, target: {})",
						account_id_to_string(&from),
						source,
						target
					);
					ita_sgx_runtime::EvmCall::<Runtime>::call {
						source,
						target,
						input,
						value,
						gas_limit,
						max_fee_per_gas,
						max_priority_fee_per_gas,
						nonce,
						access_list,
					}
					.dispatch_bypass_filter(ita_sgx_runtime::Origin::signed(from))
					.map_err(|e| StfError::Dispatch(format!("Evm Call error: {:?}", e.error)))?;
					Ok(())
				},
				#[cfg(feature = "evm")]
				TrustedCall::evm_create(
					from,
					source,
					init,
					value,
					gas_limit,
					max_fee_per_gas,
					max_priority_fee_per_gas,
					nonce,
					access_list,
				) => {
					debug!(
						"evm_create(from: {}, source: {}, value: {})",
						account_id_to_string(&from),
						source,
						value
					);
					let nonce_evm_account =
						System::account_nonce(&HashedAddressMapping::into_account_id(source));
					ita_sgx_runtime::EvmCall::<Runtime>::create {
						source,
						init,
						value,
						gas_limit,
						max_fee_per_gas,
						max_priority_fee_per_gas,
						nonce,
						access_list,
					}
					.dispatch_bypass_filter(ita_sgx_runtime::Origin::signed(from))
					.map_err(|e| StfError::Dispatch(format!("Evm Create error: {:?}", e.error)))?;
					let contract_address = evm_create_address(source, nonce_evm_account);
					info!("Trying to create evm contract with address {:?}", contract_address);
					Ok(())
				},
				#[cfg(feature = "evm")]
				TrustedCall::evm_create2(
					from,
					source,
					init,
					salt,
					value,
					gas_limit,
					max_fee_per_gas,
					max_priority_fee_per_gas,
					nonce,
					access_list,
				) => {
					debug!(
						"evm_create2(from: {}, source: {}, value: {})",
						account_id_to_string(&from),
						source,
						value
					);
					let code_hash = create_code_hash(&init);
					ita_sgx_runtime::EvmCall::<Runtime>::create2 {
						source,
						init,
						salt,
						value,
						gas_limit,
						max_fee_per_gas,
						max_priority_fee_per_gas,
						nonce,
						access_list,
					}
					.dispatch_bypass_filter(ita_sgx_runtime::Origin::signed(from))
					.map_err(|e| StfError::Dispatch(format!("Evm Create2 error: {:?}", e.error)))?;
					let contract_address = evm_create2_address(source, salt, code_hash);
					info!("Trying to create evm contract with address {:?}", contract_address);
					Ok(())
				},
			}?;
			System::inc_account_nonce(&sender);
			Ok(())
		})
	}

	/// Creates valid enclave account with a balance that is above the existential deposit.
	/// !! Requires a root to be set.
	fn create_enclave_self_account(enclave_account: &AccountId) -> StfResult<()> {
		ita_sgx_runtime::BalancesCall::<Runtime>::set_balance {
			who: MultiAddress::Id(enclave_account.clone()),
			new_free: 1000,
			new_reserved: 0,
		}
		.dispatch_bypass_filter(ita_sgx_runtime::Origin::root())
		.map_err(|e| {
			StfError::Dispatch(format!(
				"Set Balance for enclave signer account error: {:?}",
				e.error
			))
		})
		.map(|_| ())
	}

	fn shield_funds(account: AccountId, amount: u128) -> StfResult<()> {
		let account_info = System::account(&account);
		ita_sgx_runtime::BalancesCall::<Runtime>::set_balance {
			who: MultiAddress::Id(account),
			new_free: account_info.data.free + amount,
			new_reserved: account_info.data.reserved,
		}
		.dispatch_bypass_filter(ita_sgx_runtime::Origin::root())
		.map_err(|e| StfError::Dispatch(format!("Shield funds error: {:?}", e.error)))?;

		Ok(())
	}

	fn unshield_funds(account: AccountId, amount: u128) -> StfResult<()> {
		let account_info = System::account(&account);
		if account_info.data.free < amount {
			return Err(StfError::MissingFunds)
		}

		ita_sgx_runtime::BalancesCall::<Runtime>::set_balance {
			who: MultiAddress::Id(account),
			new_free: account_info.data.free - amount,
			new_reserved: account_info.data.reserved,
		}
		.dispatch_bypass_filter(ita_sgx_runtime::Origin::root())
		.map_err(|e| StfError::Dispatch(format!("Unshield funds error: {:?}", e.error)))?;
		Ok(())
	}

	pub fn update_storage(ext: &mut impl SgxExternalitiesTrait, map_update: &StateTypeDiff) {
		ext.execute_with(|| {
			map_update.iter().for_each(|(k, v)| {
				match v {
					Some(value) => sp_io::storage::set(k, value),
					None => sp_io::storage::clear(k),
				};
			});
		});
	}

	/// Updates the block number, block hash and parent hash of the parentchain block.
	pub fn update_parentchain_block(
		ext: &mut impl SgxExternalitiesTrait,
		header: ParentchainHeader,
	) -> StfResult<()> {
		ext.execute_with(|| {
			ita_sgx_runtime::ParentchainCall::<Runtime>::set_block { header }
				.dispatch_bypass_filter(ita_sgx_runtime::Origin::root())
				.map_err(|e| {
					StfError::Dispatch(format!("Update parentchain block error: {:?}", e.error))
				})
		})?;
		Ok(())
	}

	pub fn get_storage_hashes_to_update(call: &TrustedCallSigned) -> Vec<Vec<u8>> {
		let key_hashes = Vec::new();
		match call.call {
			TrustedCall::balance_set_balance(_, _, _, _) => debug!("No storage updates needed..."),
			TrustedCall::balance_transfer(_, _, _) => debug!("No storage updates needed..."),
			TrustedCall::balance_unshield(_, _, _, _) => debug!("No storage updates needed..."),
			TrustedCall::balance_shield(_, _, _) => debug!("No storage updates needed..."),
			#[cfg(feature = "evm")]
			_ => debug!("No storage updates needed..."),
		};
		key_hashes
	}

	pub fn get_storage_hashes_to_update_for_getter(getter: &Getter) -> Vec<Vec<u8>> {
		debug!(
			"No specific storage updates needed for getter. Returning those for on block: {:?}",
			getter
		);
		Self::storage_hashes_to_update_on_block()
	}

	pub fn storage_hashes_to_update_on_block() -> Vec<Vec<u8>> {
		let mut key_hashes = Vec::new();

		// get all shards that are currently registered
		key_hashes.push(shards_key_hash());
		key_hashes
	}

	pub fn get_root(ext: &mut impl SgxExternalitiesTrait) -> AccountId {
		ext.execute_with(|| Sudo::key().expect("No root account"))
	}

	pub fn get_enclave_account(ext: &mut impl SgxExternalitiesTrait) -> AccountId {
		ext.execute_with(|| enclave_signer_account())
	}

	pub fn account_nonce(ext: &mut impl SgxExternalitiesTrait, account: &AccountId) -> Index {
		ext.execute_with(|| {
			let nonce = System::account_nonce(account);
			debug!("Account {} nonce is {}", account_id_to_string(&account), nonce);
			nonce
		})
	}

	pub fn account_data(ext: &mut impl SgxExternalitiesTrait, account: &AccountId) -> AccountData {
		ext.execute_with(|| System::account(account).data)
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
/// Trait extension to simplify sidechain data access from the STF.
///
/// This should be removed when the refactoring of the STF has been done: #269
pub trait SidechainExt {
	/// get the block number of the sidechain state
	fn get_sidechain_block_number<S: SidechainSystemExt>(ext: &S) -> Option<SidechainBlockNumber>;

	/// set the block number of the sidechain state
	fn set_sidechain_block_number<S: SidechainSystemExt>(
		ext: &mut S,
		number: &SidechainBlockNumber,
	);

	/// get the last block hash of the sidechain state
	fn get_last_block_hash<S: SidechainSystemExt>(ext: &S) -> Option<BlockHash>;

	/// set the last block hash of the sidechain state
	fn set_last_block_hash<S: SidechainSystemExt>(ext: &mut S, hash: &BlockHash);

	/// get the timestamp of the sidechain state
	fn get_timestamp<S: SidechainSystemExt>(ext: &S) -> Option<Timestamp>;

	/// set the timestamp of the sidechain state
	fn set_timestamp<S: SidechainSystemExt>(ext: &mut S, timestamp: &Timestamp);
}

impl SidechainExt for Stf {
	fn get_sidechain_block_number<S: SidechainSystemExt>(ext: &S) -> Option<SidechainBlockNumber> {
		ext.get_block_number()
	}

	fn set_sidechain_block_number<S: SidechainSystemExt>(
		ext: &mut S,
		number: &SidechainBlockNumber,
	) {
		ext.set_block_number(number)
	}

	fn get_last_block_hash<S: SidechainSystemExt>(ext: &S) -> Option<BlockHash> {
		ext.get_last_block_hash()
	}

	fn set_last_block_hash<S: SidechainSystemExt>(ext: &mut S, hash: &BlockHash) {
		ext.set_last_block_hash(hash)
	}

	fn get_timestamp<S: SidechainSystemExt>(ext: &S) -> Option<Timestamp> {
		ext.get_timestamp()
	}

	fn set_timestamp<S: SidechainSystemExt>(ext: &mut S, timestamp: &Timestamp) {
		ext.set_timestamp(timestamp)
	}
}
