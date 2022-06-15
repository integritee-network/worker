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
use alloc::format;

use crate::{
	helpers::{
		account_data, account_nonce, ensure_root, get_account_info, get_board_for, increment_nonce,
		root, validate_nonce,
	},
	AccountData, AccountId, Getter, Index, ParentchainHeader, PublicGetter, ShardIdentifier, State,
	StateTypeDiff, Stf, StfError, StfResult, TrustedCall, TrustedCallSigned, TrustedGetter,
};
use codec::Encode;
use itp_settings::node::{TEEREX_MODULE, UNSHIELD_FUNDS};
use itp_storage::storage_value_key;
use itp_types::OpaqueCall;
use its_primitives::types::{BlockHash, BlockNumber as SidechainBlockNumber, Timestamp};
use its_state::SidechainSystemExt;
use log::*;
use sgx_externalities::SgxExternalitiesTrait;
use sgx_runtime::Runtime;
use sgx_tstd as std;
use sp_io::hashing::blake2_256;
use sp_runtime::MultiAddress;
use std::{prelude::v1::*, vec};
use support::traits::UnfilteredDispatchable;

impl Stf {
	pub fn init_state() -> State {
		debug!("initializing stf state");
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

		trace!("Returning updated state: {:?}", ext);
		ext
	}

	pub fn get_state(ext: &mut impl SgxExternalitiesTrait, getter: Getter) -> Option<Vec<u8>> {
		ext.execute_with(|| match getter {
			Getter::trusted(g) => match g.getter {
				TrustedGetter::free_balance(who) =>
					if let Some(info) = get_account_info(&who) {
						debug!("AccountInfo for {:x?} is {:?}", who.encode(), info);
						debug!("Account free balance is {}", info.data.free);
						Some(info.data.free.encode())
					} else {
						None
					},
				TrustedGetter::reserved_balance(who) =>
					if let Some(info) = get_account_info(&who) {
						debug!("AccountInfo for {:x?} is {:?}", who.encode(), info);
						debug!("Account reserved balance is {}", info.data.reserved);
						Some(info.data.reserved.encode())
					} else {
						None
					},
				TrustedGetter::nonce(who) =>
					if let Some(info) = get_account_info(&who) {
						debug!("AccountInfo for {:x?} is {:?}", who.encode(), info);
						debug!("Account nonce is {}", info.nonce);
						Some(info.nonce.encode())
					} else {
						None
					},
				TrustedGetter::board(who) =>
					if let Some(game) = get_board_for(who) {
						Some(game.encode())
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
	) -> StfResult<()> {
		let call_hash = blake2_256(&call.encode());
		ext.execute_with(|| {
			let sender = call.call.account().clone();
			validate_nonce(&sender, call.nonce)?;
			match call.call {
				TrustedCall::balance_set_balance(root, who, free_balance, reserved_balance) => {
					ensure_root(root)?;
					debug!(
						"balance_set_balance({:x?}, {}, {})",
						who.encode(),
						free_balance,
						reserved_balance
					);
					sgx_runtime::BalancesCall::<Runtime>::set_balance {
						who: MultiAddress::Id(who),
						new_free: free_balance,
						new_reserved: reserved_balance,
					}
					.dispatch_bypass_filter(sgx_runtime::Origin::root())
					.map_err(|_| StfError::Dispatch("balance_set_balance".to_string()))?;
					Ok(())
				},
				TrustedCall::balance_transfer(from, to, value) => {
					let origin = sgx_runtime::Origin::signed(from.clone());
					debug!("balance_transfer({:x?}, {:x?}, {})", from.encode(), to.encode(), value);
					if let Some(info) = get_account_info(&from) {
						debug!("sender balance is {}", info.data.free);
					} else {
						debug!("sender balance is zero");
					}
					sgx_runtime::BalancesCall::<Runtime>::transfer {
						dest: MultiAddress::Id(to),
						value,
					}
					.dispatch_bypass_filter(origin)
					.map_err(|_| StfError::Dispatch("balance_transfer".to_string()))?;
					Ok(())
				},
				TrustedCall::balance_unshield(account_incognito, beneficiary, value, shard) => {
					debug!(
						"balance_unshield({:x?}, {:x?}, {}, {})",
						account_incognito.encode(),
						beneficiary.encode(),
						value,
						shard
					);

					Self::unshield_funds(account_incognito, value)?;
					calls.push(OpaqueCall::from_tuple(&(
						[TEEREX_MODULE, UNSHIELD_FUNDS],
						beneficiary,
						value,
						shard,
						call_hash,
					)));
					Ok(())
				},
				TrustedCall::balance_shield(root, who, value) => {
					ensure_root(root)?;
					debug!("balance_shield({:x?}, {})", who.encode(), value);
					Self::shield_funds(who, value)?;
					Ok(())
				},
				TrustedCall::board_new_game(root, board_id, players) => {
					let origin = sgx_runtime::Origin::signed(root.clone());
					debug!("board_new_game {:x?} => {:x?})", board_id, players);
					sgx_runtime::AjunaBoardCall::<Runtime>::new_game { board_id, players }
						.dispatch_bypass_filter(origin)
						.map_err(|e| StfError::Dispatch(format!("{:?}", e.error)))?;
					Ok(())
				},
				TrustedCall::board_play_turn(sender, turn) => {
					let origin = sgx_runtime::Origin::signed(sender.clone());
					debug!("board play turn ({:x?}, {:?})", sender.encode(), turn);
					sgx_runtime::AjunaBoardCall::<Runtime>::play_turn { turn }
						.dispatch_bypass_filter(origin.clone())
						.map_err(|e| StfError::Dispatch(format!("{:?}", e.error)))?;
					Ok(())
				},
				TrustedCall::board_finish_game(sender, board_id) => {
					let origin = sgx_runtime::Origin::signed(sender.clone());
					debug!("board finished ({:x?}, {:?})", sender.encode(), board_id);
					sgx_runtime::AjunaBoardCall::<Runtime>::finish_game { board_id }
						.dispatch_bypass_filter(origin.clone())
						.map_err(|e| StfError::Dispatch(format!("{:?}", e.error)))?;
					Ok(())
				},
			}?;
			increment_nonce(&sender);
			Ok(())
		})
	}

	fn shield_funds(account: AccountId, amount: u128) -> StfResult<()> {
		match get_account_info(&account) {
			Some(account_info) => sgx_runtime::BalancesCall::<Runtime>::set_balance {
				who: MultiAddress::Id(account),
				new_free: account_info.data.free + amount,
				new_reserved: account_info.data.reserved,
			}
			.dispatch_bypass_filter(sgx_runtime::Origin::root())
			.map_err(|_| StfError::Dispatch("shield_funds".to_string()))?,
			None => sgx_runtime::BalancesCall::<Runtime>::set_balance {
				who: MultiAddress::Id(account),
				new_free: amount,
				new_reserved: 0,
			}
			.dispatch_bypass_filter(sgx_runtime::Origin::root())
			.map_err(|_| StfError::Dispatch("shield_funds::set_balance".to_string()))?,
		};
		Ok(())
	}

	fn unshield_funds(account: AccountId, amount: u128) -> StfResult<()> {
		match get_account_info(&account) {
			Some(account_info) => {
				if account_info.data.free < amount {
					return Err(StfError::MissingFunds)
				}

				sgx_runtime::BalancesCall::<Runtime>::set_balance {
					who: MultiAddress::Id(account),
					new_free: account_info.data.free - amount,
					new_reserved: account_info.data.reserved,
				}
				.dispatch_bypass_filter(sgx_runtime::Origin::root())
				.map_err(|_| StfError::Dispatch("unshield_funds::set_balance".to_string()))?;
				Ok(())
			},
			None => Err(StfError::InexistentAccount(account)),
		}
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
			sgx_runtime::ParentchainCall::<Runtime>::set_block { header }
				.dispatch_bypass_filter(sgx_runtime::Origin::root())
				.map_err(|_| StfError::Dispatch("update_parentchain_block".to_string()))
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
			TrustedCall::board_new_game(_, _, _) => debug!("No storage updates needed..."),
			TrustedCall::board_play_turn(_, _) => debug!("No storage updates needed..."),
			TrustedCall::board_finish_game(_, _) => debug!("No storage updates needed..."),
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
		ext.execute_with(|| root())
	}

	pub fn account_nonce(ext: &mut impl SgxExternalitiesTrait, account: &AccountId) -> Index {
		ext.execute_with(|| {
			let nonce = account_nonce(account);
			debug!("Account {:?} nonce is {}", account.encode(), nonce);
			nonce
		})
	}

	pub fn account_data(
		ext: &mut impl SgxExternalitiesTrait,
		account: &AccountId,
	) -> Option<AccountData> {
		ext.execute_with(|| account_data(account))
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
