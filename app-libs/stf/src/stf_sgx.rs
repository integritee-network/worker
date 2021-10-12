use crate::{
	helpers::{
		account_data, account_nonce, ensure_root, get_account_info, get_storage_value,
		increment_nonce, root, validate_nonce, get_game_for
	},
	stf_sgx_primitives::{StfError, StfResult},
	AccountData, AccountId, Getter, Index, PublicGetter, ShardIdentifier, State, StateTypeDiff,
	Stf, TrustedCall, TrustedCallSigned, TrustedGetter,
};
use codec::Encode;
use itp_settings::node::{TEEREX_MODULE, UNSHIELD};
use itp_storage::storage_value_key;
use itp_types::OpaqueCall;
use log_sgx::*;
use sgx_runtime::{BlockNumber as L1BlockNumer, Runtime, Hash, BlockNumber};
use sgx_tstd as std;
use sp_io::{hashing::blake2_256, SgxExternalitiesTrait};
use sp_runtime::MultiAddress;
use std::{prelude::v1::*, vec};
use support::traits::UnfilteredDispatchable;
use pallet_rps::Game as GameT;


pub type Game = GameT<Hash, AccountId>;

#[cfg(feature = "test")]
use crate::test_genesis::test_genesis_setup;
use its_primitives::types::{BlockHash, BlockNumber as SidechainBlockNumber, Timestamp};
use its_state::SidechainSystemExt;

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

	pub fn get_state(ext: &mut State, getter: Getter) -> Option<Vec<u8>> {
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
				TrustedGetter::game(who) => 
					if let Some(game) = get_game_for(who) {
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

	pub fn set_layer_two_block_number(ext: &mut State, number: BlockNumber) {
		ext.execute_with(|| {
			let key = storage_value_key("System", "Number");
			sp_io::storage::set(&key, &number.encode());
		})
	}

	pub fn execute(
		ext: &mut State,
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
					sgx_runtime::BalancesCall::<Runtime>::set_balance(
						MultiAddress::Id(who),
						free_balance,
						reserved_balance,
					)
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
					sgx_runtime::BalancesCall::<Runtime>::transfer(MultiAddress::Id(to), value)
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
						[TEEREX_MODULE, UNSHIELD],
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
				TrustedCall::rps_new_game(sender, opponent) => {
					let origin = sgx_runtime::Origin::signed(sender.clone());
					info!("rps new_game");
					sgx_runtime::RpsCall::<Runtime>::new_game(
						opponent,
					)
						.dispatch_bypass_filter(origin)
						.map_err(|_| StfError::Dispatch("rps_new_game".to_string()))?;
					Ok(())
				},
				TrustedCall::rps_choose(sender, weapon) => {
					let origin = sgx_runtime::Origin::signed(sender.clone());
					info!("rps choose: {:?}", weapon);
					sgx_runtime::RpsCall::<Runtime>::choose(
						weapon.clone(),
						[0u8; 32],
					)
						.dispatch_bypass_filter(origin.clone())
						.map_err(|e| {
							error!("dispatch error {:?}", e);
							StfError::Dispatch("rps_choose".to_string())
						})?;
					Ok(())
				}
				TrustedCall::rps_reveal(sender, weapon) => {
					let origin = sgx_runtime::Origin::signed(sender.clone());
					info!("rps reveal");
					sgx_runtime::RpsCall::<Runtime>::reveal(
						weapon,
						[0u8; 32],
					)
						.dispatch_bypass_filter(origin)
						.map_err(|_| StfError::Dispatch("rps_reveal".to_string()))?;
					get_game_for(sender);
					Ok(())
				},
			}?;
			increment_nonce(&sender);
			Ok(())
		})
	}

	fn shield_funds(account: AccountId, amount: u128) -> StfResult<()> {
		match get_account_info(&account) {
			Some(account_info) => sgx_runtime::BalancesCall::<Runtime>::set_balance(
				MultiAddress::Id(account),
				account_info.data.free + amount,
				account_info.data.reserved,
			)
			.dispatch_bypass_filter(sgx_runtime::Origin::root())
			.map_err(|_| StfError::Dispatch("shield_funds".to_string()))?,
			None => sgx_runtime::BalancesCall::<Runtime>::set_balance(
				MultiAddress::Id(account),
				amount,
				0,
			)
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

				sgx_runtime::BalancesCall::<Runtime>::set_balance(
					MultiAddress::Id(account),
					account_info.data.free - amount,
					account_info.data.reserved,
				)
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

	pub fn update_layer_one_block_number(ext: &mut State, number: L1BlockNumer) {
		ext.execute_with(|| {
			let key = storage_value_key("System", "LayerOneNumber");
			sp_io::storage::set(&key, &number.encode());
		});
	}

	pub fn get_layer_one_block_number(ext: &mut State) -> Option<L1BlockNumer> {
		ext.execute_with(|| get_storage_value("System", "LayerOneNumber"))
	}

	pub fn get_storage_hashes_to_update(call: &TrustedCallSigned) -> Vec<Vec<u8>> {
		let key_hashes = Vec::new();
		match call.call {
			TrustedCall::balance_set_balance(_, _, _, _) => debug!("No storage updates needed..."),
			TrustedCall::balance_transfer(_, _, _) => debug!("No storage updates needed..."),
			TrustedCall::balance_unshield(_, _, _, _) => debug!("No storage updates needed..."),
			TrustedCall::balance_shield(_, _, _) => debug!("No storage updates needed..."),
			TrustedCall::rps_new_game(_, _) => debug!("No storage updates needed..."),
			TrustedCall::rps_choose(_, _) => debug!("No storage updates needed..."),
			TrustedCall::rps_reveal(_, _) => debug!("No storage updates needed..."),
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

	pub fn get_root(ext: &mut State) -> AccountId {
		ext.execute_with(|| root())
	}

	pub fn account_nonce(ext: &mut State, account: &AccountId) -> Index {
		ext.execute_with(|| {
			let nonce = account_nonce(account);
			debug!("Account {:?} nonce is {}", account.encode(), nonce);
			nonce
		})
	}

	pub fn account_data(ext: &mut State, account: &AccountId) -> Option<AccountData> {
		ext.execute_with(|| account_data(account))
	}
}

pub fn storage_hashes_to_update_per_shard(_shard: &ShardIdentifier) -> Vec<Vec<u8>> {
	Vec::new()
}

pub fn shards_key_hash() -> Vec<u8> {
	// here you have to point to a storage value containing a Vec of ShardIdentifiers
	// the enclave uses this to autosubscribe to no shards
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
