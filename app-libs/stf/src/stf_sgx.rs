use crate::{
	stf_sgx_primitives::{
		get_account_info, increment_nonce, shards_key_hash, types::*, validate_nonce, StfError,
		StfResult,
	},
	AccountId, Getter, Index, PublicGetter, TrustedCall, TrustedCallSigned, TrustedGetter,
	UNSHIELD,
};
use codec::{Decode, Encode};
use itp_settings::node::TEEREX_MODULE;
use itp_storage::storage_value_key;
use itp_types::OpaqueCall;
use log_sgx::*;
use sgx_runtime::{BlockNumber as L1BlockNumer, Runtime};
use sgx_tstd as std;
use sp_io::{hashing::blake2_256, SgxExternalitiesTrait};
use sp_runtime::MultiAddress;
use std::prelude::v1::*;
use support::traits::UnfilteredDispatchable;

#[cfg(feature = "test")]
use crate::test_genesis::test_genesis_setup;

pub trait StfTrait = SgxExternalitiesTrait + Clone + Send + Sync;

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
		ext.execute_with(|| {
			let key = storage_value_key("System", "LayerOneNumber");
			if let Some(infovec) = sp_io::storage::get(&key) {
				if let Ok(number) = L1BlockNumer::decode(&mut infovec.as_slice()) {
					Some(number)
				} else {
					error!("Blocknumber l1 decode error");
					None
				}
			} else {
				error!("No Blocknumber l1 in state?");
				None
			}
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
					Self::ensure_root(root)?;
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
					Self::ensure_root(root)?;
					debug!("balance_shield({:x?}, {})", who.encode(), value);
					Self::shield_funds(who, value)?;
					Ok(())
				},
			}?;
			increment_nonce(&sender);
			Ok(())
		})
	}

	pub fn account_nonce(ext: &mut State, account: &AccountId) -> Index {
		ext.execute_with(|| {
			if let Some(info) = get_account_info(account) {
				debug!("Account {:?} nonce is {}", account.encode(), info.nonce);
				info.nonce
			} else {
				0 as Index
			}
		})
	}

	pub fn account_data(ext: &mut State, account: &AccountId) -> Option<AccountData> {
		ext.execute_with(|| {
			if let Some(info) = get_account_info(account) {
				debug!("Account {:?} data is {:?}", account.encode(), info.data);
				Some(info.data)
			} else {
				None
			}
		})
	}

	pub fn get_root(ext: &mut State) -> AccountId {
		ext.execute_with(|| {
			AccountId::decode(
				&mut sp_io::storage::get(&storage_value_key("Sudo", "Key")).unwrap().as_slice(),
			)
			.unwrap()
		})
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
			},
			Getter::public(g) => match g {
				PublicGetter::some_value => Some(42u32.encode()),
			},
		})
	}

	fn ensure_root(account: AccountId) -> StfResult<()> {
		if sp_io::storage::get(&storage_value_key("Sudo", "Key")).unwrap() == account.encode() {
			Ok(())
		} else {
			Err(StfError::MissingPrivileges(account))
		}
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

	pub fn get_storage_hashes_to_update(call: &TrustedCallSigned) -> Vec<Vec<u8>> {
		let key_hashes = Vec::new();
		match call.call {
			TrustedCall::balance_set_balance(_, _, _, _) => debug!("No storage updates needed..."),
			TrustedCall::balance_transfer(_, _, _) => debug!("No storage updates needed..."),
			TrustedCall::balance_unshield(_, _, _, _) => debug!("No storage updates needed..."),
			TrustedCall::balance_shield(_, _, _) => debug!("No storage updates needed..."),
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
}
