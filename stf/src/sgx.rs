use sgx_tstd as std;
use std::{collections::HashMap, prelude::v1::*, vec};

use codec::{Decode, Encode};
use derive_more::Display;
use log_sgx::*;
use sgx_externalities::SgxExternalitiesTypeTrait;
use sgx_runtime::{Balance, BlockNumber as L1BlockNumer, Runtime};
use sp_core::{crypto::AccountId32, Pair, H256 as Hash};
use sp_io::{hashing::blake2_256, SgxExternalitiesTrait};
use sp_runtime::MultiAddress;
use substratee_worker_primitives::BlockNumber;
use support::{ensure, metadata::StorageHasher, traits::UnfilteredDispatchable};

use crate::{
	AccountId, Getter, Index, PublicGetter, ShardIdentifier, StatePayload, TrustedCall,
	TrustedCallSigned, TrustedGetter, SUBSRATEE_REGISTRY_MODULE, UNSHIELD,
};

/// Simple blob that holds a call in encoded format
#[derive(Clone, Debug)]
pub struct OpaqueCall(pub Vec<u8>);

impl Encode for OpaqueCall {
	fn encode(&self) -> Vec<u8> {
		self.0.clone()
	}
}

pub trait StfTrait = SgxExternalitiesTrait + StateHash + Clone + Send + Sync;

pub trait StateHash {
	fn hash(&self) -> Hash;
}

pub mod types {
	pub use sgx_runtime::{Balance, Index};
	pub type AccountData = balances::AccountData<Balance>;
	pub type AccountInfo = system::AccountInfo<Index, AccountData>;

	pub type StateType = sgx_externalities::SgxExternalitiesType;
	pub type State = sgx_externalities::SgxExternalities;
	pub type StateTypeDiff = sgx_externalities::SgxExternalitiesDiffType;
	pub struct Stf;
}

use types::*;

const ALICE_ENCODED: [u8; 32] = [
	212, 53, 147, 199, 21, 253, 211, 28, 97, 20, 26, 189, 4, 169, 159, 214, 130, 44, 133, 88, 133,
	76, 205, 227, 154, 86, 132, 231, 165, 109, 162, 125,
];
const ALICE_FUNDS: Balance = 1000000000000000;

impl Stf {
	pub fn init_state() -> State {
		debug!("initializing stf state");
		let mut ext = State::new();
		// set initial state hash
		let state_hash: Hash = blake2_256(&ext.clone().encode()).into();
		ext.execute_with(|| {
			// do not set genesis for pallets that are meant to be on-chain
			// use get_storage_hashes_to_update instead
			sp_io::storage::set(&storage_value_key("Sudo", "Key"), &ALICE_ENCODED);
			// fund root account
			sgx_runtime::BalancesCall::<Runtime>::set_balance(
				MultiAddress::Id(AccountId32::from(ALICE_ENCODED)),
				ALICE_FUNDS,
				ALICE_FUNDS,
			)
			.dispatch_bypass_filter(sgx_runtime::Origin::root())
			.map_err(|_| StfError::Dispatch("balance_set_balance".to_string()))
			.unwrap();

			sp_io::storage::set(&storage_value_key("Balances", "TotalIssuance"), &11u128.encode());
			sp_io::storage::set(&storage_value_key("Balances", "CreationFee"), &1u128.encode());
			sp_io::storage::set(&storage_value_key("Balances", "TransferFee"), &1u128.encode());
			sp_io::storage::set(
				&storage_value_key("Balances", "TransactionBaseFee"),
				&1u128.encode(),
			);
			sp_io::storage::set(
				&storage_value_key("Balances", "TransfactionByteFee"),
				&1u128.encode(),
			);
			sp_io::storage::set(
				&storage_value_key("Balances", "ExistentialDeposit"),
				&1u128.encode(),
			);
			// Set first sidechainblock number to 0
			let init_block_number: BlockNumber = 0;
			sp_io::storage::set(
				&storage_value_key("System", "Number"),
				&init_block_number.encode(),
			);
			// Set first parent hash to initial state hash
			sp_io::storage::set(&storage_value_key("System", "LastHash"), &state_hash.encode());
			//FIXME: for testing purpose only - maybe add feature?
			// for example: feature = endowtestaccounts
			let public = AccountId32::from(
				sp_core::ed25519::Pair::from_seed(b"12345678901234567890123456789012").public(),
			);
			sgx_runtime::BalancesCall::<Runtime>::set_balance(
				MultiAddress::Id(public.clone()),
				2000,
				2000,
			)
			.dispatch_bypass_filter(sgx_runtime::Origin::root())
			.map_err(|_| StfError::Dispatch("balance_set_balance".to_string()))
			.unwrap();

			let print_public: [u8; 32] = public.clone().into();
			if let Some(info) = get_account_info(&public) {
				debug!("{:?} balance is {}", print_public, info.data.free);
			} else {
				debug!("{:?} balance is zero", print_public);
			}
		});
		ext
	}

	pub fn update_storage(
		ext: &mut impl SgxExternalitiesTrait,
		map_update: &HashMap<Vec<u8>, Option<Vec<u8>>>,
	) {
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

	pub fn update_sidechain_block_number(ext: &mut State, number: BlockNumber) {
		ext.execute_with(|| {
			let key = storage_value_key("System", "Number");
			sp_io::storage::set(&key, &number.encode());
		});
	}

	pub fn get_sidechain_block_number(ext: &mut State) -> Option<BlockNumber> {
		ext.execute_with(|| {
			let key = storage_value_key("System", "Number");
			if let Some(infovec) = sp_io::storage::get(&key) {
				if let Ok(number) = BlockNumber::decode(&mut infovec.as_slice()) {
					Some(number)
				} else {
					error!("Sidechain blocknumber decode error");
					None
				}
			} else {
				error!("No sidechain blocknumber in state?");
				None
			}
		})
	}

	pub fn update_last_block_hash(ext: &mut State, hash: Hash) {
		ext.execute_with(|| {
			let key = storage_value_key("System", "LastHash");
			sp_io::storage::set(&key, &hash.encode());
		});
	}

	pub fn get_last_block_hash(ext: &mut State) -> Option<Hash> {
		ext.execute_with(|| {
			let key = storage_value_key("System", "LastHash");
			if let Some(infovec) = sp_io::storage::get(&key) {
				if let Ok(hash) = Hash::decode(&mut infovec.as_slice()) {
					Some(hash)
				} else {
					error!("Blockhash decode error");
					None
				}
			} else {
				error!("No Blockhash in state?");
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
					calls.push(OpaqueCall(
						(
							[SUBSRATEE_REGISTRY_MODULE, UNSHIELD],
							beneficiary,
							value,
							shard,
							call_hash,
						)
							.encode(),
					));
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

	//FIXME: Add Test feature as this function is only used for unit testing currently
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

	pub fn apply_state_diff(
		ext: &mut impl StfTrait,
		state_payload: &mut StatePayload,
	) -> StfResult<()> {
		// Todo: how do we ensure that the apriori state hash matches?
		ensure!(ext.hash() == state_payload.state_hash_apriori(), StfError::StorageHashMismatch);
		let mut ext2 = ext.clone();
		Self::update_storage(&mut ext2, &StateTypeDiff::decode(state_payload.state_update.clone()));
		ensure!(
			ext2.hash() == state_payload.state_hash_aposteriori(),
			StfError::InvalidStorageDiff
		);
		*ext = ext2;
		ext.prune_state_diff();
		Ok(())
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

pub fn storage_hashes_to_update_per_shard(_shard: &ShardIdentifier) -> Vec<Vec<u8>> {
	Vec::new()
}

pub fn shards_key_hash() -> Vec<u8> {
	// here you have to point to a storage value containing a Vec of ShardIdentifiers
	// the enclave uses this to autosubscribe to no shards
	vec![]
}

// get the AccountInfo key where the account is stored
pub fn account_key_hash(account: &AccountId) -> Vec<u8> {
	storage_map_key("System", "Account", account, &StorageHasher::Blake2_128Concat)
}

fn get_account_info(who: &AccountId) -> Option<AccountInfo> {
	if let Some(infovec) = sp_io::storage::get(&storage_map_key(
		"System",
		"Account",
		who,
		&StorageHasher::Blake2_128Concat,
	)) {
		if let Ok(info) = AccountInfo::decode(&mut infovec.as_slice()) {
			Some(info)
		} else {
			None
		}
	} else {
		None
	}
}

fn validate_nonce(who: &AccountId, nonce: Index) -> StfResult<()> {
	// validate
	let expected_nonce = get_account_info(who).map_or_else(|| 0, |acc| acc.nonce);
	if expected_nonce == nonce {
		return Ok(())
	}
	Err(StfError::InvalidNonce(nonce))
}

/// increment nonce after a successful call execution
fn increment_nonce(account: &AccountId) {
	//FIXME: Proper error handling - should be taken into
	// consideration after implementing pay fee check
	if let Some(mut acc_info) = get_account_info(account) {
		debug!("incrementing account nonce");
		acc_info.nonce += 1;
		sp_io::storage::set(&account_key_hash(account), &acc_info.encode());
		debug!(
			"updated account {:?} nonce: {:?}",
			account.encode(),
			get_account_info(account).unwrap().nonce
		);
	} else {
		error!("tried to increment nonce of a non-existent account")
	}
}

pub fn storage_value_key(module_prefix: &str, storage_prefix: &str) -> Vec<u8> {
	let mut bytes = sp_core::twox_128(module_prefix.as_bytes()).to_vec();
	bytes.extend(&sp_core::twox_128(storage_prefix.as_bytes())[..]);
	bytes
}

pub fn storage_map_key<K: Encode>(
	module_prefix: &str,
	storage_prefix: &str,
	mapkey1: &K,
	hasher1: &StorageHasher,
) -> Vec<u8> {
	let mut bytes = sp_core::twox_128(module_prefix.as_bytes()).to_vec();
	bytes.extend(&sp_core::twox_128(storage_prefix.as_bytes())[..]);
	bytes.extend(key_hash(mapkey1, hasher1));
	bytes
}

pub fn storage_double_map_key<K: Encode, Q: Encode>(
	module_prefix: &str,
	storage_prefix: &str,
	mapkey1: &K,
	hasher1: &StorageHasher,
	mapkey2: &Q,
	hasher2: &StorageHasher,
) -> Vec<u8> {
	let mut bytes = sp_core::twox_128(module_prefix.as_bytes()).to_vec();
	bytes.extend(&sp_core::twox_128(storage_prefix.as_bytes())[..]);
	bytes.extend(key_hash(mapkey1, hasher1));
	bytes.extend(key_hash(mapkey2, hasher2));
	bytes
}

/// generates the key's hash depending on the StorageHasher selected
fn key_hash<K: Encode>(key: &K, hasher: &StorageHasher) -> Vec<u8> {
	let encoded_key = key.encode();
	match hasher {
		StorageHasher::Identity => encoded_key.to_vec(),
		StorageHasher::Blake2_128 => sp_core::blake2_128(&encoded_key).to_vec(),
		StorageHasher::Blake2_128Concat => {
			// copied from substrate Blake2_128Concat::hash since StorageHasher is not public
			let x: &[u8] = encoded_key.as_slice();
			sp_core::blake2_128(x).iter().chain(x.iter()).cloned().collect::<Vec<_>>()
		},
		StorageHasher::Blake2_256 => sp_core::blake2_256(&encoded_key).to_vec(),
		StorageHasher::Twox128 => sp_core::twox_128(&encoded_key).to_vec(),
		StorageHasher::Twox256 => sp_core::twox_256(&encoded_key).to_vec(),
		StorageHasher::Twox64Concat => sp_core::twox_64(&encoded_key).to_vec(),
	}
}

pub type StfResult<T> = Result<T, StfError>;

#[derive(Debug, Display, PartialEq, Eq)]
pub enum StfError {
	#[display(fmt = "Insufficient privileges {:?}, are you sure you are root?", _0)]
	MissingPrivileges(AccountId),
	#[display(fmt = "Error dispatching runtime call. {:?}", _0)]
	Dispatch(String),
	#[display(fmt = "Not enough funds to perform operation")]
	MissingFunds,
	#[display(fmt = "Account does not exist {:?}", _0)]
	InexistentAccount(AccountId),
	#[display(fmt = "Invalid Nonce {:?}", _0)]
	InvalidNonce(Index),
	StorageHashMismatch,
	InvalidStorageDiff,
}

// this must be pub to be able to test it in the enclave. In the future this should be testable
// with cargo test. See: https://github.com/scs/substraTEE-worker/issues/272.
pub mod tests {
	use super::{State, StateHash, StatePayload, Stf, StfTrait};
	use crate::sgx::StfError;
	use sgx_externalities::SgxExternalitiesTypeTrait;
	use sp_core::H256;
	use sp_runtime::traits::{BlakeTwo256, Hash};
	use support::{assert_err, assert_ok};

	impl StateHash for State {
		fn hash(&self) -> H256 {
			BlakeTwo256::hash(self.state.clone().encode().as_slice())
		}
	}

	pub fn apply_state_diff_works() {
		let mut state1 = State::new();
		let mut state2 = State::new();

		let apriori = state1.hash();
		state1.insert(b"Hello".to_vec(), b"World".to_vec());
		let aposteriori = state1.hash();

		let mut state_update =
			StatePayload::new(apriori, aposteriori, state1.state_diff.clone().encode());

		assert_ok!(Stf::apply_state_diff(&mut state2, &mut state_update));
		assert_eq!(state2.hash(), aposteriori);
		assert_eq!(*state2.get(b"Hello").unwrap(), b"World".to_vec());
		assert!(state2.state_diff.is_empty());
	}

	pub fn apply_state_diff_returns_storage_hash_mismatch_err() {
		let mut state1 = State::new();
		let mut state2 = State::new();

		let apriori = H256::from([1; 32]);
		state1.insert(b"Hello".to_vec(), b"World".to_vec());
		let aposteriori = state1.hash();

		let mut state_update =
			StatePayload::new(apriori, aposteriori, state1.state_diff.clone().encode());

		assert_err!(
			Stf::apply_state_diff(&mut state2, &mut state_update),
			StfError::StorageHashMismatch
		);
		// todo: Derive `Eq` on State
		assert_eq!(state2.hash(), State::new().hash());
		assert!(state2.state_diff.is_empty());
	}

	pub fn apply_state_diff_returns_invalid_storage_diff_err() {
		let mut state1 = State::new();
		let mut state2 = State::new();

		let apriori = state1.hash();
		state1.insert(b"Hello".to_vec(), b"World".to_vec());
		let aposteriori = H256::from([1; 32]);

		let mut state_update =
			StatePayload::new(apriori, aposteriori, state1.state_diff.clone().encode());

		assert_err!(
			Stf::apply_state_diff(&mut state2, &mut state_update),
			StfError::InvalidStorageDiff
		);
		// todo: Derive `Eq` on State
		assert_eq!(state2.hash(), State::new().hash());
		assert!(state2.state_diff.is_empty());
	}
}
