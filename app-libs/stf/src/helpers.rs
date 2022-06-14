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
use crate::{
	stf_sgx_primitives::types::*, AccountId, Index, SgxBoardId, SgxGuessingBoardStruct,
	SgxWinningBoard, StfError, StfResult, H256,
};
use codec::{Decode, Encode};
use itp_storage::{storage_double_map_key, storage_map_key, storage_value_key, StorageHasher};
use log::*;
use std::prelude::v1::*;

#[cfg(feature = "sgx")]
use crate::stf_sgx_primitives::types::{AccountData, AccountInfo};
#[cfg(feature = "std")]
use itp_types::{AccountData, AccountInfo};

pub fn get_storage_value<V: Decode>(
	storage_prefix: &'static str,
	storage_key_name: &'static str,
) -> Option<V> {
	let key = storage_value_key(storage_prefix, storage_key_name);
	get_storage_by_key_hash(key)
}

pub fn get_storage_map<K: Encode, V: Decode + Clone>(
	storage_prefix: &'static str,
	storage_key_name: &'static str,
	map_key: &K,
	hasher: &StorageHasher,
) -> Option<V> {
	let key = storage_map_key::<K>(storage_prefix, storage_key_name, map_key, hasher);
	get_storage_by_key_hash(key)
}

pub fn get_storage_double_map<K: Encode, Q: Encode, V: Decode + Clone>(
	storage_prefix: &'static str,
	storage_key_name: &'static str,
	first: &K,
	first_hasher: &StorageHasher,
	second: &Q,
	second_hasher: &StorageHasher,
) -> Option<V> {
	let key = storage_double_map_key::<K, Q>(
		storage_prefix,
		storage_key_name,
		first,
		first_hasher,
		second,
		second_hasher,
	);
	get_storage_by_key_hash(key)
}

pub fn get_storage_by_key_hash<V: Decode>(key: Vec<u8>) -> Option<V> {
	if let Some(value_encoded) = sp_io::storage::get(&key) {
		if let Ok(value) = Decode::decode(&mut value_encoded.as_slice()) {
			Some(value)
		} else {
			error!("could not decode state for key {:x?}", key);
			None
		}
	} else {
		error!("key not found in state {:x?}", key);
		None
	}
}

// get the AccountInfo key where the account is stored
pub fn account_key_hash(account: &AccountId) -> Vec<u8> {
	storage_map_key("System", "Account", account, &StorageHasher::Blake2_128Concat)
}

pub fn get_account_info(who: &AccountId) -> Option<AccountInfo> {
	get_storage_map("System", "Account", who, &StorageHasher::Blake2_128Concat)
}

pub fn validate_nonce(who: &AccountId, nonce: Index) -> StfResult<()> {
	// validate
	let expected_nonce = get_account_info(who).map_or_else(|| 0, |acc| acc.nonce);
	if expected_nonce == nonce {
		return Ok(())
	}
	Err(StfError::InvalidNonce(nonce))
}

/// increment nonce after a successful call execution
pub fn increment_nonce(account: &AccountId) {
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

pub fn account_nonce(account: &AccountId) -> Index {
	if let Some(info) = get_account_info(account) {
		info.nonce
	} else {
		0_u32
	}
}

pub fn account_data(account: &AccountId) -> Option<AccountData> {
	if let Some(info) = get_account_info(account) {
		Some(info.data)
	} else {
		None
	}
}

pub fn root() -> AccountId {
	get_storage_value("Sudo", "Key").unwrap()
}

// FIXME: Use Option<ParentchainHeader:Hash> as return type after fixing sgx-runtime issue #37
pub fn get_parentchain_blockhash() -> Option<H256> {
	get_storage_value("Parentchain", "BlockHash")
}

// FIXME: Use Option<ParentchainHeader:Hash> as return type after fixing sgx-runtime issue #37
pub fn get_parentchain_parenthash() -> Option<H256> {
	get_storage_value("Parentchain", "ParentHash")
}

pub fn get_parentchain_number() -> Option<BlockNumber> {
	get_storage_value("Parentchain", "Number")
}

pub fn ensure_root(account: AccountId) -> StfResult<()> {
	if root() == account {
		Ok(())
	} else {
		Err(StfError::MissingPrivileges(account))
	}
}

pub fn get_board_for(who: AccountId) -> Option<SgxGuessingBoardStruct> {
	if let Some(board_id) = get_storage_map::<AccountId, SgxBoardId>(
		"AjunaBoard",
		"PlayerBoards",
		&who,
		&StorageHasher::Identity,
	) {
		if let Some(board) = get_storage_map::<SgxBoardId, SgxGuessingBoardStruct>(
			"AjunaBoard",
			"BoardStates",
			&board_id,
			&StorageHasher::Identity,
		) {
			Some(board)
		} else {
			debug!("could not read board");
			None
		}
	} else {
		debug!("could not read board id");
		None
	}
}

pub fn is_winner(who: AccountId) -> Option<SgxWinningBoard> {
	if let Some(board_id) = get_storage_map::<AccountId, SgxBoardId>(
		"AjunaBoard",
		"PlayerBoards",
		&who,
		&StorageHasher::Identity,
	) {
		if let Some(winner) = get_storage_map::<SgxBoardId, AccountId>(
			"AjunaBoard",
			"BoardWinners",
			&board_id,
			&StorageHasher::Identity,
		) {
			if who == winner {
				if let Some(_board) = get_storage_map::<SgxBoardId, SgxGuessingBoardStruct>(
					"AjunaBoard",
					"BoardStates",
					&board_id,
					&StorageHasher::Identity,
				) {
					return Some(SgxWinningBoard { winner, board_id })
				}
			}
		}
	} else {
		debug!("could not read board id");
	}

	None
}
