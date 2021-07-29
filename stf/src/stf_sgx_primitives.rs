/*
	Copyright 2019 Supercomputing Systems AG

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

use crate::{AccountId, AccountInfo, Index, ShardIdentifier};
use codec::{Decode, Encode};
use derive_more::Display;
use log_sgx::*;
use sgx_tstd as std;
use std::{prelude::v1::*, vec};
use support::metadata::StorageHasher;

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

pub fn get_account_info(who: &AccountId) -> Option<AccountInfo> {
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
