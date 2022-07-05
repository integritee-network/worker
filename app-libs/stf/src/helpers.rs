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
use sp_core::H256;

use crate::{
	stf_sgx_primitives::types::*, AccountId, Index, StfError, StfResult, ENCLAVE_ACCOUNT_KEY,
};
use codec::{Decode, Encode};
use itp_storage::StorageKeyProvider;
use itp_utils::stringify::account_id_to_string;
use log::*;
use std::prelude::v1::*;

pub fn get_storage_value<V: Decode>(
	storage_prefix: &'static str,
	storage_key_name: &'static str,
	storage_key_provider: &impl StorageKeyProvider,
) -> StfResult<Option<V>> {
	let key = storage_key_provider.storage_value_key(storage_prefix, storage_key_name)?;
	Ok(get_storage_by_key_hash(key.0))
}

/// Get value in storage.
pub fn get_storage_by_key_hash<V: Decode>(key: Vec<u8>) -> Option<V> {
	if let Some(value_encoded) = sp_io::storage::get(&key) {
		if let Ok(value) = Decode::decode(&mut value_encoded.as_slice()) {
			Some(value)
		} else {
			error!("could not decode state for key {:x?}", key);
			None
		}
	} else {
		info!("key not found in state {:x?}", key);
		None
	}
}

/// Get the AccountInfo key where the account is stored.
pub fn account_key_hash(
	account: &AccountId,
	storage_key_provider: &impl StorageKeyProvider,
) -> StfResult<Vec<u8>> {
	Ok(storage_key_provider.storage_map_key("System", "Account", account)?.0)
}

pub fn get_account_info(
	who: &AccountId,
	storage_key_provider: &impl StorageKeyProvider,
) -> Option<AccountInfo> {
	let storage_map_key = match storage_key_provider.storage_map_key("System", "Account", who) {
		Ok(r) => r,
		Err(e) => {
			error!("Failed to get storage map key: {:?}", e);
			return None
		},
	};
	let maybe_storage_map = get_storage_by_key_hash(storage_map_key.0);
	if maybe_storage_map.is_none() {
		info!("Failed to get account info for account {}", account_id_to_string(who));
	}
	maybe_storage_map
}

pub fn validate_nonce(
	who: &AccountId,
	nonce: Index,
	storage_key_provider: &impl StorageKeyProvider,
) -> StfResult<()> {
	// validate
	let expected_nonce = match get_account_info(who, storage_key_provider) {
		None => {
			info!(
				"Attempted to validate account nonce of non-existent account: {}",
				account_id_to_string(who)
			);
			0
		},
		Some(account_info) => account_info.nonce,
	};
	if expected_nonce == nonce {
		return Ok(())
	}
	Err(StfError::InvalidNonce(nonce))
}

/// increment nonce after a successful call execution
pub fn increment_nonce(
	account: &AccountId,
	storage_key_provider: &impl StorageKeyProvider,
) -> StfResult<()> {
	//FIXME: Proper error handling - should be taken into
	// consideration after implementing pay fee check
	if let Some(mut acc_info) = get_account_info(account, storage_key_provider) {
		debug!("incrementing account nonce");
		acc_info.nonce += 1;
		let account_key_hash = account_key_hash(account, storage_key_provider)?;
		sp_io::storage::set(&account_key_hash, &acc_info.encode());
		debug!("updated account {} nonce: {:?}", account_id_to_string(account), acc_info.nonce);
	} else {
		error!(
			"tried to increment nonce of a non-existent account: {}",
			account_id_to_string(account)
		)
	}
	Ok(())
}

pub fn account_nonce(account: &AccountId, storage_key_provider: &impl StorageKeyProvider) -> Index {
	if let Some(info) = get_account_info(account, storage_key_provider) {
		info.nonce
	} else {
		info!("Attempted to get nonce of non-existent account: {}", account_id_to_string(account));
		0_u32
	}
}

pub fn account_data(
	account: &AccountId,
	storage_key_provider: &impl StorageKeyProvider,
) -> Option<AccountData> {
	if let Some(info) = get_account_info(account, storage_key_provider) {
		Some(info.data)
	} else {
		info!(
			"Attempted to get account data of non-existent account: {}",
			account_id_to_string(account)
		);
		None
	}
}

pub fn root(storage_key_provider: &impl StorageKeyProvider) -> StfResult<AccountId> {
	Ok(get_storage_value("Sudo", "Key", storage_key_provider)?.expect("No root account"))
}

pub fn enclave_signer_account(
	storage_key_provider: &impl StorageKeyProvider,
) -> StfResult<AccountId> {
	Ok(get_storage_value("Sudo", ENCLAVE_ACCOUNT_KEY, storage_key_provider)?
		.expect("No enclave account"))
}

// FIXME: Use Option<ParentchainHeader:Hash> as return type after fixing sgx-runtime issue #37
#[cfg(feature = "test")]
pub fn get_parentchain_blockhash(storage_key_provider: &impl StorageKeyProvider) -> Option<H256> {
	get_storage_value("Parentchain", "BlockHash", storage_key_provider)
		.unwrap()
		.unwrap()
}

// FIXME: Use Option<ParentchainHeader:Hash> as return type after fixing sgx-runtime issue #37
#[cfg(feature = "test")]
pub fn get_parentchain_parenthash(storage_key_provider: &impl StorageKeyProvider) -> Option<H256> {
	get_storage_value("Parentchain", "ParentHash", storage_key_provider)
		.unwrap()
		.unwrap()
}

#[cfg(feature = "test")]
pub fn get_parentchain_number(
	storage_key_provider: &impl StorageKeyProvider,
) -> Option<BlockNumber> {
	get_storage_value("Parentchain", "Number", storage_key_provider)
		.unwrap()
		.unwrap()
}

/// Ensures an account is a registered enclave account.
pub fn ensure_enclave_signer_account(
	account: &AccountId,
	storage_key_provider: &impl StorageKeyProvider,
) -> StfResult<()> {
	let expected_enclave_account = enclave_signer_account(storage_key_provider)?;
	if &expected_enclave_account == account {
		Ok(())
	} else {
		error!(
			"Expected enclave account {}, but found {}",
			account_id_to_string(&expected_enclave_account),
			account_id_to_string(account)
		);
		Err(StfError::RequireEnclaveSignerAccount)
	}
}

pub fn ensure_root(
	account: AccountId,
	storage_key_provider: &impl StorageKeyProvider,
) -> StfResult<()> {
	if root(storage_key_provider)? == account {
		Ok(())
	} else {
		Err(StfError::MissingPrivileges(account))
	}
}
