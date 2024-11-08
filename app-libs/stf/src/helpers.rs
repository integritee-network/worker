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
use crate::{TrustedCall, ENCLAVE_ACCOUNT_KEY};
use codec::{Decode, Encode};
use frame_support::dispatch::UnfilteredDispatchable;
use ita_sgx_runtime::{ParentchainIntegritee, ParentchainTargetA, ParentchainTargetB, Runtime};
use itp_stf_interface::{BlockMetadata, ShardCreationInfo};
use itp_stf_primitives::{
	error::{StfError, StfResult},
	types::AccountId,
};
use itp_storage::{storage_double_map_key, storage_map_key, storage_value_key, StorageHasher};
use itp_types::parentchain::{BlockNumber, GenericMortality, Hash, ParentchainId};
use itp_utils::stringify::account_id_to_string;
use log::*;
use sp_runtime::generic::Era;
use std::{format, prelude::v1::*};

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
pub fn account_key_hash<AccountId: Encode>(account: &AccountId) -> Vec<u8> {
	storage_map_key("System", "Account", account, &StorageHasher::Blake2_128Concat)
}

pub fn enclave_signer_account<AccountId: Decode>() -> AccountId {
	get_storage_value("Sudo", ENCLAVE_ACCOUNT_KEY).expect("No enclave account")
}

/// Ensures an account is a registered enclave account.
pub fn ensure_enclave_signer_account<AccountId: Encode + Decode + PartialEq>(
	account: &AccountId,
) -> StfResult<()> {
	let expected_enclave_account: AccountId = enclave_signer_account();
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

pub fn set_block_number(block_number: u32) {
	sp_io::storage::set(&storage_value_key("System", "Number"), &block_number.encode());
}

/// get shard vault from any of the parentchain interfaces
/// We assume it has been ensured elsewhere that there can't be multiple shard vaults on multiple parentchains
pub fn shard_vault() -> Option<(AccountId, ParentchainId)> {
	get_shard_vaults().into_iter().next()
}

/// get shielding target from parentchain pallets
pub fn shielding_target() -> ParentchainId {
	shard_vault().map(|v| v.1).unwrap_or(ParentchainId::Integritee)
}

/// get genesis hash of shielding target parentchain, if available
pub fn shielding_target_genesis_hash() -> Option<Hash> {
	match shielding_target() {
		ParentchainId::Integritee => ParentchainIntegritee::parentchain_genesis_hash(),
		ParentchainId::TargetA => ParentchainTargetA::parentchain_genesis_hash(),
		ParentchainId::TargetB => ParentchainTargetB::parentchain_genesis_hash(),
	}
}

/// We assume it has been ensured elsewhere that there can't be multiple shard vaults on multiple parentchains
pub fn get_shard_vaults() -> Vec<(AccountId, ParentchainId)> {
	[
		(ParentchainIntegritee::shard_vault(), ParentchainId::Integritee),
		(ParentchainTargetA::shard_vault(), ParentchainId::TargetA),
		(ParentchainTargetB::shard_vault(), ParentchainId::TargetB),
	]
	.into_iter()
	.filter_map(|vp| vp.0.map(|v| (v, vp.1)))
	.collect()
}

pub fn shard_creation_info() -> ShardCreationInfo {
	let maybe_integritee_info: Option<BlockMetadata> =
		ParentchainIntegritee::creation_block_number().and_then(|number| {
			ParentchainIntegritee::creation_block_hash().map(|hash| BlockMetadata {
				number,
				hash,
				timestamp: ParentchainIntegritee::creation_timestamp(),
			})
		});
	let maybe_target_a_info: Option<BlockMetadata> = ParentchainTargetA::creation_block_number()
		.and_then(|number| {
			ParentchainTargetA::creation_block_hash().map(|hash| BlockMetadata {
				number,
				hash,
				timestamp: ParentchainTargetA::creation_timestamp(),
			})
		});
	let maybe_target_b_info: Option<BlockMetadata> = ParentchainTargetB::creation_block_number()
		.and_then(|number| {
			ParentchainTargetB::creation_block_hash().map(|hash| BlockMetadata {
				number,
				hash,
				timestamp: ParentchainTargetB::creation_timestamp(),
			})
		});

	ShardCreationInfo {
		integritee: maybe_integritee_info,
		target_a: maybe_target_a_info,
		target_b: maybe_target_b_info,
	}
}

const PREFIX: &[u8] = b"<Bytes>";
const POSTFIX: &[u8] = b"</Bytes>";

/// This function reproduces the wrapping that occurs when the
/// `signRaw` interface is used with a signer that is injected
/// from a dapp-extension.
///
/// See: https://github.com/polkadot-js/extension/pull/743
pub fn wrap_bytes(data: &[u8]) -> Vec<u8> {
	let total_len = PREFIX.len() + data.len() + POSTFIX.len();
	let mut bytes_wrapped = Vec::with_capacity(total_len);

	bytes_wrapped.extend_from_slice(PREFIX);
	bytes_wrapped.extend_from_slice(data);
	bytes_wrapped.extend_from_slice(POSTFIX);

	bytes_wrapped
}

pub fn get_mortality(
	parentchain_id: ParentchainId,
	blocks_to_live: BlockNumber,
) -> Option<GenericMortality> {
	let (maybe_number, maybe_hash) = match parentchain_id {
		ParentchainId::Integritee =>
			(ParentchainIntegritee::block_number(), ParentchainIntegritee::block_hash()),
		ParentchainId::TargetA =>
			(ParentchainTargetA::block_number(), ParentchainTargetA::block_hash()),
		ParentchainId::TargetB =>
			(ParentchainTargetB::block_number(), ParentchainTargetB::block_hash()),
	};
	if let Some(number) = maybe_number {
		if let Some(hash) = maybe_hash {
			return Some(GenericMortality {
				era: Era::mortal(blocks_to_live.into(), number.into()),
				mortality_checkpoint: Some(hash),
			})
		}
	}
	None
}

pub fn store_note(
	sender: &AccountId,
	call: TrustedCall,
	link_to: Vec<AccountId>,
) -> Result<(), StfError> {
	ita_sgx_runtime::NotesCall::<Runtime>::note_trusted_call { link_to, payload: call.encode() }
		.dispatch_bypass_filter(ita_sgx_runtime::RuntimeOrigin::signed(sender.clone()))
		.map_err(|e| StfError::Dispatch(format!("Store note error: {:?}", e.error)))?;
	Ok(())
}
