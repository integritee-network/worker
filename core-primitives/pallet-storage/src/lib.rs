#![cfg_attr(not(feature = "std"), no_std)]

use codec::Encode;
use itp_storage::{storage_map_key, StorageHasher};
use itp_types::{AccountId, ShardIdentifier};
use sp_std::prelude::Vec;

// Separate the prefix from the rest because in our case we changed the storage prefix due to
// the rebranding. With the below implementation of the `TeerexStorageKeys`, we could simply
// define another struct `OtherStorage`, implement `StoragePrefix` for it, and get the
// `TeerexStorageKeys` implementation for free.
pub trait StoragePrefix {
	fn prefix() -> &'static str;
}

pub struct EnclaveBridgeStorage;

impl StoragePrefix for EnclaveBridgeStorage {
	fn prefix() -> &'static str {
		"EnclaveBridge"
	}
}

pub trait EnclaveBridgeStorageKeys {
	fn shard_status<T: Encode>(shard: T) -> Vec<u8>;
}

impl<S: StoragePrefix> EnclaveBridgeStorageKeys for S {
	fn shard_status<T: Encode>(shard: T) -> Vec<u8> {
		storage_map_key(Self::prefix(), "ShardStatus", &shard, &StorageHasher::Blake2_128Concat)
	}
}

pub struct TeeRexStorage;

impl StoragePrefix for TeeRexStorage {
	fn prefix() -> &'static str {
		"Teerex"
	}
}

pub trait TeerexStorageKeys {
	fn sovereign_enclaves(account: AccountId) -> Vec<u8>;
}

impl<S: StoragePrefix> TeerexStorageKeys for S {
	fn sovereign_enclaves(account: AccountId) -> Vec<u8> {
		storage_map_key(
			Self::prefix(),
			"SovereignEnclaves",
			&account,
			&StorageHasher::Blake2_128Concat,
		)
	}
}

pub struct SidechainStorage;

impl StoragePrefix for SidechainStorage {
	fn prefix() -> &'static str {
		"Sidechain"
	}
}

pub trait SidechainStorageKeys {
	fn latest_sidechain_block_confirmation(shard: ShardIdentifier) -> Vec<u8>;
}

impl<S: StoragePrefix> SidechainStorageKeys for S {
	fn latest_sidechain_block_confirmation(shard: ShardIdentifier) -> Vec<u8> {
		storage_map_key(
			Self::prefix(),
			"LatestSidechainBlockConfirmation",
			&shard,
			&StorageHasher::Blake2_128Concat,
		)
	}
}
