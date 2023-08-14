#![cfg_attr(not(feature = "std"), no_std)]

use codec::Encode;
use itp_storage::{storage_map_key, StorageHasher};
use sp_std::prelude::Vec;

pub struct EnclaveBridgeStorage;

// Separate the prefix from the rest because in our case we changed the storage prefix due to
// the rebranding. With the below implementation of the `TeerexStorageKeys`, we could simply
// define another struct `OtherStorage`, implement `StoragePrefix` for it, and get the
// `TeerexStorageKeys` implementation for free.
pub trait StoragePrefix {
	fn prefix() -> &'static str;
}

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
