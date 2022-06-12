#![cfg_attr(not(feature = "std"), no_std)]

use itp_storage::{storage_map_key, storage_value_key, StorageHasher};
use itp_types::GameId;
use sp_std::prelude::Vec;

pub const RUNNER: &str = "Runner";
pub const REGISTRY: &str = "GameRegistry";

pub struct RunnerStorage;

impl StoragePrefix for RunnerStorage {
	fn prefix() -> &'static str {
		RUNNER
	}
}

pub type StorageKey = Vec<u8>;

pub trait RunnerStorageKeys {
	/// Storage key for `runner`, we are using the concrete type `GameId` but will need to be changed
	fn runner(runner_id: GameId) -> StorageKey;
}

impl<S: StoragePrefix> RunnerStorageKeys for S {
	fn runner(runner_id: GameId) -> StorageKey {
		storage_map_key(Self::prefix(), "Runners", &runner_id, &StorageHasher::Blake2_128)
	}
}

pub struct RegistryStorage;

// Separate the prefix from the rest because in our case we changed the storage prefix due to
// the rebranding. With the below implementation of the `RegistryStorageKeys`, we could simply
// define another struct `OtherStorage`, implement `StoragePrefix` for it, and get the
// `RegistryStorageKeys` implementation for free.
pub trait StoragePrefix {
	fn prefix() -> &'static str;
}

impl StoragePrefix for RegistryStorage {
	fn prefix() -> &'static str {
		REGISTRY
	}
}

pub trait RegistryStorageKeys {
	/// Storage key for `queued`
	fn queued() -> StorageKey;
}

impl<S: StoragePrefix> RegistryStorageKeys for S {
	fn queued() -> StorageKey {
		storage_value_key(Self::prefix(), "Queued")
	}
}
