#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode};
use sp_std::prelude::Vec;

use itp_storage::{storage_map_key, StorageHasher};

pub struct RegistryStorage;

// Separate the prefix from the rest because in our case we changed the storage prefix due to
// the rebranding. With the below implementation of the `TeerexStorageKeys`, we could simply
// define another struct `OtherStorage`, implement `StoragePrefix` for it, and get the
// `TeerexStorageKeys` implementation for free.
pub trait StoragePrefix {
	fn prefix() -> &'static str;
}

impl StoragePrefix for RegistryStorage {
	fn prefix() -> &'static str {
		"Registry"
	}
}

pub trait RegistryStorageKeys {
	fn queue_game() -> Vec<u8>;
}

#[derive(Encode)]
pub struct GameEngine {
	id: u8,
	version: u8,
}

impl<S: StoragePrefix> RegistryStorageKeys for S {
	fn queue_game() -> Vec<u8> {
		let game_engine = GameEngine { id: 1u8, version: 1u8 };
		storage_map_key(Self::prefix(), "GameQueues", &game_engine, &StorageHasher::Identity)
	}
}
