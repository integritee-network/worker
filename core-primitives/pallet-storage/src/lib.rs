#![cfg_attr(not(feature = "std"), no_std)]

use codec::Encode;
use hex_literal::hex;
use itp_storage::{storage_map_key, storage_value_key, StorageHasher};
use itp_types::{AccountId, ShardIdentifier};
use sp_std::prelude::Vec;

// this is a hack, just couldn't find the twox128 input to get this key
const PALLET_VERSION_STORAGE_KEY_POSTFIX_HEX: [u8; 16] = hex!("4e7b9012096b41c4eb3aaf947f6ea429");

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
	fn upgradable_shard_config<T: Encode>(shard: T) -> Vec<u8>;
	fn pallet_version() -> Vec<u8>;
}

impl<S: StoragePrefix> EnclaveBridgeStorageKeys for S {
	fn shard_status<T: Encode>(shard: T) -> Vec<u8> {
		storage_map_key(Self::prefix(), "ShardStatus", &shard, &StorageHasher::Blake2_128Concat)
	}
	fn upgradable_shard_config<T: Encode>(shard: T) -> Vec<u8> {
		storage_map_key(
			Self::prefix(),
			"ShardConfigRegistry",
			&shard,
			&StorageHasher::Blake2_128Concat,
		)
	}

	fn pallet_version() -> Vec<u8> {
		let mut bytes = sp_core::twox_128(Self::prefix().as_bytes()).to_vec();
		bytes.extend(PALLET_VERSION_STORAGE_KEY_POSTFIX_HEX.to_vec());
		bytes
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

	fn pallet_version() -> Vec<u8>;
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

	fn pallet_version() -> Vec<u8> {
		let mut bytes = sp_core::twox_128(Self::prefix().as_bytes()).to_vec();
		bytes.extend(PALLET_VERSION_STORAGE_KEY_POSTFIX_HEX.to_vec());
		bytes
	}
}

pub struct SidechainPalletStorage;

impl StoragePrefix for SidechainPalletStorage {
	fn prefix() -> &'static str {
		"Sidechain"
	}
}

pub trait SidechainPalletStorageKeys {
	fn latest_sidechain_block_confirmation(shard: ShardIdentifier) -> Vec<u8>;

	fn pallet_version() -> Vec<u8>;
}

impl<S: StoragePrefix> SidechainPalletStorageKeys for S {
	fn latest_sidechain_block_confirmation(shard: ShardIdentifier) -> Vec<u8> {
		storage_map_key(
			Self::prefix(),
			"LatestSidechainBlockConfirmation",
			&shard,
			&StorageHasher::Blake2_128Concat,
		)
	}

	fn pallet_version() -> Vec<u8> {
		let mut bytes = sp_core::twox_128(Self::prefix().as_bytes()).to_vec();
		bytes.extend(PALLET_VERSION_STORAGE_KEY_POSTFIX_HEX.to_vec());
		bytes
	}
}
