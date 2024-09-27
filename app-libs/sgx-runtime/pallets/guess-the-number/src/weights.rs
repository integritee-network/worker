pub use frame_support::weights::{constants::RocksDbWeight, Weight};

/// Weight functions needed for pallet_parentchain.
pub trait WeightInfo {
	fn set_block() -> Weight;
	fn init_shard_vault() -> Weight;
	fn init_parentchain_genesis_hash() -> Weight;
	fn force_account_info() -> Weight;
	fn set_now() -> Weight;
	fn set_creation_block() -> Weight;
	fn set_creation_timestamp() -> Weight;
}

/// Weights for pallet_parentchain using the Integritee parachain node and recommended hardware.
impl WeightInfo for () {
	fn set_block() -> Weight {
		Weight::from_parts(10_000, 0u64)
	}
	fn init_shard_vault() -> Weight {
		Weight::from_parts(10_000, 0u64)
	}
	fn init_parentchain_genesis_hash() -> Weight {
		Weight::from_parts(10_000, 0u64)
	}
	fn force_account_info() -> Weight {
		Weight::from_parts(10_000, 0u64)
	}
	fn set_now() -> Weight {
		Weight::from_parts(10_000, 0u64)
	}
	fn set_creation_block() -> Weight {
		Weight::from_parts(10_000, 0u64)
	}
	fn set_creation_timestamp() -> Weight {
		Weight::from_parts(10_000, 0u64)
	}
}
