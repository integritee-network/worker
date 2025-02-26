pub use frame_support::weights::{constants::RocksDbWeight, Weight};

/// Weight functions needed for pallet_parentchain.
pub trait WeightInfo {
	fn set_shard_config() -> Weight;
	fn set_shard_mode() -> Weight;
}

/// Weights for pallet_parentchain using the Integritee parachain node and recommended hardware.
impl WeightInfo for () {
	fn set_shard_config() -> Weight {
		Weight::from_parts(10_000, 0u64)
	}
	fn set_shard_mode() -> Weight {
		Weight::from_parts(10_000, 0u64)
	}
}
