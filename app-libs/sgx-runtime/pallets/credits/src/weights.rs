pub use frame_support::weights::{constants::RocksDbWeight, Weight};

/// Weight functions needed for pallet_parentchain.
pub trait WeightInfo {
	fn create_class() -> Weight;
	fn claim() -> Weight;
}

/// Weights for pallet_parentchain using the Integritee parachain node and recommended hardware.
impl WeightInfo for () {
	fn create_class() -> Weight {
		Weight::from_parts(10_000, 0u64)
	}

	fn claim() -> Weight {
		Weight::from_parts(10_000, 0u64)
	}
}
