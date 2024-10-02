pub use frame_support::weights::{constants::RocksDbWeight, Weight};

/// Weight functions needed for pallet_parentchain.
pub trait WeightInfo {
	fn push_by_one_day() -> Weight;
	fn set_winnings() -> Weight;
	fn guess() -> Weight;
}

/// Weights for pallet_parentchain using the Integritee parachain node and recommended hardware.
impl WeightInfo for () {
	fn push_by_one_day() -> Weight {
		Weight::from_parts(10_000, 0u64)
	}

	fn set_winnings() -> Weight {
		Weight::from_parts(10_000, 0u64)
	}
	fn guess() -> Weight {
		Weight::from_parts(10_000, 0u64)
	}
}
