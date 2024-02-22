pub use frame_support::weights::{constants::RocksDbWeight, Weight};

/// Weight functions needed for pallet_parentchain.
pub trait WeightInfo {
	fn add_raffle() -> Weight;
	fn register_for_raffle() -> Weight;
}

/// Weights for pallet_parentchain using the Integritee parachain node and recommended hardware.
impl WeightInfo for () {
	fn add_raffle() -> Weight {
		Weight::from_parts(10_000, 0u64)
	}
	fn register_for_raffle() -> Weight {
		Weight::from_parts(10_000, 0u64)
	}
}
