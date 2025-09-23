/*
	Copyright 2021 Integritee AG

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

		http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.

*/

pub use frame_support::weights::{constants::RocksDbWeight, Weight};

/// Weight functions needed for pallet_parentchain.
pub trait WeightInfo {
	fn create_class() -> Weight;
	fn claim() -> Weight;
	fn mint() -> Weight;
	fn redeem() -> Weight;
}

/// Weights for pallet_parentchain using the Integritee parachain node and recommended hardware.
impl WeightInfo for () {
	fn create_class() -> Weight {
		Weight::from_parts(10_000, 0u64)
	}

	fn claim() -> Weight {
		Weight::from_parts(10_000, 0u64)
	}

	fn mint() -> Weight {
		Weight::from_parts(10_000, 0u64)
	}

	fn redeem() -> Weight {
		Weight::from_parts(10_000, 0u64)
	}
}
