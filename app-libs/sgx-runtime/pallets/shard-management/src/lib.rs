#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode};
use enclave_bridge_primitives::UpgradableShardConfig;
use frame_support::{dispatch::DispatchResult, ensure};
pub use pallet::*;
use scale_info::TypeInfo;

pub type UpgradableShardConfigAndChangedBlock<AccountId, BlockNumber> =
	(UpgradableShardConfig<AccountId, BlockNumber>, BlockNumber);

#[derive(Encode, Decode, Debug, Copy, Clone, PartialEq, Eq, Default, TypeInfo)]
#[repr(u8)]
pub enum ShardMode {
	#[default]
	Initializing = 0,
	Normal = 1,
	MaintenanceOngoing = 2,
	Retired = 3,
}

#[frame_support::pallet]
pub mod pallet {
	use crate::{weights::WeightInfo, ShardMode, UpgradableShardConfigAndChangedBlock};
	use enclave_bridge_primitives::UpgradableShardConfig;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;
	use sp_runtime::traits::{AtLeast32Bit, Scale};

	const STORAGE_VERSION: StorageVersion = StorageVersion::new(1);
	#[pallet::pallet]
	#[pallet::storage_version(STORAGE_VERSION)]
	#[pallet::without_storage_info]
	pub struct Pallet<T>(PhantomData<T>);

	/// Configuration trait.
	#[pallet::config]
	pub trait Config: frame_system::Config {
		type WeightInfo: WeightInfo;

		/// Type used for expressing timestamp.
		type Moment: Parameter
			+ Default
			+ AtLeast32Bit
			+ Scale<Self::BlockNumber, Output = Self::Moment>
			+ Copy
			+ MaxEncodedLen
			+ scale_info::StaticTypeInfo;
	}

	#[pallet::error]
	pub enum Error<T> {
		Retired,
	}

	#[pallet::storage]
	#[pallet::getter(fn reward_destination)]
	pub type RewardDestinations<T: Config> =
		StorageMap<_, Blake2_128Concat, T::AccountId, T::AccountId, OptionQuery>;

	#[pallet::storage]
	#[pallet::getter(fn shard_mode)]
	pub(super) type ShardModeRegistry<T: Config> = StorageValue<_, ShardMode, ValueQuery>;

	#[pallet::storage]
	#[pallet::getter(fn upgradable_shard_config)]
	pub(super) type UpgradableShardConfigRegistry<T: Config> = StorageValue<
		_,
		UpgradableShardConfigAndChangedBlock<T::AccountId, T::BlockNumber>,
		OptionQuery,
	>;

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		#[pallet::call_index(0)]
		#[pallet::weight(T::WeightInfo::set_shard_config())]
		pub fn set_shard_config(
			origin: OriginFor<T>,
			config: UpgradableShardConfig<T::AccountId, T::BlockNumber>,
			parentchain_block_number: T::BlockNumber,
		) -> DispatchResult {
			ensure_root(origin)?;
			if let Some((current, _)) = Self::upgradable_shard_config() {
				if current == config {
					return Ok(())
				}
			}
			if config.active_config.maintenance_mode {
				let _ = Self::do_set_shard_mode(ShardMode::MaintenanceOngoing);
			}
			<UpgradableShardConfigRegistry<T>>::put((config, parentchain_block_number));
			Ok(())
		}

		#[pallet::call_index(1)]
		#[pallet::weight(T::WeightInfo::set_shard_mode())]
		pub fn set_shard_mode(origin: OriginFor<T>, new_shard_mode: ShardMode) -> DispatchResult {
			ensure_root(origin)?;
			Self::do_set_shard_mode(new_shard_mode)?;
			Ok(())
		}
	}
}

impl<T: Config> Pallet<T> {
	pub fn do_set_shard_mode(mode: ShardMode) -> DispatchResult {
		// retired is sticky, can't change back
		ensure!(Self::shard_mode() != ShardMode::Retired, Error::<T>::Retired);
		<ShardModeRegistry<T>>::put(mode);
		Ok(())
	}
}
#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;
pub mod weights;
