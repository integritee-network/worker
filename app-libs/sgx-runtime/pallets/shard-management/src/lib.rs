#![cfg_attr(not(feature = "std"), no_std)]

use enclave_bridge_primitives::UpgradableShardConfig;
pub use pallet::*;

pub type UpgradableShardConfigAndChangedBlock<AccountId, BlockNumber> =
	(UpgradableShardConfig<AccountId, BlockNumber>, BlockNumber);
#[frame_support::pallet]
pub mod pallet {
	use crate::{weights::WeightInfo, UpgradableShardConfigAndChangedBlock};
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
		/// Sahrd vault has been previously initialized and can't be overwritten
		ShardVaultAlreadyInitialized,
		/// Parentchain genesis hash has already been initialized and can^t be overwritten
		GenesisAlreadyInitialized,
	}

	#[pallet::storage]
	#[pallet::getter(fn reward_destination)]
	pub type RewardDestinations<T: Config> =
		StorageMap<_, Blake2_128Concat, T::AccountId, T::AccountId, OptionQuery>;

	#[pallet::storage]
	#[pallet::getter(fn maintenance_mode_start_block_number)]
	pub(super) type MaintenanceModeStartBlockNumber<T: Config> =
		StorageValue<_, T::BlockNumber, OptionQuery>;

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
			<UpgradableShardConfigRegistry<T>>::put((config, parentchain_block_number));
			Ok(())
		}
	}
}

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;
pub mod weights;
