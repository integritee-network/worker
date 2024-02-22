#![cfg_attr(not(feature = "std"), no_std)]

use frame_support::storage::PrefixIterator;
use parity_scale_codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_core::MaxEncodedLen;
use sp_std::fmt::Debug;

pub use pallet::*;

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;
pub mod weights;

pub type RaffleIndex = u32;
pub type WinnerCount = u32;

#[derive(Debug, Clone, Encode, Decode, Eq, PartialEq, TypeInfo, MaxEncodedLen)]
pub struct Raffle<AccountId: Debug> {
	owner: AccountId,
	winner_count: WinnerCount,
}

#[frame_support::pallet]
pub mod pallet {
	use crate::{weights::WeightInfo, Raffle, RaffleIndex, WinnerCount};
	use frame_support::{pallet_prelude::*, sp_runtime::traits::Header};
	use frame_system::{pallet_prelude::*, AccountInfo};
	use sp_runtime::traits::{AtLeast32Bit, Scale};

	const STORAGE_VERSION: StorageVersion = StorageVersion::new(0);
	#[pallet::pallet]
	#[pallet::storage_version(STORAGE_VERSION)]
	#[pallet::without_storage_info]
	pub struct Pallet<T>(PhantomData<T>);

	/// Configuration trait.
	#[pallet::config]
	pub trait Config: frame_system::Config {
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
		type WeightInfo: WeightInfo;
	}

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// A new raffle has been registered
		RaffleAdded { index: RaffleIndex, raffle: Raffle<T::AccountId> },

		/// Someone has registered for a raffle
		RaffleRegistration { who: T::AccountId, index: RaffleIndex },
	}

	#[pallet::error]
	pub enum Error<T> {
		/// The raffle does not exist
		NonexistentRaffle,
	}

	/// Ongoing raffles.
	#[pallet::storage]
	#[pallet::getter(fn ongoing_raffles)]
	pub type OnGoingRaffles<T: Config> =
		StorageMap<_, Blake2_128Concat, RaffleIndex, Raffle<T::AccountId>, OptionQuery>;

	#[pallet::storage]
	#[pallet::getter(fn registrations)]
	pub type Registrations<T: Config> = StorageDoubleMap<
		_,
		Blake2_128Concat,
		RaffleIndex,
		Blake2_128Concat,
		T::AccountId,
		(),
		OptionQuery,
	>;

	#[pallet::storage]
	#[pallet::getter(fn raffle_count)]
	pub type RaffleCount<T> = StorageValue<_, RaffleIndex, ValueQuery>;

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		#[pallet::call_index(0)]
		#[pallet::weight(T::WeightInfo::add_raffle())]
		pub fn add_raffle(origin: OriginFor<T>, winner_count: WinnerCount) -> DispatchResult {
			let sender = ensure_signed(origin)?;
			let index = Self::raffle_count();

			let raffle = Raffle { owner: sender, winner_count };

			OnGoingRaffles::<T>::insert(index, &raffle);
			RaffleCount::<T>::put(index + 1);

			Self::deposit_event(Event::RaffleAdded { index, raffle });
			Ok(())
		}

		#[pallet::call_index(1)]
		#[pallet::weight(T::WeightInfo::register_for_raffle())]
		pub fn register_for_raffle(origin: OriginFor<T>, index: RaffleIndex) -> DispatchResult {
			let sender = ensure_signed(origin)?;

			ensure!(OnGoingRaffles::<T>::contains_key(index), Error::<T>::NonexistentRaffle);

			Registrations::<T>::insert(index, &sender, ());

			Self::deposit_event(Event::RaffleRegistration { who: sender, index });
			Ok(())
		}
	}
}

impl<T: Config> Pallet<T> {
	pub fn raffle_registrations(index: RaffleIndex) -> Vec<T::AccountId> {
		Registrations::<T>::iter_prefix(index).map(|kv| kv.0).collect()
	}
}
