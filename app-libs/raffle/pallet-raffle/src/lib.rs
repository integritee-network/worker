#![cfg_attr(not(feature = "std"), no_std)]

use frame_support::{dispatch::DispatchResult, ensure};
use itp_binary_merkle_tree::{merkle_proof, merkle_root, MerkleProofWithCodec};
use parity_scale_codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_core::{MaxEncodedLen, H256};
use sp_runtime::traits::Keccak256;
use sp_std::{fmt::Debug, vec::Vec};

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
	registration_open: bool,
}

#[frame_support::pallet]
pub mod pallet {
	use crate::{weights::WeightInfo, Raffle, RaffleIndex, Shuffle, WinnerCount};
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;
	use sp_core::H256;
	use sp_std::vec::Vec;

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

		/// Implements random shuffling of values.
		///
		/// If you use this on-chain you need to make sure to have a deterministic seed based
		/// on-chain values. If you use this in SGX, we want to make sure that the randomness
		/// is as secure as possible, hence we  use the SGX's randomness, which uses a hardware
		/// secured randomness source: https://en.wikipedia.org/wiki/RDRAND.
		type Shuffle: Shuffle;
	}

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// A new raffle has been registered
		RaffleAdded { index: RaffleIndex, raffle: Raffle<T::AccountId> },

		/// Someone has registered for a raffle
		RaffleRegistration { who: T::AccountId, index: RaffleIndex },

		/// Winners were drawn of a raffle
		WinnersDrawn { index: RaffleIndex, winners: Vec<T::AccountId>, registrations_root: H256 },
	}

	#[pallet::error]
	pub enum Error<T> {
		/// The raffle does not exist
		NonexistentRaffle,
		/// The registrations for that raffles are closed
		RegistrationsClosed,
		/// Only the raffle owner can draw the winners
		OnlyRaffleOwnerCanDrawWinners,
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

			let raffle = Raffle { owner: sender, winner_count, registration_open: true };

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
			ensure!(
				OnGoingRaffles::<T>::get(index)
					.expect("Asserted above that the key exists; qed")
					.registration_open,
				Error::<T>::RegistrationsClosed
			);

			Registrations::<T>::insert(index, &sender, ());

			Self::deposit_event(Event::RaffleRegistration { who: sender, index });
			Ok(())
		}

		#[pallet::call_index(2)]
		#[pallet::weight(T::WeightInfo::draw_winners())]
		pub fn draw_winners(origin: OriginFor<T>, index: RaffleIndex) -> DispatchResult {
			let sender = ensure_signed(origin)?;
			Self::try_draw_winners(sender, index)
		}
	}
}

impl<T: Config> Pallet<T> {
	pub fn raffle_registrations(index: RaffleIndex) -> Vec<T::AccountId> {
		Registrations::<T>::iter_prefix(index).map(|kv| kv.0).collect()
	}

	fn try_draw_winners(owner: T::AccountId, index: RaffleIndex) -> DispatchResult {
		let raffle =
			OnGoingRaffles::<T>::get(index).ok_or_else(|| Error::<T>::NonexistentRaffle)?;
		ensure!(raffle.registration_open, Error::<T>::RegistrationsClosed);
		ensure!(raffle.owner == owner, Error::<T>::OnlyRaffleOwnerCanDrawWinners);

		let mut registrations = Self::raffle_registrations(index);
		let registrations_root = Self::merkle_root(&registrations);
		<T as Config>::Shuffle::shuffle(&mut registrations);

		let count = core::cmp::min(registrations.len(), raffle.winner_count as usize);
		let winners = registrations[..count].to_vec();

		OnGoingRaffles::<T>::mutate(index, |r| r.as_mut().map(|r| r.registration_open = false));

		Self::deposit_event(Event::WinnersDrawn { index, winners, registrations_root });
		Ok(())
	}

	pub fn merkle_proof_for_registration(
		index: RaffleIndex,
		account: &T::AccountId,
	) -> Option<MerkleProofWithCodec<H256, Vec<u8>>> {
		let registrations = Self::raffle_registrations(index);
		Self::merkle_proof(account, &registrations)
	}

	pub(crate) fn merkle_root(accounts: &[T::AccountId]) -> H256 {
		merkle_root::<Keccak256, _>(accounts.iter().map(Encode::encode))
	}

	pub(crate) fn merkle_proof(
		account: &T::AccountId,
		registrations: &[T::AccountId],
	) -> Option<MerkleProofWithCodec<H256, Vec<u8>>> {
		let leaf_index = Self::merkle_leaf_index_for_registration(account, &registrations)?;
		Some(
			merkle_proof::<Keccak256, _, _>(registrations.iter().map(Encode::encode), leaf_index)
				.into(),
		)
	}

	pub(crate) fn merkle_leaf_index_for_registration(
		account: &T::AccountId,
		registrations: &[T::AccountId],
	) -> Option<usize> {
		registrations.iter().position(|a| a == account)
	}
}

pub trait Shuffle {
	fn shuffle<T>(values: &mut [T]);
}
