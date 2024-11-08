#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode};
use frame_support::{pallet_prelude::Get, traits::Currency};
pub use pallet::*;
use scale_info::TypeInfo;

use sp_std::{vec, vec::Vec};

pub type BalanceOf<T> =
	<<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

pub type BucketIndex = u32;
pub type NoteIndex = u64;

#[derive(Encode, Decode, Copy, Clone, PartialEq, Eq, sp_core::RuntimeDebug, TypeInfo)]
pub struct BucketInfo {
	index: BucketIndex,
	bytes: u32,
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, sp_core::RuntimeDebug, TypeInfo)]
/// opaque payloads are fine as it will never be necessary to act on the content within the runtime
pub enum TrustedNote {
	/// opaque trusted call. it's up to the client to care about decoding potentially
	/// different versions
	TrustedCall(Vec<u8>),
	/// opaque because we may persist the event log across runtime upgrades without storage migration
	SgxRuntimeEvent(Vec<u8>),
}

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;

	const STORAGE_VERSION: StorageVersion = StorageVersion::new(1);
	#[pallet::pallet]
	#[pallet::storage_version(STORAGE_VERSION)]
	#[pallet::without_storage_info]
	pub struct Pallet<T>(PhantomData<T>);

	/// Configuration trait.
	#[pallet::config]
	pub trait Config: frame_system::Config + pallet_timestamp::Config {
		#[pallet::constant]
		type MomentsPerDay: Get<Self::Moment>;

		type Currency: Currency<Self::AccountId>;

		/// max encoded length of note. a typical trusted call is expected to be 3x32 byte + 256 byte for utf8 content
		#[pallet::constant]
		type MaxNoteSize: Get<u32>;
	}

	#[pallet::error]
	pub enum Error<T> {
		BucketPurged,
		Overflow,
		TooManyLinkedAccounts,
		NoteTooLong,
	}

	#[pallet::storage]
	#[pallet::getter(fn last_note_index)]
	pub(super) type LastNoteIndex<T: Config> = StorageValue<_, NoteIndex, OptionQuery>;

	#[pallet::storage]
	#[pallet::getter(fn buckets)]
	pub(super) type Buckets<T: Config> =
		StorageMap<_, Blake2_128Concat, BucketIndex, BucketInfo, OptionQuery>;

	#[pallet::storage]
	#[pallet::getter(fn notes)]
	pub(super) type Notes<T: Config> = StorageDoubleMap<
		_,
		Blake2_128Concat,
		BucketIndex,
		Blake2_128Concat,
		NoteIndex,
		TrustedNote,
		OptionQuery,
	>;

	#[pallet::storage]
	#[pallet::getter(fn notes_lookup)]
	pub(super) type NotesLookup<T: Config> = StorageDoubleMap<
		_,
		Blake2_128Concat,
		BucketIndex,
		Blake2_128Concat,
		T::AccountId,
		Vec<NoteIndex>,
		ValueQuery,
	>;

	#[pallet::call]
	impl<T: Config> Pallet<T>
	where
		sp_core::H256: From<<T as frame_system::Config>::Hash>,
	{
		#[pallet::call_index(0)]
		#[pallet::weight((10_000, DispatchClass::Normal, Pays::Yes))]
		pub fn note_trusted_call(
			origin: OriginFor<T>,
			// who is involved in this note (usually sender and recipient)
			link_to: Vec<T::AccountId>,
			payload: Vec<u8>,
		) -> DispatchResultWithPostInfo {
			ensure_signed(origin)?;
			ensure!(link_to.len() < 3, Error::<T>::TooManyLinkedAccounts);
			ensure!(payload.len() <= T::MaxNoteSize::get() as usize, Error::<T>::NoteTooLong);
			let bucket_index = 0; // todo
			let mut bucket =
				Self::buckets(bucket_index).unwrap_or(BucketInfo { index: 0, bytes: 0 });
			bucket.bytes += payload.len() as u32;
			let note_index = if let Some(index) = Self::last_note_index() {
				index.checked_add(1).ok_or(Error::<T>::Overflow)?
			} else {
				0
			};
			<Notes<T>>::insert(bucket_index, note_index, TrustedNote::TrustedCall(payload));
			for account in link_to {
				<NotesLookup<T>>::mutate(bucket_index, account, |v| v.push(note_index));
			}
			<Buckets<T>>::insert(bucket_index, bucket);
			<LastNoteIndex<T>>::put(note_index);
			Ok(().into())
		}
	}
}

impl<T: Config> Pallet<T> where sp_core::H256: From<<T as frame_system::Config>::Hash> {}
#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;
