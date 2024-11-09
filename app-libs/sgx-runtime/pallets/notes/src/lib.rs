#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode};
use frame_support::{dispatch::DispatchResult, ensure, pallet_prelude::Get, traits::Currency};
pub use pallet::*;
use pallet_timestamp::Pallet as Timestamp;
use scale_info::TypeInfo;
use sp_runtime::Saturating;
use sp_std::{vec, vec::Vec};

pub type BalanceOf<T> =
	<<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

pub type BucketIndex = u32;
pub type NoteIndex = u64;

#[derive(Encode, Decode, Copy, Clone, PartialEq, Eq, sp_core::RuntimeDebug, TypeInfo)]
pub struct BucketInfo<T: pallet_timestamp::Config> {
	index: BucketIndex,
	bytes: u32,
	begins_at: <T as pallet_timestamp::Config>::Moment,
	ends_at: <T as pallet_timestamp::Config>::Moment,
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
	pub trait Config: frame_system::Config + pallet_timestamp::Config + TypeInfo {
		#[pallet::constant]
		type MomentsPerDay: Get<Self::Moment>;

		type Currency: Currency<Self::AccountId>;

		/// max encoded length of note. a typical trusted call is expected to be 3x32 byte + 256 byte for utf8 content
		#[pallet::constant]
		type MaxNoteSize: Get<u32>;

		/// max size of a bucket in bytes
		#[pallet::constant]
		type MaxBucketSize: Get<u32>;

		/// max size of all persisted buckets in bytes
		#[pallet::constant]
		type MaxTotalSize: Get<u32>;
	}

	#[pallet::error]
	pub enum Error<T> {
		BucketPurged,
		Overflow,
		TooManyLinkedAccounts,
		NoteTooLong,
		EnforceRetentionLimitFailed,
	}

	#[pallet::storage]
	#[pallet::getter(fn last_note_index)]
	pub(super) type LastNoteIndex<T: Config> = StorageValue<_, NoteIndex, OptionQuery>;

	#[pallet::storage]
	#[pallet::getter(fn last_bucket_index)]
	pub(super) type LastBucketIndex<T: Config> = StorageValue<_, BucketIndex, OptionQuery>;

	#[pallet::storage]
	#[pallet::getter(fn first_bucket_index)]
	pub(super) type FirstBucketIndex<T: Config> = StorageValue<_, BucketIndex, OptionQuery>;

	#[pallet::storage]
	#[pallet::getter(fn closed_buckets_size)]
	pub(super) type ClosedBucketsSize<T: Config> = StorageValue<_, u32, ValueQuery>;

	#[pallet::storage]
	#[pallet::getter(fn buckets)]
	pub(super) type Buckets<T: Config> =
		StorageMap<_, Blake2_128Concat, BucketIndex, BucketInfo<T>, OptionQuery>;

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

			let (bucket_index, note_index) = Self::store_note(TrustedNote::TrustedCall(payload))?;

			for account in link_to {
				<NotesLookup<T>>::mutate(bucket_index, account, |v| v.push(note_index));
			}
			Ok(().into())
		}
	}
}

impl<T: Config + TypeInfo> Pallet<T> {
	fn store_note(note: TrustedNote) -> Result<(BucketIndex, NoteIndex), Error<T>> {
		let bytes = note.encoded_size() as u32;
		let mut bucket = Self::get_bucket_with_room_for(bytes)?;

		let note_index = if let Some(index) = Self::last_note_index() {
			index.checked_add(1).ok_or(Error::<T>::Overflow)?
		} else {
			0
		};
		bucket.bytes = bucket.bytes.saturating_add(bytes as u32);
		<Buckets<T>>::insert(bucket.index, bucket.clone());
		<Notes<T>>::insert(bucket.index, note_index, note);
		<LastNoteIndex<T>>::put(note_index);
		Ok((bucket.index, note_index))
	}
	fn get_bucket_with_room_for(free: u32) -> Result<BucketInfo<T>, Error<T>> {
		ensure!(free <= T::MaxNoteSize::get(), Error::<T>::NoteTooLong);
		if Self::first_bucket_index().is_none() {
			<FirstBucketIndex<T>>::put(0);
		}
		let new_bucket_index = if let Some(bucket_index) = Self::last_bucket_index() {
			if let Some(bucket) = Self::buckets(bucket_index) {
				if bucket.bytes + free <= T::MaxBucketSize::get() {
					return Ok(bucket)
				}
			}
			bucket_index.saturating_add(1)
		} else {
			0
		};
		<LastBucketIndex<T>>::put(new_bucket_index);
		Self::new_bucket(new_bucket_index)
	}

	fn new_bucket(index: BucketIndex) -> Result<BucketInfo<T>, Error<T>> {
		let now = Timestamp::<T>::get();
		let bucket = BucketInfo::<T> { index, bytes: 0, begins_at: now, ends_at: now };
		Self::enforce_retention_limits(index)?;
		Ok(bucket)
	}

	fn enforce_retention_limits(stop_at_bucket_index: BucketIndex) -> Result<(), Error<T>> {
		if Self::closed_buckets_size() + T::MaxBucketSize::get() < T::MaxTotalSize::get() {
			return Ok(())
		};
		if let Some(bi) = Self::first_bucket_index() {
			if bi >= stop_at_bucket_index {
				return Ok(())
			};
			let purged_bucket_size = Self::buckets(bi).map(|b| b.bytes).unwrap_or(0);
			<Buckets<T>>::remove(bi);
			<Notes<T>>::clear_prefix(bi, u32::MAX, None);
			<NotesLookup<T>>::clear_prefix(bi, u32::MAX, None);
			<ClosedBucketsSize<T>>::mutate(|s| *s = s.saturating_sub(purged_bucket_size));
			<FirstBucketIndex<T>>::put(bi.saturating_add(1));
		} else {
			return Err(Error::<T>::EnforceRetentionLimitFailed)
		};
		// when limits change, it may not be enough to purge one bucket only
		Self::enforce_retention_limits(stop_at_bucket_index)?;
		Ok(())
	}
}
#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;
