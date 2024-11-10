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
pub struct BucketInfo<Moment> {
	pub index: BucketIndex,
	pub bytes: u32,
	pub begins_at: Moment,
	pub ends_at: Moment,
}

#[derive(Encode, Decode, Copy, Clone, PartialEq, Eq, sp_core::RuntimeDebug, TypeInfo)]
pub struct BucketRange<Moment> {
	pub maybe_first: Option<BucketInfo<Moment>>,
	pub maybe_last: Option<BucketInfo<Moment>>,
}
// Bump this version to indicate type changes breaking downstream decoding of wrapped payloads in TrustedNote
pub const NOTE_VERSION: u16 = 1;

#[derive(Encode, Decode, Clone, PartialEq, Eq, sp_core::RuntimeDebug, TypeInfo)]
/// opaque payloads are fine as it will never be necessary to act on the content within the runtime
pub enum TrustedNote {
	/// opaque trusted call which executed successfully. it's up to the client to care about decoding potentially
	/// different versions
	SuccessfulTrustedCall(Vec<u8>),
	/// opaque because we may persist the event log across runtime upgrades without storage migration
	SgxRuntimeEvent(Vec<u8>),
	/// plain utf8 string
	String(Vec<u8>),
	/// IPFS cid
	Ipfs([u8; 46]),
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, sp_core::RuntimeDebug, TypeInfo)]
pub struct TimestampedTrustedNote<Moment> {
	pub timestamp: Moment,
	pub version: u16,
	pub note: TrustedNote,
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
		StorageMap<_, Blake2_128Concat, BucketIndex, BucketInfo<T::Moment>, OptionQuery>;

	#[pallet::storage]
	#[pallet::getter(fn notes)]
	pub(super) type Notes<T: Config> = StorageDoubleMap<
		_,
		Blake2_128Concat,
		BucketIndex,
		Blake2_128Concat,
		NoteIndex,
		TimestampedTrustedNote<T::Moment>,
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
			let note = TimestampedTrustedNote::<T::Moment> {
				timestamp: Timestamp::<T>::get(),
				version: NOTE_VERSION,
				note: TrustedNote::SuccessfulTrustedCall(payload),
			};
			let (bucket_index, note_index) = Self::store_note(note)?;

			for account in link_to {
				<NotesLookup<T>>::mutate(bucket_index, account, |v| v.push(note_index));
			}
			Ok(().into())
		}
	}
}

impl<T: Config> Pallet<T> {
	fn store_note(
		note: TimestampedTrustedNote<T::Moment>,
	) -> Result<(BucketIndex, NoteIndex), Error<T>> {
		let now = Timestamp::<T>::get();
		let bytes = note.encoded_size() as u32;
		let mut bucket = Self::get_bucket_with_room_for(bytes)?;

		let note_index = if let Some(index) = Self::last_note_index() {
			index.checked_add(1).ok_or(Error::<T>::Overflow)?
		} else {
			0
		};
		bucket.bytes = bucket.bytes.saturating_add(bytes);
		bucket.ends_at = now;
		<Buckets<T>>::insert(bucket.index, bucket.clone());
		<Notes<T>>::insert(bucket.index, note_index, note);
		<LastNoteIndex<T>>::put(note_index);
		Ok((bucket.index, note_index))
	}
	fn get_bucket_with_room_for(free: u32) -> Result<BucketInfo<T::Moment>, Error<T>> {
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

	fn new_bucket(index: BucketIndex) -> Result<BucketInfo<T::Moment>, Error<T>> {
		let now = Timestamp::<T>::get();
		let bucket = BucketInfo::<T::Moment> { index, bytes: 0, begins_at: now, ends_at: now };
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
