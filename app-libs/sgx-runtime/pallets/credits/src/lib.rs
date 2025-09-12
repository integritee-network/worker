#![cfg_attr(not(feature = "std"), no_std)]

use codec::Decode;
use frame_support::{
	dispatch::DispatchResult,
	pallet_prelude::Get,
	traits::{Currency, ExistenceRequirement, OnTimestampSet},
	PalletId,
};
use itp_randomness::Randomness;
use log::*;
use sp_core::H256;
use sp_runtime::{
	traits::{CheckedDiv, Hash, Saturating, Zero},
	SaturatedConversion,
};
use sp_std::{cmp::min, ops::Rem, vec, vec::Vec};

pub use pallet::*;

pub type BalanceOf<T> =
	<<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

pub struct BalanceWithExpiry<T> {
	balance: BalanceOf<T>,
	expiry: Option<T::Moment>,
}

pub type CreditClassId = u32;
pub enum CreditsRole {
	/// may issue new credits to an account.
	Minter,
	/// may redeem/burn credits from accounts
	Redeemer,
}

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use crate::weights::WeightInfo;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;
	use sp_runtime::traits::Zero;

	const STORAGE_VERSION: StorageVersion = StorageVersion::new(1);
	#[pallet::pallet]
	#[pallet::storage_version(STORAGE_VERSION)]
	#[pallet::without_storage_info]
	pub struct Pallet<T>(PhantomData<T>);

	/// Configuration trait.
	#[pallet::config]
	pub trait Config: frame_system::Config + pallet_timestamp::Config {
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
		type WeightInfo: WeightInfo;

		#[pallet::constant]
		type MomentsPerDay: Get<Self::Moment>;

		type Currency: Currency<Self::AccountId>;
		/// The pallet id, used for deriving technical account ID for the pot.
		#[pallet::constant]
		type PalletId: Get<PalletId>;
	}

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		CreatedClass {
			id: CreditClassId,
		},
		Minted {
			id: CreditClassId,
			to: T::AccountId,
			amount: BalanceOf<T>,
			expiry: Option<T::Moment>,
		},
		Redeemed {
			id: CreditClassId,
			from: T::AccountId,
			amount: BalanceOf<T>,
		},
	}

	#[pallet::error]
	pub enum Error<T> {
		ClassIdExists,
	}

	#[pallet::storage]
	#[pallet::getter(fn credits)]
	pub type Credits<T: Config> = StorageDoubleMap<
		_,
		Blake2_128Concat,
		CreditClassId,
		Blake2_128Concat,
		T::AccountId,
		Vec<BalanceWithExpiry<T>>,
		ValueQuery,
	>;

	#[pallet::storage]
	#[pallet::getter(fn admin)]
	pub(super) type Admin<T: Config> =
		StorageMap<_, Blake2_128Concat, T::AccountId, T::AccountId, OptionQuery>;

	#[pallet::storage]
	#[pallet::getter(fn total_minted_by)]
	pub type TotalMintedBy<T: Config> = StorageDoubleMap<
		_,
		Blake2_128Concat,
		CreditClassId,
		Blake2_128Concat,
		T::AccountId,
		BalanceOf<T>,
		ValueQuery,
	>;

	#[pallet::storage]
	#[pallet::getter(fn total_redeemed_by)]
	pub type TotalRedeemedBy<T: Config> = StorageDoubleMap<
		_,
		Blake2_128Concat,
		CreditClassId,
		Blake2_128Concat,
		T::AccountId,
		BalanceOf<T>,
		ValueQuery,
	>;

	#[pallet::call]
	impl<T: Config> Pallet<T>
	where
		sp_core::H256: From<<T as frame_system::Config>::Hash>,
	{
		/// create a new credit class
		#[pallet::call_index(0)]
		#[pallet::weight((<T as Config>::WeightInfo::create(), DispatchClass::Normal, Pays::Yes)
        )]
		pub fn create_class(origin: OriginFor<T>, id: CreditClassId) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;
			ensure!(!<Credits<T>>::contains_prefix(id), Error::<T>::ClassIdExists);
			<Credits<T>>::insert(id, &sender, vec![]);
			Self::deposit_event(Event::CreatedClass { id });
			Ok(().into())
		}
	}
}

impl<T: Config> Pallet<T> {}
#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;
pub mod weights;
