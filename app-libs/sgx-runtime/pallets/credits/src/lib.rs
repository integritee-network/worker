#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode};
use frame_support::{
	dispatch::DispatchResult,
	pallet_prelude::Get,
	traits::{Currency, ExistenceRequirement, OnTimestampSet},
	PalletId, StorageDoubleMap as StorageDoubleMapTrait,
};
use itp_randomness::Randomness;
use log::*;
use scale_info::TypeInfo;
use sp_core::H256;
use sp_runtime::{
	traits::{CheckedDiv, Hash, Saturating, Zero},
	SaturatedConversion,
};
use sp_std::{cmp::min, cmp::Ordering, ops::Rem, vec, vec::Vec};

pub use pallet::*;

pub type BalanceOf<T> =
	<<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

#[derive(Encode, Decode, Debug, Copy, Clone, PartialEq, Eq, Default, TypeInfo)]
pub struct BalanceWithExpiry<Balance, Moment>
where
	Balance: Copy + Saturating + Zero + Encode + Decode,
	Moment: Copy + Saturating + Zero + Encode + Decode,
{
	balance: Balance,
	expiry: Option<Moment>,
}

#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq, Default, TypeInfo)]
pub struct SortedCreditsStore<Balance, Moment>
where
	Balance: Copy + Saturating + Zero + Encode + Decode,
	Moment: Copy + Saturating + Zero + Encode + Decode + Ord,
{
	balances_with_expiry: Vec<BalanceWithExpiry<Balance, Moment>>,
}

impl<Balance, Moment> SortedCreditsStore<Balance, Moment>
where
	Balance: Copy + Saturating + Zero + Encode + Decode,
	Moment: Copy + Saturating + Zero + Encode + Decode + Ord,
{
	pub fn new() -> Self {
		Self { balances_with_expiry: vec![] }
	}

	pub fn len(&self) -> usize {
		self.balances_with_expiry.len()
	}

	pub fn push(&mut self, credit: BalanceWithExpiry<Balance, Moment>) {
		self.balances_with_expiry.push(credit);
		self.balances_with_expiry.sort_by(|a, b| {
			match (a.expiry, b.expiry) {
				(Some(a_expiry), Some(b_expiry)) => a_expiry.cmp(&b_expiry),
				(Some(_), None) => Ordering::Less,
				(None, Some(_)) => Ordering::Greater,
				(None, None) => Ordering::Equal,
			}
		});
	}

	pub fn append(&mut self, other: &mut SortedCreditsStore<Balance, Moment>) -> DispatchResult {
		self.balances_with_expiry.append(&mut other.balances_with_expiry);
		self.balances_with_expiry.sort_by(|a, b| {
			match (a.expiry, b.expiry) {
				(Some(a_expiry), Some(b_expiry)) => a_expiry.cmp(&b_expiry),
				(Some(_), None) => Ordering::Less,
				(None, Some(_)) => Ordering::Greater,
				(None, None) => Ordering::Equal,
			}
		});
		Ok(())
	}

	/// Get the total balance of all credits, ignoring expiry.
	pub fn total(&self) -> Balance
	where
		Balance: Saturating,
	{
		self.balances_with_expiry.iter().fold(Balance::zero(), |acc, x| acc.saturating_add(x.balance))
	}

	/// Expire credits that have passed their expiry time.
	pub fn expire(&mut self, now: Moment)
	where
		Moment: Saturating + PartialOrd,
	{
		self.balances_with_expiry.retain(|c| match c.expiry {
			Some(expiry) => expiry > now,
			None => true,
		});
	}

	/// Redeem credits, starting from the ones that expire the soonest.
	/// Does not check expiry, that should be done explicitly beforehand using `expire()`.
	pub fn redeem(&mut self, mut amount: Balance) -> Result<(), ()>
	where
		Balance: Saturating + PartialOrd,
	{
		if self.total() < amount {
			return Err(());
		}
		for credit in &mut self.balances_with_expiry {
			if amount.is_zero() {
				break;
			}
			if credit.balance <= amount {
				amount = amount.saturating_sub(credit.balance);
				credit.balance = Balance::zero();
			} else {
				credit.balance = credit.balance.saturating_sub(amount);
				amount = Balance::zero();
			}
		}
		self.balances_with_expiry.retain(|c| !c.balance.is_zero());
		Ok(())
	}

	pub fn get_balance_with_soonest_expiry(&self) -> Option<BalanceWithExpiry<Balance, Moment>> {
		self.balances_with_expiry.first().copied()
	}
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
	}

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		CreatedClass {
			id: CreditClassId,
		},
		Claimed {
			id: CreditClassId,
			commitment: T::Hash,
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
		InvalidClassId,
		NoClaimableCredits,
		InsufficientBalance,
		Unauthorized,
		ClassAdminUndefined,
		ExpiryInPast,
	}

	#[pallet::storage]
	#[pallet::getter(fn credits)]
	pub type Credits<T: Config> = StorageDoubleMap<
		_,
		Blake2_128Concat,
		CreditClassId,
		Blake2_128Concat,
		T::AccountId,
		SortedCreditsStore<BalanceOf<T>, T::Moment>,
		ValueQuery,
	>;

	#[pallet::storage]
	#[pallet::getter(fn admin)]
	pub(super) type Admin<T: Config> =
		StorageMap<_, Blake2_128Concat, CreditClassId, T::AccountId, OptionQuery>;

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
		#[pallet::weight((<T as Config>::WeightInfo::create_class(), DispatchClass::Normal, Pays::Yes)
        )]
		pub fn create_class(origin: OriginFor<T>, id: CreditClassId) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;
			ensure!(!<Credits<T>>::contains_prefix(id), Error::<T>::ClassIdExists);
			<Credits<T>>::insert(
				id,
				&sender,
				SortedCreditsStore::new(),
			);
			Self::deposit_event(Event::CreatedClass { id });
			Ok(().into())
		}

		/// create a new credit class
		#[pallet::call_index(1)]
		#[pallet::weight((<T as Config>::WeightInfo::claim(), DispatchClass::Normal, Pays::Yes)
        )]
		pub fn claim(
			origin: OriginFor<T>,
			id: CreditClassId,
			secret: T::Hash,
		) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;
			let commitment = T::Hashing::hash_of(&secret);
			let commitment_account = T::AccountId::decode(&mut H256::from(commitment).as_bytes())
				.expect("32 bytes can always construct an AccountId32");
			let mut claimables = <Credits<T>>::get(id, &commitment_account);
			ensure!(claimables.len() > 0, Error::<T>::NoClaimableCredits);
			<Credits<T>>::remove(id, &commitment_account);
			let mut sender_credits = <Credits<T>>::get(id, &sender);
			sender_credits.append(&mut claimables);
			<Credits<T>>::insert(id, &sender, sender_credits);
			Self::deposit_event(Event::Claimed { id, commitment });
			Ok(().into())
		}

		#[pallet::call_index(2)]
		#[pallet::weight((<T as Config>::WeightInfo::mint(), DispatchClass::Normal, Pays::Yes)
        )]
		pub fn mint(
			origin: OriginFor<T>,
			id: CreditClassId,
			owner: T::AccountId,
			amount: BalanceOf<T>,
			maybe_expiry: Option<T::Moment>,
		) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;
			ensure!(<Credits<T>>::contains_prefix(id), Error::<T>::InvalidClassId);
			let admin = Self::admin(id).ok_or(Error::<T>::ClassAdminUndefined)?;
			ensure!(admin == sender, Error::<T>::Unauthorized);
			if let Some(expiry) = maybe_expiry {
				ensure!(expiry > <pallet_timestamp::Pallet<T>>::get(), Error::<T>::ExpiryInPast);
			}
			let credit = BalanceWithExpiry { balance: amount, expiry: maybe_expiry };

			let mut credits = Self::credits(id, &sender);
			credits.expire(<pallet_timestamp::Pallet<T>>::get());
			credits.push(credit);
			Credits::<T>::insert(id, &owner, credits);
			TotalMintedBy::<T>::mutate(id, &sender, |total| *total = total.saturating_add(amount));
			Self::deposit_event(Event::Minted { id, to: owner, amount, expiry: maybe_expiry });
			Ok(().into())
		}

		#[pallet::call_index(3)]
		#[pallet::weight((<T as Config>::WeightInfo::redeem(), DispatchClass::Normal, Pays::Yes)
		)]
		pub fn redeem(
			origin: OriginFor<T>,
			id: CreditClassId,
			owner: T::AccountId,
			amount: BalanceOf<T>,
		) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;
			ensure!(<Credits<T>>::contains_prefix(id), Error::<T>::InvalidClassId);
			let admin = Self::admin(id).ok_or(Error::<T>::ClassAdminUndefined)?;
			ensure!(admin == sender, Error::<T>::Unauthorized);

			let mut credits = Self::credits(id, &sender);
			credits.expire(<pallet_timestamp::Pallet<T>>::get());
			credits.redeem(amount).map_err(|_| Error::<T>::InsufficientBalance)?;
			Credits::<T>::insert(id, &owner, credits);
			TotalRedeemedBy::<T>::mutate(id, &sender, |total| *total = total.saturating_add(amount));

			Self::deposit_event(Event::Redeemed { id, from: owner, amount });
			Ok(().into())
		}
	}
}

impl<T: Config> Pallet<T> where sp_core::H256: From<<T as frame_system::Config>::Hash> {}
#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;
pub mod weights;
