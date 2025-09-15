#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode};
use frame_support::{
	pallet_prelude::Get,
	traits::{Currency, ReservableCurrency},
	StorageDoubleMap as StorageDoubleMapTrait,
};
pub use pallet::*;
use scale_info::TypeInfo;
use sp_core::H256;
use sp_runtime::{
	traits::{Hash, Saturating, Zero},
	DispatchError,
};
use sp_std::{cmp::Ordering, marker::PhantomData, vec, vec::Vec};

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

	pub fn is_empty(&self) -> bool {
		self.balances_with_expiry.is_empty()
	}

	pub fn push(&mut self, credit: BalanceWithExpiry<Balance, Moment>) {
		self.balances_with_expiry.push(credit);
		self.balances_with_expiry.sort_by(|a, b| match (a.expiry, b.expiry) {
			(Some(a_expiry), Some(b_expiry)) => a_expiry.cmp(&b_expiry),
			(Some(_), None) => Ordering::Less,
			(None, Some(_)) => Ordering::Greater,
			(None, None) => Ordering::Equal,
		});
	}

	pub fn append(&mut self, other: &mut SortedCreditsStore<Balance, Moment>) {
		self.balances_with_expiry.append(&mut other.balances_with_expiry);
		self.balances_with_expiry.sort_by(|a, b| match (a.expiry, b.expiry) {
			(Some(a_expiry), Some(b_expiry)) => a_expiry.cmp(&b_expiry),
			(Some(_), None) => Ordering::Less,
			(None, Some(_)) => Ordering::Greater,
			(None, None) => Ordering::Equal,
		});
	}

	/// Get the total balance of all credits, ignoring expiry.
	pub fn total(&self) -> Balance
	where
		Balance: Saturating,
	{
		self.balances_with_expiry
			.iter()
			.fold(Balance::zero(), |acc, x| acc.saturating_add(x.balance))
	}

	/// Expire credits that have passed their expiry time.
	pub fn expire(&mut self, now: Moment) -> usize
	where
		Moment: Saturating + PartialOrd,
	{
		let old_len = self.balances_with_expiry.len();
		self.balances_with_expiry.retain(|c| match c.expiry {
			Some(expiry) => expiry > now,
			None => true,
		});
		let new_len = self.balances_with_expiry.len();
		old_len.saturating_sub(new_len)
	}

	/// Redeem credits, starting from the ones that expire the soonest.
	/// Does not check expiry, that should be done explicitly beforehand using `expire()`.
	pub fn redeem(&mut self, mut amount: Balance) -> Result<usize, DispatchError>
	where
		Balance: Saturating + PartialOrd,
	{
		if self.total() < amount {
			return Err(DispatchError::Other("Insufficient balance"));
		}
		let old_len = self.balances_with_expiry.len();
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
		let new_len = self.balances_with_expiry.len();
		Ok(old_len.saturating_sub(new_len))
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
		type MaxEntriesPerAccount: Get<u8>;
		type Currency: ReservableCurrency<Self::AccountId>;
	}

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		CreatedClass {
			id: CreditClassId,
		},
		DestroyedClass {
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
		ClassNotEmpty,
		InvalidClassId,
		NoClaimableCredits,
		InsufficientBalance,
		TooManyEntries,
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

	#[pallet::storage]
	#[pallet::getter(fn total_deposit)]
	pub type TotalDeposit<T: Config> =
		StorageMap<_, Blake2_128Concat, CreditClassId, BalanceOf<T>, ValueQuery>;

	#[pallet::call]
	impl<T: Config> Pallet<T>
	where
		sp_core::H256: From<<T as frame_system::Config>::Hash>,
	{
		/// create a new credit class
		#[pallet::call_index(0)]
		#[pallet::weight((<T as Config>::WeightInfo::create_class(), DispatchClass::Normal, Pays::Yes)
        )]
		pub fn create_class(
			origin: OriginFor<T>,
			id: CreditClassId,
			deposit: BalanceOf<T>,
		) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;
			ensure!(!<Credits<T>>::contains_prefix(id), Error::<T>::ClassIdExists);
			T::Currency::reserve(&sender, deposit)?;
			TotalDeposit::<T>::insert(id, deposit);
			<Credits<T>>::insert(id, &sender, SortedCreditsStore::new());
			<Admin<T>>::insert(id, &sender);
			Self::deposit_event(Event::CreatedClass { id });
			Ok(().into())
		}

		/// create a new credit class
		#[pallet::call_index(1)]
		#[pallet::weight((<T as Config>::WeightInfo::create_class(), DispatchClass::Normal, Pays::Yes)
        )]
		pub fn destroy_class(
			origin: OriginFor<T>,
			id: CreditClassId,
		) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;
			ensure!(<Credits<T>>::contains_prefix(id), Error::<T>::InvalidClassId);
			let admin = Self::admin(id).ok_or(Error::<T>::ClassAdminUndefined)?;
			ensure!(admin == sender, Error::<T>::Unauthorized);
			// TODO: consider limiting to avoid overweight execution
			let _ = Credits::<T>::clear_prefix(id, u32::max_value(), None);
			let unreserve = Self::total_deposit(id);
			TotalDeposit::<T>::remove(id);
			Admin::<T>::remove(id);
			TotalMintedBy::<T>::remove(id, &admin);
			TotalRedeemedBy::<T>::remove(id, &admin);
			T::Currency::unreserve(&admin, unreserve);
			Self::deposit_event(Event::DestroyedClass { id });
			Ok(().into())
		}

		/// create a new credit class
		#[pallet::call_index(2)]
		#[pallet::weight((<T as Config>::WeightInfo::claim(), DispatchClass::Normal, Pays::Yes)
        )]
		pub fn claim(
			origin: OriginFor<T>,
			id: CreditClassId,
			secret: T::Hash,
			item_deposit: BalanceOf<T>,
		) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;
			ensure!(<Credits<T>>::contains_prefix(id), Error::<T>::InvalidClassId);
			let admin = Self::admin(id).ok_or(Error::<T>::ClassAdminUndefined)?;
			let commitment = T::Hashing::hash_of(&secret);
			let commitment_account = T::AccountId::decode(&mut H256::from(commitment).as_bytes())
				.expect("32 bytes can always construct an AccountId32");
			let mut claimables = <Credits<T>>::get(id, &commitment_account);
			let mut sender_credits = <Credits<T>>::get(id, &sender);
			ensure!(!claimables.is_empty(), Error::<T>::NoClaimableCredits);
			ensure!(
				claimables.len() + sender_credits.len() < T::MaxEntriesPerAccount::get() as usize,
				Error::<T>::TooManyEntries
			);
			let expired_count = claimables.expire(<pallet_timestamp::Pallet<T>>::get());
			if expired_count > 0 {
				let deposit =
					item_deposit.saturating_mul(BalanceOf::<T>::from(expired_count as u32));
				TotalDeposit::<T>::mutate(id, |total| *total = total.saturating_sub(deposit));
				T::Currency::unreserve(&admin, deposit);
			}
			<Credits<T>>::remove(id, &commitment_account);
			sender_credits.append(&mut claimables);
			<Credits<T>>::insert(id, &sender, sender_credits);
			Self::deposit_event(Event::Claimed { id, commitment });
			Ok(().into())
		}

		#[pallet::call_index(3)]
		#[pallet::weight((<T as Config>::WeightInfo::mint(), DispatchClass::Normal, Pays::Yes)
        )]
		pub fn mint(
			origin: OriginFor<T>,
			id: CreditClassId,
			owner: T::AccountId,
			amount: BalanceOf<T>,
			maybe_expiry: Option<T::Moment>,
			item_deposit: BalanceOf<T>,
		) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;
			ensure!(<Credits<T>>::contains_prefix(id), Error::<T>::InvalidClassId);
			let admin = Self::admin(id).ok_or(Error::<T>::ClassAdminUndefined)?;
			ensure!(admin == sender, Error::<T>::Unauthorized);
			if let Some(expiry) = maybe_expiry {
				ensure!(expiry > <pallet_timestamp::Pallet<T>>::get(), Error::<T>::ExpiryInPast);
			}
			let credit = BalanceWithExpiry { balance: amount, expiry: maybe_expiry };

			let mut credits = Self::credits(id, &owner);
			ensure!(
				credits.len() < T::MaxEntriesPerAccount::get() as usize,
				Error::<T>::TooManyEntries
			);
			let expired_count = credits.expire(<pallet_timestamp::Pallet<T>>::get());
			if expired_count > 1 {
				let deposit = item_deposit
					.saturating_mul(BalanceOf::<T>::from(expired_count.saturating_sub(1) as u32));
				TotalDeposit::<T>::mutate(id, |total| *total = total.saturating_sub(deposit));
				T::Currency::unreserve(&admin, deposit);
			} else if expired_count == 0 {
				let deposit = item_deposit;
				T::Currency::reserve(&admin, deposit)?;
				TotalDeposit::<T>::mutate(id, |total| *total = total.saturating_add(deposit));
			}
			credits.push(credit);
			Credits::<T>::insert(id, &owner, credits);
			TotalMintedBy::<T>::mutate(id, &sender, |total| *total = total.saturating_add(amount));
			Self::deposit_event(Event::Minted { id, to: owner, amount, expiry: maybe_expiry });
			Ok(().into())
		}

		#[pallet::call_index(4)]
		#[pallet::weight((<T as Config>::WeightInfo::redeem(), DispatchClass::Normal, Pays::Yes)
        )]
		pub fn redeem(
			origin: OriginFor<T>,
			id: CreditClassId,
			owner: T::AccountId,
			amount: BalanceOf<T>,
			item_deposit: BalanceOf<T>,
		) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;
			ensure!(<Credits<T>>::contains_prefix(id), Error::<T>::InvalidClassId);
			let admin = Self::admin(id).ok_or(Error::<T>::ClassAdminUndefined)?;
			ensure!(admin == sender, Error::<T>::Unauthorized);
			let mut credits = Self::credits(id, &owner);
			let expired_count = credits.expire(<pallet_timestamp::Pallet<T>>::get());
			let used_count = credits.redeem(amount).map_err(|_| Error::<T>::InsufficientBalance)?;
			let deposit = item_deposit.saturating_mul(BalanceOf::<T>::from(
				expired_count.saturating_add(used_count) as u32,
			));
			TotalDeposit::<T>::mutate(id, |total| *total = total.saturating_sub(deposit));
			T::Currency::unreserve(&admin, deposit);
			Credits::<T>::insert(id, &owner, credits);
			TotalRedeemedBy::<T>::mutate(id, &sender, |total| {
				*total = total.saturating_add(amount)
			});

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
