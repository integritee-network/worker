#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode};
use frame_support::{
	ensure,
	pallet_prelude::Get,
	traits::{Currency, ReservableCurrency},
};
pub use pallet::*;
use scale_info::TypeInfo;
use sp_std::{vec, vec::Vec};
pub type BalanceOf<T> =
	<<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

#[derive(Encode, Decode, Clone, PartialEq, Eq, sp_core::RuntimeDebug, TypeInfo)]
pub struct SessionProxyCredentials<Balance> {
	pub role: SessionProxyRole<Balance>,
	pub expiry: Option<u64>,
	pub seed: [u8; 32],
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, sp_core::RuntimeDebug, TypeInfo)]
pub enum SessionProxyRole<Balance> {
	/// can only read balance for proxied account
	ReadBalance,
	/// can read all state for proxied account
	ReadAny,
	/// can perform all actions except token transfers on behalf of proxied account.
	NonTransfer,
	/// can perform all actions on behalf of proxied account
	Any,
	/// can only perform transfers up to a cumulative limit and read balance.
	TransferAllowance(Balance),
}

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;
	use sp_std::cmp::Ordering;

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

		type Currency: ReservableCurrency<Self::AccountId>;

		#[pallet::constant]
		type MaxProxiesPerOwner: Get<u8>;
	}

	#[pallet::error]
	pub enum Error<T> {
		SelfProxyForbidden,
		TooManyProxies,
	}

	#[pallet::storage]
	#[pallet::getter(fn session_proxies)]
	pub type SessionProxies<T: Config> = StorageDoubleMap<
		_,
		Blake2_128Concat,
		T::AccountId,
		Blake2_128Concat,
		T::AccountId,
		(SessionProxyCredentials<BalanceOf<T>>, BalanceOf<T>),
		OptionQuery,
	>;

	#[pallet::call]
	impl<T: Config> Pallet<T>
	where
		sp_core::H256: From<<T as frame_system::Config>::Hash>,
	{
		#[pallet::call_index(0)]
		#[pallet::weight((10_000, DispatchClass::Normal, Pays::Yes))]
		pub fn add_proxy(
			origin: OriginFor<T>,
			delegate: T::AccountId,
			credentials: SessionProxyCredentials<BalanceOf<T>>,
			deposit: BalanceOf<T>,
		) -> DispatchResultWithPostInfo {
			let delegator = ensure_signed(origin)?;
			ensure!(delegator != delegate, Error::<T>::SelfProxyForbidden);
			if let Some(old_deposit) =
				Self::session_proxies(&delegator, &delegate).map(|(_, deposit)| deposit)
			{
				//updating an existing delegate with potentially different deposit
				match deposit.cmp(&old_deposit) {
					Ordering::Greater => T::Currency::reserve(&delegator, deposit - old_deposit)?,
					Ordering::Less => _ = T::Currency::unreserve(&delegator, old_deposit - deposit),
					_ => (),
				}
			} else {
				// adding a new delegate
				let num_proxies_pre = SessionProxies::<T>::iter_prefix(&delegator).count();
				ensure!(
					num_proxies_pre < T::MaxProxiesPerOwner::get() as usize,
					Error::<T>::TooManyProxies
				);
				T::Currency::reserve(&delegator, deposit)?;
			};
			SessionProxies::<T>::insert(&delegator, &delegate, (credentials, deposit));
			Ok(().into())
		}

		#[pallet::call_index(1)]
		#[pallet::weight((10_000, DispatchClass::Normal, Pays::Yes))]
		pub fn remove_proxy(
			origin: OriginFor<T>,
			delegate: T::AccountId,
		) -> DispatchResultWithPostInfo {
			let delegator = ensure_signed(origin)?;
			if let Some((_, deposit)) = SessionProxies::<T>::get(&delegator, &delegate) {
				T::Currency::unreserve(&delegator, deposit);
				SessionProxies::<T>::remove(&delegator, &delegate);
			}
			Ok(().into())
		}
	}
}

impl<T: Config> Pallet<T> {
	pub fn get_all_proxy_credentials_for(
		owner: &T::AccountId,
	) -> Vec<SessionProxyCredentials<BalanceOf<T>>> {
		SessionProxies::<T>::iter_prefix(owner)
			.map(|(_key, (value, _deposit))| value)
			.collect()
	}
}
#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;
