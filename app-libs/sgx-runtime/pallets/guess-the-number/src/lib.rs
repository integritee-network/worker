#![cfg_attr(not(feature = "std"), no_std)]

use codec::Decode;
use frame_support::dispatch::DispatchResult;
use frame_support::pallet_prelude::Get;
use frame_support::traits::{ConstU8, Currency, ExistenceRequirement, OnTimestampSet};
use frame_support::PalletId;
use log::{info, warn};
use sp_core::H256;
use sp_runtime::traits::{CheckedDiv, Hash, Saturating, Zero};
use sp_std::{ops::Rem, cmp::min};
use itp_randomness::Randomness;
use sp_runtime::SaturatedConversion;

pub use pallet::*;

pub type BalanceOf<T> =
<<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

pub type GuessType = u32;
pub type RoundIndexType = u32;


#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use crate::{weights::WeightInfo};
    use frame_support::{pallet_prelude::*};
    use frame_system::{pallet_prelude::*};
    use sp_runtime::traits::{Zero};

    const STORAGE_VERSION: StorageVersion = StorageVersion::new(1);
    #[pallet::pallet]
    #[pallet::storage_version(STORAGE_VERSION)]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(PhantomData<T>);

    /// Configuration trait.
    #[pallet::config]
    pub trait Config: frame_system::Config + pallet_timestamp::Config {
        type RuntimeEvent: From<Event<Self>>
        + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        type WeightInfo: WeightInfo;

        #[pallet::constant]
        type MomentsPerDay: Get<Self::Moment>;

        #[pallet::constant]
        type RoundDuration: Get<Self::Moment>;

        /// Required origin to interfere with the scheduling (though can always be Root)
        type GameMaster: EnsureOrigin<Self::RuntimeOrigin>;

        /// random source and tooling
        type Randomness: Randomness;

        type Currency: Currency<Self::AccountId>;
        /// The pallet id, used for deriving technical account ID for the pot.
        #[pallet::constant]
        type PalletId: Get<PalletId>;

        #[pallet::constant]
        type MaxAttempts: Get<u8>;

        #[pallet::constant]
        type MaxWinners: Get<u8>;
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        RoundSchedulePushedByOneDay,
    }

    #[pallet::error]
    pub enum Error<T> {
        NoDrawYet,
        TooManyAttempts,
        TooManyWinners,
    }

    #[pallet::storage]
    #[pallet::getter(fn current_round_index)]
    pub(super) type CurrentRoundIndex<T: Config> =
    StorageValue<_, RoundIndexType, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn lucky_number)]
    pub(super) type LuckyNumber<T: Config> =
    StorageValue<_, GuessType, OptionQuery>;

    #[pallet::storage]
    #[pallet::getter(fn guess_attempts)]
    pub(super) type GuessAttempts<T: Config> =
    StorageMap<_, Blake2_128Concat, T::AccountId, u8, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn last_winning_distance)]
    pub(super) type LastWinningDistance<T: Config> =
    StorageValue<_, GuessType, OptionQuery>;
    #[pallet::storage]
    #[pallet::getter(fn winning_distance)]
    pub(super) type WinningDistance<T: Config> =
    StorageValue<_, GuessType, OptionQuery>;

    #[pallet::storage]
    #[pallet::getter(fn last_winners)]
    pub(super) type LastWinners<T: Config> =
    StorageValue<_, Vec<T::AccountId>, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn winners)]
    pub(super) type Winners<T: Config> =
    StorageValue<_, Vec<T::AccountId>, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn winnings)]
    pub(super) type Winnings<T: Config> =
    StorageValue<_, BalanceOf<T>, ValueQuery>;

    #[pallet::type_value]
    pub(super) fn DefaultForNextRoundTimestamp<T: Config>() -> T::Moment {
        T::Moment::zero()
    }

    #[pallet::storage]
    #[pallet::getter(fn next_round_timestamp)]
    pub(super) type NextRoundTimestamp<T: Config> =
    StorageValue<_, T::Moment, ValueQuery, DefaultForNextRoundTimestamp<T>>;

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Push next round by one entire day
        ///
        /// May only be called from `T::GameMaster`.
        #[pallet::call_index(0)]
        #[pallet::weight((<T as Config>::WeightInfo::push_by_one_day(), DispatchClass::Normal, Pays::Yes)
        )]
        pub fn push_by_one_day(origin: OriginFor<T>) -> DispatchResultWithPostInfo {
            T::GameMaster::ensure_origin(origin)?;
            let tnext = Self::next_round_timestamp().saturating_add(T::MomentsPerDay::get());
            <NextRoundTimestamp<T>>::put(tnext);
            Self::deposit_event(Event::RoundSchedulePushedByOneDay);
            Ok(().into())
        }

        #[pallet::call_index(1)]
        #[pallet::weight((<T as Config>::WeightInfo::guess(), DispatchClass::Normal, Pays::Yes)
        )]
        pub fn guess(origin: OriginFor<T>, guess: GuessType) -> DispatchResultWithPostInfo {
            let sender = ensure_signed(origin)?;
            ensure!(Self::guess_attempts(&sender) < T::MaxAttempts::get(), Error::<T>::TooManyAttempts);
            let lucky_number = <LuckyNumber<T>>::get().ok_or_else(|| Error::<T>::NoDrawYet)?;
            let distance = GuessType::abs_diff(lucky_number, guess);
            if distance <= Self::winning_distance().unwrap_or(GuessType::MAX) {
                <WinningDistance<T>>::put(distance);
                let mut winners = <Winners<T>>::get();
                ensure!(winners.len() < T::MaxWinners::get() as usize, Error::<T>::TooManyWinners);
                if !winners.contains(&sender) {
                    winners.push(sender.clone());
                    Winners::<T>::put(winners);
                }
            }
            Ok(().into())
        }
    }
}

impl<T: Config> Pallet<T>
where
    sp_core::H256: From<<T as frame_system::Config>::Hash>,
{
    pub fn get_pot_account() -> T::AccountId {
        let pot_identifier = <T as Config>::PalletId::get();
        let pot_id_hash: H256 = T::Hashing::hash_of(&pot_identifier.0.as_slice()).into();
        T::AccountId::decode(&mut pot_id_hash.as_bytes())
            .expect("32 bytes can always construct an AccountId32")
    }

    pub fn payout_winners() {
        let pot = Self::get_pot_account();
        let winners = Self::winners();
        let winnings = min(Self::winnings(), T::Currency::free_balance(&pot));
        let winnings_per_winner = winnings.checked_div(&BalanceOf::<T>::saturated_from(winners.len() as u32)).unwrap_or_default();

        for winner in winners {
            if T::Currency::transfer(&pot, &winner, winnings_per_winner, ExistenceRequirement::AllowDeath).is_err() {
                warn!("error transferring reards")
            };
        }
    }

    fn progress_round() -> DispatchResult {
        let current_round_index = <CurrentRoundIndex<T>>::get();
        let last_round_timestamp = Self::next_round_timestamp();

        Self::end_round()?;

        let next_round_index = current_round_index.saturating_add(1);
        <CurrentRoundIndex<T>>::put(next_round_index);
        info!("new round with index {}", next_round_index);

        let next = last_round_timestamp.saturating_add(T::RoundDuration::get());
        <NextRoundTimestamp<T>>::put(next);

        Self::start_round()
    }

    fn end_round() -> DispatchResult {
        let current_round_index = <CurrentRoundIndex<T>>::get();
        info!("ending round {}", current_round_index);
        Self::payout_winners();
        <LastWinners<T>>::put(Self::winners());
        <Winners<T>>::kill();
        <LastWinningDistance<T>>::put(Self::winning_distance().unwrap_or(GuessType::MAX));
        <WinningDistance<T>>::kill();

        Ok(())
    }

    fn start_round() -> DispatchResult {
        let current_round_index = <CurrentRoundIndex<T>>::get();
        info!("starting round {}", current_round_index);

        let lucky_number = T::Randomness::random_u32(0, 10_000);
        // todo: delete this log
        info!("winning number:  {}", lucky_number);
        <LuckyNumber<T>>::put(lucky_number);
        Ok(())
    }
}
impl<T: Config> OnTimestampSet<T::Moment> for Pallet<T>
where
    sp_core::H256: From<<T as frame_system::Config>::Hash>,
{
    fn on_timestamp_set(now: T::Moment) {
        if Self::next_round_timestamp() == T::Moment::zero() {
            // only executed in first block after genesis.

            // in case we upgrade from a runtime that didn't have this pallet or other curiosities
            if <CurrentRoundIndex<T>>::get() == 0 {
                <CurrentRoundIndex<T>>::put(1);
            }

            // set phase start to 0:00 UTC on the day of genesis
            let next = (now - now.rem(T::MomentsPerDay::get()))
                .saturating_add(T::RoundDuration::get());
            <NextRoundTimestamp<T>>::put(next);
            if Self::start_round().is_err() {
                warn!("start first round failed")
            };
        } else if Self::next_round_timestamp() < now && Self::progress_round().is_err() {
            warn!("progress round phase failed");
        };
    }
}
#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;
pub mod weights;
