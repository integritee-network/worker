#![cfg_attr(not(feature = "std"), no_std)]

use frame_support::dispatch::DispatchResult;
use frame_support::pallet_prelude::Get;
use frame_support::traits::OnTimestampSet;
use log::{info, warn};
use sp_runtime::traits::{Saturating, Zero};
use sp_std::{ops::Rem};
use itp_randomness::Randomness;
pub use pallet::*;

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
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        RoundSchedulePushedByOneDay,
    }

    #[pallet::error]
    pub enum Error<T> {}

    #[pallet::storage]
    #[pallet::getter(fn parent_hash)]
    pub(super) type ParentHash<T: Config> =
    StorageValue<_, T::Hash, OptionQuery>;

    #[pallet::storage]
    #[pallet::getter(fn current_round_index)]
    pub(super) type CurrentRoundIndex<T: Config> =
    StorageValue<_, u32, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn winning_number)]
    pub(super) type WinningNumber<T: Config> =
    StorageValue<_, u32, ValueQuery>;


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
    }
}

impl<T: Config> Pallet<T> {
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
        Ok(())
    }

    fn start_round() -> DispatchResult {
        let current_round_index = <CurrentRoundIndex<T>>::get();
        info!("starting round {}", current_round_index);
        let winning_number = T::Randomness::random_u32(0, 10_000);
        // todo: delete this log
        info!("winning number:  {}", winning_number);
        <WinningNumber<T>>::put(winning_number);
        Ok(())
    }

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
        } else if Self::next_round_timestamp() < now && Self::progress_round().is_err() {
            warn!("progress ceremony phase failed");
        };
    }
}
impl<T: Config> OnTimestampSet<T::Moment> for Pallet<T> {
    fn on_timestamp_set(moment: T::Moment) {
        Self::on_timestamp_set(moment)
    }
}
#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;
pub mod weights;
