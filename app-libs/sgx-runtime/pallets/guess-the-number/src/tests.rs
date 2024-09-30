/*
	Copyright 2021 Integritee AG and Supercomputing Systems AG

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

		http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.

*/
use crate::{mock::*, Error, Event};
use frame_support::{assert_err, assert_noop, assert_ok};
use frame_support::pallet_prelude::DispatchResultWithPostInfo;
use frame_support::traits::Hooks;
use frame_system::AccountInfo;
use pallet_balances::AccountData;
use sp_core::H256;
use sp_keyring::AccountKeyring;
use sp_runtime::{generic, traits::{BlakeTwo256, Header as HeaderT}, DispatchError, DispatchError::BadOrigin};
use sp_runtime::traits::Scale;

const TEN_MIN: u64 = 600_000;
const ONE_DAY: u64 = 86_400_000;

/// Run until a particular block.
pub fn run_to_block(n: u64) {
    while System::block_number() < n {
        if System::block_number() > 1 {
            System::on_finalize(System::block_number());
        }
        Timestamp::on_finalize(System::block_number());
        System::set_block_number(System::block_number() + 1);
        System::on_initialize(System::block_number());
    }
}

pub fn set_timestamp(t: u64) {
    let _ = pallet_timestamp::Pallet::<Test>::set(RuntimeOrigin::none(), t);
}

pub fn assert_dispatch_err(actual: DispatchResultWithPostInfo, expected: DispatchError) {
    assert_eq!(actual.unwrap_err().error, expected)
}

pub fn get_num_events<T: frame_system::Config>() -> usize {
    frame_system::Pallet::<T>::events().len()
}
pub fn events<T: frame_system::Config>() -> Vec<T::RuntimeEvent> {
    let events = frame_system::Pallet::<T>::events()
        .into_iter()
        .map(|evt| evt.event)
        .collect::<Vec<_>>();
    frame_system::Pallet::<T>::reset_events();
    events
}
pub fn last_event<T: frame_system::Config>() -> Option<T::RuntimeEvent> {
    event_at_index::<T>(get_num_events::<T>() - 1)
}

pub fn event_at_index<T: frame_system::Config>(index: usize) -> Option<T::RuntimeEvent> {
    let events = frame_system::Pallet::<T>::events();
    if events.len() < index {
        return None;
    }
    let frame_system::EventRecord { event, .. } = &events[index];
    Some(event.clone())
}
#[test]
fn round_progression_works() {
    new_test_ext().execute_with(|| {
        System::set_block_number(System::block_number() + 1); // this is needed to assert events
        assert!(true)
    })
}

#[test]
fn push_by_one_day_errs_with_bad_origin() {
    new_test_ext().execute_with(|| {
        assert_dispatch_err(
            GuessTheNumber::push_by_one_day(RuntimeOrigin::signed(AccountKeyring::Bob.into())),
            DispatchError::BadOrigin,
        );
    });
}

#[test]
fn timestamp_callback_works() {
    new_test_ext().execute_with(|| {
        //large offset since 1970 to when first block is generated
        const GENESIS_TIME: u64 = 1_585_058_843_000;
        const ONE_DAY: u64 = 86_400_000;
        System::set_block_number(0);

        set_timestamp(GENESIS_TIME);

        assert_eq!(GuessTheNumber::current_round_index(), 1);
        assert_eq!(
            GuessTheNumber::next_round_timestamp(),
            (GENESIS_TIME - GENESIS_TIME.rem(ONE_DAY)) + ONE_DAY
        );

        run_to_block(1);
        set_timestamp(GENESIS_TIME + ONE_DAY);
        assert_eq!(GuessTheNumber::current_round_index(), 2);

        run_to_block(2);
        set_timestamp(GENESIS_TIME + 2 * ONE_DAY);
        assert_eq!(GuessTheNumber::current_round_index(), 3);
    });
}

#[test]
fn push_one_day_works() {
    new_test_ext().execute_with(|| {
        System::set_block_number(System::block_number() + 1); // this is needed to assert events
        let genesis_time: u64 = 0 * TEN_MIN + 1;

        System::set_block_number(0);
        set_timestamp(genesis_time);

        assert_eq!(
            GuessTheNumber::next_round_timestamp(),
            (genesis_time - genesis_time.rem(ONE_DAY)) + ONE_DAY
        );


        run_to_block(1);
        set_timestamp(genesis_time + TEN_MIN);

        assert_ok!(GuessTheNumber::push_by_one_day(RuntimeOrigin::signed(master())));

        assert_eq!(last_event::<Test>(), Some(Event::RoundSchedulePushedByOneDay.into()));
        assert_eq!(
            GuessTheNumber::next_round_timestamp(),
            (genesis_time - genesis_time.rem(ONE_DAY)) + 2 * ONE_DAY
        );
    });
}
