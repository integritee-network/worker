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
use crate::{mock::*, Error, Event as RaffleEvent, Raffle};
use frame_support::{assert_err, assert_noop, assert_ok};
use frame_system::AccountInfo;
use pallet_balances::AccountData;
use sp_core::H256;
use sp_keyring::AccountKeyring;
use sp_runtime::{
	generic,
	traits::{BlakeTwo256, Header as HeaderT},
	DispatchError::BadOrigin,
};

mod add_raffle {
	use super::*;
	use crate::{OnGoingRaffles, Raffle};
	use frame_support::assert_ok;
	use sp_keyring::AccountKeyring;

	#[test]
	fn add_raffle_works() {
		new_test_ext().execute_with(|| {
			let winner_count = 1;
			assert_ok!(Raffles::add_raffle(
				RuntimeOrigin::signed(AccountKeyring::Alice.into()),
				winner_count
			));

			let expected_raffle =
				Raffle { owner: AccountKeyring::Alice.to_account_id(), winner_count };
			System::assert_last_event(RuntimeEvent::Raffles(RaffleEvent::RaffleAdded {
				index: 0,
				raffle: expected_raffle.clone(),
			}));

			assert_eq!(Raffles::ongoing_raffles(0).unwrap(), expected_raffle)
		})
	}
}

mod register_for_raffle {
	use super::*;
	use crate::Raffle;
	use frame_support::assert_ok;
	use sp_keyring::AccountKeyring;

	#[test]
	fn register_for_raffle_works() {
		new_test_ext().execute_with(|| {
			let winner_count = 1;
			assert_ok!(Raffles::add_raffle(
				RuntimeOrigin::signed(AccountKeyring::Alice.into()),
				winner_count
			));

			let raffle_index = 0;

			// register bob for raffle and ensure he is signed up
			assert_ok!(Raffles::register_for_raffle(
				RuntimeOrigin::signed(AccountKeyring::Bob.into()),
				raffle_index
			));
			System::assert_last_event(RuntimeEvent::Raffles(RaffleEvent::RaffleRegistration {
				who: AccountKeyring::Bob.to_account_id(),
				index: raffle_index,
			}));
			assert_eq!(Raffles::raffle_registrations(0), vec![AccountKeyring::Bob.to_account_id()]);

			// register charlie for raffle and ensure charlie and bob is signed up
			assert_ok!(Raffles::register_for_raffle(
				RuntimeOrigin::signed(AccountKeyring::Charlie.into()),
				raffle_index
			));
			System::assert_last_event(RuntimeEvent::Raffles(RaffleEvent::RaffleRegistration {
				who: AccountKeyring::Charlie.to_account_id(),
				index: raffle_index,
			}));
			assert_eq!(
				Raffles::raffle_registrations(0),
				vec![AccountKeyring::Bob.to_account_id(), AccountKeyring::Charlie.to_account_id(),]
			);
		})
	}
}
