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
use super::*;
use crate::{mock::*, BalanceOf, Error, Event};
use frame_support::{
	assert_err, assert_ok,
	pallet_prelude::DispatchResultWithPostInfo,
	traits::{Currency, Hooks},
};
use pallet_balances::Error as BalancesError;
use sp_keyring::AccountKeyring;
use sp_runtime::{
	traits::{Header as HeaderT, Scale},
	DispatchError,
};

const TEN_MIN: u64 = 600_000;
const ONE_DAY: u64 = 86_400_000;
const GENESIS_TIME: u64 = 1_585_058_843_000;

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
		return None
	}
	let frame_system::EventRecord { event, .. } = &events[index];
	Some(event.clone())
}

#[test]
fn sorted_credits_store_works() {
	new_test_ext().execute_with(|| {
		let mut scs = SortedCreditsStore::<BalanceOf<Test>, Moment>::new();
		assert_eq!(scs.total(), 0u64);
		assert_eq!(scs.len(), 0);

		let credit1 = BalanceWithExpiry { balance: 100u64, expiry: Some(10) };
		let credit2 = BalanceWithExpiry { balance: 50u64, expiry: Some(20) };
		let credit3 = BalanceWithExpiry { balance: 25u64, expiry: None };
		let credit4 = BalanceWithExpiry { balance: 40u64, expiry: Some(15) };

		scs.push(credit1);
		assert_eq!(scs.total(), 100u64);
		scs.push(credit2);
		assert_eq!(scs.total(), 150u64);
		scs.push(credit3);
		assert_eq!(scs.total(), 175u64);

		scs.expire(11);
		assert_eq!(scs.total(), 75u64);

		scs.push(credit4);
		assert_eq!(scs.get_balance_with_soonest_expiry(), Some(credit4));
		assert_eq!(scs.redeem(41u64), Ok(1));
		assert_eq!(
			scs.get_balance_with_soonest_expiry(),
			Some(BalanceWithExpiry { balance: 49u64, expiry: Some(20) })
		);
		assert!(scs.redeem(100u64).is_err());
		assert_eq!(scs.len(), 2);

		let mut scs2 = SortedCreditsStore::<BalanceOf<Test>, Moment>::new();
		scs2.push(credit1);
		scs2.push(credit2);
		scs.append(&mut scs2);
		assert_eq!(scs.total(), 224u64);
		assert_eq!(scs.len(), 4);
		assert_eq!(scs.redeem(224u64), Ok(4));
	});
}
#[test]
fn create_class_works() {
	new_test_ext().execute_with(|| {
		let alice = AccountKeyring::Alice.to_account_id();
		System::set_block_number(1);
		let class_id = 42u32;
		assert_ok!(Dut::create_class(RuntimeOrigin::signed(alice.clone()), class_id));
		assert_eq!(last_event::<Test>(), Some(Event::CreatedClass { id: class_id }.into()));
		assert!(Credits::<Test>::contains_prefix(class_id));
		assert_eq!(Admin::<Test>::get(class_id), Some(alice.clone()));
	});
}

#[test]
fn create_class_with_existing_id_fails() {
	new_test_ext().execute_with(|| {
		let alice = AccountKeyring::Alice.to_account_id();
		System::set_block_number(1);
		let class_id = 42u32;
		assert_ok!(Dut::create_class(RuntimeOrigin::signed(alice.clone()), class_id));
		assert_err!(
			Dut::create_class(RuntimeOrigin::signed(alice.clone()), class_id),
			Error::<Test>::ClassIdExists
		);
	});
}

#[test]
fn create_class_lacking_deposit_fails() {
	new_test_ext().execute_with(|| {
		let alice = AccountKeyring::Alice.to_account_id();
		System::set_block_number(1);
		let class_id = 42u32;
		Balances::make_free_balance_be(&alice, 9u64.into());
		assert_err!(
			Dut::create_class(RuntimeOrigin::signed(alice.clone()), class_id),
			BalancesError::<Test>::InsufficientBalance
		);
	});
}
#[test]
fn claim_works() {
	new_test_ext().execute_with(|| {
		let alice = AccountKeyring::Alice.to_account_id();
		System::set_block_number(1);
		let class_id = 42u32;
		Admin::<Test>::insert(class_id, &alice);
		let credit = BalanceWithExpiry { balance: 100u64, expiry: None };
		let mut credits = SortedCreditsStore::<BalanceOf<Test>, Moment>::new();
		credits.push(credit);

		let secret = H256::repeat_byte(1);
		let commitment = <Test as frame_system::Config>::Hashing::hash_of(&secret);
		let commitment_account = <Test as frame_system::Config>::AccountId::decode(
			&mut H256::from(commitment).as_bytes(),
		)
		.expect("32 bytes can always construct an AccountId32");

		Credits::<Test>::insert(class_id, &commitment_account, credits.clone());

		assert_ok!(Dut::claim(RuntimeOrigin::signed(alice.clone()), class_id, secret));
		assert_eq!(Dut::credits(class_id, &commitment_account).len(), 0);
		assert_eq!(Dut::credits(class_id, &alice), credits);

		assert_eq!(last_event::<Test>(), Some(Event::Claimed { id: class_id, commitment }.into()));
	});
}

#[test]
fn claim_oversize_fails() {
	new_test_ext().execute_with(|| {
		let alice = AccountKeyring::Alice.to_account_id();
		System::set_block_number(1);
		let class_id = 42u32;
		Admin::<Test>::insert(class_id, &alice);
		let mut store = SortedCreditsStore::<BalanceOf<Test>, Moment>::new();
		for _i in 0..MaxEntriesPerAccount::get() - 1 {
			store.push(BalanceWithExpiry { balance: 1u64, expiry: None });
		}

		let secret = H256::repeat_byte(1);
		let commitment = <Test as frame_system::Config>::Hashing::hash_of(&secret);
		let commitment_account = <Test as frame_system::Config>::AccountId::decode(
			&mut H256::from(commitment).as_bytes(),
		)
		.expect("32 bytes can always construct an AccountId32");

		Credits::<Test>::insert(class_id, &commitment_account, store.clone());
		Credits::<Test>::insert(class_id, &alice, store);

		assert_err!(
			Dut::claim(RuntimeOrigin::signed(alice.clone()), class_id, secret),
			Error::<Test>::TooManyEntries
		);
	});
}

#[test]
fn mint_works() {
	new_test_ext().execute_with(|| {
		let alice = AccountKeyring::Alice.to_account_id();
		let bob = AccountKeyring::Bob.to_account_id();
		System::set_block_number(1);
		set_timestamp(GENESIS_TIME);
		let class_id = 42u32;
		Credits::<Test>::insert(class_id, &alice, SortedCreditsStore::new());
		Admin::<Test>::insert(class_id, &alice);

		let balance = 100u64;
		let expiry = Some(GENESIS_TIME + ONE_DAY);
		assert_ok!(Dut::mint(
			RuntimeOrigin::signed(alice.clone()),
			class_id,
			bob.clone(),
			balance,
			expiry
		));
		assert_eq!(
			last_event::<Test>(),
			Some(Event::Minted { id: class_id, to: bob.clone(), amount: balance, expiry }.into())
		);
		let expected_credit = BalanceWithExpiry { balance, expiry };
		let mut expected_credits = SortedCreditsStore::<BalanceOf<Test>, Moment>::new();
		expected_credits.push(expected_credit);
		assert_eq!(Dut::credits(class_id, &bob), expected_credits);
		assert_eq!(Dut::total_minted_by(class_id, &alice), balance);
	});
}

#[test]
fn mint_lacking_deposit_fails() {
	new_test_ext().execute_with(|| {
		let alice = AccountKeyring::Alice.to_account_id();
		let bob = AccountKeyring::Bob.to_account_id();
		System::set_block_number(1);
		set_timestamp(GENESIS_TIME);
		let class_id = 42u32;
		Credits::<Test>::insert(class_id, &alice, SortedCreditsStore::new());
		Admin::<Test>::insert(class_id, &alice);
		Balances::make_free_balance_be(&alice, 0u64.into());

		let balance = 100u64;
		assert_err!(
			Dut::mint(RuntimeOrigin::signed(alice.clone()), class_id, bob.clone(), balance, None),
			BalancesError::<Test>::InsufficientBalance
		);
	});
}

#[test]
fn mint_oversize_fails() {
	new_test_ext().execute_with(|| {
		let alice = AccountKeyring::Alice.to_account_id();
		let bob = AccountKeyring::Bob.to_account_id();
		System::set_block_number(1);
		let class_id = 42u32;
		Admin::<Test>::insert(class_id, &alice);
		let mut store = SortedCreditsStore::<BalanceOf<Test>, Moment>::new();
		for _i in 0..MaxEntriesPerAccount::get() {
			store.push(BalanceWithExpiry { balance: 1u64, expiry: None });
		}
		Credits::<Test>::insert(class_id, &bob, store);

		assert_err!(
			Dut::mint(RuntimeOrigin::signed(alice.clone()), class_id, bob.clone(), 1u64, None),
			Error::<Test>::TooManyEntries
		);
	});
}

#[test]
fn redeem_works() {
	new_test_ext().execute_with(|| {
		let alice = AccountKeyring::Alice.to_account_id();
		let bob = AccountKeyring::Bob.to_account_id();
		System::set_block_number(1);

		let class_id = 42u32;
		Admin::<Test>::insert(class_id, &alice);
		let balance = 50u64;
		let credit = BalanceWithExpiry { balance: 2 * balance, expiry: None };
		let mut credits = SortedCreditsStore::<BalanceOf<Test>, Moment>::new();
		credits.push(credit);
		assert_eq!(credits.total(), 100u64);
		Credits::<Test>::insert(class_id, &bob, credits.clone());

		assert_ok!(Dut::redeem(
			RuntimeOrigin::signed(alice.clone()),
			class_id,
			bob.clone(),
			balance,
		));
		assert_eq!(
			last_event::<Test>(),
			Some(Event::Redeemed { id: class_id, from: bob.clone(), amount: balance }.into())
		);
		let expected_credit = BalanceWithExpiry { balance, expiry: None };
		let mut expected_credits = SortedCreditsStore::<BalanceOf<Test>, Moment>::new();
		expected_credits.push(expected_credit);
		assert_eq!(Dut::credits(class_id, &bob), expected_credits);
		assert_eq!(Dut::total_redeemed_by(class_id, &alice), balance);
		assert_ok!(Dut::redeem(
			RuntimeOrigin::signed(alice.clone()),
			class_id,
			bob.clone(),
			balance,
		));
		assert_eq!(Dut::total_redeemed_by(class_id, &alice), 2 * balance);

		assert_err!(
			Dut::redeem(RuntimeOrigin::signed(alice.clone()), class_id, bob.clone(), balance,),
			Error::<Test>::InsufficientBalance
		);
	});
}

#[test]
fn deposits_work() {
	new_test_ext().execute_with(|| {
		let alice = AccountKeyring::Alice.to_account_id();
		let bob = AccountKeyring::Bob.to_account_id();
		System::set_block_number(1);
		let class_id = 42u32;
		assert_ok!(Dut::create_class(RuntimeOrigin::signed(alice.clone()), class_id));
		assert_eq!(Balances::reserved_balance(&alice), 10u64);

		assert_ok!(Dut::mint(
			RuntimeOrigin::signed(alice.clone()),
			class_id,
			bob.clone(),
			100u64,
			None
		));
		assert_eq!(Balances::reserved_balance(&alice), 11u64);

		assert_ok!(Dut::redeem(RuntimeOrigin::signed(alice.clone()), class_id, bob.clone(), 50u64));
		assert_eq!(Balances::reserved_balance(&alice), 11u64);

		assert_ok!(Dut::redeem(RuntimeOrigin::signed(alice.clone()), class_id, bob.clone(), 50u64));
		assert_eq!(Balances::reserved_balance(&alice), 10u64);
		assert_eq!(TotalDeposit::<Test>::get(class_id), 10u64);

		assert_ok!(Dut::destroy_class(RuntimeOrigin::signed(alice.clone()), class_id));
		assert_eq!(Balances::reserved_balance(&alice), 0u64);
	});
}
