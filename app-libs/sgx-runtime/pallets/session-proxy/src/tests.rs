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
use crate::{mock::*, SessionProxyCredentials, SessionProxyRole};

use frame_support::{assert_ok, pallet_prelude::DispatchResultWithPostInfo, traits::Hooks};

use sp_keyring::AccountKeyring;
use sp_runtime::DispatchError;

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
fn add_proxy_works() {
	new_test_ext().execute_with(|| {
		System::set_block_number(0);
		let now: u64 = 234;
		set_timestamp(now);
		let alice = AccountKeyring::Alice.to_account_id();
		let bob = AccountKeyring::Bob.to_account_id();
		let credentials =
			SessionProxyCredentials { role: SessionProxyRole::Any, expiry: None, seed: [0u8; 32] };
		let deposit = Balance::from(10u32);

		assert_ok!(SessionProxy::add_proxy(
			RuntimeOrigin::signed(alice.clone()),
			bob.clone(),
			credentials.clone(),
			deposit
		));
		assert_eq!(
			SessionProxy::session_proxies(alice.clone(), bob.clone()),
			Some((credentials, deposit))
		);
		assert_eq!(Balances::reserved_balance(alice.clone()), deposit);

		// make sure overwrite happens if adding again but updates deposit
		let credentials = SessionProxyCredentials {
			role: SessionProxyRole::NonTransfer,
			expiry: None,
			seed: [0u8; 32],
		};
		let new_deposit = Balance::from(5u32);
		assert_ok!(SessionProxy::add_proxy(
			RuntimeOrigin::signed(alice.clone()),
			bob.clone(),
			credentials.clone(),
			new_deposit
		));
		assert_eq!(
			SessionProxy::session_proxies(alice.clone(), bob.clone()),
			Some((credentials, new_deposit))
		);
		assert_eq!(Balances::reserved_balance(alice.clone()), new_deposit);
	})
}

#[test]
fn remove_proxy_works() {
	new_test_ext().execute_with(|| {
		System::set_block_number(0);
		let now: u64 = 234;
		set_timestamp(now);
		let alice = AccountKeyring::Alice.to_account_id();
		let bob = AccountKeyring::Bob.to_account_id();
		let role = SessionProxyRole::Any;
		let credentials = SessionProxyCredentials { role, expiry: None, seed: [0u8; 32] };

		assert_ok!(SessionProxy::add_proxy(
			RuntimeOrigin::signed(alice.clone()),
			bob.clone(),
			credentials.clone(),
			9999
		));
		assert_eq!(
			SessionProxy::session_proxies(alice.clone(), bob.clone()),
			Some((credentials, 9999))
		);

		assert_ok!(SessionProxy::remove_proxy(RuntimeOrigin::signed(alice.clone()), bob.clone(),));
		// unreserve should happen
		assert_eq!(Balances::reserved_balance(alice.clone()), 0);
	})
}
