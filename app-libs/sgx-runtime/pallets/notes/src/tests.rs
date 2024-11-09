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
use crate::{
	mock::*, BalanceOf, BucketInfo, Buckets, Config, Error, TimestampedTrustedNote, TrustedNote,
};
use codec::Encode;
use frame_support::{
	assert_err, assert_ok,
	pallet_prelude::{DispatchResultWithPostInfo, Get},
	traits::{Currency, Hooks},
};

use crate::pallet::{ClosedBucketsSize, FirstBucketIndex, LastBucketIndex};
use ita_stf::TrustedCall;
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
fn new_bucket_works() {
	new_test_ext().execute_with(|| {
		let bucket = Notes::new_bucket(0).unwrap();
		assert_eq!(bucket.index, 0);
		assert_eq!(bucket.bytes, 0);

		let bucket2 = Notes::new_bucket(1).unwrap();
		assert_eq!(bucket2.index, 1);
		assert_eq!(bucket2.bytes, 0);
	});
}
#[test]
fn get_bucket_with_room_for_works() {
	new_test_ext().execute_with(|| {
		let bucket = BucketInfo {
			index: 0,
			bytes: MaxBucketSize::get() - 500,
			begins_at: Default::default(),
			ends_at: Default::default(),
		};
		<Buckets<Test>>::insert(0, bucket);
		<LastBucketIndex<Test>>::put(0);
		assert_eq!(Notes::get_bucket_with_room_for(500).unwrap().index, 0);
		assert_eq!(Notes::last_bucket_index(), Some(0));
		assert_eq!(Notes::first_bucket_index(), Some(0));
		let new_bucket = Notes::get_bucket_with_room_for(512).unwrap();
		assert_eq!(new_bucket.index, 1);
		assert_eq!(new_bucket.bytes, 0);
		assert_eq!(Notes::last_bucket_index(), Some(1));
		assert_eq!(Notes::first_bucket_index(), Some(0));
	});
}

#[test]
fn enforce_retention_limits_works() {
	new_test_ext().execute_with(|| {
		let first_bucket_size = MaxBucketSize::get() - 500;
		let bucket = BucketInfo {
			index: 0,
			bytes: first_bucket_size,
			begins_at: Default::default(),
			ends_at: Default::default(),
		};

		<Buckets<Test>>::insert(0, bucket);
		<LastBucketIndex<Test>>::put(0);
		<FirstBucketIndex<Test>>::put(0);
		Notes::enforce_retention_limits(99).unwrap();
		assert_eq!(Notes::last_bucket_index(), Some(0));
		assert_eq!(Notes::first_bucket_index(), Some(0));

		let closed_buckets_size = MaxTotalSize::get() - MaxBucketSize::get() + 1;
		<ClosedBucketsSize<Test>>::put(closed_buckets_size);

		assert_eq!(Notes::get_bucket_with_room_for(500).unwrap().index, 0);

		let new_bucket = Notes::get_bucket_with_room_for(512).unwrap();
		assert_eq!(new_bucket.index, 1);
		assert_eq!(new_bucket.bytes, 0);
		assert_eq!(Notes::last_bucket_index(), Some(1));
		assert_eq!(Notes::first_bucket_index(), Some(1));
		assert!(Notes::buckets(0).is_none());
		assert_eq!(Notes::closed_buckets_size(), closed_buckets_size - first_bucket_size);
	});
}

#[test]
fn note_trusted_call_works() {
	new_test_ext().execute_with(|| {
		System::set_block_number(0);
		let now: u64 = 234;
		set_timestamp(now);
		let alice = AccountKeyring::Alice.to_account_id();
		let bob = AccountKeyring::Bob.to_account_id();
		let call = TrustedCall::balance_transfer(bob.clone(), alice.clone(), 0);
		assert_ok!(Notes::note_trusted_call(
			RuntimeOrigin::signed(bob.clone()),
			[bob.clone(), alice.clone()].into(),
			call.encode()
		));
		assert_eq!(Notes::notes_lookup(0, alice.clone()), vec![0]);
		assert_eq!(Notes::notes_lookup(0, bob.clone()), vec![0]);
		let expected_note = TimestampedTrustedNote::<Moment> {
			timestamp: now,
			version: 1,
			note: TrustedNote::SuccessfulTrustedCall(call.encode()),
		};
		assert_eq!(Notes::notes(0, 0), Some(expected_note.clone()));
		let bucket = Notes::buckets(0).unwrap();
		assert_eq!(bucket.bytes, expected_note.encoded_size() as u32);

		let charlie = AccountKeyring::Charlie.to_account_id();
		let call2 = TrustedCall::balance_transfer(charlie.clone(), alice.clone(), 42);
		assert_ok!(Notes::note_trusted_call(
			RuntimeOrigin::signed(charlie.clone()),
			[charlie.clone(), alice.clone()].into(),
			call2.encode()
		));
		assert_eq!(Notes::notes_lookup(0, alice.clone()), vec![0, 1]);
		assert_eq!(Notes::notes_lookup(0, bob.clone()), vec![0]);
		assert_eq!(Notes::notes_lookup(0, charlie.clone()), vec![1]);
		assert_eq!(
			Notes::notes(0, 1),
			Some(TimestampedTrustedNote::<Moment> {
				timestamp: now,
				version: 1,
				note: TrustedNote::SuccessfulTrustedCall(call2.encode())
			})
		);

		let call3 = TrustedCall::noop(charlie.clone());
		assert_ok!(Notes::note_trusted_call(
			RuntimeOrigin::signed(charlie.clone()),
			[charlie.clone()].into(),
			call3.encode()
		));
		assert_eq!(Notes::notes_lookup(0, alice.clone()), vec![0, 1]);
		assert_eq!(Notes::notes_lookup(0, bob.clone()), vec![0]);
		assert_eq!(Notes::notes_lookup(0, charlie.clone()), vec![1, 2]);
		assert_eq!(
			Notes::notes(0, 2),
			Some(TimestampedTrustedNote::<Moment> {
				timestamp: now,
				version: 1,
				note: TrustedNote::SuccessfulTrustedCall(call3.encode())
			})
		);
	})
}
