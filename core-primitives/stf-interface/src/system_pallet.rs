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
extern crate alloc;
use alloc::{boxed::Box, vec::Vec};

/// Interface trait of the system pallet for account specific data.
pub trait SystemPalletAccountInterface<State, AccountId> {
	type Index;
	type AccountData;

	/// Get the nonce for a given account and state.
	fn get_account_nonce(state: &mut State, account_id: &AccountId) -> Self::Index;

	/// Get the account date for a given account and state.
	fn get_account_data(state: &mut State, account: &AccountId) -> Self::AccountData;
}

/// Interface trait of the system pallet for event specific interactions.
pub trait SystemPalletEventInterface<State> {
	type EventRecord;
	type EventIndex;
	type BlockNumber;
	type Hash;

	/// Get a Vec of bounded events.
	fn get_events(state: &mut State) -> Vec<Box<Self::EventRecord>>;

	/// Get the count of the currently stored events.
	fn get_event_count(state: &mut State) -> Self::EventIndex;

	/// Get the event topics
	fn get_event_topics(
		state: &mut State,
		topic: &Self::Hash,
	) -> Vec<(Self::BlockNumber, Self::EventIndex)>;

	/// Reset everything event related.
	fn reset_events(state: &mut State);
}
