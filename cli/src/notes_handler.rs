/*
	Copyright 2021 Integritee AG

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

use crate::{trusted_cli::TrustedCli, trusted_operation::perform_trusted_operation, Cli};
use codec::Decode;
use ita_stf::{Getter, PublicGetter, TrustedCall, TrustedCallSigned, TrustedGetter};
use itp_stf_primitives::types::{KeyPair, TrustedOperation};
use itp_types::{AccountId, Moment};
use log::{debug, trace, warn};
use pallet_notes::{BucketIndex, BucketRange, TimestampedTrustedNote, TrustedNote};
use sp_core::sr25519 as sr25519_core;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NoteCategory {
	Other,
	ConversationWith(AccountId), // non-financial notes (chat messages)
	                             //TransfersWith(AccountId),    // native or assets
}

pub struct NotesHandler<'a> {
	cli: &'a Cli,
	trusted_args: &'a TrustedCli,
	account: AccountId,
	signer: sr25519_core::Pair,
	bucket_range: BucketRange<Moment>,
	pub last_fetched_timestamp: Moment,
	pub last_fetched_bucket_index: BucketIndex,
	pub conversation_counterparties: HashSet<AccountId>,
	notes: HashMap<NoteCategory, Vec<TimestampedTrustedNote<Moment>>>,
}

impl<'a> NotesHandler<'a> {
	pub fn new(
		cli: &'a Cli,
		trusted_args: &'a TrustedCli,
		account: AccountId,
		signer: sr25519_core::Pair,
	) -> Self {
		let bucket_range =
			get_note_buckets_info(&cli, &trusted_args).expect("Failed to get note buckets info");
		let notes = HashMap::new();
		let last_fetched_timestamp = 0u64;
		let last_fetched_bucket_index = 0u32;
		let conversation_counterparties = HashSet::new();
		NotesHandler {
			cli,
			trusted_args,
			account,
			signer,
			bucket_range,
			last_fetched_timestamp,
			last_fetched_bucket_index,
			conversation_counterparties,
			notes,
		}
	}

	pub fn fetch_history(&mut self) {
		let first_bucket_index =
			self.bucket_range.maybe_first.map(|bucket| bucket.index).unwrap_or_default();
		let last_bucket_index =
			self.bucket_range.maybe_last.map(|bucket| bucket.index).unwrap_or_default();
		for bucket_index in first_bucket_index..=last_bucket_index {
			let top = TrustedOperation::<TrustedCallSigned, Getter>::get(Getter::trusted(
				TrustedGetter::notes_for(self.account.clone(), bucket_index)
					.sign(&KeyPair::Sr25519(Box::new(self.signer.clone()))),
			));
			let maybe_notes: Option<Vec<TimestampedTrustedNote<Moment>>> =
				perform_trusted_operation(&self.cli, &self.trusted_args, &top).ok();
			maybe_notes.map(|notes| notes.iter().for_each(|note| self.store_note(note.clone())));
			self.last_fetched_bucket_index = bucket_index;
		}
	}

	pub fn update(&mut self) {
		self.bucket_range = get_note_buckets_info(&self.cli, &self.trusted_args)
			.expect("Failed to get note buckets info");
		let last_bucket_index =
			self.bucket_range.maybe_last.map(|bucket| bucket.index).unwrap_or_default();

		for bucket_index in self.last_fetched_bucket_index..=last_bucket_index {
			let last_fetched_timestamp = self.last_fetched_timestamp;
			let top = TrustedOperation::<TrustedCallSigned, Getter>::get(Getter::trusted(
				TrustedGetter::notes_for(self.account.clone(), bucket_index)
					.sign(&KeyPair::Sr25519(Box::new(self.signer.clone()))),
			));
			if let Ok(notes) = perform_trusted_operation::<Vec<TimestampedTrustedNote<Moment>>>(
				&self.cli,
				&self.trusted_args,
				&top,
			) {
				notes
					.iter()
					.filter(|&note| note.timestamp > last_fetched_timestamp)
					.for_each(|note| self.store_note(note.clone()));
			};
			self.last_fetched_bucket_index = bucket_index;
		}
	}
	fn store_note(&mut self, note: TimestampedTrustedNote<Moment>) {
		let category = match note.note {
			TrustedNote::SuccessfulTrustedCall(ref tc) => {
				let call = TrustedCall::decode(&mut tc.as_slice())
					.map_err(|e| {
						warn!("error decoding TrustedNote::SuccessfulTrustedCall: {:?}", e);
						e
					})
					.ok();
				if call.is_none() {
					return
				}
				match call.unwrap() {
					TrustedCall::send_note(from, to, msg) => {
						let counterparty =
							if from == self.account { to.clone() } else { from.clone() };
						self.conversation_counterparties.insert(counterparty.clone());
						trace!(
							"Storing note from {:?} to {:?}: {}",
							from,
							to,
							String::from_utf8_lossy(&msg)
						);
						NoteCategory::ConversationWith(counterparty)
					},
					_ => NoteCategory::Other,
				}
			},
			_ => NoteCategory::Other,
		};
		if note.timestamp > self.last_fetched_timestamp {
			self.last_fetched_timestamp = note.timestamp;
		}
		self.notes.entry(category).or_default().push(note);
	}

	pub fn conversation_with(
		&self,
		counterparty: &AccountId,
		maybe_since: Option<Moment>,
	) -> Vec<TimestampedTrustedNote<Moment>> {
		let since = maybe_since.unwrap_or_default();
		if let Some(notes) = self.notes.get(&NoteCategory::ConversationWith(counterparty.clone())) {
			notes.iter().filter(|note| note.timestamp >= since).cloned().collect()
		} else {
			Vec::new()
		}
	}

	pub fn unanswered_conversation_with(
		&self,
		counterparty: &AccountId,
		maybe_since: Option<Moment>,
	) -> Vec<TimestampedTrustedNote<Moment>> {
		let conversation = self.conversation_with(counterparty, maybe_since);
		let my_last_note = conversation
			.iter()
			.cloned()
			.filter(|note| {
				if let TrustedNote::SuccessfulTrustedCall(ref tc) = note.note {
					if let Ok(TrustedCall::send_note(from, _to, _msg)) =
						TrustedCall::decode(&mut tc.as_slice())
					{
						self.account == from
					} else {
						false
					}
				} else {
					false
				}
			})
			.last()
			.clone();
		if let Some(last_note) = my_last_note {
			conversation
				.into_iter()
				.filter(|note| note.timestamp > last_note.timestamp)
				.collect()
		} else {
			conversation
		}
	}
}

pub(crate) fn get_note_buckets_info(
	cli: &Cli,
	trusted_args: &TrustedCli,
) -> Option<BucketRange<Moment>> {
	let top = TrustedOperation::<TrustedCallSigned, Getter>::get(Getter::public(
		PublicGetter::note_buckets_info,
	));
	let maybe_bucket_range: Option<BucketRange<Moment>> =
		perform_trusted_operation(cli, trusted_args, &top).ok();
	debug!("maybe_bucket_range: {:?}", maybe_bucket_range);
	maybe_bucket_range
}
